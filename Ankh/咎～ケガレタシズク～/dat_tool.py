#!/usr/bin/env python3
"""Unpack/repack Ankh DAT archives, decoding and restoring SNR LZSS members."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


HEADER = struct.Struct("<I")
ENTRY = struct.Struct("<8sIII")
MANIFEST_NAME = ".dat_tool.json"
FORMAT_ID = "toga-dat-v1"
MAX_U32 = 0xFFFFFFFF
CHUNK_SIZE = 1024 * 1024
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,8}$")
SNR_MAGIC = b"snr\0"
GPD_MAGIC = b"gpd\0"
GPD_SUFFIX = ".gpd"
RING_SIZE = 4096
RING_MASK = RING_SIZE - 1
RING_START = 4078
MAX_MATCH = 18


class DatError(Exception):
    """Raised when an archive or member directory is invalid."""


@dataclass(frozen=True)
class ArchiveEntry:
    name: str
    reserved: int
    size: int
    offset: int


def lzss_decompress(data: bytes, expected_size: int) -> bytes:
    if expected_size > len(data) * 9:
        raise DatError("SNR decoded size is impossible for the stored LZSS stream")
    ring = bytearray(RING_SIZE)
    write_pos = RING_START
    cursor = 0
    flags = 0
    output = bytearray()

    while cursor < len(data):
        flags >>= 1
        if flags & 0x100 == 0:
            flags = data[cursor] | 0xFF00
            cursor += 1
        if flags & 1:
            if cursor >= len(data):
                raise DatError("truncated SNR LZSS literal")
            value = data[cursor]
            cursor += 1
            output.append(value)
            ring[write_pos] = value
            write_pos = (write_pos + 1) & RING_MASK
        else:
            if cursor + 1 >= len(data):
                raise DatError("truncated SNR LZSS match")
            low, high = data[cursor], data[cursor + 1]
            cursor += 2
            source_pos = ((high & 0xF0) << 4) | low
            for index in range((high & 0x0F) + 3):
                value = ring[(source_pos + index) & RING_MASK]
                output.append(value)
                ring[write_pos] = value
                write_pos = (write_pos + 1) & RING_MASK

        if len(output) > expected_size:
            raise DatError("SNR LZSS output exceeds its declared decoded size")

    if len(output) != expected_size:
        raise DatError(
            f"SNR LZSS decoded {len(output)} bytes; header declares {expected_size}"
        )
    return bytes(output)


def lzss_compress(data: bytes) -> bytes:
    ring = bytearray(RING_SIZE)
    write_pos = RING_START
    positions: dict[bytes, set[int]] = {b"\0\0\0": set(range(RING_SIZE))}

    def key_at(start: int) -> bytes:
        return bytes(ring[(start + delta) & RING_MASK] for delta in range(3))

    def write_ring(value: int) -> None:
        affected = {
            (write_pos - 2) & RING_MASK,
            (write_pos - 1) & RING_MASK,
            write_pos,
        }
        old_keys = {start: key_at(start) for start in affected}
        for start, key in old_keys.items():
            bucket = positions.get(key)
            if bucket is not None:
                bucket.discard(start)
                if not bucket:
                    del positions[key]
        ring[write_pos] = value
        for start in affected:
            positions.setdefault(key_at(start), set()).add(start)

    output = bytearray()
    cursor = 0
    while cursor < len(data):
        flag_offset = len(output)
        output.append(0)
        flags = 0
        for bit in range(8):
            if cursor >= len(data):
                break

            lookahead = min(MAX_MATCH, len(data) - cursor)
            best_length = 0
            best_pos = 0
            if lookahead >= 3:
                key = data[cursor : cursor + 3]
                candidates = set(positions.get(key, ()))
                candidates.add((write_pos - 1) & RING_MASK)
                candidates.add((write_pos - 2) & RING_MASK)
                for candidate in candidates:
                    length = 0
                    while length < lookahead:
                        source_pos = (candidate + length) & RING_MASK
                        distance = (source_pos - write_pos) & RING_MASK
                        value = data[cursor + distance] if distance < length else ring[source_pos]
                        if value != data[cursor + length]:
                            break
                        length += 1
                    if length > best_length:
                        best_length = length
                        best_pos = candidate
                        if best_length == lookahead:
                            break

            if best_length >= 3:
                output.append(best_pos & 0xFF)
                output.append(((best_pos >> 4) & 0xF0) | (best_length - 3))
                for value in data[cursor : cursor + best_length]:
                    write_ring(value)
                    write_pos = (write_pos + 1) & RING_MASK
                cursor += best_length
            else:
                flags |= 1 << bit
                value = data[cursor]
                output.append(value)
                write_ring(value)
                write_pos = (write_pos + 1) & RING_MASK
                cursor += 1

        output[flag_offset] = flags
    return bytes(output)


def validate_name(name: str) -> bytes:
    if not NAME_RE.fullmatch(name):
        raise DatError(
            f"member name {name!r} must be 1-8 ASCII letters, digits, '_' or '-'; "
            "extensions and path components are not allowed"
        )
    return name.encode("ascii")


def decode_name(raw: bytes, index: int) -> str:
    head, separator, tail = raw.partition(b"\0")
    if separator and any(tail):
        raise DatError(f"entry {index} has nonzero bytes after its NUL-padded name")
    try:
        name = head.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DatError(f"entry {index} has a non-ASCII name") from exc
    validate_name(name)
    return name


def parse_archive(path: Path) -> tuple[list[ArchiveEntry], int, str]:
    file_size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        header = stream.read(HEADER.size)
        if len(header) != HEADER.size:
            raise DatError("file is too short to contain a DAT entry count")
        count = HEADER.unpack(header)[0]
        table_size = count * ENTRY.size
        table_end = HEADER.size + table_size
        if table_end > file_size:
            raise DatError(
                f"index table ends at 0x{table_end:X}, beyond file size 0x{file_size:X}"
            )

        raw_table = stream.read(table_size)
        if len(raw_table) != table_size:
            raise DatError("truncated DAT index table")

        entries: list[ArchiveEntry] = []
        names: set[str] = set()
        expected_offset = table_end
        for index in range(count):
            raw_name, reserved, size, offset = ENTRY.unpack_from(
                raw_table, index * ENTRY.size
            )
            name = decode_name(raw_name, index)
            if name in names:
                raise DatError(f"duplicate member name {name!r}")
            names.add(name)
            if offset != expected_offset:
                raise DatError(
                    f"entry {name!r} starts at 0x{offset:X}; "
                    f"expected contiguous offset 0x{expected_offset:X}"
                )
            end = offset + size
            if end > file_size:
                raise DatError(
                    f"entry {name!r} ends at 0x{end:X}, beyond file size 0x{file_size:X}"
                )
            entries.append(ArchiveEntry(name, reserved, size, offset))
            expected_offset = end

        if expected_offset != file_size:
            raise DatError(
                f"archive has {file_size - expected_offset} unexplained trailing bytes"
            )

        stream.seek(0)
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return entries, table_end, digest.hexdigest()


def unpack_archive(archive: Path, output_dir: Path) -> None:
    entries, table_end, archive_hash = parse_archive(archive)
    if output_dir.resolve() == archive.resolve() or output_dir.resolve() == archive.parent.resolve():
        raise DatError("output directory must not be the archive or its parent directory")
    if output_dir.exists():
        if not output_dir.is_dir():
            raise DatError(f"output path is not a directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise DatError(f"output directory is not empty: {output_dir}")
    else:
        output_dir.mkdir(parents=True)

    manifest_entries = []
    compressed_count = 0
    with archive.open("rb") as source:
        for entry in entries:
            source.seek(entry.offset)
            prefix = source.read(min(8, entry.size))
            filename = entry.name + GPD_SUFFIX if prefix.startswith(GPD_MAGIC) else entry.name
            target = output_dir / filename
            if prefix[:4] == SNR_MAGIC:
                if entry.size < 8 or len(prefix) != 8:
                    raise DatError(f"truncated SNR member header in {entry.name!r}")
                decoded_size = HEADER.unpack(prefix[4:8])[0]
                compressed_data = source.read(entry.size - 8)
                if len(compressed_data) != entry.size - 8:
                    raise DatError(f"truncated SNR member payload in {entry.name!r}")
                stored_payload = prefix + compressed_data
                decoded = lzss_decompress(compressed_data, decoded_size)
                with target.open("xb") as destination:
                    destination.write(decoded)
                manifest_entries.append(
                    {
                        "name": entry.name,
                        "filename": filename,
                        "reserved": entry.reserved,
                        "codec": "snr-lzss",
                        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                        "stored_payload_b64": base64.b64encode(stored_payload).decode("ascii"),
                    }
                )
                compressed_count += 1
            else:
                source.seek(entry.offset)
                remaining = entry.size
                with target.open("xb") as destination:
                    while remaining:
                        chunk = source.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise DatError(f"truncated payload while extracting {entry.name!r}")
                        destination.write(chunk)
                        remaining -= len(chunk)
                manifest_entries.append(
                    {
                        "name": entry.name,
                        "filename": filename,
                        "reserved": entry.reserved,
                        "codec": "raw",
                    }
                )

    manifest = {
        "format": FORMAT_ID,
        "source_name": archive.name,
        "source_sha256": archive_hash,
        "table_end": table_end,
        "entries": manifest_entries,
    }
    manifest_path = output_dir / MANIFEST_NAME
    with manifest_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")

    print(f"Unpacked {len(entries)} members to {output_dir}")
    print(
        f"Decoded {compressed_count} SNR LZSS members; copied "
        f"{len(entries) - compressed_count} raw members. Archive SHA-256: {archive_hash}"
    )


def load_manifest(
    directory: Path, files: dict[str, Path]
) -> tuple[list[str], dict[str, dict[str, object]]]:
    manifest_path = directory / MANIFEST_NAME
    if not manifest_path.exists():
        names = sorted(files)
        decoded_script_names = [
            name
            for name in names
            if files[name].name == name
            and re.fullmatch(r"(?:mem_\d{3}|s_\d{3}|s_end|snr\d{2})", name)
        ]
        for name in decoded_script_names:
            with files[name].open("rb") as stream:
                if stream.read(4) != SNR_MAGIC:
                    raise DatError(
                        f"{name!r} looks like a decoded SNR member, but {MANIFEST_NAME} "
                        "is missing; restore the manifest before packing"
                    )
        return names, {name: {"reserved": 0, "codec": "raw"} for name in names}

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatError(f"cannot read manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT_ID:
        raise DatError(f"unsupported manifest format in {manifest_path}")
    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, list):
        raise DatError("manifest has no entries list")

    names: list[str] = []
    metadata: dict[str, dict[str, object]] = {}
    for item in raw_entries:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise DatError("manifest contains a malformed entry")
        name = item["name"]
        validate_name(name)
        reserved = item.get("reserved")
        if not isinstance(reserved, int) or not 0 <= reserved <= MAX_U32:
            raise DatError(f"manifest entry {name!r} has an invalid reserved field")
        if name in metadata:
            raise DatError(f"manifest contains duplicate member {name!r}")
        codec = item.get("codec", "raw")
        if codec not in ("raw", "snr-lzss"):
            raise DatError(f"manifest entry {name!r} has an unsupported codec")
        filename = item.get("filename", name)
        if filename != name and not (codec == "raw" and filename == name + GPD_SUFFIX):
            raise DatError(f"manifest entry {name!r} has an invalid filename {filename!r}")
        if name in files and files[name].name != filename:
            raise DatError(
                f"manifest entry {name!r} expects {filename!r}, found {files[name].name!r}"
            )
        names.append(name)
        metadata[name] = {
            "reserved": reserved,
            "codec": codec,
            "decoded_sha256": item.get("decoded_sha256"),
            "stored_payload_b64": item.get("stored_payload_b64"),
        }

    if set(names) != set(files):
        missing = sorted(set(names) - set(files))
        extra = sorted(set(files) - set(names))
        raise DatError(f"member list differs from manifest; missing={missing}, extra={extra}")
    return names, metadata


def pack_directory(input_dir: Path, archive: Path) -> None:
    if not input_dir.is_dir():
        raise DatError(f"input directory does not exist: {input_dir}")
    input_resolved = input_dir.resolve()
    archive_resolved = archive.resolve()
    if archive_resolved == input_resolved or input_resolved in archive_resolved.parents:
        raise DatError("output archive must be outside the input directory")
    if archive.exists():
        raise DatError(f"refusing to overwrite existing file: {archive}")

    files: dict[str, Path] = {}
    for item in input_dir.iterdir():
        if item.name == MANIFEST_NAME:
            continue
        if item.is_symlink() or not item.is_file():
            raise DatError(f"only regular member files are allowed: {item}")
        name = item.stem if item.suffix.lower() == GPD_SUFFIX else item.name
        validate_name(name)
        if name in files:
            raise DatError(f"multiple files map to DAT index name {name!r}")
        if item.stat().st_size > MAX_U32:
            raise DatError(f"member is too large for a 32-bit size field: {item.name}")
        files[name] = item

    names, metadata = load_manifest(input_dir, files)
    table_end = HEADER.size + len(names) * ENTRY.size
    if table_end > MAX_U32:
        raise DatError("DAT index exceeds the 32-bit offset limit")

    entries: list[ArchiveEntry] = []
    encoded_payloads: dict[str, bytes] = {}
    offset = table_end
    for name in names:
        member_path = files[name]
        member_data = None
        if metadata[name]["codec"] == "snr-lzss":
            member_data = member_path.read_bytes()
            if len(member_data) > MAX_U32:
                raise DatError(f"decoded SNR member is too large: {name}")
            original_b64 = metadata[name]["stored_payload_b64"]
            decoded_hash = metadata[name]["decoded_sha256"]
            stored = None
            if isinstance(original_b64, str) and decoded_hash == hashlib.sha256(member_data).hexdigest():
                try:
                    candidate = base64.b64decode(original_b64, validate=True)
                    declared = HEADER.unpack(candidate[4:8])[0] if candidate[:4] == SNR_MAGIC and len(candidate) >= 8 else -1
                    if (
                        candidate[:4] == SNR_MAGIC
                        and declared == len(member_data)
                        and lzss_decompress(candidate[8:], declared) == member_data
                    ):
                        stored = candidate
                except (ValueError, DatError, struct.error):
                    stored = None
            if stored is None:
                compressed = lzss_compress(member_data)
                stored = SNR_MAGIC + HEADER.pack(len(member_data)) + compressed
            encoded_payloads[name] = stored
            size = len(stored)
        else:
            size = member_path.stat().st_size
        end = offset + size
        if end > MAX_U32:
            raise DatError(f"archive exceeds the 32-bit offset limit at member {name!r}")
        entries.append(ArchiveEntry(name, int(metadata[name]["reserved"]), size, offset))
        offset = end

    archive.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{archive.name}.", suffix=".tmp", dir=archive.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(HEADER.pack(len(entries)))
            for entry in entries:
                output.write(
                    ENTRY.pack(
                        validate_name(entry.name).ljust(8, b"\0"),
                        entry.reserved,
                        entry.size,
                        entry.offset,
                    )
                )
            for entry in entries:
                if entry.name in encoded_payloads:
                    output.write(encoded_payloads[entry.name])
                    continue
                source_path = files[entry.name]
                if source_path.stat().st_size != entry.size:
                    raise DatError(f"member changed while packing: {entry.name}")
                with source_path.open("rb") as source:
                    remaining = entry.size
                    while remaining:
                        chunk = source.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise DatError(f"member was truncated while packing: {entry.name}")
                        output.write(chunk)
                        remaining -= len(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.rename(temporary, archive)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    print(f"Packed {len(entries)} members into {archive}")
    print("SNR members are stored as LZSS; other members are copied verbatim.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Unpack/repack Ankh .dat archives; SNR members are transparently "
            "LZSS-decoded and extracted with no extension; GPD members are "
            "extracted as .gpd files without image conversion. Keep "
            f"{MANIFEST_NAME} to preserve DAT index order and repack decoded SNR members."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    unpack_parser = commands.add_parser("unpack", help="extract an archive")
    unpack_parser.add_argument("archive", type=Path)
    unpack_parser.add_argument("output_dir", type=Path)
    pack_parser = commands.add_parser("pack", help="create an archive from member files")
    pack_parser.add_argument("input_dir", type=Path)
    pack_parser.add_argument("archive", type=Path)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "unpack":
            unpack_archive(args.archive, args.output_dir)
        else:
            pack_directory(args.input_dir, args.archive)
    except (DatError, OSError, struct.error) as exc:
        print(f"dat_tool: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
