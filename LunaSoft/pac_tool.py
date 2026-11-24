#!/usr/bin/env python3
"""Read and write the LunaSoft PAC archives used by lus004.exe.

Observed layout (little-endian): 16-byte header, then 0x10C-byte records,
then a data area. Payloads are stored verbatim by the PAC container; the
container has no compression/encryption flag or transform. Files such as
SEQF .seq resources are kept as-is (their inner file format is not rewritten).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

MAGIC = bytes.fromhex("82 CF 82 AD")
HEADER_SIZE = 0x10
NAME_FIELD_SIZE = 0x100
ENTRY_SIZE = 0x10C
MANIFEST_NAME = ".pac_tool_manifest.json"
MANIFEST_VERSION = 1
ALIGNMENT = 0x10


class PacError(Exception):
    """Invalid archive or unsafe filesystem operation."""


@dataclass
class Entry:
    name: str
    raw_name: bytes
    name_length: int
    offset: int
    payload: bytes
    gap_after: bytes = b""
    source_offset: int = 0
    source_size: int = 0
    source_sha256: str = ""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def align_up(value: int, alignment: int = ALIGNMENT) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def safe_relative_name(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    p = PurePosixPath(normalized)
    if (not normalized or normalized.startswith("/") or ":" in normalized
            or any(part in ("", ".", "..") for part in p.parts)):
        raise PacError(f"unsafe archive path: {name!r}")
    return p


def parse_archive(path: Path) -> tuple[bytes, int, int, bytes, list[Entry], bytes, bytes]:
    data = path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise PacError("file is shorter than the PAC header")
    magic, count, data_offset, reserved = struct.unpack_from("<4sIII", data, 0)
    if magic != MAGIC:
        raise PacError(f"unrecognized PAC signature: {magic.hex(' ').upper()}")
    table_end = HEADER_SIZE + count * ENTRY_SIZE
    if table_end > len(data) or data_offset < table_end or data_offset > len(data):
        raise PacError(
            f"invalid table/data boundary: count={count}, table_end=0x{table_end:X}, "
            f"data_offset=0x{data_offset:X}, file_size=0x{len(data):X}"
        )

    entries: list[Entry] = []
    for i in range(count):
        rec = HEADER_SIZE + i * ENTRY_SIZE
        raw_name = data[rec:rec + NAME_FIELD_SIZE]
        primary = raw_name.split(b"\0", 1)[0]
        if not primary:
            raise PacError(f"entry {i} has an empty path")
        try:
            name = primary.decode("cp932")
        except UnicodeDecodeError as exc:
            raise PacError(f"entry {i} path is not valid CP932: {exc}") from exc
        safe_relative_name(name)
        offset, size, name_length = struct.unpack_from("<III", data, rec + NAME_FIELD_SIZE)
        if name_length != len(primary):
            raise PacError(
                f"entry {i} name length mismatch: field={name_length}, bytes={len(primary)}"
            )
        start = data_offset + offset
        end = start + size
        if start < data_offset or end > len(data):
            raise PacError(
                f"entry {i} payload outside archive: offset=0x{offset:X}, size=0x{size:X}"
            )
        payload = data[start:end]
        entries.append(Entry(
            name=name,
            raw_name=raw_name,
            name_length=name_length,
            offset=offset,
            payload=payload,
            source_offset=offset,
            source_size=size,
            source_sha256=sha256(payload),
        ))

    # The game and both supplied samples store entries in table/data order.
    # Reject overlap or non-monotonic tables rather than silently rebuilding them wrongly.
    previous_end = 0
    for i, entry in enumerate(entries):
        if entry.offset < previous_end:
            raise PacError(f"entry {i} overlaps or is out of data order")
        previous_end = entry.offset + len(entry.payload)
        if i + 1 < len(entries):
            next_offset = entries[i + 1].offset
            if next_offset < previous_end:
                raise PacError(f"entry {i} overlaps entry {i + 1}")
            entry.gap_after = data[data_offset + previous_end:data_offset + next_offset]
    trailer_start = data_offset + previous_end
    trailing = data[trailer_start:]
    header_gap = data[table_end:data_offset]
    return magic, count, data_offset, struct.pack("<I", reserved), entries, header_gap, trailing


def make_raw_name(path_name: str) -> tuple[bytes, int]:
    p = safe_relative_name(path_name)
    try:
        encoded = str(p).encode("cp932")
    except UnicodeEncodeError as exc:
        raise PacError(f"path cannot be encoded as CP932: {path_name!r}") from exc
    if len(encoded) > NAME_FIELD_SIZE - 2:
        raise PacError(f"path is too long for the PAC name field: {path_name!r}")
    # The samples store a secondary "/basename" lookup string for .seq entries.
    secondary = b""
    if p.suffix.lower() == ".seq":
        secondary = b"/" + p.name.encode("cp932") + b"\0"
    content = encoded + b"\0" + secondary
    if len(content) > NAME_FIELD_SIZE:
        raise PacError(f"path plus secondary lookup name is too long: {path_name!r}")
    return content.ljust(NAME_FIELD_SIZE, b"\0"), len(encoded)


def load_manifest(root: Path) -> dict[str, Any] | None:
    path = root / MANIFEST_NAME
    if not path.exists():
        return None
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PacError(f"cannot read manifest {path}: {exc}") from exc
    if manifest.get("format") != "LunaSoft PAC" or manifest.get("version") != MANIFEST_VERSION:
        raise PacError("unsupported PAC manifest format/version")
    return manifest


def unpack_archive(archive: Path, output_dir: Path, overwrite: bool = False) -> None:
    magic, count, data_offset, reserved, entries, header_gap, trailing = parse_archive(archive)
    output_dir = output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise PacError(f"output directory is not empty (use --overwrite): {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    manifest_entries: list[dict[str, Any]] = []
    for entry in entries:
        rel = safe_relative_name(entry.name)
        key = str(rel).casefold()
        if key in seen:
            raise PacError(f"duplicate output path (case-insensitive): {entry.name}")
        seen.add(key)
        target = output_dir.joinpath(*rel.parts).resolve()
        if os.path.commonpath([str(output_dir), str(target)]) != str(output_dir):
            raise PacError(f"archive path escapes output directory: {entry.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(entry.payload)
        manifest_entries.append({
            "path": entry.name,
            "raw_name_hex": entry.raw_name.hex(),
            "name_length": entry.name_length,
            "offset": entry.source_offset,
            "size": entry.source_size,
            "sha256": entry.source_sha256,
            "gap_after_hex": entry.gap_after.hex(),
        })

    manifest = {
        "format": "LunaSoft PAC",
        "version": MANIFEST_VERSION,
        "source_file": archive.name,
        "source_sha256": sha256(archive.read_bytes()),
        "magic_hex": magic.hex(),
        "reserved_hex": reserved.hex(),
        "entry_count": count,
        "data_offset": data_offset,
        "header_gap_hex": header_gap.hex(),
        "trailing_hex": trailing.hex(),
        "entries": manifest_entries,
    }
    (output_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Unpacked {count} files: {archive} -> {output_dir}")
    print(f"PAC layer transforms: none (payloads copied verbatim); data_offset=0x{data_offset:X}")


def entries_from_directory(root: Path, manifest: dict[str, Any] | None) -> tuple[list[Entry], bytes, bytes, int, bytes]:
    root = root.resolve()
    if manifest is not None:
        entries: list[Entry] = []
        listed: set[str] = set()
        for i, item in enumerate(manifest.get("entries", [])):
            name = str(item["path"])
            rel = safe_relative_name(name)
            key = str(rel).casefold()
            listed.add(key)
            file_path = root.joinpath(*rel.parts).resolve()
            if os.path.commonpath([str(root), str(file_path)]) != str(root):
                raise PacError(f"manifest path escapes input directory: {name}")
            if not file_path.is_file():
                raise PacError(f"missing extracted file: {file_path}")
            raw_name = bytes.fromhex(item["raw_name_hex"])
            if len(raw_name) != NAME_FIELD_SIZE:
                raise PacError(f"manifest entry {i} has invalid raw_name_hex length")
            payload = file_path.read_bytes()
            entries.append(Entry(
                name=name,
                raw_name=raw_name,
                name_length=int(item["name_length"]),
                offset=0,
                payload=payload,
                gap_after=bytes.fromhex(item.get("gap_after_hex", "")),
                source_offset=int(item.get("offset", 0)),
                source_size=int(item.get("size", -1)),
                source_sha256=str(item.get("sha256", "")),
            ))
        actual: set[str] = set()
        for file_path in root.rglob("*"):
            if file_path.is_file() and file_path.name != MANIFEST_NAME:
                actual.add(file_path.relative_to(root).as_posix().casefold())
        extras = actual - listed
        if extras:
            raise PacError("unlisted files in input directory: " + ", ".join(sorted(extras)[:8]))
        return (
            entries,
            bytes.fromhex(manifest.get("header_gap_hex", "")),
            bytes.fromhex(manifest.get("trailing_hex", "")),
            int(manifest.get("data_offset", 0)),
            bytes.fromhex(manifest.get("reserved_hex", "00000000")),
        )

    files = sorted(
        (p for p in root.rglob("*") if p.is_file() and p.name != MANIFEST_NAME),
        key=lambda p: p.relative_to(root).as_posix().casefold(),
    )
    if not files:
        raise PacError("input directory contains no files")
    entries = []
    seen: set[str] = set()
    for file_path in files:
        name = file_path.relative_to(root).as_posix()
        key = name.casefold()
        if key in seen:
            raise PacError(f"duplicate output path (case-insensitive): {name}")
        seen.add(key)
        raw_name, name_length = make_raw_name(name)
        payload = file_path.read_bytes()
        entries.append(Entry(name, raw_name, name_length, 0, payload))
    return entries, b"", b"", 0, b"\0\0\0\0"


def build_archive(entries: list[Entry], header_gap: bytes, trailing: bytes,
                  requested_data_offset: int, reserved: bytes) -> bytes:
    count = len(entries)
    table_end = HEADER_SIZE + count * ENTRY_SIZE
    if requested_data_offset >= table_end:
        data_offset = requested_data_offset
    else:
        data_offset = align_up(table_end)
        header_gap = b""
    if data_offset != table_end + len(header_gap):
        # A source archive may have no table gap (as these samples do); for a
        # changed entry count, use a clean 16-byte boundary instead.
        if requested_data_offset == 0 or data_offset < table_end + len(header_gap):
            data_offset = align_up(table_end)
            header_gap = b""
        else:
            header_gap = b"\0" * (data_offset - table_end)

    records = bytearray()
    data_region = bytearray()
    for i, entry in enumerate(entries):
        if len(entry.raw_name) != NAME_FIELD_SIZE:
            raise PacError(f"entry {i} raw name field must be 256 bytes")
        primary = entry.raw_name.split(b"\0", 1)[0]
        if len(primary) != entry.name_length:
            raise PacError(f"entry {i} name_length disagrees with stored name")
        offset = len(data_region)
        records.extend(entry.raw_name)
        records.extend(struct.pack("<III", offset, len(entry.payload), entry.name_length))
        data_region.extend(entry.payload)
        if i + 1 < count:
            next_offset = align_up(len(data_region))
            pad_size = next_offset - len(data_region)
            unchanged = (
                len(entry.payload) == entry.source_size
                and entry.source_sha256
                and sha256(entry.payload) == entry.source_sha256
            )
            if unchanged and len(entry.gap_after) == pad_size:
                data_region.extend(entry.gap_after)
            else:
                data_region.extend(b"\0" * pad_size)
    data_region.extend(trailing)

    header = struct.pack("<4sIII", MAGIC, count, data_offset, struct.unpack("<I", reserved)[0])
    result = bytearray(header)
    result.extend(records)
    result.extend(header_gap)
    if len(result) != data_offset:
        raise PacError(f"internal error constructing data offset: {len(result)} != {data_offset}")
    result.extend(data_region)
    return bytes(result)


def pack_directory(input_dir: Path, output_file: Path, overwrite: bool = False) -> None:
    input_dir = input_dir.resolve()
    manifest = load_manifest(input_dir)
    entries, header_gap, trailing, data_offset, reserved = entries_from_directory(input_dir, manifest)
    output_file = output_file.resolve()
    if output_file.exists() and not overwrite:
        raise PacError(f"output exists (use --overwrite): {output_file}")
    if manifest is not None:
        source_name = manifest.get("source_file")
        if source_name and output_file.name.casefold() == str(source_name).casefold():
            raise PacError("refusing to overwrite the original archive; choose a new output name")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    packed = build_archive(entries, header_gap, trailing, data_offset, reserved)
    output_file.write_bytes(packed)
    print(f"Packed {len(entries)} files: {input_dir} -> {output_file}")
    print(f"PAC layer transforms: none (payloads copied verbatim); output_size={len(packed)}")


def verify_archive(archive: Path) -> None:
    raw = archive.read_bytes()
    magic, count, data_offset, reserved, entries, header_gap, trailing = parse_archive(archive)
    rebuilt = build_archive(entries, header_gap, trailing, data_offset, reserved)
    digest = sha256(raw)
    if rebuilt != raw:
        first = next((i for i, (a, b) in enumerate(zip(rebuilt, raw)) if a != b), min(len(rebuilt), len(raw)))
        raise PacError(
            f"round-trip mismatch: original={len(raw)} rebuilt={len(rebuilt)} first_difference=0x{first:X}"
        )
    print(f"OK: {archive} | entries={count} | data_offset=0x{data_offset:X}")
    print(f"Round-trip: byte-identical | SHA-256={digest}")
    print("PAC layer compression/encryption: none; entry payloads are stored verbatim.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LunaSoft PAC unpack/pack/verify tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p_unpack = sub.add_parser("unpack", help="extract an archive and write a preservation manifest")
    p_unpack.add_argument("archive", type=Path)
    p_unpack.add_argument("-o", "--output", type=Path, required=True, help="output directory")
    p_unpack.add_argument("--overwrite", action="store_true", help="allow overwriting extracted files")

    p_pack = sub.add_parser("pack", help="rebuild an archive from a directory")
    p_pack.add_argument("input_dir", type=Path)
    p_pack.add_argument("-o", "--output", type=Path, required=True, help="output .pac/.dat file")
    p_pack.add_argument("--overwrite", action="store_true", help="allow overwriting output file")

    p_verify = sub.add_parser("verify", help="validate structure and exact in-memory round-trip")
    p_verify.add_argument("archive", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "unpack":
            unpack_archive(args.archive, args.output, args.overwrite)
        elif args.command == "pack":
            pack_directory(args.input_dir, args.output, args.overwrite)
        elif args.command == "verify":
            verify_archive(args.archive)
        return 0
    except (PacError, OSError, ValueError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
