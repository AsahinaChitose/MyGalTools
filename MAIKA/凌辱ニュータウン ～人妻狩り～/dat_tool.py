#!/usr/bin/env python3
"""Extract and rebuild the RAPNTWN MIK01 archives (Python 3.10+, stdlib only)."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from struct import Struct
import sys
from typing import BinaryIO


HEADER = Struct("<8sHI2s")
DIRECTORY_ENTRY = Struct("<12sI")
WRAPPER = Struct("<2sII")
BLOCK = Struct("<BI")
MIK_MAGIC = b"MIK01\x1a\0\0"
BPR_MAGIC = b"BPR01"
MANIFEST = ".mik01.json"
CACHE = ".mik01-stored"
RAW = "raw"
IMAGE = "E1/LZSS/BPR01"
IMAGE_BUFFER = 0x180000  # Src region size passed to sub_419F48.
DAT_LIMIT = 0x7FFFFFFF  # Signed offsets passed to SetFilePointer.
RING_MASK, RING_START = 0xFFF, 0xFEE
NAME = re.compile(rb"[A-Z0-9_@#$%~!()+-]+(?:\.[A-Z0-9_@#$%~!()+-]+)?")
RESERVED = {b"CON", b"AUX", b"NUL", b"PRN"} | {
    prefix + bytes([digit]) for prefix in (b"COM", b"LPT") for digit in range(48, 58)
}


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    name: str
    offset: int
    size: int


def filename(field: bytes) -> str:
    stem = field.rstrip(b"\0")
    if not NAME.fullmatch(stem) or stem.split(b".", 1)[0] in RESERVED:
        raise FormatError(f"unsafe or unsupported entry name: {field!r}")
    return stem.decode("ascii")


def read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise FormatError(f"short read: expected {size}, got {len(data)} bytes")
    return data


def read_directory(stream: BinaryIO) -> tuple[bytes, list[Entry]]:
    magic, count, toc, reserved = HEADER.unpack(read_exact(stream, HEADER.size))
    if magic != MIK_MAGIC:
        raise FormatError("not a RAPNTWN MIK01 archive")
    eof = stream.seek(0, 2)
    if not HEADER.size <= toc <= DAT_LIMIT or toc + count * DIRECTORY_ENTRY.size != eof:
        raise FormatError("directory offset/count does not match file size")
    stream.seek(toc)
    entries, names = [], set()
    offset = HEADER.size
    for field, size in DIRECTORY_ENTRY.iter_unpack(read_exact(stream, eof - toc)):
        name = filename(field)
        if name in names:
            raise FormatError(f"duplicate directory name: {name}")
        if offset + size > toc:
            raise FormatError(f"{name}: entry overlaps the directory")
        names.add(name)
        entries.append(Entry(name, offset, size))
        offset += size
    if offset != toc:
        raise FormatError("sum of entry sizes does not reach the directory")
    return reserved, entries


def lzss_decode(data: bytes | bytearray, size: int) -> bytearray:
    """Check all source/output bounds; copy from known prior output instead of a ring."""
    out = bytearray()
    pos = 0
    while len(out) < size:
        if pos >= len(data):
            raise FormatError("truncated LZSS flags")
        flags = data[pos]
        pos += 1
        for bit in range(8):
            if flags & (1 << bit):
                if pos == len(data):
                    raise FormatError("truncated LZSS literal")
                out.append(data[pos])
                pos += 1
            else:
                if pos + 2 > len(data):
                    raise FormatError("truncated LZSS reference")
                hi = data[pos + 1]
                ref = data[pos] | ((hi & 0xF0) << 4)
                length = (hi & 0x0F) + 3
                pos += 2
                end = len(out)
                if end + length > size:
                    raise FormatError("LZSS reference exceeds declared size")
                distance = ((end + RING_START - ref) & RING_MASK) or 4096
                start = end - distance
                if -4096 <= start < -RING_START:
                    raise FormatError("LZSS reference uses uninitialized dictionary bytes")
                if start < 0:
                    zeros = min(-start, length)
                    out.extend(b"\0" * zeros)
                    length -= zeros
                    start = 0
                if length:
                    pattern = out[start:start + length]
                    if len(pattern) < length:
                        pattern = (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]
                    out.extend(pattern)
            if len(out) == size:
                # Original archives can omit the unused tail of the final group.
                # Our encoder supplies zero literals for the EXE's whole-group loop.
                extra = len(data) - pos
                if extra and (
                    extra != 7 - bit or flags >> (bit + 1) != (1 << extra) - 1 or any(data[pos:])
                ):
                    raise FormatError("unexpected bytes after the LZSS stream")
                return out
    raise FormatError("empty LZSS output")


def lzss_encode(data: bytes) -> bytes:
    """Greedy 3-byte dictionary, using the EXE's 4 KiB/18-byte match format."""
    out = bytearray()
    last: dict[bytes, int] = {}
    pos, size = 0, len(data)
    while pos < size:
        flag_at = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if pos == size:
                flags |= 0xFF & ~((1 << bit) - 1)
                out.extend(b"\0" * (8 - bit))
                break
            match = last.get(data[pos:pos + 3], -4097)
            length = 1
            if pos - match <= 4096 and size - pos >= 3:
                limit = min(18, size - pos)
                length = 3
                while length < limit and data[match + length] == data[pos + length]:
                    length += 1
                ref = (match + RING_START) & RING_MASK
                out.extend((ref & 0xFF, (ref >> 4 & 0xF0) | (length - 3)))
            else:
                flags |= 1 << bit
                out.append(data[pos])
            end = pos + length
            for i in range(pos, min(end, size - 2)):
                last[data[i:i + 3]] = i
            pos = end
        out[flag_at] = flags
    return bytes(out)


def bpr_decode(data: bytearray) -> bytearray:
    if not data.startswith(BPR_MAGIC):
        raise FormatError("expected BPR01 after LZSS")
    pos = len(BPR_MAGIC)
    out = bytearray()
    while pos < len(data):
        if data[pos] == 0xFF:
            if pos + 1 != len(data):
                raise FormatError("bytes after BPR01 end marker")
            return out
        if pos + BLOCK.size > len(data):
            raise FormatError("truncated BPR01 block header")
        kind, count = BLOCK.unpack_from(data, pos)
        pos += BLOCK.size
        if not 0 < count <= IMAGE_BUFFER - len(out):
            raise FormatError("invalid BPR01 output length")
        # The EXE treats any tag other than 01 or FF as a literal block.
        stored = 1 if kind == 1 else count
        if pos + stored > len(data):
            raise FormatError("truncated BPR01 block")
        piece = data[pos:pos + stored]
        out.extend(piece * count if kind == 1 else piece)
        pos += stored
    raise FormatError("missing BPR01 end marker")


def bpr_encode(data: bytes) -> bytes:
    out = bytearray(BPR_MAGIC)
    last = 0
    for run in re.finditer(rb"(.)\1{11,}", data, re.DOTALL):
        if run.start() > last:
            out.extend(BLOCK.pack(2, run.start() - last))
            out.extend(data[last:run.start()])
        out.extend(BLOCK.pack(1, run.end() - run.start()))
        out.extend(run.group(1))
        last = run.end()
    if last < len(data):
        out.extend(BLOCK.pack(2, len(data) - last))
        out.extend(data[last:])
    out.append(0xFF)
    return bytes(out)


def check_bmp(data: bytes | bytearray) -> None:
    if not data.startswith(b"BM") or not 26 <= len(data) <= IMAGE_BUFFER:
        raise FormatError("expected a BMP within the game's image buffer")
    size, offset, dib = (int.from_bytes(data[i:i + 4], "little") for i in (2, 10, 14))
    if size != len(data) or dib < 12 or not 14 + dib <= offset < size:
        raise FormatError("invalid BMP header, length, or pixel offset")


def swap_e1_bytes(data: bytearray) -> None:
    # Absolute offsets in sub_454C24/sub_454D22, including the wrapper header.
    data[17], data[21] = data[21], data[17]
    data[19], data[22] = data[22], data[19]


def decode_entry(name: str, data: bytes) -> tuple[str, bytes | bytearray]:
    if not name.endswith(".BMP"):
        return RAW, data
    if data.startswith(b"BM"):
        check_bmp(data)
        return RAW, data
    if not data.startswith(b"E1") or not 23 <= len(data) <= IMAGE_BUFFER:
        raise FormatError("expected a supported E1-wrapped BMP")
    _, packed, expanded = WRAPPER.unpack_from(data)
    if packed != len(data) - WRAPPER.size or not 0 < expanded <= IMAGE_BUFFER:
        raise FormatError("invalid E1 sizes")
    block = bytearray(data)
    swap_e1_bytes(block)
    image = bpr_decode(lzss_decode(block[WRAPPER.size:], expanded))
    check_bmp(image)
    return IMAGE, image


def encode_image(data: bytes) -> bytearray:
    check_bmp(data)
    inner = bpr_encode(data)
    # The EXE may decode up to seven extra literal bytes in the final group.
    if len(inner) > IMAGE_BUFFER - 7:
        inner = BPR_MAGIC + BLOCK.pack(2, len(data)) + data + b"\xFF"
    if len(inner) > IMAGE_BUFFER - 7:
        raise FormatError("BPR01 output would exceed the game's image buffer")
    lzss = lzss_encode(inner)
    if not 23 <= WRAPPER.size + len(lzss) <= IMAGE_BUFFER:
        raise FormatError("E1 output would exceed the game's image buffer")
    encoded = bytearray(WRAPPER.pack(b"E1", len(lzss), len(inner)))
    encoded.extend(lzss)
    swap_e1_bytes(encoded)
    return encoded


def scan(archive: Path, output: Path | None = None, *, keep_stored=True) -> None:
    with archive.open("rb") as stream:
        reserved, entries = read_directory(stream)
        if output is not None:
            output.mkdir(parents=True, exist_ok=False)
        records, counts = [], Counter()
        for i, entry in enumerate(entries):
            stream.seek(entry.offset)
            stored = read_exact(stream, entry.size)
            try:
                codec, data = decode_entry(entry.name, stored)
            except FormatError as err:
                raise FormatError(f"{entry.name} at 0x{entry.offset:X}: {err}") from err
            counts[codec] += 1
            if output is not None:
                (output / entry.name).write_bytes(data)
                record = {"name": entry.name, "codec": codec, "sha256": sha256(data).hexdigest()}
                if codec == IMAGE and keep_stored:
                    cache = output / CACHE
                    cache.mkdir(exist_ok=True)
                    (cache / f"{i:04d}.e1").write_bytes(stored)
                    record["stored_sha256"] = sha256(stored).hexdigest()
                records.append(record)
        if output is not None:
            (output / MANIFEST).write_text(
                json.dumps({"version": 1, "reserved": reserved.hex(), "entries": records}, indent=2) + "\n",
                encoding="utf-8",
            )
    print(f"{archive.name}: {len(entries)} entries ({summary(counts)})"
          + (f" extracted to {output}" if output is not None else " verified"))


def load_manifest(source: Path) -> tuple[bytes, list[dict]]:
    raw = json.loads((source / MANIFEST).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise FormatError("unsupported manifest version")
    reserved = raw.get("reserved")
    if not isinstance(reserved, str) or not re.fullmatch(r"[0-9a-fA-F]{4}", reserved):
        raise FormatError("invalid manifest header bytes")
    records = raw.get("entries")
    if not isinstance(records, list) or len(records) > 65535:
        raise FormatError("invalid manifest entry count")
    names = set()
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            raise FormatError("invalid manifest record")
        name = record["name"]
        field = name.encode("ascii", errors="backslashreplace")
        if len(field) > 12 or filename(field) != name or name in names:
            raise FormatError(f"invalid or duplicate manifest name: {name!r}")
        if record.get("codec") not in (RAW, IMAGE) or (record["codec"] == IMAGE and not name.endswith(".BMP")):
            raise FormatError(f"{name}: invalid manifest codec")
        for key in ("sha256", "stored_sha256"):
            if key == "stored_sha256" and key not in record:
                continue
            value = record.get(key)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise FormatError(f"{name}: invalid manifest {key}")
        names.add(name)
    return bytes.fromhex(reserved), records


def pack(source: Path, archive: Path, *, recompress=False) -> None:
    reserved, records = load_manifest(source)
    counts = Counter()
    toc = bytearray()
    # Exclusive creation protects the original archive or any existing result.
    stream = archive.open("xb")
    try:
        with stream:
            stream.write(b"\0" * HEADER.size)
            for i, record in enumerate(records):
                name, codec = record["name"], record["codec"]
                try:
                    data = (source / name).read_bytes()
                    cache = source / CACHE / f"{i:04d}.e1"
                    if codec == RAW:
                        if name.endswith(".BMP"):
                            check_bmp(data)
                        counts[RAW] += 1
                    elif (not recompress and "stored_sha256" in record and cache.is_file()
                          and sha256(data).hexdigest() == record["sha256"]):
                        data = cache.read_bytes()
                        if sha256(data).hexdigest() != record["stored_sha256"]:
                            raise FormatError("stored cache changed; rerun with --recompress")
                        counts["E1 reused"] += 1
                    else:
                        data = encode_image(data)
                        counts["E1 recompressed"] += 1
                    if stream.tell() + len(data) > DAT_LIMIT:
                        raise FormatError("archive exceeds the game's signed data offset limit")
                except (FormatError, OSError) as err:
                    raise FormatError(f"{name}: {err}") from err
                stream.write(data)
                toc.extend(DIRECTORY_ENTRY.pack(name.encode("ascii"), len(data)))
            toc_offset = stream.tell()
            stream.write(toc)
            stream.seek(0)
            stream.write(HEADER.pack(MIK_MAGIC, len(records), toc_offset, reserved))
    except BaseException:
        archive.unlink(missing_ok=True)
        raise
    print(f"{archive}: {len(records)} entries rebuilt ({summary(counts)})")


def summary(counts: Counter) -> str:
    return ", ".join(f"{count} {kind}" for kind, count in counts.items()) or "empty"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    extract = commands.add_parser("unpack", help="extract ADB/DAT bytes and decoded BMPs")
    extract.add_argument("archive", type=Path)
    extract.add_argument("directory", type=Path, help="new output directory")
    extract.add_argument("--no-cache", action="store_true", help="omit the original E1 payload cache")
    rebuild = commands.add_parser("pack", help="rebuild using the extraction manifest and files")
    rebuild.add_argument("directory", type=Path)
    rebuild.add_argument("archive", type=Path, help="new archive (will not overwrite)")
    rebuild.add_argument("--recompress", action="store_true", help="encode all E1 images even if unchanged")
    for action, description in (("list", "list entries without decoding"), ("verify", "decode every entry and check its format")):
        commands.add_parser(action, help=description).add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "unpack":
            scan(args.archive, args.directory, keep_stored=not args.no_cache)
        elif args.action == "pack":
            pack(args.directory, args.archive, recompress=args.recompress)
        elif args.action == "verify":
            scan(args.archive)
        else:
            with args.archive.open("rb") as stream:
                _, entries = read_directory(stream)
            for entry in entries:
                print(f"{entry.offset:08X} {entry.size:10d} {entry.name}")
            print(f"{len(entries)} entries")
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
