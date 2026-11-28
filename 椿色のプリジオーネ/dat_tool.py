#!/usr/bin/env python3
"""List, extract and build the BINZ archives read by TSUBAKI.exe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import tempfile
from collections import Counter
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


MAGIC = b"BINZ"
HEADER = struct.Struct("<4sI")
RECORD = struct.Struct("<32sIII")
UINT32_MAX = (1 << 32) - 1
WINDOW = 4096
MASK = WINDOW - 1
CURSOR = WINDOW - 18
MANIFEST = ".binz.json"
YPK1 = b"YPK1"
YPK1_TABLE = bytes((((byte & 15) << 4) | (byte >> 4)) ^ 0xCC for byte in range(256))


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    name: str
    name_field: bytes
    offset: int
    size: int
    stored: int


def name_bytes(name: str) -> bytes:
    if not isinstance(name, str) or not name or name.endswith((" ", ".")):
        raise FormatError(f"Invalid member name: {name!r}")
    if re.search(r'[\x00-\x1f/\\:<>"|?*]', name):
        raise FormatError(f"Member name must be a plain filename: {name!r}")
    stem = name.split(".", 1)[0].rstrip(" ").upper()
    if name.casefold() == MANIFEST or re.fullmatch(r"CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]", stem):
        raise FormatError(f"Reserved member name: {name!r}")
    encoded = name.encode("cp932")
    if len(encoded) >= 32 or encoded.decode("cp932") != name:
        raise FormatError(f"Name must round-trip in at most 31 CP932 bytes: {name!r}")
    return encoded


def check_names(names: list[str]) -> None:
    seen = set()
    for name in names:
        name_bytes(name)
        key = name.casefold()
        if key in seen:
            raise FormatError(f"Duplicate member name: {name!r}")
        seen.add(key)


def read_exact(file: BinaryIO, size: int) -> bytes:
    data = file.read(size)
    if len(data) != size:
        raise FormatError(f"Unexpected EOF at 0x{file.tell():X}")
    return data


def physical_order(entries: list[Entry]) -> list[int]:
    return sorted(range(len(entries)), key=lambda i: (entries[i].offset, entries[i].stored))


def read_index(file: BinaryIO) -> tuple[list[Entry], int]:
    limit = file.seek(0, os.SEEK_END)
    file.seek(0)
    magic, count = HEADER.unpack(read_exact(file, HEADER.size))
    table_end = HEADER.size + count * RECORD.size
    if magic != MAGIC or count == 0 or table_end > limit or limit > UINT32_MAX:
        raise FormatError("Invalid BINZ header, archive size or entry count")
    entries = []
    for _ in range(count):
        field, offset, size, stored = RECORD.unpack(read_exact(file, RECORD.size))
        raw, sep, _ = field.partition(b"\0")
        if not sep:
            raise FormatError("Unterminated BINZ filename")
        name = raw.decode("cp932")
        if offset < table_end or offset + stored > limit:
            raise FormatError(f"Out-of-bounds member: {name!r} at 0x{offset:X}")
        if size != stored and (size == 0 or stored == 0 or size > 9 * stored):
            raise FormatError(f"Invalid LZSS lengths for {name!r}: {stored} -> {size}")
        entries.append(Entry(name, field, offset, size, stored))
    check_names([entry.name for entry in entries])
    cursor = table_end
    for index in physical_order(entries):
        entry = entries[index]
        if entry.offset < cursor:
            raise FormatError(f"Overlapping member: {entry.name!r} at 0x{entry.offset:X}")
        cursor = entry.offset + entry.stored
    return entries, limit


def decompress(data: bytes, size: int) -> bytes:
    """Expand the zero-filled 4 KiB ring used by sub_431C80."""
    output = bytearray()
    pos = 0
    while len(output) < size:
        if pos >= len(data):
            raise FormatError(f"Truncated LZSS flags at 0x{pos:X}")
        flags = data[pos]
        pos += 1
        for _ in range(8):
            written = len(output)
            if written == size:
                break
            if flags & 1:
                if pos >= len(data):
                    raise FormatError(f"Truncated LZSS literal at 0x{pos:X}")
                output.append(data[pos])
                pos += 1
            else:
                if pos + 2 > len(data):
                    raise FormatError(f"Truncated LZSS reference at 0x{pos:X}")
                lo, hi = data[pos], data[pos + 1]
                pos += 2
                slot = lo | ((hi & 0xF0) << 4)
                length = min((hi & 15) + 3, size - written)
                distance = ((written + CURSOR - slot - 1) & MASK) + 1
                start = written - distance
                if start < 0:
                    padding = min(-start, length)
                    chunk = bytes(padding) + output[:length - padding]
                else:
                    chunk = output[start:start + length]
                if len(chunk) < length:
                    chunk = (chunk * ((length + len(chunk) - 1) // len(chunk)))[:length]
                output.extend(chunk)
            flags >>= 1
    if pos != len(data):
        raise FormatError(f"LZSS stream has {len(data) - pos} trailing bytes")
    return bytes(output)


def compress(plain: bytes) -> bytes:
    """Emit BINZ LZSS tokens and store the member raw if compression cannot help."""
    source = bytes(WINDOW) + plain
    end = len(source)
    pos = WINDOW
    output = bytearray()
    while pos < end:
        flag_at = len(output)
        output.append(0)
        flags = 0
        for bit in range(8):
            if pos == end:
                break
            limit = min(18, end - pos)
            match_length = 0
            if limit >= 3:
                low = pos - WINDOW
                # The start of a match must precede pos, but its end may overlap.
                length = 3
                candidate = source.rfind(source[pos:pos + length], low, pos + length - 1)
                target = source[pos:pos + limit]
                while candidate >= 0:
                    match_start = candidate
                    if source[candidate:candidate + limit] == target:
                        match_length = limit
                        break
                    while source[candidate + length] == source[pos + length]:
                        length += 1
                    match_length = length
                    length += 1
                    candidate = source.rfind(source[pos:pos + length], low, pos + length - 1)
                    if length == limit and candidate >= 0:
                        match_start, match_length = candidate, limit
                        break
            if match_length:
                slot = (match_start - WINDOW + CURSOR) & MASK
                output.extend((slot & 0xFF, ((slot >> 4) & 0xF0) | (match_length - 3)))
                pos += match_length
            else:
                flags |= 1 << bit
                output.append(source[pos])
                pos += 1
        output[flag_at] = flags
        if len(output) >= len(plain):
            return plain
    return bytes(output)


def unpack_member(file: BinaryIO, entry: Entry) -> tuple[bytes, bool]:
    file.seek(entry.offset)
    data = read_exact(file, entry.stored)
    if entry.stored != entry.size:
        try:
            data = decompress(data, entry.size)
        except FormatError as error:
            raise FormatError(f"{entry.name} at 0x{entry.offset:X}: {error}") from error
    encrypted = data.startswith(YPK1)
    if encrypted:
        data = data[4:].translate(YPK1_TABLE)
    return data, encrypted


def archive_digest(file: BinaryIO) -> str:
    file.seek(0)
    return hashlib.file_digest(file, "sha256").hexdigest()


def require_new(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)


def show_index(source: Path) -> None:
    with source.open("rb") as file:
        entries, _ = read_index(file)
    for entry in entries:
        mode = "raw" if entry.size == entry.stored else "lzss"
        print(f"0x{entry.offset:08X}  {entry.size:>10}  {entry.stored:>10}  {mode:4}  {entry.name}")
    print(f"{len(entries)} member(s)")


def unpack(source: Path, target: Path) -> None:
    require_new(target)
    with source.open("rb") as file, tempfile.TemporaryDirectory(dir=target.parent) as temp:
        entries, _ = read_index(file)
        staging = Path(temp) / "files"
        staging.mkdir()
        stats: Counter[str] = Counter()
        members = []
        for entry in entries:
            data, encrypted = unpack_member(file, entry)
            (staging / entry.name).write_bytes(data)
            members.append({"name": entry.name, "ypk1": encrypted, "sha256": hashlib.sha256(data).hexdigest()})
            stats["lzss" if entry.size != entry.stored else "raw"] += 1
            stats["ypk1"] += encrypted
        manifest = {"format": "BINZ/1", "source_sha256": archive_digest(file), "members": members}
        (staging / MANIFEST).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.rename(target)
    print(f"Unpacked {len(entries)} members into {target} ({stats['lzss']} LZSS, {stats['raw']} raw, {stats['ypk1']} YPK1)")


def pack_members(folder: Path) -> tuple[list[dict], dict | None]:
    index = folder / MANIFEST
    if index.is_symlink():
        raise FormatError(f"Symbolic link is not supported: {index}")
    paths = {path.name: path for path in folder.iterdir() if path.name != MANIFEST}
    if not all(path.is_file() and not path.is_symlink() for path in paths.values()):
        raise FormatError("BINZ input must be a flat directory of regular files")
    if index.exists():
        manifest = json.loads(index.read_text(encoding="utf-8"))
        members = manifest.get("members") if isinstance(manifest, dict) else None
        if not isinstance(members, list) or manifest.get("format") != "BINZ/1":
            raise FormatError(f"Invalid {MANIFEST}")
        if any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
               or type(item.get("ypk1")) is not bool for item in members):
            raise FormatError(f"Invalid member metadata in {MANIFEST}")
        names = [item["name"] for item in members]
        missing = set(names) - paths.keys()
        extra = paths.keys() - set(names)
        if missing or extra:
            raise FormatError(f"Folder differs from {MANIFEST}: missing {sorted(missing)!r}, extra {sorted(extra)!r}")
    else:
        manifest = None
        names = sorted(paths, key=str.casefold)
        members = [{"name": name, "ypk1": False} for name in names]
    if not members:
        raise FormatError("BINZ requires at least one member")
    check_names(names)
    return members, manifest


def copy_range(source: BinaryIO, target: BinaryIO, offset: int, length: int) -> None:
    if length:
        source.seek(offset)
    while length:
        chunk = read_exact(source, min(length, 1024 * 1024))
        target.write(chunk)
        length -= len(chunk)


def pack(folder: Path, target: Path, base: Path | None) -> None:
    members, manifest = pack_members(folder)
    require_new(target)
    if base is not None and manifest is None:
        raise FormatError(f"--base requires the {MANIFEST} created by unpack")
    base_context = base.open("rb") if base is not None else nullcontext()
    table_end = HEADER.size + len(members) * RECORD.size
    records = [b""] * len(members)
    stats: Counter[str] = Counter()
    with base_context as source, tempfile.TemporaryDirectory(dir=target.parent) as temp:
        if source is not None:
            original, archive_end = read_index(source)
            if (archive_digest(source) != manifest.get("source_sha256")
                    or [entry.name for entry in original] != [item["name"] for item in members]):
                raise FormatError("Base archive does not match the extraction manifest")
            order = physical_order(original)
        else:
            order = range(len(members))
        staged = Path(temp) / "archive.dat"
        with staged.open("wb") as out:
            out.seek(table_end)
            old_cursor = table_end
            for index in order:
                item = members[index]
                name = item["name"]
                if source is not None:
                    entry = original[index]
                    copy_range(source, out, old_cursor, entry.offset - old_cursor)
                    old_cursor = entry.offset + entry.stored
                    name_field = entry.name_field
                else:
                    name_field = name_bytes(name)
                start = out.tell()
                plain = (folder / name).read_bytes()
                if source is not None and item.get("sha256") == hashlib.sha256(plain).hexdigest():
                    original_plain, was_encrypted = unpack_member(source, entry)
                    unchanged = plain == original_plain and item["ypk1"] == was_encrypted
                else:
                    unchanged = False
                if unchanged:
                    size, stored = entry.size, entry.stored
                    copy_range(source, out, entry.offset, stored)
                    stats["reused"] += 1
                else:
                    if item["ypk1"]:
                        plain = YPK1 + plain.translate(YPK1_TABLE)
                    elif plain.startswith(YPK1):
                        raise FormatError(f"{name!r} starts with YPK1. Set its ypk1 flag in {MANIFEST} to wrap it.")
                    data = compress(plain)
                    size, stored = len(plain), len(data)
                    out.write(data)
                    stats["encoded"] += 1
                if size > UINT32_MAX or out.tell() > UINT32_MAX:
                    raise FormatError("BINZ exceeds its 32-bit size limit")
                records[index] = RECORD.pack(name_field, start, size, stored)
            if source is not None:
                copy_range(source, out, old_cursor, archive_end - old_cursor)
                if out.tell() > UINT32_MAX:
                    raise FormatError("BINZ exceeds its 32-bit size limit")
            out.truncate()
            out.seek(0)
            out.write(HEADER.pack(MAGIC, len(records)))
            out.writelines(records)
        if os.name == "nt":
            staged.rename(target)
        else:
            os.link(staged, target)
    print(f"Packed {len(members)} members into {target} ({stats['encoded']} encoded, {stats['reused']} reused)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="List the archive table")
    listing.add_argument("archive", type=Path)
    extracting = commands.add_parser("unpack", help="Extract and decode all archive members")
    extracting.add_argument("archive", type=Path)
    extracting.add_argument("directory", type=Path)
    packing = commands.add_parser("pack", help="Build an archive from a directory")
    packing.add_argument("directory", type=Path)
    packing.add_argument("archive", type=Path)
    packing.add_argument("--base", type=Path, help="Reuse unchanged encoded members and preserve unindexed spans")
    args = parser.parse_args()
    try:
        if args.command == "list":
            show_index(args.archive)
        elif args.command == "unpack":
            unpack(args.archive, args.directory)
        else:
            pack(args.directory, args.archive, args.base)
    except (OSError, ValueError) as error:
        parser.exit(1, f"dat_tool: {error}\n")


if __name__ == "__main__":
    main()
