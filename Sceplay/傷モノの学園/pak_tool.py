#!/usr/bin/env python3
"""List, unpack, repack and verify flat Sceplay PAK archives.

The PAK stores native resources directly, including G24A files with their own
image compression. The extraction manifest records the original index order
and filename bytes so a round trip preserves the original resource indices.
"""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path, PureWindowsPath
import struct
import tempfile


MAGIC = b"pak\0"
FORMAT = "PAK/SCEPLAY"
MANIFEST = "__sceplay_pak__.json"
NAME_SIZE = 0x18
MISSING = 0xFFFFFFFF
MAX_ARCHIVE = 0x7FFFFFFF  # The game's 32-bit fseek takes a signed long.
HEADER = struct.Struct("<4sI")
U32 = struct.Struct("<I")
CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Slot:
    name: str
    field: bytes
    size: int
    offset: int

    @property
    def present(self):
        return self.offset != MISSING


def decode_name(field):
    if len(field) != NAME_SIZE:
        raise ValueError("expected a 24-byte filename field")
    name = field.split(b"\0", 1)[0].decode("cp932")
    if (not name or name[-1] in ". " or name.casefold() == MANIFEST.casefold()
            or any(ord(char) < 32 or char in '<>:"/\\|?*' for char in name)
            or PureWindowsPath(name).is_reserved()):
        raise ValueError(f"unsafe or reserved filename: {name!r}")
    return name


def encode_name(name):
    raw = name.encode("cp932")
    if len(raw) >= NAME_SIZE:
        raise ValueError(f"filename exceeds 23 CP932 bytes: {name!r}")
    return raw.ljust(NAME_SIZE, b"\0")


def unique_names(slots):
    seen = set()
    for slot in slots:
        if slot.present:
            key = slot.name.casefold()
            if key in seen:
                raise ValueError(f"duplicate filename: {slot.name!r}")
            seen.add(key)


def read_index(stream):
    archive_size = os.fstat(stream.fileno()).st_size
    raw_header = stream.read(HEADER.size)
    if len(raw_header) != HEADER.size:
        raise ValueError("truncated PAK header")
    magic, count = HEADER.unpack(raw_header)
    if magic != MAGIC:
        raise ValueError("expected Sceplay signature 'pak\\0'")
    index_size = count * (NAME_SIZE + 2 * U32.size)
    data_start = HEADER.size + index_size
    if not count or data_start > min(archive_size, MAX_ARCHIVE):
        raise ValueError(f"invalid entry count: {count}")

    index = stream.read(index_size)
    if len(index) != index_size:
        raise ValueError("truncated PAK index")
    sizes_base = NAME_SIZE * count
    offsets_base = sizes_base + U32.size * count
    slots = []
    for i in range(count):
        field = index[i * NAME_SIZE:(i + 1) * NAME_SIZE]
        name = decode_name(field)
        size, = U32.unpack_from(index, sizes_base + i * U32.size)
        offset, = U32.unpack_from(index, offsets_base + i * U32.size)
        if offset != MISSING and (offset < data_start or offset + size > archive_size):
            raise ValueError(f"entry #{i} {name!r} is outside the PAK payload")
        slots.append(Slot(name, field, size, offset))
    unique_names(slots)
    return slots


def read_data(source, size):
    while size:
        block = source.read(min(size, CHUNK))
        if not block:
            raise ValueError("file ended while reading an entry")
        size -= len(block)
        yield block


def unpack(archive, directory):
    directory = directory.absolute()
    if os.path.lexists(directory):
        raise FileExistsError(f"destination exists: {directory}")
    with archive.open("rb") as source:
        slots = read_index(source)
        with tempfile.TemporaryDirectory(prefix=".pak-", dir=directory.parent) as tmp:
            stage = Path(tmp) / "files"
            stage.mkdir()
            records = []
            for slot in slots:
                record = {"name": slot.name, "field": slot.field.hex()}
                records.append(record)
                if slot.present:
                    source.seek(slot.offset)
                    with (stage / slot.name).open("xb") as destination:
                        for block in read_data(source, slot.size):
                            destination.write(block)
                else:
                    record["missing_size"] = slot.size
            manifest = json.dumps({"format": FORMAT, "entries": records},
                                  ensure_ascii=False, indent=2)
            (stage / MANIFEST).write_text(manifest + "\n", encoding="utf-8")
            stage.rename(directory)
    print(f"Unpacked {sum(slot.present for slot in slots)} files to {directory}")


def pack_index(directory):
    manifest = directory / MANIFEST
    if manifest.is_file():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or data.get("format") != FORMAT
                or not isinstance(data.get("entries"), list)):
            raise ValueError("invalid Sceplay extraction manifest")
        records = data["entries"]
    else:
        files = sorted((path for path in directory.iterdir() if path.is_file()),
                       key=lambda path: path.name.casefold())
        records = [{"name": path.name, "field": encode_name(path.name).hex()} for path in files]
    if not records:
        raise ValueError("no entries to pack")
    offset = HEADER.size + (NAME_SIZE + 2 * U32.size) * len(records)
    if offset > MAX_ARCHIVE:
        raise ValueError("PAK index exceeds the engine's 32-bit seek range")
    slots = []
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("field"), str):
            raise ValueError("invalid filename field in manifest")
        field = bytes.fromhex(record["field"])
        name = decode_name(field)
        if name != record.get("name"):
            raise ValueError(f"manifest filename differs from filename bytes: {name!r}")
        if "missing_size" in record:
            size = record["missing_size"]
            if type(size) is not int or not 0 <= size <= MISSING:
                raise ValueError(f"invalid missing-entry size: {name!r}")
            slots.append(Slot(name, field, size, MISSING))
            continue
        path = directory / name
        if not path.is_file():
            raise ValueError(f"input is missing or not a regular file: {path}")
        size = path.stat().st_size
        if offset + size > MAX_ARCHIVE:
            raise ValueError(f"PAK exceeds the engine's 32-bit seek range at {name!r}")
        slots.append(Slot(name, field, size, offset))
        offset += size
    unique_names(slots)
    return slots


def pack(directory, archive):
    archive = archive.absolute()
    if os.path.lexists(archive):
        raise FileExistsError(f"destination exists: {archive}")
    slots = pack_index(directory)
    with tempfile.TemporaryDirectory(prefix=".pak-", dir=archive.parent) as tmp:
        stage = Path(tmp) / "archive.pak"
        with stage.open("wb") as destination:
            destination.write(HEADER.pack(MAGIC, len(slots)))
            destination.writelines(slot.field for slot in slots)
            destination.writelines(U32.pack(slot.size) for slot in slots)
            destination.writelines(U32.pack(slot.offset) for slot in slots)
            for slot in slots:
                if slot.present:
                    with (directory / slot.name).open("rb") as source:
                        for block in read_data(source, slot.size):
                            destination.write(block)
                        if source.read(1):
                            raise ValueError(f"input grew while packing: {slot.name!r}")
        if os.name == "nt":
            stage.rename(archive)
        else:
            os.link(stage, archive)
    print(f"Packed {sum(slot.present for slot in slots)} files into {archive}")


def list_archive(archive):
    with archive.open("rb") as source:
        slots = read_index(source)
    print(f"{'#':>6}  {'offset':>10}  {'size':>10}  name")
    for i, slot in enumerate(slots):
        offset = f"0x{slot.offset:08X}" if slot.present else "(missing)"
        print(f"{i:6d}  {offset:>10}  {slot.size:10d}  {slot.name}")


def verify(archive, directory):
    with archive.open("rb") as source:
        slots = read_index(source)
        for slot in slots:
            if not slot.present:
                continue
            source.seek(slot.offset)
            with (directory / slot.name).open("rb") as extracted:
                for block in read_data(source, slot.size):
                    if extracted.read(len(block)) != block:
                        raise ValueError(f"entry bytes differ: {slot.name!r}")
                if extracted.read(1):
                    raise ValueError(f"extracted file is longer than entry: {slot.name!r}")
    print(f"Verified {sum(slot.present for slot in slots)} files against {archive}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="show entry order, offsets and sizes")
    listing.add_argument("archive", type=Path)
    extract = commands.add_parser("unpack", help="extract native resources to a new directory")
    extract.add_argument("archive", type=Path)
    extract.add_argument("directory", type=Path)
    build = commands.add_parser("pack", help="build a new PAK from a directory")
    build.add_argument("directory", type=Path)
    build.add_argument("archive", type=Path)
    check = commands.add_parser("verify", help="compare extracted resources against a PAK")
    check.add_argument("archive", type=Path)
    check.add_argument("directory", type=Path)
    args = parser.parse_args()

    try:
        if args.command == "list":
            list_archive(args.archive)
        elif args.command == "unpack":
            unpack(args.archive, args.directory)
        elif args.command == "pack":
            pack(args.directory, args.archive)
        else:
            verify(args.archive, args.directory)
    except (OSError, ValueError) as error:
        parser.exit(1, f"pak_tool: {error}\n")


if __name__ == "__main__":
    main()
