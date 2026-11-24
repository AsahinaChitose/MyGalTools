#!/usr/bin/env python3
"""Unpack and rebuild the ScnPac.Dat layout from Campus NewEdition."""

import argparse
import struct
import sys
from contextlib import suppress
from pathlib import Path


U32 = struct.Struct("<I")
ENTRY_COUNT = 639
LZ_START = 2
LZ_END = 171  # Exclusive. The TOC itself has no per-entry compression flag.
SCENE_LIMIT = 0x64000
ENTRY_2_LIMIT = 0x10000
MAX_FILE_SIZE = 0x7FFFFFFF  # The executable uses _llseek with signed LONG offsets.
SOURCE_COPY = ".original.dat"
MAX_DISTANCE = 1024
MAX_MATCH = 32
MAX_LITERAL = 128


class FormatError(ValueError):
    pass


def read_entries(archive: bytes) -> list[bytes]:
    table_size = U32.size * (ENTRY_COUNT + 2)
    if not table_size <= len(archive) <= MAX_FILE_SIZE:
        raise FormatError("Invalid archive size")
    count, = U32.unpack_from(archive)
    if count != ENTRY_COUNT:
        raise FormatError(f"Unsupported entry layout: expected {ENTRY_COUNT}, got {count}")
    offsets = struct.unpack_from(f"<{count + 1}I", archive, U32.size)
    if offsets[0] != table_size or offsets[-1] != len(archive):
        raise FormatError("The first offset or EOF offset does not match the archive size")
    ranges = list(zip(offsets, offsets[1:]))
    if any(start > end for start, end in ranges):
        raise FormatError("Archive offsets are not in ascending order")
    return [archive[start:end] for start, end in ranges]


def decode_lz(stored: bytes, limit: int = SCENE_LIMIT) -> bytes:
    """Decode the exact byte stream consumed by SERAPH.EXE at 0x416660."""
    if len(stored) < U32.size:
        raise FormatError("Missing LZ size header")
    expected, = U32.unpack_from(stored)
    if expected > limit:
        raise FormatError(f"Decoded size {expected} exceeds the engine limit {limit}")
    pos = U32.size
    output = bytearray()
    while len(output) < expected:
        token_pos = pos
        if pos >= len(stored):
            raise FormatError(f"Missing LZ token at +0x{pos:X}")
        token = stored[pos]
        pos += 1
        if token & 0x80:
            if pos >= len(stored):
                raise FormatError(f"Truncated LZ back-reference at +0x{token_pos:X}")
            code = (token << 8) | stored[pos]
            pos += 1
            distance = ((code >> 5) & 0x3FF) + 1
            length = (code & 0x1F) + 1
            if distance > len(output) or len(output) + length > expected:
                raise FormatError(f"Out-of-range LZ back-reference at +0x{token_pos:X}")
            for _ in range(length):
                output.append(output[-distance])  # Overlapping copies are valid.
        else:
            length = token + 1
            if pos + length > len(stored) or len(output) + length > expected:
                raise FormatError(f"Invalid LZ literal run at +0x{token_pos:X}")
            output.extend(stored[pos:pos + length])
            pos += length
    if pos != len(stored):
        raise FormatError(f"Trailing data after LZ stream at +0x{pos:X}")
    return bytes(output)


def encode_lz(data: bytes, limit: int = SCENE_LIMIT) -> bytes:
    """Emit bounded literal runs and greedy matches in SERAPH's LZ format."""
    if len(data) > limit:
        raise FormatError(f"Decoded size {len(data)} exceeds the engine limit {limit}")
    output = bytearray(U32.pack(len(data)))
    literals = bytearray()
    pos = 0
    while pos < len(data):
        length, distance = find_match(data, pos)
        if length:
            emit_literals(output, literals)
            code = 0x8000 | ((distance - 1) << 5) | (length - 1)
            output.extend(code.to_bytes(2, "big"))
            pos += length
        else:
            literals.append(data[pos])
            pos += 1
            if len(literals) == MAX_LITERAL:
                emit_literals(output, literals)
    emit_literals(output, literals)
    return bytes(output)


def find_match(data: bytes, pos: int) -> tuple[int, int]:
    # Search for matches of at least three bytes for the two-byte token.
    # The latest candidate starts at pos - 1, which allows overlaps.
    cap = min(MAX_MATCH, len(data) - pos)
    if cap < 3:
        return 0, 0
    first = max(0, pos - MAX_DISTANCE)
    prefix = data[pos:pos + 3]
    candidate = data.rfind(prefix, first, pos + 2)
    best_length = best_distance = 0
    while candidate >= first:
        length = 3
        while length < cap and data[candidate + length] == data[pos + length]:
            length += 1
        if length > best_length:
            best_length, best_distance = length, pos - candidate
            if best_length == cap:
                break
        candidate = data.rfind(prefix, first, candidate + 2)
    return best_length, best_distance


def emit_literals(output: bytearray, literals: bytearray) -> None:
    if literals:
        output.append(len(literals) - 1)
        output.extend(literals)
        literals.clear()


def entry_limit(index: int) -> int:
    return ENTRY_2_LIMIT if index == 2 else SCENE_LIMIT


def decode_entry(index: int, stored: bytes) -> bytes:
    if not LZ_START <= index < LZ_END:
        return stored
    try:
        return decode_lz(stored, entry_limit(index))
    except FormatError as exc:
        raise FormatError(f"Entry {index:04d}: {exc}") from exc


def write_new(path: Path, data: bytes) -> None:
    stream = path.open("xb")
    try:
        with stream:
            stream.write(data)
    except (OSError, KeyboardInterrupt):
        with suppress(OSError):
            path.unlink()
        raise


def unpack(archive: Path, output: Path) -> None:
    source = archive.read_bytes()
    payloads = [decode_entry(index, stored) for index, stored in enumerate(read_entries(source))]
    output.mkdir()
    written = []
    try:
        for index, data in enumerate(payloads):
            path = output / f"{index:05d}"
            write_new(path, data)
            written.append(path)
        path = output / SOURCE_COPY
        write_new(path, source)
        written.append(path)
    except (OSError, KeyboardInterrupt):
        for path in written:
            with suppress(OSError):
                path.unlink()
        with suppress(OSError):
            output.rmdir()
        raise
    lz_count = LZ_END - LZ_START
    print(f"Unpacked {len(payloads)} entries ({lz_count} LZ, {len(payloads) - lz_count} raw) to {output}")


def pack(directory: Path, output: Path) -> None:
    source_path = directory / SOURCE_COPY
    if not source_path.is_file():
        source_path = Path(__file__).resolve().parent / "ScnPac.Dat"
        if not source_path.is_file():
            source_path = Path(__file__).resolve().parent.parent / "ScnPac.Dat"
    original_entries = read_entries(source_path.read_bytes())
    stored_entries = []
    offsets = [U32.size * (ENTRY_COUNT + 2)]
    recompressed = 0
    for index, original in enumerate(original_entries):
        path = directory / f"{index:05d}"
        if not path.is_file():
            path = directory / f"{index:04d}.bin"
        payload = path.read_bytes()
        if LZ_START <= index < LZ_END:
            if payload == decode_entry(index, original):
                stored = original
            else:
                try:
                    stored = encode_lz(payload, entry_limit(index))
                except FormatError as exc:
                    raise FormatError(f"Entry {index:04d}: {exc}") from exc
                recompressed += 1
        else:
            stored = payload
        end = offsets[-1] + len(stored)
        if end > MAX_FILE_SIZE:
            raise FormatError("Rebuilt archive is too large for the engine's file offsets")
        offsets.append(end)
        stored_entries.append(stored)
    header = struct.pack(f"<{ENTRY_COUNT + 2}I", ENTRY_COUNT, *offsets)
    write_new(output, b"".join([header, *stored_entries]))
    print(f"Packed {ENTRY_COUNT} entries ({recompressed} recompressed) to {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    unpack_cmd = commands.add_parser("unpack", help="decode entries to a new directory")
    unpack_cmd.add_argument("archive", type=Path)
    unpack_cmd.add_argument("output_dir", type=Path)
    pack_cmd = commands.add_parser("pack", help="rebuild an archive from an unpacked directory")
    pack_cmd.add_argument("input_dir", type=Path, help=f"directory with five-digit entries (legacy .bin names accepted) and optional {SOURCE_COPY}")
    pack_cmd.add_argument("archive", type=Path, help="path to a new output archive")
    args = parser.parse_args()
    try:
        if args.command == "unpack":
            unpack(args.archive, args.output_dir)
        else:
            pack(args.input_dir, args.archive)
    except FileExistsError as exc:
        print(f"Output already exists at {exc.filename}", file=sys.stderr)
        return 1
    except (FormatError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
