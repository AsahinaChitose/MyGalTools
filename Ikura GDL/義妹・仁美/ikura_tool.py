#!/usr/bin/env python3
"""Unpack and rebuild HITOMI's Ikura GDL SM2MPX10 ISF and GGD archives."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from struct import Struct, pack, pack_into, unpack_from
from tempfile import TemporaryDirectory
from typing import BinaryIO


HEADER = Struct('<8sII12sI')
RECORD = Struct('<12sII')
MAGIC = b'SM2MPX10'
KINDS = {b'ISF': 'ISF', b'GGD': 'GGD'}
INVERT = bytes(i ^ 255 for i in range(256))
ROR2 = bytes((i >> 2) | ((i << 6) & 255) for i in range(256))
ROL2 = bytes(((i << 2) & 255) | (i >> 6) for i in range(256))
ISF_MAGIC = b'HITOMI'
FULL_MAGIC = b'FULL'.translate(INVERT)
INDEXED_MAGIC = b'256G'.translate(INVERT)
GGA_MAGIC = b'GGA00000'
MANIFEST = 'ikura.json'
CACHE = '.ikura-originals'
BMP_FILE = Struct('<2sIHHI')
BMP_INFO = Struct('<IiiHHIIiiII')
BGRA_MASKS = (0xFF0000, 0xFF00, 0xFF, 0xFF000000)


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class Member:
    name_field: bytes
    offset: int
    size: int

    @property
    def name(self) -> str:
        return member_name(self.name_field)


@dataclass(frozen=True)
class Bitmap:
    width: int
    height: int
    bits: int
    pixels: bytes
    palette: bytes = b''


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & -boundary


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_exact(source: BinaryIO, size: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise FormatError(f'unexpected EOF while reading {size} bytes')
    return data


def member_name(name_field: bytes) -> str:
    if len(name_field) != 12:
        raise FormatError('member name field must be 12 bytes')
    raw = name_field.split(b'\0', 1)[0]
    if not re.fullmatch(rb'[A-Za-z0-9_~$-]+\.[A-Za-z0-9_~$-]+', raw):
        raise FormatError(f'invalid member name: {name_field.hex()}')
    name = raw.decode('ascii')
    if name.split('.', 1)[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *(
        f'{prefix}{number}' for prefix in ('COM', 'LPT') for number in range(1, 10)
    )}:
        raise FormatError(f'reserved member name: {name}')
    return name


def archive_index(source: BinaryIO) -> tuple[bytes, list[Member]]:
    total = source.seek(0, os.SEEK_END)
    source.seek(0)
    magic, count, index_end, tag, index_offset = HEADER.unpack(read_exact(source, HEADER.size))
    if magic != MAGIC or tag.split(b'\0', 1)[0].upper() not in KINDS:
        raise FormatError('expected a HITOMI SM2MPX10 ISF or GGD archive')
    if index_offset != HEADER.size or index_end != index_offset + count * RECORD.size:
        raise FormatError('inconsistent archive directory offsets')
    if not count or not index_end <= total <= 0xFFFFFFFF:
        raise FormatError('invalid archive size or member count')
    members = [Member(*fields) for fields in RECORD.iter_unpack(read_exact(source, count * RECORD.size))]
    previous_name = ''
    end = index_end
    for member in members:
        name = member.name.casefold()
        if name <= previous_name:
            raise FormatError(f'duplicate or unsorted directory entry: {member.name}')
        previous_name = name
        if member.offset != align(end, 16) or member.offset + member.size > total:
            raise FormatError(f'{member.name}: invalid offset or size at 0x{member.offset:x}')
        source.seek(end)
        if any(read_exact(source, member.offset - end)):
            raise FormatError(f'{member.name}: nonzero alignment bytes at 0x{end:x}')
        end = member.offset + member.size
    if total != align(end, 16):
        raise FormatError('invalid size after the final member')
    source.seek(end)
    if any(read_exact(source, total - end)):
        raise FormatError('nonzero padding after the final member')
    return tag, members


def transform_isf(data: bytes, *, encode: bool) -> bytes:
    if len(data) < 14 or not data.startswith(ISF_MAGIC):
        raise FormatError('expected a HITOMI script header')
    table_end = unpack_from('<I', data, 6)[0]
    if not 8 <= table_end <= len(data) - len(ISF_MAGIC) or table_end % 4:
        raise FormatError(f'invalid ISF table boundary: 0x{table_end:x}')
    mode = data[10:12]
    if mode == b'\x95\x97':
        table = ROL2 if encode else ROR2
    elif mode == b'\x97\xd1':
        table = INVERT
    elif mode == b'\x89\xce':
        table = bytes(i ^ data[12] for i in range(256))
    else:
        raise FormatError(f'unsupported HITOMI script mode {mode.hex()}')
    result = data[:14] + data[14:].translate(table)
    plaintext = data if encode else result
    index_size = table_end + len(ISF_MAGIC) - 14
    for (offset,) in Struct('<I').iter_unpack(plaintext[14:14 + index_size]):
        # Runtime pointers are relative to the VM's code area, including references
        # to labels that coincide with the end of that area.
        if offset > len(data) - table_end - len(ISF_MAGIC):
            raise FormatError(f'ISF entry offset 0x{offset:x} lies outside the code area')
    return result


def pixel_copy(output: bytearray, unit: int, distance: int, count: int, limit: int) -> None:
    if not count:
        return
    back = distance * unit
    needed = count * unit
    if not 0 < back <= len(output) or len(output) + needed > limit:
        raise FormatError(f'invalid image back-reference at decoded offset 0x{len(output):x}')
    start = len(output) - back
    pattern = output[start:start + min(needed, back)]
    repeats, remainder = divmod(needed, len(pattern))
    output.extend(pattern * repeats)
    output.extend(pattern[:remainder])


def decode_full(source: bytes, size: int) -> tuple[bytes, bytes]:
    output = bytearray()
    limit = align_pixels(size)
    pos = 0
    while len(output) < size:
        if pos >= len(source):
            raise FormatError('truncated FULL pixel stream')
        opcode = source[pos]
        pos += 1
        if opcode >= 5:
            end = pos + (opcode - 4) * 3
            if end > len(source) or len(output) + end - pos > limit:
                raise FormatError(f'invalid FULL literal at 0x{pos - 1:x}')
            output.extend(source[pos:end])
        else:
            end = pos + (1, 2, 3, 1, 2)[opcode]
            if end > len(source):
                raise FormatError(f'truncated FULL command at 0x{pos - 1:x}')
            arg = source[pos:end]
            count = arg[0] if opcode <= 2 else 1
            distance = (1 if opcode == 0 else int.from_bytes(arg[1:] if opcode <= 2 else arg, 'little'))
            pixel_copy(output, 3, distance, count, limit)
        pos = end
    return bytes(output), source[pos:]


def align_pixels(size: int) -> int:
    return (size + 2) // 3 * 3


def decode_gga(source: bytes, width: int, height: int) -> bytes:
    output = bytearray()
    limit = width * height * 4
    pos = 0
    while pos < len(source):
        opcode = source[pos]
        pos += 1
        if opcode >= 12:
            end = pos + (opcode - 11) * 4
            if end > len(source) or len(output) + end - pos > limit:
                raise FormatError(f'invalid GGA literal at 0x{pos - 1:x}')
            output.extend(source[pos:end])
        elif opcode >= 8:
            pixel_copy(output, 4, (1, width, width + 1, width - 1)[opcode - 8], 1, limit)
            end = pos
        else:
            end = pos + (1, 2, 1, 2, 2, 3, 3, 4)[opcode]
            if end > len(source):
                raise FormatError(f'truncated GGA command at 0x{pos - 1:x}')
            arg = source[pos:end]
            if opcode <= 1:
                distance, count = 1, int.from_bytes(arg, 'little')
            elif opcode <= 3:
                distance, count = int.from_bytes(arg, 'little'), 1
            else:
                distance_size = 1 if opcode <= 5 else 2
                distance = int.from_bytes(arg[:distance_size], 'little')
                count = int.from_bytes(arg[distance_size:], 'little')
            pixel_copy(output, 4, distance, count, limit)
        pos = end
    if len(output) != limit:
        raise FormatError(f'GGA decoded {len(output)} bytes, expected {limit}')
    return bytes(output)


def encode_pixels(data: bytes, unit: int, row_distance: int) -> bytes:
    """Greedy pixel RLE/LZ encoder for FULL (3 bytes) and GGA (4 bytes)."""
    if unit == 3:
        widened = bytearray(len(data) // 3 * 4)
        for channel in range(3):
            widened[channel::4] = data[channel::3]
        values = memoryview(widened).cast('I')
        max_match, max_literal, literal_base = 255, 251, 4
    else:
        values = memoryview(data).cast('I')
        max_match, max_literal, literal_base = 65535, 244, 11
    output = bytearray()
    last = {}
    pos = literal_start = 0
    while pos < len(values):
        value = values[pos]
        previous = last.get(value, -65536)
        last[value] = pos
        if previous != pos - 1 and pos >= row_distance and values[pos - row_distance] == value:
            previous = pos - row_distance
        distance = pos - previous
        count = 0
        if distance <= 65535:
            count = 1
            end = min(pos + max_match, len(values))
            while pos + count < end and values[previous + count] == values[pos + count]:
                count += 1
        if count < 2:
            pos += 1
            if pos - literal_start == max_literal:
                output.append(literal_base + max_literal)
                output.extend(data[literal_start * unit:pos * unit])
                literal_start = pos
            continue
        if pos > literal_start:
            output.append(literal_base + pos - literal_start)
            output.extend(data[literal_start * unit:pos * unit])
        if unit == 3:
            if distance == 1:
                output.extend((0, count))
            elif distance <= 255:
                output.extend((1, count, distance))
            else:
                output.extend(pack('<BBH', 2, count, distance))
        elif distance == 1:
            output.extend(pack('<BB', 0, count) if count <= 255 else pack('<BH', 1, count))
        elif distance <= 255:
            output.extend(pack('<BBB', 4, distance, count) if count <= 255 else pack('<BBH', 5, distance, count))
        else:
            output.extend(pack('<BHB', 6, distance, count) if count <= 255 else pack('<BHH', 7, distance, count))
        pos += count
        literal_start = pos
    if pos > literal_start:
        output.append(literal_base + pos - literal_start)
        output.extend(data[literal_start * unit:])
    return bytes(output)


def decode_lzss(source: bytes, size: int) -> tuple[bytes, bytes]:
    ring = bytearray(4096)
    current = 0xFEE
    output = bytearray()
    pos = 0
    while len(output) < size:
        if pos >= len(source):
            raise FormatError('truncated 256G LZSS flag')
        flags = source[pos]
        pos += 1
        for bit in range(8):
            if len(output) >= size:
                break
            length = 1 if flags & (1 << bit) else 2
            if pos + length > len(source):
                raise FormatError('truncated 256G LZSS token')
            if length == 1:
                value = source[pos]
                output.append(value)
                ring[current] = value
                current = (current + 1) & 0xFFF
            else:
                second = source[pos + 1]
                offset = source[pos] | ((second & 0xF0) << 4)
                count = (second & 15) + 3
                if len(output) + count > size:
                    raise FormatError('256G LZSS match crosses the decoded image boundary')
                for i in range(count):
                    value = ring[(offset + i) & 0xFFF]
                    output.append(value)
                    ring[current] = value
                    current = (current + 1) & 0xFFF
            pos += length
    return bytes(output), source[pos:]


def encode_lzss(data: bytes) -> bytes:
    output = bytearray()
    pos = 0
    while pos < len(data):
        flag_offset = len(output)
        output.append(0)
        for bit in range(8):
            if pos == len(data):
                break
            end = min(pos + 18, len(data))
            previous = -1
            if end - pos >= 3:
                previous = data.rfind(data[pos:pos + 3], max(0, pos - 4096), pos + 2)
            if previous < 0:
                output[flag_offset] |= 1 << bit
                output.append(data[pos])
                pos += 1
                continue
            count = 3
            while pos + count < end and data[previous + count] == data[pos + count]:
                count += 1
            offset = (previous + 0xFEE) & 0xFFF
            output.extend((offset & 255, ((offset >> 4) & 0xF0) | (count - 3)))
            pos += count
    return bytes(output)


def dimensions(width: int, height: int) -> None:
    if not (0 < width <= 0x7FFF and 0 < height <= 0x7FFF and width * height * 4 <= 0x7FFFFFFF):
        raise FormatError(f'unsupported image dimensions {width} x {height}')


def bmp_bytes(bitmap: Bitmap) -> bytes:
    info_size = 108 if bitmap.bits == 32 else BMP_INFO.size
    extra = bitmap.palette
    if bitmap.bits == 32:
        extra = pack('<4I4s', *BGRA_MASKS, b'BGRs') + bytes(48)
    offset = BMP_FILE.size + info_size + len(bitmap.palette)
    info = BMP_INFO.pack(info_size, bitmap.width, -bitmap.height, 1, bitmap.bits,
                         3 if bitmap.bits == 32 else 0, len(bitmap.pixels),
                         0, 0, 256 if bitmap.palette else 0, 0)
    return BMP_FILE.pack(b'BM', offset + len(bitmap.pixels), 0, 0, offset) + info + extra + bitmap.pixels


def parse_bmp(data: bytes, expected_bits: int) -> Bitmap:
    if len(data) < BMP_FILE.size + BMP_INFO.size:
        raise FormatError('truncated BMP header')
    magic, _, _, _, offset = BMP_FILE.unpack_from(data)
    info_size, width, signed_height, planes, bits, compression, _, _, _, colors, _ = BMP_INFO.unpack_from(data, 14)
    height = abs(signed_height)
    dimensions(width, height)
    end_info = 14 + info_size
    if magic != b'BM' or planes != 1 or bits != expected_bits or not 54 <= end_info <= offset <= len(data):
        raise FormatError(f'expected a {expected_bits}-bit Windows BMP')
    if bits == 32 and compression in (3, 6):
        if offset < 70 or unpack_from('<4I', data, 54) != BGRA_MASKS:
            raise FormatError('expected BMP bit masks for BGRA8888')
    elif compression != 0:
        raise FormatError('expected an uncompressed BMP')
    palette = b''
    if bits == 8:
        if colors not in (0, 256) or end_info + 1024 > offset:
            raise FormatError('expected a 256-entry BGRA-indexed BMP palette')
        palette = data[end_info:end_info + 1024]
    stride = align(width * (bits // 8), 4)
    end = offset + stride * height
    pixels = data[offset:end]
    if end > len(data):
        raise FormatError('truncated BMP pixel array')
    if signed_height > 0:
        pixels = b''.join(pixels[row:row + stride] for row in range(len(pixels) - stride, -1, -stride))
    return Bitmap(width, height, bits, pixels, palette)


def decode_image(data: bytes) -> tuple[bytes, dict]:
    if data.startswith(FULL_MAGIC) and len(data) >= 8:
        width, height = unpack_from('<HH', data, 4)
        dimensions(width, height)
        size = align(width * 3, 4) * height
        pixels, trailer = decode_full(data[8:], size)
        meta = {'codec': 'FULL', 'overrun': pixels[size:].hex(), 'trailer': trailer.hex()}
        bitmap = Bitmap(width, height, 24, pixels[:size])
    elif data.startswith(INDEXED_MAGIC) and len(data) >= 1072:
        header, width, signed_height, planes, bits, compression, *_ = BMP_INFO.unpack_from(data, 4)
        height = abs(signed_height)
        dimensions(width, height)
        if (header, planes, bits, compression) != (40, 1, 8, 0):
            raise FormatError('unsupported 256G bitmap header')
        size = align(width, 4) * height
        pixels, trailer = decode_lzss(data[1072:], size)
        meta = {'codec': '256G', 'header': data[:44].hex(), 'trailer': trailer.hex()}
        bitmap = Bitmap(width, height, 8, pixels, data[44:1068])
    elif data.startswith(GGA_MAGIC) and len(data) >= 48:
        width, height = unpack_from('<HH', data, 8)
        dimensions(width, height)
        offset, size, aux_offset, aux_size = unpack_from('<4I', data, 16)
        if aux_offset != 48 or offset != 48 + aux_size or offset + size != len(data):
            raise FormatError('inconsistent GGA pixel or auxiliary offsets')
        meta = {'codec': 'GGA', 'prefix': data[:offset].hex()}
        bitmap = Bitmap(width, height, 32, decode_gga(data[offset:], width, height))
    else:
        raise FormatError(f'unknown GGD image signature {data[:8].hex()}')
    return bmp_bytes(bitmap), meta


def encode_image(data: bytes, meta: dict) -> bytes:
    codec = meta['codec']
    if codec == 'FULL':
        bmp = parse_bmp(data, 24)
        required = align_pixels(len(bmp.pixels)) - len(bmp.pixels)
        extra = bytes.fromhex(meta['overrun'])[:required].ljust(required, b'\0')
        pixels = encode_pixels(bmp.pixels + extra, 3, align(bmp.width * 3, 4) // 3)
        return FULL_MAGIC + pack('<HH', bmp.width, bmp.height) + pixels + bytes.fromhex(meta['trailer'])
    if codec == '256G':
        bmp = parse_bmp(data, 8)
        header = bytearray.fromhex(meta['header'])
        if len(header) != 44 or not header.startswith(INDEXED_MAGIC):
            raise FormatError('invalid 256G header in manifest')
        pack_into('<ii', header, 8, bmp.width, -bmp.height)
        pack_into('<I', header, 24, len(bmp.pixels))
        return (bytes(header) + bmp.palette + pack('<I', len(bmp.pixels)) + encode_lzss(bmp.pixels)
                + bytes.fromhex(meta['trailer']))
    if codec == 'GGA':
        bmp = parse_bmp(data, 32)
        prefix = bytearray.fromhex(meta['prefix'])
        if len(prefix) < 48 or not prefix.startswith(GGA_MAGIC):
            raise FormatError('invalid GGA prefix in manifest')
        old_dimensions = unpack_from('<HH', prefix, 8)
        if len(prefix) > 48 and old_dimensions != (bmp.width, bmp.height):
            raise FormatError('GGA with auxiliary rectangles requires its original dimensions')
        pixels = encode_pixels(bmp.pixels, 4, bmp.width)
        pack_into('<HH', prefix, 8, bmp.width, bmp.height)
        pack_into('<I', prefix, 20, len(pixels))
        return bytes(prefix) + pixels
    raise FormatError(f'unknown image codec {codec!r}')


def image_name(name: str) -> str:
    return f'{name}.bmp'


def unpack_archive(archive: Path, destination: Path) -> Counter:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f'output already exists: {destination}')
    counts = Counter()
    with archive.open('rb') as source, TemporaryDirectory(prefix='.ikura-', dir=destination.parent) as temp:
        tag, members = archive_index(source)
        kind = KINDS[tag.split(b'\0', 1)[0].upper()]
        output = Path(temp) / 'output'
        output.mkdir()
        if kind == 'GGD':
            (output / CACHE).mkdir()
        entries = []
        for member in members:
            source.seek(member.offset)
            data = read_exact(source, member.size)
            name = member.name
            try:
                if kind == 'ISF':
                    decoded = transform_isf(data, encode=False)
                    meta = {'codec': 'ISF'}
                    path = output / name
                else:
                    decoded, meta = decode_image(data)
                    meta['encoded_sha256'] = digest(data)
                    meta['decoded_sha256'] = digest(decoded)
                    (output / CACHE / name).write_bytes(data)
                    path = output / image_name(name)
                path.write_bytes(decoded)
            except FormatError as error:
                raise FormatError(f'{name} at archive offset 0x{member.offset:x}: {error}') from error
            meta['name_hex'] = member.name_field.hex()
            entries.append(meta)
            counts[meta['codec']] += 1
        manifest = {'format': 'SM2MPX10', 'tag_hex': tag.hex(), 'entries': entries}
        (output / MANIFEST).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        output.rename(destination)
    return counts


def pack_archive(source: Path, archive: Path, *, recompress: bool) -> Counter:
    if archive.exists() or archive.is_symlink():
        raise FileExistsError(f'output already exists: {archive}')
    manifest = json.loads((source / MANIFEST).read_text(encoding='utf-8'))
    tag = bytes.fromhex(manifest['tag_hex'])
    kind = KINDS.get(tag.split(b'\0', 1)[0].upper())
    entries = manifest['entries']
    if manifest['format'] != 'SM2MPX10' or len(tag) != 12 or kind is None or not entries:
        raise FormatError('invalid HITOMI archive manifest')
    fields = [bytes.fromhex(entry['name_hex']) for entry in entries]
    names = [member_name(field) for field in fields]
    lookup_names = [name.casefold() for name in names]
    if lookup_names != sorted(set(lookup_names)):
        raise FormatError('manifest members must be unique and sorted by name for engine lookup')
    index_end = HEADER.size + RECORD.size * len(entries)
    counts = Counter()
    with TemporaryDirectory(prefix='.ikura-', dir=archive.parent) as temp:
        staging = Path(temp) / 'archive'
        with staging.open('wb') as output:
            output.write(HEADER.pack(MAGIC, len(entries), index_end, tag, HEADER.size))
            output.seek(align(index_end, 16))
            table = bytearray()
            for entry, field, name in zip(entries, fields, names):
                offset = output.tell()
                try:
                    if kind == 'ISF':
                        data = transform_isf((source / name).read_bytes(), encode=True)
                    else:
                        decoded = (source / image_name(name)).read_bytes()
                        cached = source / CACHE / name
                        data = None
                        if not recompress and cached.is_file() and digest(decoded) == entry['decoded_sha256']:
                            candidate = cached.read_bytes()
                            if digest(candidate) == entry['encoded_sha256']:
                                data = candidate
                        if data is None:
                            data = encode_image(decoded, entry)
                except FormatError as error:
                    raise FormatError(f'{name}: {error}') from error
                if align(offset + len(data), 16) > 0xFFFFFFFF:
                    raise FormatError('archive exceeds the 32-bit size limit')
                table.extend(RECORD.pack(field, offset, len(data)))
                output.write(data)
                output.write(bytes((-output.tell()) % 16))
                counts[entry['codec']] += 1
            output.seek(HEADER.size)
            output.write(table)
        if os.name == 'nt':
            staging.rename(archive)
        else:
            os.link(staging, archive)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    unpack_parser = commands.add_parser('unpack', help='decrypt ISF files or decompress GGD files to BMP')
    unpack_parser.add_argument('archive', type=Path)
    unpack_parser.add_argument('directory', type=Path)
    pack_parser = commands.add_parser('pack', help='rebuild an archive from its unpacked directory')
    pack_parser.add_argument('directory', type=Path)
    pack_parser.add_argument('archive', type=Path)
    pack_parser.add_argument('--recompress', action='store_true', help='re-encode every image, including unchanged images')
    args = parser.parse_args()
    try:
        if args.command == 'unpack':
            counts = unpack_archive(args.archive, args.directory)
        else:
            counts = pack_archive(args.directory, args.archive, recompress=args.recompress)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f'ikura_tool: {error}\n')
    codecs = ', '.join(f'{codec}={count}' for codec, count in sorted(counts.items()))
    print(f'{args.command}: {sum(counts.values())} members ({codecs})')


if __name__ == '__main__':
    main()
