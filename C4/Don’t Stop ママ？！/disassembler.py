"""Disassemble C4 Mp17 scripts into editable UTF-8 assembly."""

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from struct import unpack_from

from opcodelist import (
    CHOICE_LIMIT, FILE_LIMIT, HEADER_SIZE, MAGIC, OPCODES, POOL_XOR, SUBOPS,
    TERMINATORS, WIDTHS, FormatError, cli, codec_name, error_exit, jobs,
    value_token, variable, wire_text_fragments, write_output,
)


class Reader:
    def __init__(self, data, start, end):
        self.data = data
        self.pos = start
        self.end = end

    def take(self, width, signed=False):
        start = self.pos
        self.pos += width
        if self.pos > self.end:
            raise FormatError(f"0x{start:04X}: operand crosses code boundary 0x{self.end:04X}")
        return int.from_bytes(self.data[start:self.pos], "little", signed=signed)


def read_group(reader, group):
    items = []
    width = 2 if group == "expr" else 1
    while True:
        start = reader.pos
        opcode = reader.take(width)
        spec = SUBOPS[group].get(opcode)
        if spec is None:
            if group == "expr":
                items.append(("PUSH", (opcode if opcode < 0x8000 else opcode - 0x10000,)))
                continue
            raise FormatError(f"0x{start:04X}: unknown {group} sub-opcode 0x{opcode:02X}")
        name, kinds = spec
        values = tuple(reader.take(2, signed=kind != "index") for kind in kinds)
        if group == "expr" or opcode != TERMINATORS[group]:
            items.append((name, values))
        if opcode == TERMINATORS[group]:
            return items


@dataclass
class Instruction:
    address: int
    end: int
    opcode: int
    operands: tuple[int, ...]
    groups: list


@dataclass
class Script:
    instructions: list[Instruction]
    text: dict[int, bytes]
    extra: bytes
    symbols: list[bytes]
    locals_count: int
    reserved: int


def c_strings(data, base, name):
    if data and not data.endswith(b"\0"):
        raise FormatError(f"0x{base + len(data):04X}: unterminated {name}")
    return data[:-1].split(b"\0") if data else []


def read_script(data):
    if len(data) < HEADER_SIZE or data[:4] != MAGIC:
        raise FormatError("expected a 16-byte Mp17 header")
    if len(data) > FILE_LIMIT:
        raise FormatError(f"script exceeds the engine's {FILE_LIMIT}-byte read buffer")
    code_end, pool_length, locals_count, extra_length, symbol_count, reserved = unpack_from("<6H", data, 4)
    pool_end = code_end + pool_length
    extra_end = pool_end + extra_length
    if not HEADER_SIZE < code_end <= pool_end <= extra_end <= len(data):
        raise FormatError("code, text pool or extra-section boundary is outside the file")
    pool = bytes(byte ^ POOL_XOR for byte in data[code_end:pool_end])
    records = {}
    offset = 0
    for raw in c_strings(pool, code_end, "text-pool record"):
        records[offset] = raw
        offset += len(raw) + 1
    symbols = c_strings(data[extra_end:], extra_end, "symbol-table entry")
    if len(symbols) != symbol_count:
        raise FormatError(f"0x{extra_end:04X}: expected {symbol_count} symbol entries, found {len(symbols)}")

    reader = Reader(data, HEADER_SIZE, code_end)
    instructions = []
    while reader.pos < code_end:
        address = reader.pos
        byte = reader.take(1)
        if byte not in OPCODES:
            previous = f", preceding instruction at 0x{instructions[-1].address:04X}" if instructions else ""
            raise FormatError(f"0x{address:04X}: unknown opcode 0x{byte:02X}{previous}")
        spec = OPCODES[byte]
        operands = tuple(reader.take(WIDTHS[kind], signed=kind == "i16") for kind in spec.operands)
        groups = [(kind, read_group(reader, kind)) for kind in spec.groups]
        instructions.append(Instruction(address, reader.pos, byte, operands, groups))

    addresses = {insn.address: insn for insn in instructions}
    for insn in instructions:
        for kind, value in zip(OPCODES[insn.opcode].operands, insn.operands):
            if kind == "target" and value not in addresses:
                raise FormatError(f"0x{insn.address:04X}: branch target 0x{value:04X} is not an instruction")
            if kind == "text" and value not in records:
                raise FormatError(f"0x{insn.address:04X}: text offset 0x{value:04X} is not a record start")
            if kind in ("counter", "i16") and value >= 1024:
                raise FormatError(f"0x{insn.address:04X}: counter index {value} exceeds the VM's 1024 slots")
            if kind == "text" and insn.opcode in (0x01, 0x03) and len(records[value]) > CHOICE_LIMIT:
                raise FormatError(f"0x{insn.address:04X}: choice text exceeds {CHOICE_LIMIT} bytes")
        if insn.opcode in (0x01, 0x03) and insn.end not in addresses:
            raise FormatError(f"0x{insn.address:04X}: choice has no continuation instruction")
        if insn.opcode == 0x06:
            following = addresses.get(insn.end)
            if following is None or following.end != following.address + 1 or following.end not in addresses:
                raise FormatError(f"0x{insn.address:04X}: false path does not skip exactly one instruction")
    return Script(instructions, records, data[pool_end:extra_end], symbols, locals_count, reserved)


def label(address):
    return f"loc_{address:04X}"


def render_group(kind, terms, symbols):
    rendered = []
    for name, values in terms:
        _, kinds = next(spec for spec in SUBOPS[kind].values() if spec[0] == name)
        rendered.append(name)
        for operand, value in zip(kinds, values):
            if operand == "var" and value >= 0:
                raise FormatError(f"{name}: expected a negatively encoded update variable, found {value}")
            if operand == "index":
                if value > 0x7FFF:
                    raise FormatError(f"{name}: invalid signed variable index {value}")
                rendered.append(variable(value, symbols))
            else:
                rendered.append(value_token(value, symbols))
    return " ".join([f"        .{kind}", *rendered])


def disassemble(data, encoding):
    script = read_script(data)
    symbols = [raw.decode("ascii", "replace") for raw in script.symbols]
    references = Counter()
    labels = {HEADER_SIZE}
    for insn in script.instructions:
        for kind, value in zip(OPCODES[insn.opcode].operands, insn.operands):
            if kind == "target":
                labels.update((value, insn.end))
            elif kind == "text":
                references[value] += 1
        if insn.opcode == 0x06:
            labels.add(insn.end + 1)

    ids = {offset: f"@text_{index:03d}" for index, offset in enumerate(script.text)}
    lines = [".format Mp17", f".encoding {encoding}", f".locals {script.locals_count}",
             f".reserved 0x{script.reserved:04X}", f".original_sha256 {sha256(data).hexdigest()}", "", ".code"]
    for insn in script.instructions:
        if insn.address in labels:
            lines.extend(("", label(insn.address) + ":"))
        spec = OPCODES[insn.opcode]
        fields = [spec.mnemonic]
        continuation = []
        for kind, value in zip(spec.operands, insn.operands):
            if kind == "target":
                fields.append(label(value))
            elif kind == "text":
                first, *continuation = wire_text_fragments(script.text[value], encoding)
                fields.extend((ids[value], first))
            else:
                fields.append(str(value))
        lines.append("    " + " ".join(fields))
        lines.extend(f"        | {part}" for part in continuation)
        try:
            lines.extend(render_group(kind, terms, symbols) for kind, terms in insn.groups)
        except FormatError as error:
            raise FormatError(f"0x{insn.address:04X}: {error}") from error
    lines.extend(("", ".pool"))
    for offset, raw in script.text.items():
        ident = ids[offset]
        if references[offset] == 0:
            first, *continuation = wire_text_fragments(raw, encoding)
            lines.append(f"    .text {ident} {first}")
            lines.extend(f"        | {part}" for part in continuation)
        else:
            digest = " " + sha256(raw).hexdigest() if references[offset] > 1 else ""
            lines.append(f"    .text_id {ident}{digest}")
    lines.extend(("", ".extra"))
    for index in range(0, len(script.extra), 16):
        values = " ".join(map(str, script.extra[index:index + 16]))
        lines.append(f"    .byte {values}")
    lines.extend(("", ".symbols"))
    for raw in script.symbols:
        first, *continuation = wire_text_fragments(raw, encoding)
        lines.append(f"    .symbol {first}")
        lines.extend(f"        | {part}" for part in continuation)
    lines.extend(("", ".end", ""))
    return "\n".join(lines)


def main(argv=None):
    args = cli(__doc__, argv)
    try:
        encoding = codec_name(args.encoding or "cp932")
        exports = []
        for source, target in jobs(args, ".mpx", ".asm.txt", ".asm.txt"):
            try:
                exports.append((target, disassemble(source.read_bytes(), encoding).encode("utf-8")))
            except (FormatError, UnicodeError) as error:
                raise FormatError(f"{source}: {error}") from error
        for target, data in exports:
            write_output(target, data)
        print(f"Disassembled {len(exports)} Mp17 file(s) as UTF-8 ({encoding} source).")
        return 0
    except (FormatError, OSError) as error:
        return error_exit(error)


if __name__ == "__main__":
    raise SystemExit(main())
