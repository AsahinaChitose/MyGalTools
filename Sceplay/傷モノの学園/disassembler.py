#!/usr/bin/env python3
"""Disassemble Sceplay .sce files to editable UTF-8 .asm.txt files."""

import argparse
import codecs
from pathlib import Path
import struct
import unicodedata

from opcodelist import BANKS, DEFAULT_ENCODING, EVAL_NAMES, OPCODES, plan_jobs, script_encoding, write_output


HEADER = struct.Struct("<BH")
EXPR = struct.Struct("<BBBBHH")
JUMP = struct.Struct("<I")


def decode_script(data):
    """Return (offset, Opcode, operands) records and validate local addresses."""
    instructions = []
    offset = 0
    if not data:
        raise ValueError("empty script")
    while offset < len(data):
        start = offset
        try:
            tag, number = HEADER.unpack_from(data, offset)
            opcode = OPCODES.get((tag, number))
            if opcode is None:
                if 1 <= tag <= 3:
                    raise ValueError(f"runtime-selected command via {BANKS[tag]}[{number}] has no static layout")
                raise ValueError(f"unknown opcode (tag={tag}, number={number})")
            offset += HEADER.size
            values = []
            for kind in opcode.operands:
                if kind in "VK":
                    operand_tag, value = HEADER.unpack_from(data, offset)
                    if operand_tag >= len(BANKS):
                        raise ValueError(f"invalid value tag {operand_tag} at 0x{offset:X}")
                    values.append((operand_tag, value))
                    offset += HEADER.size
                elif kind in "SX":
                    end = data.find(b"\0", offset)
                    if end < 0:
                        raise ValueError(f"unterminated string at 0x{offset:X}")
                    values.append(data[offset:end])
                    offset = end + 1
                elif kind == "J":
                    values.append(JUMP.unpack_from(data, offset)[0])
                    offset += JUMP.size
                elif kind == "E":
                    expression = EXPR.unpack_from(data, offset)
                    operator, left_tag, right_tag, *_ = expression
                    if operator >= len(EVAL_NAMES) or max(left_tag, right_tag) >= len(BANKS):
                        raise ValueError(f"invalid EVAL variant {operator}/{left_tag}/{right_tag}")
                    values.append(expression)
                    offset += EXPR.size
            instructions.append((start, opcode, values))
        except (ValueError, struct.error) as error:
            context = data[max(0, start - 3):start + 11].hex(" ")
            detail = "truncated instruction or operand" if isinstance(error, struct.error) else str(error)
            raise ValueError(f"0x{start:08X}, operand cursor 0x{offset:08X}: {detail} [{context}]") from error
    boundaries = {start for start, _, _ in instructions}
    for start, opcode, values in instructions:
        if opcode.operands == "J" and values[0] not in boundaries:
            raise ValueError(f"0x{start:08X}: {opcode.mnemonic} target 0x{values[0]:08X} is not an instruction")
    return instructions


def quote_text(data, encoding):
    """Show characters only when that spelling can reproduce their input bytes."""
    decoder = codecs.getincrementaldecoder(encoding)(errors="surrogateescape")
    chunks = []
    start = 0

    def append(raw, text):
        if not raw:
            return
        if (len(text) == 1 and text.isprintable() or text == "\u3000") and (
                not unicodedata.category(text).startswith("C") and text.encode(encoding) == raw):
            if text in '\\"{':
                chunks.append("\\")
            chunks.append(text)
        else:
            chunks.append("{{" + ":".join(f"{byte:02X}" for byte in raw) + "}}")

    if data.isascii() and all(32 <= byte < 127 for byte in data):
        text = data.decode("ascii").replace("\\", "\\\\").replace('"', '\\"').replace("{", "\\{")
        return f'"{text}"'
    for pos in range(1, len(data) + 1):
        text = decoder.decode(data[pos - 1:pos])
        if text:
            append(data[start:pos], text)
            start = pos
    append(data[start:], decoder.decode(b"", final=True))
    return '"' + "".join(chunks) + '"'


def format_value(tag, value, string_slot=False):
    if tag:
        return f"{BANKS[tag]}[{value}]"
    return f"str[{value}]" if string_slot else str(value)


def label(address):
    return f"loc_{address:08X}"


def disassemble(data, encoding=DEFAULT_ENCODING):
    encoding = script_encoding(encoding)
    instructions = decode_script(data)
    targets = {0, *(values[0] for _, op, values in instructions if op.operands == "J")}
    lines = ["; Sceplay scene script", f".encoding {encoding}"]
    for start, opcode, values in instructions:
        if start in targets:
            lines.extend(("", label(start) + ":"))
        mnemonic = opcode.mnemonic
        args = []
        for kind, value in zip(opcode.operands, values):
            if kind in "VK":
                args.append(format_value(*value, string_slot=kind == "K"))
            elif kind in "SX":
                args.append(quote_text(value, encoding))
            elif kind == "J":
                args.append(label(value))
            elif kind == "E":
                operator, left_tag, right_tag, result, left, right = value
                mnemonic += "." + EVAL_NAMES[operator]
                args.extend((f"t[{result}]", format_value(left_tag, left), format_value(right_tag, right)))
        if args:
            rows = [", ".join(args[i:i + 8]) for i in range(0, len(args), 8)]
            lines.append(f"    {mnemonic:<24} " + ", \\\n                             ".join(rows))
        else:
            lines.append("    " + mnemonic)
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", metavar="script_or_directory")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--encoding", default=DEFAULT_ENCODING, help="source text encoding (default: cp932)")
    args = parser.parse_args()
    try:
        jobs = plan_jobs(args.inputs, args.output, ".sce", ".asm.txt", "_asm")
        encoding = script_encoding(args.encoding)
        for source, target in jobs:
            try:
                write_output(target, disassemble(source.read_bytes(), encoding).encode("utf-8"))
            except (OSError, ValueError) as error:
                raise ValueError(f"{source}: {error}") from error
        print(f"Disassembled {len(jobs)} script(s) to UTF-8 assembly.")
    except (LookupError, OSError, ValueError) as error:
        parser.exit(1, f"disassembler: {error}\n")


if __name__ == "__main__":
    main()
