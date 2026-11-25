#!/usr/bin/env python3
"""Assemble UTF-8 Sceplay .asm.txt files and relocate local branches."""

import argparse
from collections import Counter
from pathlib import Path
import re
import struct
import sys

from opcodelist import BANKS, DEFAULT_ENCODING, EVAL_NUMBERS, MNEMONICS, plan_jobs, script_encoding, write_output


HEADER = struct.Struct("<BH")
EXPR = struct.Struct("<BBBBHH")
JUMP = struct.Struct("<I")
TOKEN = re.compile(r'\s+|;.*|"(?:[^"\\]|\\.)*"|,|\\|[^\s;,"\\]+')
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
VALUE = re.compile(r"(a|b|t|str)\[([^\[\]]+)\]")
BYTE_LIST = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})*")
GBK_SUBSTITUTIONS = {"・": "·", "♪": "～", "｢": "「"}


def records(text):
    first_line = 0
    pending = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not pending:
            first_line = line_number
        cursor = 0
        tokens = []
        while cursor < len(line):
            match = TOKEN.match(line, cursor)
            if match is None:
                raise ValueError(f"line {line_number}: invalid token or unterminated string at column {cursor + 1}")
            token = match[0]
            cursor = match.end()
            if token.startswith(";"):
                break
            if not token.isspace():
                tokens.append(token)
        if not tokens:
            continue
        if tokens[-1] == "\\":
            pending.extend(tokens[:-1])
            if not pending:
                raise ValueError(f"line {line_number}: unexpected line continuation")
            continue
        yield first_line, pending + tokens
        pending = []
    if pending:
        raise ValueError(f"line {first_line}: dangling line continuation")


def operands(tokens):
    result = []
    previous_comma = False
    for token in tokens:
        if token == ",":
            if not result or previous_comma:
                raise ValueError("unexpected comma")
            previous_comma = True
        else:
            result.append(token)
            previous_comma = False
    if previous_comma:
        raise ValueError("trailing comma")
    return result


def number(token, maximum):
    if re.fullmatch(r"[0-9]+", token):
        value = int(token, 10)
    elif re.fullmatch(r"0[xX][0-9a-fA-F]+", token):
        value = int(token, 16)
    else:
        raise ValueError(f"expected an unsigned integer, got {token!r}")
    if value > maximum:
        raise ValueError(f"integer {value} is outside 0..{maximum}")
    return value


def tagged_value(token, kind="V"):
    match = VALUE.fullmatch(token)
    if match is None:
        return 0, number(token, 0xFFFF)
    bank, index = match.groups()
    if bank == "str":
        if kind != "K":
            raise ValueError(f"unexpected string-slot operand {token!r}")
        return 0, number(index, 31)
    return BANKS.index(bank), number(index, 0xFFFF)


def string_bytes(token, encoding, substitutions):
    if not token.startswith('"') or not token.endswith('"'):
        raise ValueError("expected a double-quoted string")
    content = token[1:-1]
    result = bytearray()
    plain = []

    def flush():
        if plain:
            result.extend("".join(plain).encode(encoding))
            plain.clear()

    pos = 0
    while pos < len(content):
        char = content[pos]
        if char == "\\":
            pos += 1
            if pos == len(content) or content[pos] not in '\\"{':
                raise ValueError("invalid string escape; use {{XX}} for literal control bytes")
            plain.append(content[pos])
        elif content.startswith("{{", pos):
            end = content.find("}}", pos + 2)
            if end < 0 or BYTE_LIST.fullmatch(content[pos + 2:end]) is None:
                raise ValueError("invalid byte placeholder; expected {{XX}} or {{XX:YY}}")
            flush()
            result.extend(bytes.fromhex(content[pos + 2:end].replace(":", " ")))
            pos = end + 2
            continue
        else:
            if substitutions is not None and char in GBK_SUBSTITUTIONS:
                substitutions[char] += 1
                char = GBK_SUBSTITUTIONS[char]
            plain.append(char)
        pos += 1
    flush()
    if 0 in result:
        raise ValueError("NUL ends this operand and cannot appear inside a string")
    return bytes(result) + b"\0"


def assemble(text, encoding=None, *, strict_gbk=False, substitutions=None):
    forced = script_encoding(encoding) if encoding is not None else None
    codec = forced or DEFAULT_ENCODING
    counts = substitutions if substitutions is not None else Counter()
    labels = {}
    offsets = set()
    fixups = []
    binary = bytearray()
    have_encoding = False
    for line, tokens in records(text):
        head, *tail = tokens
        try:
            if head == ".encoding":
                if have_encoding or labels or binary or len(tail) != 1:
                    raise ValueError("expected one .encoding directive before the first label or instruction")
                declared = script_encoding(tail[0])
                codec = forced or declared
                have_encoding = True
                continue
            if head.endswith(":"):
                name = head[:-1]
                if tail or IDENTIFIER.fullmatch(name) is None:
                    raise ValueError("invalid label definition")
                if name in labels:
                    raise ValueError(f"duplicate label {name!r}")
                labels[name] = (len(binary), line)
                continue
            mnemonic, _, variant = head.upper().partition(".")
            opcode = MNEMONICS.get(mnemonic)
            if opcode is None or (mnemonic != "EVAL" and "." in head):
                raise ValueError(f"unknown instruction {head!r}")
            args = operands(tail)
            expected = 3 if opcode.operands == "E" else len(opcode.operands)
            if len(args) != expected:
                raise ValueError(f"{head} expects {expected} operands, got {len(args)}")
            offsets.add(len(binary))
            binary.extend(HEADER.pack(opcode.tag, opcode.number))
            if opcode.operands == "E":
                if variant not in EVAL_NUMBERS:
                    raise ValueError(f"unknown EVAL variant {variant!r}")
                destination = VALUE.fullmatch(args[0])
                if destination is None or destination[1] != "t":
                    raise ValueError("EVAL destination must be t[index]")
                result = number(destination[2], 255)
                left_tag, left = tagged_value(args[1])
                right_tag, right = tagged_value(args[2])
                binary.extend(EXPR.pack(EVAL_NUMBERS[variant], left_tag, right_tag, result, left, right))
                continue
            for kind, arg in zip(opcode.operands, args):
                if kind in "VK":
                    binary.extend(HEADER.pack(*tagged_value(arg, kind)))
                elif kind in "SX":
                    payload = string_bytes(arg, codec, counts if codec == "gbk" and not strict_gbk else None)
                    if (kind == "X" and opcode.tag == 4 and len(payload) > 64):
                        raise ValueError("scene name exceeds the VM's 63-byte input buffer")
                    if opcode.number == 200 and len(payload) > 256:
                        raise ValueError("SET_STRING exceeds the VM's 255-byte string-slot capacity")
                    binary.extend(payload)
                elif kind == "J":
                    if IDENTIFIER.fullmatch(arg) is None:
                        raise ValueError("local target must be a label")
                    fixups.append((len(binary), arg, line))
                    binary.extend(b"\0" * JUMP.size)
        except (LookupError, ValueError) as error:
            raise ValueError(f"line {line}: {error}") from error
    if not binary:
        raise ValueError("assembly contains no instructions")
    for offset, name, line in fixups:
        if name not in labels:
            raise ValueError(f"line {line}: undefined label {name!r}")
        address, definition_line = labels[name]
        if address not in offsets:
            raise ValueError(f"line {line}: label {name!r} on line {definition_line} has no instruction")
        if address > 0xFFFFFFFF:
            raise ValueError(f"line {line}: label {name!r} does not fit in a 32-bit address")
        JUMP.pack_into(binary, offset, address)
    return bytes(binary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", metavar="asm.txt_or_directory")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--encoding", help="output string codec (default: .encoding, then cp932)")
    parser.add_argument("--strict-gbk", action="store_true", help="reject the three GBK punctuation substitutions")
    args = parser.parse_args()
    try:
        jobs = plan_jobs(args.inputs, args.output, ".asm.txt", ".sce", "_rebuild",
                         single_suffix=".rebuild", allow_named_text=True)
        for source, target in jobs:
            try:
                counts = Counter()
                payload = assemble(source.read_text(encoding="utf-8-sig"), args.encoding,
                                   strict_gbk=args.strict_gbk, substitutions=counts)
                write_output(target, payload)
                if counts:
                    explanation = ", ".join(f"{char} -> {GBK_SUBSTITUTIONS[char]} ({count})"
                                            for char, count in sorted(counts.items()))
                    print(f"{source}: GBK substitutions: {explanation}", file=sys.stderr)
            except (LookupError, OSError, ValueError) as error:
                raise ValueError(f"{source}: {error}") from error
        print(f"Assembled {len(jobs)} script(s).")
    except (OSError, ValueError) as error:
        parser.exit(1, f"assembler: {error}\n")


if __name__ == "__main__":
    main()
