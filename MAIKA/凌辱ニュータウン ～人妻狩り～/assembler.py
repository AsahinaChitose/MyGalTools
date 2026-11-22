#!/usr/bin/env python3
"""Assemble UTF-8 semantic assembly to RAPNTWN ADB bytecode."""

from __future__ import annotations

from dataclasses import dataclass
import re
import sys

from disassembler import ScriptError, displayable, is_end_edge, parse_script, run_cli, script_codec
from opcodelist import BUFFER_SIZE, MNEMONICS, OPTIONAL_GALLERY, STRINGS, SUBCODES, WIDTHS, Opcode


SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
TOKEN = re.compile(r'\s*("(?:\\.|[^"\\])*"|,|[^"\s,;]+)')
PLACEHOLDER = re.compile(r"\{\{([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})*)\}\}")
ENCODE_SUBCODE = {kind: {name: num for num, name in codes.items()} for kind, codes in SUBCODES.items()}


@dataclass(frozen=True)
class Fixup:
    offset: int
    name: str
    kind: str
    line: int
    op: Opcode


def line_tokens(line: str) -> list[str]:
    tokens = []
    pos = 0
    while pos < len(line):
        if not line[pos:].strip() or line[pos:].lstrip().startswith(";"):
            break
        match = TOKEN.match(line, pos)
        if match is None:
            raise ScriptError("invalid token or unterminated quoted string")
        tokens.append(match[1])
        pos = match.end()
    return tokens


def operands(tokens: list[str]) -> list[str]:
    if tokens and (len(tokens) % 2 != 1 or "," in tokens[::2] or any(t != "," for t in tokens[1::2])):
        raise ScriptError("operands must be separated by single commas")
    return tokens[::2]


def unsigned(token: str, width: int) -> int:
    if re.fullmatch(r"[0-9]+", token):
        n = int(token)
    elif re.fullmatch(r"0[xX][0-9a-fA-F]+", token):
        n = int(token, 16)
    else:
        raise ScriptError(f"invalid unsigned integer: {token!r}")
    if n >= 1 << (8 * width):
        raise ScriptError(f"{token} overflows u{width * 8}")
    return n


def expression(token: str) -> int:
    reg = re.fullmatch(r"var\[([^\]]+)\]", token)
    value = unsigned(reg[1] if reg else token, 2)
    if value >= 0x8000:
        raise ScriptError("literal or variable index exceeds 15 bits")
    return value | (0x8000 if reg else 0)


def unquote(token: str, encoding: str) -> bytes:
    if not (len(token) >= 2 and token[0] == token[-1] == '"'):
        raise ScriptError("expected a double-quoted string")
    text = token[1:-1]
    out = bytearray()
    pos = 0
    while pos < len(text):
        char = text[pos]
        if char == "\\":
            pos += 1
            if pos == len(text) or text[pos] not in '\\"{}':
                raise ScriptError("invalid escape; use {{XX}} for literal control bytes")
            char = text[pos]
        elif char == "{" and text.startswith("{{", pos):
            match = PLACEHOLDER.match(text, pos)
            if match is None:
                raise ScriptError("invalid {{XX[:XX]}} byte placeholder")
            raw = bytes.fromhex(match[1].replace(":", " "))
            if 0 in raw:
                raise ScriptError("NUL would terminate the string prematurely")
            out.extend(raw)
            pos = match.end()
            continue
        elif not displayable(char):
            raise ScriptError("nonprinting characters must use {{XX}} placeholders")
        try:
            raw = char.encode(encoding)
        except UnicodeEncodeError as err:
            raise ScriptError(f"{char!r} (U+{ord(char):04X}) cannot be encoded as {encoding}") from err
        if 0 in raw:
            raise ScriptError("NUL would terminate the string prematurely")
        out.extend(raw)
        pos += 1
    return bytes(out)


def assemble(text: str, encoding: str | None = None) -> bytes:
    if encoding is not None:
        encoding = script_codec(encoding)
    header: dict[str, str] = {}
    labels: dict[str, tuple[int, str]] = {}
    fixups: list[Fixup] = []
    out = bytearray()
    state = "header"
    pending: list[str] = []
    source_codec = "cp932"

    def bind(kind: str) -> None:
        for name in pending:
            labels[name] = (len(out), kind)
        pending.clear()

    for line, raw in enumerate(text.split("\n"), 1):
        try:
            tokens = line_tokens(raw)
            if not tokens:
                continue
            name, *args = tokens
            if name.endswith(":"):
                mark = name[:-1]
                if args or state not in {"code", "data"} or not SYMBOL.fullmatch(mark):
                    raise ScriptError("invalid label declaration")
                if mark in labels or mark in pending or mark == "NONE":
                    raise ScriptError(f"duplicate or reserved label: {mark}")
                pending.append(mark)
            elif name in {".format", ".encoding", ".script"}:
                if state != "header" or len(args) != 1 or name in header:
                    raise ScriptError(f"invalid or duplicate {name} declaration")
                header[name] = args[0]
            elif name == ".code":
                if args or state != "header" or header.get(".format") != "RAPNTWN_ADB_V1":
                    raise ScriptError("expected .format RAPNTWN_ADB_V1 before .code")
                if not re.fullmatch(r"[A-Za-z0-9_@.-]+", header.get(".script", "")):
                    raise ScriptError("expected a valid .script identifier")
                source_codec = script_codec(header.get(".encoding", "cp932"))
                state = "code"
            elif name == ".endcode":
                if args or pending or state != "code" or not out:
                    raise ScriptError("unexpected .endcode, empty code, or unmatched label")
                state = "data"
            elif name == ".gallery":
                if args or state != "data" or not pending:
                    raise ScriptError(".gallery needs a label after .endcode")
                bind("g")
                state = "gallery"
            elif name == ".region":
                values = operands(args)
                if state != "gallery" or len(values) != 5:
                    raise ScriptError(".region needs five u16 fields inside .gallery")
                row = [unsigned(val, 2) for val in values]
                if row[0] == 0xFFFF:
                    raise ScriptError("a region cannot begin with the gallery terminator")
                for val in row:
                    out.extend(val.to_bytes(2, "little"))
            elif name == ".endgallery":
                if args or state != "gallery":
                    raise ScriptError("unexpected .endgallery")
                out.extend(b"\xff\xff")
                state = "data"
            elif name == ".eof":
                if args or state != "data" or not pending:
                    raise ScriptError(".eof needs a label after the last section")
                bind("eof")
                state = "eof"
            else:
                if state != "code":
                    raise ScriptError(f"unexpected {name} outside .code")
                bind("p")
                mnemonic, dot, variant = name.partition(".")
                op = MNEMONICS.get(mnemonic)
                if op is None or not op.supported:
                    raise ScriptError(f"unknown or unverified instruction: {name}")
                if bool(dot) != bool(op.sub_opcodes):
                    raise ScriptError(f"invalid or missing sub-opcode: {name}")
                args = operands(args)
                if len(args) != sum(kind not in SUBCODES for kind in op.operands):
                    raise ScriptError(f"incorrect operand count for {name}")
                itr = iter(args)
                out.extend(op.bytecode)
                for kind in op.operands:
                    if kind in SUBCODES:
                        value = ENCODE_SUBCODE[kind].get(variant)
                        if value is None:
                            raise ScriptError(f"unknown sub-opcode: {name}")
                        out.append(value)
                        continue
                    token = next(itr)
                    if kind in STRINGS:
                        codec = (encoding or source_codec) if kind == "s" else source_codec
                        value = unquote(token, codec)
                        if kind == "e" and not re.fullmatch(rb"[A-Za-z0-9_@-]+", value):
                            raise ScriptError("invalid external script symbol")
                        out.extend(value + b"\0")
                    elif kind in "pgj":
                        if kind == "g" and token == "NONE" and op.code in OPTIONAL_GALLERY:
                            out.extend(b"\0" * 4)
                            continue
                        if not SYMBOL.fullmatch(token) or token == "NONE":
                            raise ScriptError(f"expected a symbolic target, not {token!r}")
                        fixups.append(Fixup(len(out), token, kind, line, op))
                        out.extend(b"\0" * WIDTHS[kind])
                    else:
                        width = WIDTHS[kind]
                        value = expression(token) if kind == "v" else unsigned(token, width)
                        out.extend(value.to_bytes(width, "little"))
            if len(out) > BUFFER_SIZE:
                raise ScriptError("script exceeds the EXE's 1 MiB script buffer")
        except (ValueError, LookupError) as err:
            raise ScriptError(f"line {line}: {err}") from err
    if pending or state not in {"data", "eof"}:
        raise ScriptError("unclosed section or label without a record")
    script = header[".script"]
    for ref in fixups:
        if ref.name not in labels:
            raise ScriptError(f"line {ref.line}: unresolved label {ref.name}")
        offset, category = labels[ref.name]
        if ref.kind == "j":
            if category != "p" or offset != ref.offset + 14:
                raise ScriptError(f"line {ref.line}: conditional skip must span exactly 14 bytes to {ref.name}")
            continue
        if category != ref.kind and not (
            ref.kind == "p" and category == "eof" and is_end_edge(script, ref.op, ref.offset + 4, len(out))
        ):
            raise ScriptError(f"line {ref.line}: wrong target section for {ref.name}")
        out[ref.offset:ref.offset + 4] = offset.to_bytes(4, "little")
    result = bytes(out)
    parse_script(result, script)
    return result


if __name__ == "__main__":
    sys.exit(run_cli(assembly=assemble))
