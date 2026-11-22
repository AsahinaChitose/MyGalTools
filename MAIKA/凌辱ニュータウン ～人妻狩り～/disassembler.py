#!/usr/bin/env python3
"""Disassemble RAPNTWN ADB scripts to editable UTF-8 semantic assembly."""

from __future__ import annotations

import argparse
import codecs
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re
import sys

from opcodelist import BUFFER_SIZE, EOF_EDGE, OPCODES, OPTIONAL_GALLERY, STRINGS, SUBCODES, WIDTHS, Opcode


class ScriptError(ValueError):
    pass


@dataclass(frozen=True)
class Instruction:
    offset: int
    end: int
    op: Opcode
    values: tuple[int | bytes, ...]


@dataclass(frozen=True)
class Program:
    code: tuple[Instruction, ...]
    gallery: dict[int, list[tuple[int, ...]]]


def script_codec(name: str) -> str:
    codec = codecs.lookup(name).name
    ascii_bytes = bytes(range(128))
    try:
        if ascii_bytes.decode(codec).encode("ascii") == ascii_bytes and ascii_bytes.decode("ascii").encode(codec) == ascii_bytes:
            return codec
    except (UnicodeError, TypeError, LookupError):
        pass
    raise ScriptError(f"{name!r} is not an ASCII-compatible script encoding")


def label(offset: int) -> str:
    return f"loc_{offset:08x}"


def bad(data: bytes, offset: int, reason: str) -> ScriptError:
    lo = max(0, offset - 6)
    hi = min(len(data), offset + 16)
    return ScriptError(f"0x{offset:08X}: {reason}; bytes 0x{lo:X}..0x{hi:X}: {data[lo:hi].hex(' ')}")


def word(data: bytes, offset: int, limit: int, width: int) -> int:
    if offset + width > limit:
        raise bad(data, offset, f"truncated {width}-byte field")
    return int.from_bytes(data[offset:offset + width], "little")


def is_end_edge(script: str, op: Opcode, end: int, size: int) -> bool:
    return (script.upper(), op.code) == EOF_EDGE and end + 9 == size


def parse_script(data: bytes, script: str) -> Program:
    if not 2 <= len(data) <= BUFFER_SIZE:
        raise ScriptError(f"script size must be between 2 and {BUFFER_SIZE} bytes")
    pos, code_limit = 0, len(data)
    code, gallery_refs = [], set()
    while pos < code_limit:
        start = pos
        value = word(data, pos, code_limit, 2)
        op = OPCODES.get(value)
        if op is None or not op.supported:
            reason = "unknown" if op is None else f"unverified layout for {op.mnemonic},"
            raise bad(data, start, f"{reason} opcode 0x{value:04X}")
        pos += 2
        values = []
        for kind in op.operands:
            if kind in STRINGS:
                end = data.find(b"\0", pos, code_limit)
                if end < 0:
                    raise bad(data, pos, f"unterminated string in {op.mnemonic}")
                value = data[pos:end]
                if kind == "e" and not re.fullmatch(rb"[A-Za-z0-9_@-]+", value):
                    raise bad(data, pos, "invalid external script symbol")
                pos = end + 1
            elif kind == "j":
                value = pos + 14
            else:
                width = WIDTHS[kind]
                value = word(data, pos, code_limit, width)
                pos += width
                if kind in SUBCODES and value not in SUBCODES[kind]:
                    raise bad(data, pos - 1, f"unknown sub-opcode 0x{value:02X} in {op.mnemonic}")
                if kind == "g" and not (value == 0 and op.code in OPTIONAL_GALLERY):
                    if not pos <= value < len(data):
                        raise bad(data, pos - width, f"invalid gallery address 0x{value:X}")
                    gallery_refs.add(value)
                    code_limit = min(code_limit, value)
            values.append(value)
        code.append(Instruction(start, pos, op, tuple(values)))

    starts = {ins.offset for ins in code}
    for ins in code:
        for kind, value in zip(ins.op.operands, ins.values):
            if kind not in ("p", "j") or value in starts:
                continue
            if kind == "p" and value == len(data) and not gallery_refs and is_end_edge(script, ins.op, ins.end, len(data)):
                continue
            raise bad(data, ins.offset, f"{ins.op.mnemonic} target 0x{value:X} is not an instruction boundary")

    gallery = {}
    while pos < len(data):
        start = pos
        if start not in gallery_refs:
            raise bad(data, start, "unreferenced bytes between gallery tables or after the last table")
        rows = []
        while word(data, pos, len(data), 2) != 0xFFFF:
            rows.append(tuple(word(data, pos + i, len(data), 2) for i in range(0, 10, 2)))
            pos += 10
        pos += 2
        gallery[start] = rows
    if gallery.keys() != gallery_refs:
        raise bad(data, code_limit, f"gallery references inside a record: {sorted(gallery_refs - gallery.keys())}")
    return Program(tuple(code), gallery)


@lru_cache(maxsize=65536)
def _decode_atom(chunk: bytes, encoding: str) -> str | None:
    try:
        return chunk.decode(encoding)
    except UnicodeError:
        return None


def displayable(char: str) -> bool:
    return char.isprintable() or char == "\u3000"


def quote(raw: bytes, encoding: str) -> str:
    out = ['"']
    pos = 0
    while pos < len(raw):
        for n in range(1, min(4, len(raw) - pos) + 1):
            chunk = raw[pos:pos + n]
            char = _decode_atom(chunk, encoding)
            if char is None or len(char) != 1:
                continue
            if displayable(char) and char.encode(encoding) == chunk:
                out.append(("\\" if char in '\\"{}' else "") + char)
            else:
                out.append("{{" + ":".join(f"{b:02X}" for b in chunk) + "}}")
            pos += n
            break
        else:
            out.append(f"{{{{{raw[pos]:02X}}}}}")
            pos += 1
    return "".join(out) + '"'


def disassemble(data: bytes, script: str, encoding: str = "cp932") -> str:
    if not re.fullmatch(r"[A-Za-z0-9_@.-]+", script):
        raise ScriptError(f"invalid script identifier: {script!r}")
    encoding = script_codec(encoding)
    program = parse_script(data, script)
    targets = {0, *(value for ins in program.code for kind, value in zip(ins.op.operands, ins.values) if kind in "pj")}
    out = ["; RAPNTWN ADB semantic assembly (UTF-8)", ".format RAPNTWN_ADB_V1",
           f".encoding {encoding}", f".script {script}", ".code"]
    for ins in program.code:
        if ins.offset in targets:
            out.extend(("", label(ins.offset) + ":"))
        name = ins.op.mnemonic
        args = []
        for kind, value in zip(ins.op.operands, ins.values):
            if kind in STRINGS:
                args.append(quote(value, encoding))
            elif kind in SUBCODES:
                name += "." + SUBCODES[kind][value]
            elif kind == "v":
                args.append(f"var[{value & 0x7fff}]" if value & 0x8000 else str(value))
            elif kind in "pjg":
                args.append("NONE" if kind == "g" and value == 0 else label(value))
            else:
                args.append(str(value))
        out.append("    " + name + (" " + ", ".join(args) if args else ""))
    out.append(".endcode")
    for offset, rows in program.gallery.items():
        out.extend(("", label(offset) + ":", "    .gallery"))
        out.extend("    .region " + ", ".join(map(str, row)) for row in rows)
        out.append("    .endgallery")
    if len(data) in targets:
        out.extend(("", label(len(data)) + ":", "    .eof"))
    return "\n".join(out) + "\n"


def _matches(path: Path, suffix: str) -> bool:
    name = path.name.lower()
    return path.is_file() and (name.endswith(suffix.lower()) or (suffix == ".asm.txt" and name == "asm.txt"))


def _base(path: Path, suffix: str) -> str:
    return path.name[:-len(suffix)] if path.name.lower().endswith(suffix.lower()) else path.stem


def output_jobs(inputs: list[Path], output: Path | None, *, assemble: bool) -> list[tuple[Path, Path]]:
    suffix = ".asm.txt" if assemble else ".ADB"
    ending = ".ADB" if assemble else ".asm.txt"
    jobs = []
    for source in inputs:
        if source.is_dir():
            group = sorted(path for path in source.rglob("*") if _matches(path, suffix))
            if not group:
                raise ScriptError(f"{source}: no {suffix} files")
            target = output or source.resolve().with_name(source.resolve().name + ("_rebuild" if assemble else "_asm"))
            if target.is_file():
                raise ScriptError(f"directory input needs an output directory: {target}")
            for path in group:
                rel = path.relative_to(source)
                jobs.append((path, target / rel.with_name(_base(path, suffix) + ending)))
        elif source.is_file():
            if not _matches(source, suffix) and not (assemble and source.suffix.lower() == ".txt"):
                raise ScriptError(f"unexpected input extension: {source}")
            base = _base(source, suffix)
            if output is None:
                dest = source.with_name(base + (".rebuild" if assemble else "") + ending)
            elif output.is_dir() or len(inputs) > 1 or not output.suffix:
                dest = output / (base + ending)
            else:
                dest = output
            jobs.append((source, dest))
        else:
            raise ScriptError(f"input does not exist: {source}")
    seen = set()
    for _, dest in jobs:
        resolved = dest.resolve()
        key = str(resolved).casefold()
        if key in seen or dest.exists():
            raise ScriptError(f"output already exists or is duplicated: {dest}")
        seen.add(key)
    return jobs


def run_cli(*, assembly=None) -> int:
    assemble = assembly is not None
    try:
        sys.stderr.reconfigure(errors="backslashreplace")
    except AttributeError:
        pass
    parser = argparse.ArgumentParser(description=("Assemble UTF-8 RAPNTWN VM text to ADB." if assemble else __doc__))
    parser.add_argument("input", type=Path, nargs="+", help="script file(s) or directory")
    parser.add_argument("-o", "--output", type=Path, help="new output file or directory")
    parser.add_argument("--encoding", help="display text encoding (default: .encoding on assembly; cp932 otherwise)")
    args = parser.parse_args()
    try:
        codec = script_codec(args.encoding) if args.encoding else None
        jobs = output_jobs(args.input, args.output, assemble=assemble)
        # Prepare every result before creating outputs, so one malformed file
        # or encoding error does not leave a partially converted directory.
        results = []
        for source, dest in jobs:
            try:
                if assemble:
                    result = assembly(source.read_text(encoding="utf-8-sig"), codec)
                else:
                    result = disassemble(source.read_bytes(), source.stem, codec or "cp932").encode("utf-8")
            except (ValueError, OSError) as err:
                raise ScriptError(f"{source}: {err}") from err
            results.append((dest, result))
        for dest, result in results:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("xb") as stream:
                stream.write(result)
        print(f"{'Assembled' if assemble else 'Disassembled'} {len(results)} script(s).")
        return 0
    except (ValueError, OSError, LookupError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_cli())
