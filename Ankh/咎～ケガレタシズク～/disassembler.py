#!/usr/bin/env python3
"""Disassemble decoded Ankh SNR bytecode into editable UTF-8 asm.txt files."""

from __future__ import annotations

import argparse
import codecs
import hashlib
import json
import re
import shutil
import struct
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opcodelist import (
    COMMAND_WIDTH,
    INTEGER_FORMAT,
    MAX_INSTRUCTIONS,
    OPCODES,
    RESERVED_OPCODES,
    SCRIPT_ENCODING,
)

# Speaker labels observed in this game's scripts without a preceding SET_NAME.
_IMPLICIT_SPEAKER_NAMES = frozenset({"？？？", "男", "女の声", "寮母", "生徒", "女子生徒", "男子生徒"})


class DisassemblyError(Exception):
    """Raised when a script does not match the verified Ankh bytecode layout."""


@dataclass(frozen=True)
class Target:
    offset: int


@dataclass
class Instruction:
    offset: int
    opcode: int
    end: int
    operands: list[Any] = field(default_factory=list)
    target_operands: set[int] = field(default_factory=set)


class Reader:
    def __init__(self, data: bytes, path: Path):
        self.data = data
        self.path = path
        self.position = 0

    def read_u32(self, at: int) -> int:
        if at < 0 or at + COMMAND_WIDTH > len(self.data):
            raise DisassemblyError(f"{self.path}: truncated u32 at offset 0x{at:X}")
        return struct.unpack_from(INTEGER_FORMAT, self.data, at)[0]

    def read_bytes(self, count: int, at: int) -> bytes:
        if count > len(self.data) - at:
            raise DisassemblyError(
                f"{self.path}: field of {count} bytes at 0x{at:X} exceeds file size 0x{len(self.data):X}"
            )
        return self.data[at : at + count]


def _decode_fields(
    reader: Reader,
    position: int,
    descriptors: list[dict[str, Any]],
    values: dict[str, Any],
    operands: list[Any],
    target_operands: set[int],
    depth: int = 0,
) -> int:
    if depth > 8:
        raise DisassemblyError(f"{reader.path}: opcode schema nesting is too deep")
    for desc in descriptors:
        kind = desc["kind"]
        if kind in ("u32", "target"):
            value = reader.read_u32(position)
            position += COMMAND_WIDTH
            if kind == "target":
                target_operands.add(len(operands))
                operands.append(Target(value))
            else:
                operands.append(value)
            values[desc["name"]] = value
        elif kind == "text":
            length = reader.read_u32(position)
            position += COMMAND_WIDTH
            raw = reader.read_bytes(length, position)
            position += length
            operands.append(raw)
            values[desc["name"]] = raw
        elif kind == "text_slots":
            count = int(desc["count"])
            lengths = [reader.read_u32(position + i * COMMAND_WIDTH) for i in range(count)]
            position += count * COMMAND_WIDTH
            slots = []
            for index, length in enumerate(lengths):
                if length > 10:
                    raise DisassemblyError(
                        f"{reader.path}: opcode text slot {index} is {length} bytes; handler buffer holds 10"
                    )
                raw = reader.read_bytes(length, position)
                position += length
                slots.append(raw)
                operands.append(raw)
            values[desc["name"]] = slots
        elif kind == "repeat":
            count = values.get(desc["count"])
            if not isinstance(count, int) or count > int(desc["maximum"]):
                raise DisassemblyError(
                    f"{reader.path}: invalid {desc['count']} value {count!r} at instruction"
                )
            for _ in range(count):
                position = _decode_fields(
                    reader, position, desc["fields"], values, operands, target_operands, depth + 1
                )
        elif kind == "when":
            if values.get(desc["field"]) == desc["equals"]:
                position = _decode_fields(
                    reader, position, desc["fields"], values, operands, target_operands, depth + 1
                )
        else:
            raise DisassemblyError(f"unsupported opcode schema field {kind!r}")
    return position


def decode_script(data: bytes, path: Path) -> list[Instruction]:
    reader = Reader(data, path)
    instructions: list[Instruction] = []
    while reader.position < len(data):
        if len(instructions) >= MAX_INSTRUCTIONS:
            raise DisassemblyError(f"{path}: instruction limit exceeded")
        start = reader.position
        opcode = reader.read_u32(start)
        reader.position += COMMAND_WIDTH
        if opcode in RESERVED_OPCODES:
            raise DisassemblyError(f"{path}: reserved/invalid opcode {opcode} at 0x{start:X}")
        spec = OPCODES.get(opcode)
        if spec is None:
            raise DisassemblyError(f"{path}: unknown opcode {opcode} at 0x{start:X}")
        operands: list[Any] = []
        targets: set[int] = set()
        reader.position = _decode_fields(
            reader, reader.position, spec["fields"], {}, operands, targets
        )
        if reader.position <= start:
            raise DisassemblyError(f"{path}: opcode {opcode} made no progress at 0x{start:X}")
        instructions.append(Instruction(start, opcode, reader.position, operands, targets))

    boundaries = {instruction.offset for instruction in instructions}
    boundaries.add(len(data))
    for instruction in instructions:
        for index in instruction.target_operands:
            target = instruction.operands[index]
            if target.offset not in boundaries:
                raise DisassemblyError(
                    f"{path}: {OPCODES[instruction.opcode]['mnemonic']} at 0x{instruction.offset:X} "
                    f"targets 0x{target.offset:X}, which is not an instruction boundary"
                )
    return instructions


def _format_text(raw: bytes, encoding: str) -> str:
    chunks: list[str] = []
    cursor = 0
    while cursor < len(raw):
        decoded = None
        width = 0
        for candidate_width in range(1, min(4, len(raw) - cursor) + 1):
            try:
                decoded = raw[cursor : cursor + candidate_width].decode(encoding, errors="strict")
            except UnicodeDecodeError:
                continue
            width = candidate_width
            break
        if decoded is None:
            chunks.append(f"{{{{{raw[cursor]:02X}}}}}")
            cursor += 1
            continue

        source_unit = raw[cursor : cursor + width]
        try:
            roundtrip = decoded.encode(encoding, errors="strict") == source_unit
        except UnicodeEncodeError:
            roundtrip = False
        if (
            not roundtrip
            or any(unicodedata.category(char).startswith("C") for char in decoded)
            or any(char in "{}" for char in decoded)
        ):
            chunks.append("{{" + ":".join(f"{byte:02X}" for byte in source_unit) + "}}")
        else:
            chunks.append(decoded.replace("\\", "\\\\").replace('"', '\\"'))
        cursor += width
    return '"' + "".join(chunks) + '"'


def _render_operand(value: Any, encoding: str, labels: set[int]) -> str:
    if isinstance(value, Target):
        if value.offset not in labels:
            raise DisassemblyError(f"missing label for branch target 0x{value.offset:X}")
        return f"loc_{value.offset:08X}"
    if isinstance(value, bytes):
        return _format_text(value, encoding)
    if isinstance(value, int):
        return f"0x{value:08X}"
    raise DisassemblyError(f"cannot render operand value {value!r}")


def _is_name_message(
    instructions: list[Instruction], index: int, encoding: str, labels: set[int]
) -> bool:
    instruction = instructions[index]
    if instruction.opcode != 1:
        return False
    message_id, raw_text, wait_mode = instruction.operands
    if wait_mode != 2:
        return False
    if raw_text == b"N1" or (index > 0 and instructions[index - 1].opcode == 15):
        return True
    if index + 1 == len(instructions):
        return False
    following = instructions[index + 1]
    if following.opcode != 1 or following.offset in labels:
        return False
    # Mode 2 also occurs in narration. Require both a known label and a dialogue start.
    return (
        following.operands[0] == message_id + 1
        and raw_text.decode(encoding, errors="replace") in _IMPLICIT_SPEAKER_NAMES
        and following.operands[1].decode(encoding, errors="replace").startswith(("「", "『"))
    )


def render_assembly(
    data: bytes, instructions: list[Instruction], encoding: str
) -> tuple[str, list[dict[str, Any]]]:
    labels = {
        operand.offset
        for instruction in instructions
        for index, operand in enumerate(instruction.operands)
        if index in instruction.target_operands
    }
    lines = [
        "; Ankh SNR semantic assembly. Text byte provenance is stored in .toga_asm_meta.json.",
        ".format toga-snr-v1",
        f".encoding {encoding}",
        f".source_size {len(data)}",
        f".source_sha256 {hashlib.sha256(data).hexdigest()}",
        "",
    ]
    by_offset = {instruction.offset: instruction for instruction in instructions}
    provenance = []
    for index, instruction in enumerate(instructions):
        if instruction.offset in labels:
            lines.extend(("", f"loc_{instruction.offset:08X}:"))
        spec = OPCODES[instruction.opcode]
        rendered = [
            _render_operand(value, encoding, labels) for value in instruction.operands
        ]
        mnemonic = spec["mnemonic"]
        if _is_name_message(instructions, index, encoding, labels):
            mnemonic = "NAME"
            rendered = rendered[:-1]
        operands = " " + ", ".join(rendered) if rendered else ""
        lines.append(f"    {mnemonic}{operands}")
        provenance.append({
            "opcode": instruction.opcode,
            "text_sha256": [
                hashlib.sha256(value).hexdigest()
                for value in instruction.operands
                if isinstance(value, bytes)
            ],
        })
    if len(data) in labels:
        lines.extend(("", f"loc_{len(data):08X}:"))
    if not by_offset and len(data):
        raise DisassemblyError("nonempty script has no instruction")
    return "\n".join(lines) + "\n", provenance


def source_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise DisassemblyError(f"input does not exist: {path}")
    excluded = {".dat_tool.json"}
    ignored_suffixes = {".asm.txt", ".json", ".py", ".md", ".yml", ".yaml"}
    files = []
    for item in path.rglob("*"):
        if not item.is_file() or item.is_symlink() or item.name in excluded:
            continue
        lowered = item.name.lower()
        if any(lowered.endswith(suffix) for suffix in ignored_suffixes):
            continue
        files.append(item)
    if not files:
        raise DisassemblyError(f"no script files found in {path}")
    return sorted(files)


def output_plan(input_path: Path, files: list[Path], output: Path | None) -> tuple[Path, dict[Path, Path], bool]:
    is_directory = input_path.is_dir()
    if is_directory:
        output_root = output or input_path.with_name(input_path.name + "_asm")
        if output_root.exists() and not output_root.is_dir():
            raise DisassemblyError(f"directory output is not a directory: {output_root}")
        if output_root.resolve() == input_path.resolve() or input_path.resolve() in output_root.resolve().parents:
            raise DisassemblyError("output directory must be outside the input directory")
        mapping = {
            source: output_root / source.relative_to(input_path).with_name(source.name + ".asm.txt")
            for source in files
        }
        return output_root, mapping, True

    destination = output or Path(str(input_path) + ".asm.txt")
    if destination.exists() and destination.is_dir():
        destination = destination / (input_path.name + ".asm.txt")
    return destination.parent, {input_path: destination}, False


def disassemble(input_path: Path, output: Path | None, encoding: str) -> None:
    try:
        codec = codecs.lookup(encoding).name
    except LookupError as exc:
        raise DisassemblyError(f"unknown text encoding {encoding!r}") from exc
    files = source_files(input_path)
    output_root, mapping, batch = output_plan(input_path, files, output)
    products: dict[Path, tuple[str, list[dict[str, Any]]]] = {}
    provenance_scripts: dict[str, dict[str, Any]] = {}
    stats = []
    for source, destination in mapping.items():
        data = source.read_bytes()
        instructions = decode_script(data, source)
        content, instruction_meta = render_assembly(data, instructions, codec)
        products[destination] = (content, instruction_meta)
        key = destination.relative_to(output_root).as_posix() if batch else destination.name
        provenance_scripts[key] = {
            "source_sha256": hashlib.sha256(data).hexdigest(),
            "instructions": instruction_meta,
        }
        stats.append((source, len(instructions), len(data)))

    for destination in products:
        if destination.exists():
            raise DisassemblyError(f"refusing to overwrite existing output: {destination}")
    provenance_path = (
        output_root / ".toga_asm_meta.json"
        if batch
        else Path(str(next(iter(products))) + ".meta.json")
    )
    if provenance_path.exists():
        raise DisassemblyError(f"refusing to overwrite existing output: {provenance_path}")
    if batch and input_path.is_dir():
        manifest = input_path / ".dat_tool.json"
        manifest_target = output_root / manifest.name
        if manifest.exists() and manifest_target.exists():
            raise DisassemblyError(f"refusing to overwrite existing output: {manifest_target}")

    for destination, (content, _) in products.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    provenance_path.parent.mkdir(parents=True, exist_ok=True)
    with provenance_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(
            {"format": "toga-snr-asm-meta-v1", "scripts": provenance_scripts},
            stream,
            ensure_ascii=True,
            indent=2,
        )
        stream.write("\n")
    if batch:
        manifest = input_path / ".dat_tool.json"
        if manifest.is_file():
            output_root.mkdir(parents=True, exist_ok=True)
            shutil.copy2(manifest, output_root / manifest.name)

    print(f"Disassembled {len(stats)} script(s) to {output_root if batch else next(iter(products))}")
    print(f"Text encoding: {codec}; asm.txt encoding: UTF-8")
    print(f"Text byte provenance: {provenance_path}")
    print(f"Instructions: {sum(count for _, count, _ in stats)}; bytes: {sum(size for _, _, size in stats)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Disassemble decoded Ankh SNR bytecode into UTF-8 semantic assembly. "
            "For a directory, outputs <directory>_asm by default."
        )
    )
    parser.add_argument("input", type=Path, help="one decoded script or a directory of scripts")
    parser.add_argument("-o", "--output", type=Path, help="output asm file or directory")
    parser.add_argument("--encoding", default=SCRIPT_ENCODING, help="script text encoding (default: cp932)")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        disassemble(args.input, args.output, args.encoding)
    except (DisassemblyError, OSError, struct.error, ValueError, json.JSONDecodeError) as exc:
        print(f"disassembler: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
