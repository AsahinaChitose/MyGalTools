#!/usr/bin/env python3
"""Assemble semantic Ankh SNR asm.txt files back into script bytecode."""

from __future__ import annotations

import argparse
import codecs
import hashlib
import json
import re
import shutil
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opcodelist import (
    COMMAND_WIDTH,
    INTEGER_FORMAT,
    MAX_TEXT_BYTES,
    OPCODE_BY_MNEMONIC,
    OPCODES,
)


class AssemblyError(Exception):
    """Raised when semantic assembly input is malformed or unsafe to encode."""


LABEL_RE = re.compile(r"loc_[A-Za-z0-9_]+\Z")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
SOURCE_ANNOTATION_RE = re.compile(r"@src=sha256:([0-9a-fA-F]{64})\Z")


@dataclass
class TextOperand:
    parts: list[str | bytes]
    source_sha256: str | None


@dataclass
class Fixup:
    offset: int
    label: str
    line: int


@dataclass
class Instruction:
    mnemonic: str
    opcode: int
    operands: list[str]
    line: int
    source_hashes: list[str] = field(default_factory=list)
    payload: bytes = b""
    fixups: list[Fixup] = field(default_factory=list)


@dataclass
class AssemblyDocument:
    items: list[Instruction]
    label_positions: dict[str, int]
    source_encoding: str
    source_size: int | None
    source_sha256: str | None


def _strip_comment(line: str) -> str:
    quoted = False
    escaped = False
    for index, char in enumerate(line):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == ";":
            return line[:index]
    if quoted:
        raise AssemblyError("unterminated quoted string")
    return line


def _split_operands(source: str) -> list[str]:
    if not source.strip():
        return []
    result: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(source):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == ",":
            result.append(source[start:index].strip())
            start = index + 1
    if quoted:
        raise AssemblyError("unterminated quoted operand")
    result.append(source[start:].strip())
    if any(not operand for operand in result):
        raise AssemblyError("empty operand")
    return result


def _parse_text_operand(
    token: str, source_encoding: str, provenance_hash: str | None = None
) -> TextOperand:
    if not token.startswith('"'):
        raise AssemblyError(f"expected a quoted text operand, got {token!r}")
    escaped = False
    closing = None
    for index in range(1, len(token)):
        char = token[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            closing = index
            break
    if closing is None:
        raise AssemblyError("unterminated quoted text operand")

    suffix = token[closing + 1 :]
    source_hash = provenance_hash.lower() if provenance_hash else None
    if suffix:
        match = SOURCE_ANNOTATION_RE.fullmatch(suffix)
        if not match:
            raise AssemblyError(f"invalid text provenance annotation {suffix!r}")
        inline_hash = match.group(1).lower()
        if source_hash is not None and source_hash != inline_hash:
            raise AssemblyError("inline text hash conflicts with sidecar provenance")
        source_hash = inline_hash

    inner = token[1:closing]
    segments: list[str | bytes] = []
    characters: list[str] = []

    def flush_text() -> None:
        if characters:
            segments.append("".join(characters))
            characters.clear()

    index = 0
    while index < len(inner):
        char = inner[index]
        if char == "\\":
            index += 1
            if index >= len(inner):
                raise AssemblyError("dangling backslash in text operand")
            escaped_char = inner[index]
            escapes = {"\\": "\\", '"': '"', "n": "\n", "r": "\r"}
            if escaped_char not in escapes:
                raise AssemblyError(f"unsupported text escape \\{escaped_char}")
            characters.append(escapes[escaped_char])
            index += 1
            continue
        if inner.startswith("{{", index):
            end = inner.find("}}", index + 2)
            if end < 0:
                raise AssemblyError("unterminated byte placeholder")
            hex_parts = inner[index + 2 : end].split(":")
            if not hex_parts or any(not re.fullmatch(r"[0-9a-fA-F]{2}", part) for part in hex_parts):
                raise AssemblyError(f"invalid byte placeholder {{{{{inner[index + 2:end]}}}}}")
            flush_text()
            segments.append(bytes(int(part, 16) for part in hex_parts))
            index = end + 2
            continue
        if char in "{}":
            raise AssemblyError("literal braces must be represented with byte placeholders")
        characters.append(char)
        index += 1
    flush_text()
    return TextOperand(segments, source_hash)


def _encode_text_operand(operand: TextOperand, output_encoding: str) -> bytes:
    # The target codec applies even when the text still matches its source hash.
    # Only explicit byte placeholders bypass character encoding.
    try:
        encoded = b"".join(
            part if isinstance(part, bytes) else part.encode(output_encoding)
            for part in operand.parts
        )
    except UnicodeEncodeError as exc:
        bad_text = exc.object[exc.start : exc.end]
        raise AssemblyError(
            f"{bad_text!r} cannot be encoded as {output_encoding}"
        ) from exc
    if len(encoded) > MAX_TEXT_BYTES:
        raise AssemblyError("text field exceeds the 32-bit length limit")
    return encoded


def _parse_u32(token: str) -> int:
    try:
        value = int(token, 0)
    except ValueError as exc:
        raise AssemblyError(f"expected a decimal or hexadecimal u32, got {token!r}") from exc
    if not 0 <= value <= 0xFFFFFFFF:
        raise AssemblyError(f"integer operand out of range: {token!r}")
    return value


def _parse_directive(line: str, metadata: dict[str, Any], line_number: int) -> None:
    parts = line.split(None, 1)
    directive = parts[0]
    value = parts[1].strip() if len(parts) > 1 else ""
    if directive == ".format":
        if value != "toga-snr-v1":
            raise AssemblyError(f"line {line_number}: unsupported format {value!r}")
        metadata["format"] = value
    elif directive == ".encoding":
        if not value:
            raise AssemblyError(f"line {line_number}: .encoding requires a codec")
        try:
            metadata["encoding"] = codecs.lookup(value).name
        except LookupError as exc:
            raise AssemblyError(f"line {line_number}: unknown encoding {value!r}") from exc
    elif directive == ".source_size":
        try:
            size = int(value, 0)
        except ValueError as exc:
            raise AssemblyError(f"line {line_number}: invalid .source_size") from exc
        if size < 0:
            raise AssemblyError(f"line {line_number}: invalid .source_size")
        metadata["source_size"] = size
    elif directive == ".source_sha256":
        if not SHA256_RE.fullmatch(value):
            raise AssemblyError(f"line {line_number}: invalid .source_sha256")
        metadata["source_sha256"] = value.lower()
    else:
        raise AssemblyError(f"line {line_number}: unknown directive {directive!r}")


def parse_assembly(
    path: Path, provenance: dict[str, Any] | None = None
) -> AssemblyDocument:
    metadata: dict[str, Any] = {}
    items: list[Instruction] = []
    labels: dict[str, int] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        try:
            line = _strip_comment(raw_line).strip()
            if not line:
                continue
            if line.startswith("."):
                _parse_directive(line, metadata, line_number)
                continue
            if line.endswith(":"):
                label = line[:-1].strip()
                if not LABEL_RE.fullmatch(label):
                    raise AssemblyError(f"invalid label {label!r}")
                if label in labels:
                    raise AssemblyError(f"duplicate label {label!r}")
                labels[label] = len(items)
                continue
            parts = line.split(None, 1)
            mnemonic = parts[0].upper()
            opcode = 1 if mnemonic == "NAME" else OPCODE_BY_MNEMONIC.get(mnemonic)
            if opcode is None:
                raise AssemblyError(f"unknown instruction {mnemonic!r}")
            operands = _split_operands(parts[1]) if len(parts) > 1 else []
            if mnemonic == "NAME":
                if len(operands) != 2:
                    raise AssemblyError("NAME expects message_id and quoted speaker name")
                operands.append("0x00000002")
            items.append(Instruction(mnemonic, opcode, operands, line_number))
        except AssemblyError as exc:
            raise AssemblyError(f"{path}:{line_number}: {exc}") from exc

    if metadata.get("format") != "toga-snr-v1":
        raise AssemblyError(f"{path}: missing .format toga-snr-v1 header")
    if "encoding" not in metadata:
        raise AssemblyError(f"{path}: missing .encoding header")
    if not items and not labels:
        raise AssemblyError(f"{path}: assembly contains no instructions")
    if provenance is not None:
        source_hash = provenance.get("source_sha256")
        if not isinstance(source_hash, str) or not SHA256_RE.fullmatch(source_hash):
            raise AssemblyError(f"{path}: invalid source hash in provenance sidecar")
        if metadata.get("source_sha256") != source_hash.lower():
            raise AssemblyError(f"{path}: provenance sidecar belongs to a different source script")
        instruction_meta = provenance.get("instructions")
        if not isinstance(instruction_meta, list):
            raise AssemblyError(f"{path}: invalid instruction metadata in provenance sidecar")
        for index, instruction in enumerate(items):
            if index >= len(instruction_meta):
                break
            entry = instruction_meta[index]
            if not isinstance(entry, dict) or entry.get("opcode") != instruction.opcode:
                continue
            hashes = entry.get("text_sha256", [])
            if not isinstance(hashes, list) or any(
                not isinstance(value, str) or not SHA256_RE.fullmatch(value)
                for value in hashes
            ):
                raise AssemblyError(f"{path}: invalid text hash in provenance sidecar")
            instruction.source_hashes = [value.lower() for value in hashes]
    return AssemblyDocument(
        items,
        labels,
        metadata["encoding"],
        metadata.get("source_size"),
        metadata.get("source_sha256"),
    )


def _compile_fields(
    descriptors: list[dict[str, Any]],
    tokens: list[str],
    cursor: int,
    values: dict[str, Any],
    payload: bytearray,
    fixups: list[Fixup],
    instruction: Instruction,
    source_encoding: str,
    output_encoding: str,
    text_index: list[int],
    depth: int = 0,
) -> int:
    if depth > 8:
        raise AssemblyError("opcode schema nesting is too deep")
    for desc in descriptors:
        kind = desc["kind"]
        if kind in ("u32", "target"):
            if cursor >= len(tokens):
                raise AssemblyError(f"line {instruction.line}: missing operand {desc['name']!r}")
            token = tokens[cursor]
            cursor += 1
            if kind == "u32":
                value = _parse_u32(token)
                payload.extend(struct.pack(INTEGER_FORMAT, value))
                values[desc["name"]] = value
            else:
                if not LABEL_RE.fullmatch(token):
                    raise AssemblyError(f"line {instruction.line}: branch target must be a label, got {token!r}")
                fixups.append(Fixup(len(payload), token, instruction.line))
                payload.extend(b"\0" * COMMAND_WIDTH)
        elif kind == "text":
            if cursor >= len(tokens):
                raise AssemblyError(f"line {instruction.line}: missing text operand {desc['name']!r}")
            provenance_hash = (
                instruction.source_hashes[text_index[0]]
                if text_index[0] < len(instruction.source_hashes)
                else None
            )
            value = _parse_text_operand(tokens[cursor], source_encoding, provenance_hash)
            text_index[0] += 1
            cursor += 1
            raw = _encode_text_operand(value, output_encoding)
            if len(raw) > MAX_TEXT_BYTES:
                raise AssemblyError("text field exceeds the 32-bit length limit")
            payload.extend(struct.pack(INTEGER_FORMAT, len(raw)))
            payload.extend(raw)
            values[desc["name"]] = value
        elif kind == "text_slots":
            count = int(desc["count"])
            if cursor + count > len(tokens):
                raise AssemblyError(f"line {instruction.line}: expected {count} text slot operands")
            slots = []
            for i in range(count):
                provenance_hash = (
                    instruction.source_hashes[text_index[0]]
                    if text_index[0] < len(instruction.source_hashes)
                    else None
                )
                text = _parse_text_operand(tokens[cursor + i], source_encoding, provenance_hash)
                slots.append(_encode_text_operand(text, output_encoding))
                text_index[0] += 1
            cursor += count
            for index, raw in enumerate(slots):
                if len(raw) > 10:
                    raise AssemblyError(
                        f"line {instruction.line}: text slot {index} exceeds the handler's 10-byte buffer"
                    )
            for raw in slots:
                payload.extend(struct.pack(INTEGER_FORMAT, len(raw)))
            for raw in slots:
                payload.extend(raw)
            values[desc["name"]] = slots
        elif kind == "repeat":
            count = values.get(desc["count"])
            if not isinstance(count, int) or count > int(desc["maximum"]):
                raise AssemblyError(
                    f"line {instruction.line}: invalid {desc['count']} value {count!r}"
                )
            for _ in range(count):
                cursor = _compile_fields(
                    desc["fields"], tokens, cursor, values, payload, fixups,
                    instruction, source_encoding, output_encoding, text_index, depth + 1,
                )
        elif kind == "when":
            if values.get(desc["field"]) == desc["equals"]:
                cursor = _compile_fields(
                    desc["fields"], tokens, cursor, values, payload, fixups,
                    instruction, source_encoding, output_encoding, text_index, depth + 1,
                )
        else:
            raise AssemblyError(f"unsupported opcode schema field {kind!r}")
    return cursor


def assemble_document(document: AssemblyDocument, output_encoding: str) -> bytes:
    try:
        output_encoding = codecs.lookup(output_encoding).name
    except LookupError as exc:
        raise AssemblyError(f"unknown output encoding {output_encoding!r}") from exc

    for instruction in document.items:
        spec = OPCODES[instruction.opcode]
        payload = bytearray(struct.pack(INTEGER_FORMAT, instruction.opcode))
        fixups: list[Fixup] = []
        try:
            cursor = _compile_fields(
                spec["fields"], instruction.operands, 0, {}, payload, fixups,
                instruction, document.source_encoding, output_encoding, [0],
            )
        except AssemblyError as exc:
            if str(exc).startswith(f"line {instruction.line}:"):
                raise
            raise AssemblyError(f"line {instruction.line}: {exc}") from exc
        if cursor != len(instruction.operands):
            raise AssemblyError(
                f"line {instruction.line}: {len(instruction.operands) - cursor} unexpected operand(s)"
            )
        instruction.payload = bytes(payload)
        instruction.fixups = fixups

    label_offsets: dict[str, int] = {}
    instruction_offsets: list[int] = []
    position = 0
    labels_at_position: dict[int, list[str]] = {}
    for label, item_index in document.label_positions.items():
        labels_at_position.setdefault(item_index, []).append(label)
    for item_index, instruction in enumerate(document.items):
        for label in labels_at_position.get(item_index, []):
            label_offsets[label] = position
        instruction_offsets.append(position)
        position += len(instruction.payload)
        if position > 0xFFFFFFFF:
            raise AssemblyError("assembled script exceeds the 32-bit address limit")
    for label in labels_at_position.get(len(document.items), []):
        label_offsets[label] = position

    output = bytearray()
    for instruction, offset in zip(document.items, instruction_offsets):
        encoded = bytearray(instruction.payload)
        for fixup in instruction.fixups:
            target = label_offsets.get(fixup.label)
            if target is None:
                raise AssemblyError(f"line {fixup.line}: unresolved branch label {fixup.label!r}")
            struct.pack_into(INTEGER_FORMAT, encoded, fixup.offset, target)
        output.extend(encoded)
    if document.source_size is not None and not output:
        raise AssemblyError("assembly produced an empty script")
    return bytes(output)


def assembly_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise AssemblyError(f"input does not exist: {path}")
    files = sorted(item for item in path.rglob("*.asm.txt") if item.is_file() and not item.is_symlink())
    if not files:
        raise AssemblyError(f"no *.asm.txt files found in {path}")
    return files


def load_provenance(input_path: Path) -> dict[str, Any] | None:
    if input_path.is_dir():
        candidates = [input_path / ".toga_asm_meta.json"]
    else:
        candidates = [
            Path(str(input_path) + ".meta.json"),
            input_path.parent / ".toga_asm_meta.json",
        ]
    metadata_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if metadata_path is None:
        return None
    try:
        document = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AssemblyError(f"invalid provenance sidecar {metadata_path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("format") != "toga-snr-asm-meta-v1":
        raise AssemblyError(f"unsupported provenance sidecar format: {metadata_path}")
    if not isinstance(document.get("scripts"), dict):
        raise AssemblyError(f"invalid scripts map in provenance sidecar: {metadata_path}")
    return document


def provenance_for(
    input_path: Path, source: Path, document: dict[str, Any] | None
) -> dict[str, Any] | None:
    if document is None:
        return None
    key = source.relative_to(input_path).as_posix() if input_path.is_dir() else source.name
    entry = document["scripts"].get(key)
    if entry is not None and not isinstance(entry, dict):
        raise AssemblyError(f"invalid provenance entry for {key!r}")
    return entry


def output_plan(input_path: Path, files: list[Path], output: Path | None) -> tuple[Path, dict[Path, Path], bool]:
    if input_path.is_dir():
        output_root = output or input_path.with_name(input_path.name + "_rebuild")
        if output_root.exists() and not output_root.is_dir():
            raise AssemblyError(f"directory output is not a directory: {output_root}")
        if output_root.resolve() == input_path.resolve() or input_path.resolve() in output_root.resolve().parents:
            raise AssemblyError("output directory must be outside the input directory")
        mapping = {}
        for source in files:
            relative = source.relative_to(input_path)
            basename = relative.name[:-len(".asm.txt")]
            mapping[source] = output_root / relative.with_name(basename)
        return output_root, mapping, True

    if output is not None and output.exists() and output.is_dir():
        name = input_path.name[:-len(".asm.txt")] if input_path.name.endswith(".asm.txt") else input_path.stem
        destination = output / (name + ".rebuild")
    else:
        destination = output or Path(
            str(input_path)[:-len(".asm.txt")] + ".rebuild"
            if input_path.name.endswith(".asm.txt")
            else input_path.stem + ".rebuild"
        )
    return destination.parent, {input_path: destination}, False


def assemble(input_path: Path, output: Path | None, encoding: str | None) -> None:
    files = assembly_files(input_path)
    output_root, mapping, batch = output_plan(input_path, files, output)
    provenance = load_provenance(input_path)
    products: dict[Path, tuple[bytes, AssemblyDocument, str]] = {}
    for source, destination in mapping.items():
        entry = provenance_for(input_path, source, provenance)
        document = parse_assembly(source, entry)
        chosen_encoding = encoding or document.source_encoding
        try:
            data = assemble_document(document, chosen_encoding)
        except AssemblyError as exc:
            raise AssemblyError(f"{source}: {exc}") from exc
        products[destination] = (data, document, chosen_encoding)

    for destination in products:
        if destination.exists():
            raise AssemblyError(f"refusing to overwrite existing output: {destination}")
    manifest = input_path / ".dat_tool.json" if input_path.is_dir() else None
    manifest_target = output_root / ".dat_tool.json"
    if batch and manifest is not None and manifest.is_file() and manifest_target.exists():
        if manifest.read_bytes() != manifest_target.read_bytes():
            raise AssemblyError(f"refusing to overwrite different manifest: {manifest_target}")

    for destination, (data, _, _) in products.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
    if batch and manifest is not None and manifest.is_file() and not manifest_target.exists():
        output_root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manifest, manifest_target)

    matches = 0
    for source, destination in mapping.items():
        data, document, chosen_encoding = products[destination]
        same = document.source_sha256 == hashlib.sha256(data).hexdigest()
        matches += int(same)
        print(
            f"Assembled {source.name} -> {destination} ({len(data)} bytes, "
            f"encoding={chosen_encoding}, source SHA-256 {'matches' if same else 'differs'})"
        )
    if batch:
        print(f"Assembled {len(products)} script(s) to {output_root}; source hashes matched: {matches}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Assemble UTF-8 Ankh SNR asm.txt files. A directory produces an "
            "extensionless script set suitable for dat_tool.py pack."
        )
    )
    parser.add_argument("input", type=Path, help="one asm.txt file or a directory of asm.txt files")
    parser.add_argument("-o", "--output", type=Path, help="output script file or directory")
    parser.add_argument("--encoding", help="encoding for all text fields (defaults to the .encoding header)")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        assemble(args.input, args.output, args.encoding)
    except (AssemblyError, OSError, struct.error, ValueError) as exc:
        print(f"assembler: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
