#!/usr/bin/env python3
"""Extract and inject Ankh SNR dialogue, names, choices, and story overlays as JSON."""

from __future__ import annotations

import argparse
import codecs
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assembler import AssemblyError, _parse_text_operand

FORMAT = "ankh-snr-json-v1"
DEFAULT_ENCODING = "cp932"
DEFAULT_INJECT_ENCODING = "gbk"
INDENT = "\u3000"
THREE_LINE_CHAR_LIMIT = 28
OPEN_QUOTES = {"\u300c": "\u300d", "\u300e": "\u300f"}
CLOSE_QUOTES = {value: key for key, value in OPEN_QUOTES.items()}
PLACEHOLDER_RE = re.compile(r"\{\{(?:[0-9a-fA-F]{2})(?::[0-9a-fA-F]{2})*\}\}")
MNEMONIC_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\b")


class AsmJsonError(Exception):
    """Raised when an assembly or translation JSON is unsafe to process."""


@dataclass(frozen=True)
class Operand:
    token: str
    start: int
    end: int


@dataclass(frozen=True)
class Instruction:
    line: int
    mnemonic: str
    operands: tuple[Operand, ...]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _line_parts(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n") or line.endswith("\r"):
        return line[:-1], line[-1:]
    return line, ""


def _code_before_comment(line: str) -> str:
    quoted = escaped = False
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
        raise AsmJsonError("unterminated quoted operand")
    return line


def _split_operands(line: str, match: re.Match[str]) -> tuple[Operand, ...]:
    code = _code_before_comment(line)
    cursor = match.end()
    while cursor < len(code) and code[cursor].isspace():
        cursor += 1
    if cursor == len(code):
        return ()
    result: list[Operand] = []
    start = cursor
    quoted = escaped = False
    for index in range(cursor, len(code)):
        char = code[index]
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
            left, right = start, index
            while left < right and code[left].isspace():
                left += 1
            while right > left and code[right - 1].isspace():
                right -= 1
            if left == right:
                raise AsmJsonError("empty assembly operand")
            result.append(Operand(code[left:right], left, right))
            start = index + 1
    if quoted:
        raise AsmJsonError("unterminated quoted operand")
    left, right = start, len(code)
    while left < right and code[left].isspace():
        left += 1
    while right > left and code[right - 1].isspace():
        right -= 1
    if left == right:
        raise AsmJsonError("empty final assembly operand")
    result.append(Operand(code[left:right], left, right))
    return tuple(result)


def parse_instructions(lines: list[str]) -> tuple[list[Instruction], set[int]]:
    instructions: list[Instruction] = []
    labels: set[int] = set()
    for index, original in enumerate(lines):
        line, _ending = _line_parts(original)
        stripped = line.strip()
        if re.match(r"^loc_[A-Za-z0-9_]+:\s*(?:;.*)?$", stripped):
            labels.add(index + 1)
            continue
        match = MNEMONIC_RE.match(line)
        if not match:
            continue
        try:
            operands = _split_operands(line, match)
        except AsmJsonError as exc:
            raise AsmJsonError(f"line {index + 1}: {exc}") from exc
        instructions.append(Instruction(index + 1, match.group(1).upper(), operands))
    return instructions, labels


def _decode_text(token: str, encoding: str, line: int) -> str:
    try:
        parsed = _parse_text_operand(token, encoding)
    except (AssemblyError, UnicodeError) as exc:
        raise AsmJsonError(f"line {line}: cannot decode text operand: {exc}") from exc
    return "".join(
        "{{" + ":".join(f"{byte:02X}" for byte in part) + "}}"
        if isinstance(part, bytes) else part
        for part in parsed.parts
    )


def _integer(operand: Operand, line: int, what: str) -> int:
    try:
        value = int(operand.token, 0)
    except ValueError as exc:
        raise AsmJsonError(f"line {line}: invalid {what}: {operand.token!r}") from exc
    if not 0 <= value <= 0xFFFFFFFF:
        raise AsmJsonError(f"line {line}: {what} is outside u32 range")
    return value


def _text(insn: Instruction, operand_index: int, encoding: str) -> str:
    if operand_index >= len(insn.operands):
        raise AsmJsonError(f"line {insn.line}: {insn.mnemonic} is missing text")
    return _decode_text(insn.operands[operand_index].token, encoding, insn.line)


def _strip_indent(text: str) -> tuple[str, bool]:
    return (text[1:], True) if text.startswith(INDENT) else (text, False)


def _quote_stack(texts: list[str]) -> list[str]:
    stack: list[str] = []
    for text in texts:
        for char in text:
            if char in OPEN_QUOTES:
                stack.append(char)
            elif char in CLOSE_QUOTES and stack and stack[-1] == CLOSE_QUOTES[char]:
                stack.pop()
    return stack


def _entry_id(stem: str, message_id: int | None, kind: str, suffix: str = "") -> str:
    base = f"{stem}#{message_id:08X}" if message_id is not None else f"{stem}#text"
    return f"{base}:{kind}{suffix}"


def _source_part(insn: Instruction, operand_index: int, text: str, role: str) -> dict[str, Any]:
    normalized, had_indent = _strip_indent(text)
    return {"line": insn.line, "operand": operand_index, "role": role,
            "leading_ideographic_space": had_indent, "original": normalized}


def scan_asm(path: Path, encoding: str) -> tuple[list[str], list[dict[str, Any]], dict[str, Any]]:
    raw = path.read_bytes()
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AsmJsonError(f"{path}: asm must be UTF-8: {exc}") from exc
    lines = source.splitlines(keepends=True)
    instructions, labels = parse_instructions(lines)
    entries: list[dict[str, Any]] = []
    metadata_entries: list[dict[str, Any]] = []
    pending_name: tuple[str, dict[str, Any]] | None = None
    stem = path.name.removesuffix(".asm.txt")

    index = 0
    while index < len(instructions):
        insn = instructions[index]
        if insn.mnemonic == "NAME":
            if len(insn.operands) != 2:
                raise AsmJsonError(f"{path}:{insn.line}: NAME must have two operands")
            speaker_id = _integer(insn.operands[0], insn.line, "NAME message id")
            speaker = _text(insn, 1, encoding)
            pending_name = (speaker, {
                "line": insn.line, "operand": 1,
                "message_id": speaker_id, "original": speaker,
            })
            index += 1
            continue

        if insn.mnemonic == "MESSAGE":
            if len(insn.operands) != 3:
                raise AsmJsonError(f"{path}:{insn.line}: MESSAGE must have three operands")
            message_id = _integer(insn.operands[0], insn.line, "MESSAGE id")
            text = _text(insn, 1, encoding)
            parts = [(insn, text)]
            next_index = index + 1
            stack = _quote_stack([text])
            while stack and next_index < len(instructions):
                previous = parts[-1][0]
                candidate = instructions[next_index]
                if (
                    candidate.mnemonic != "MESSAGE"
                    or any(previous.line < label <= candidate.line for label in labels)
                    or len(candidate.operands) != 3
                ):
                    break
                candidate_id = _integer(candidate.operands[0], candidate.line, "MESSAGE id")
                candidate_text = _text(candidate, 1, encoding)
                _normalized, had_indent = _strip_indent(candidate_text)
                previous_id = _integer(previous.operands[0], previous.line, "MESSAGE id")
                if candidate_id != previous_id + 1 or not had_indent:
                    break
                parts.append((candidate, candidate_text))
                stack = _quote_stack([text_part for _part_insn, text_part in parts])
                next_index += 1

            if len(parts) > 1 and not stack:
                normalized_parts = [_strip_indent(text_part)[0] for _part_insn, text_part in parts]
                combined = "\n".join(normalized_parts)
                speaker = None
                name_source = None
                if pending_name and normalized_parts[0].startswith(("\u300c", "\u300e")):
                    speaker, name_source = pending_name
                entry_id = _entry_id(stem, message_id, "text")
                entries.append({"id": entry_id,
                                **({"name": speaker} if speaker is not None else {}),
                                "pre_jp": combined, "message": combined})
                metadata_entries.append({
                    "id": entry_id, "kind": "text", "original_message": combined,
                    "parts": [_source_part(part_insn, 1, text_part, "message")
                              for part_insn, text_part in parts],
                    "name_source": name_source,
                })
                index += len(parts)
                pending_name = None
                continue

            normalized, _had_indent = _strip_indent(text)
            speaker = None
            name_source = None
            if pending_name and normalized.startswith(("\u300c", "\u300e")):
                speaker, name_source = pending_name
            entry_id = _entry_id(stem, message_id, "text")
            entries.append({"id": entry_id,
                            **({"name": speaker} if speaker is not None else {}),
                            "pre_jp": normalized, "message": normalized})
            metadata_entries.append({
                "id": entry_id, "kind": "text", "original_message": normalized,
                "parts": [_source_part(insn, 1, text, "message")],
                "name_source": name_source,
            })
            pending_name = None
            index += 1
            continue

        if insn.mnemonic == "CHOICE":
            if len(insn.operands) < 4:
                raise AsmJsonError(f"{path}:{insn.line}: CHOICE has too few operands")
            count = _integer(insn.operands[0], insn.line, "CHOICE count")
            selection_var = _integer(insn.operands[1], insn.line, "CHOICE selection variable")
            if count == 0 or len(insn.operands) != 2 + count * 2:
                raise AsmJsonError(f"{path}:{insn.line}: CHOICE count does not match operands")
            for choice_index in range(count):
                operand_index = 2 + choice_index * 2
                text = _text(insn, operand_index, encoding)
                normalized, _had_indent = _strip_indent(text)
                flag_id = _integer(insn.operands[operand_index + 1], insn.line, "CHOICE flag id")
                entry_id = _entry_id(stem, None, "choice", f"-{insn.line:06d}-{choice_index + 1}")
                entries.append({"id": entry_id, "kind": f"choice-{choice_index + 1}",
                                "pre_jp": normalized, "message": normalized})
                metadata_entries.append({
                    "id": entry_id, "kind": "choice", "original_message": normalized,
                    "parts": [_source_part(insn, operand_index, text, "choice")],
                    "choice_index": choice_index + 1, "choice_count": count,
                    "selection_var": selection_var, "flag_id": flag_id,
                })
            pending_name = None
            index += 1
            continue

        # In this game, only s_001 uses this opcode for story text; start uses it for tests.
        if insn.mnemonic == "DRAW_INLINE_RESOURCE" and stem.casefold() == "s_001":
            if len(insn.operands) != 4:
                raise AsmJsonError(f"{path}:{insn.line}: DRAW_INLINE_RESOURCE must have four operands")
            part = _source_part(insn, 0, _text(insn, 0, encoding), "draw-inline")
            normalized = part["original"]
            entry_id = _entry_id(stem, None, "draw-inline", f"-{insn.line:06d}")
            entries.append({"id": entry_id, "kind": "draw-inline",
                            "pre_jp": normalized, "message": normalized})
            metadata_entries.append({"id": entry_id, "kind": "draw-inline",
                                     "original_message": normalized, "parts": [part]})

        pending_name = None
        index += 1

    metadata = {"format": FORMAT, "source_file": path.name,
                "source_sha256": sha256(raw), "encoding": encoding,
                "entries": metadata_entries}
    return lines, entries, metadata


def asm_files(src: Path) -> tuple[list[Path], Path | None]:
    if src.is_file():
        if not src.name.endswith(".asm.txt"):
            raise AsmJsonError(f"input is not an .asm.txt file: {src}")
        return [src], None
    if not src.is_dir():
        raise AsmJsonError(f"input does not exist: {src}")
    files = sorted(path for path in src.rglob("*.asm.txt")
                   if path.is_file() and not path.is_symlink())
    if not files:
        raise AsmJsonError(f"no .asm.txt files found in {src}")
    return files, src


def _relative_output(path: Path, root: Path | None, suffix: str) -> Path:
    if root is None:
        return Path(path.name.removesuffix(".asm.txt") + suffix)
    return path.relative_to(root).with_name(path.name.removesuffix(".asm.txt") + suffix)


def _write_new_or_same(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == data:
            return
        raise AsmJsonError(f"refusing to overwrite existing file: {path}")
    with path.open("xb") as stream:
        stream.write(data)


def extract(src: Path, out: Path, encoding: str) -> tuple[int, int, int]:
    try:
        codec = codecs.lookup(encoding).name
    except LookupError as exc:
        raise AsmJsonError(f"unknown encoding {encoding!r}") from exc
    files, root = asm_files(src)
    total = named = choices = 0
    for path in files:
        _lines, entries, metadata = scan_asm(path, codec)
        json_path = out / _relative_output(path, root, ".json")
        meta_path = Path(str(json_path) + ".meta.json")
        json_data = (json.dumps(entries, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        meta_data = (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        _write_new_or_same(json_path, json_data)
        _write_new_or_same(meta_path, meta_data)
        total += len(entries)
        named += sum("name" in item for item in entries)
        choices += sum(str(item.get("kind", "")).startswith("choice-") for item in entries)
        print(f"{path.name}: {len(entries)} 条 -> {json_path}")
    print(f"提取完成：{total} 条文本/选项，其中 {named} 条带人名、{choices} 条选项")
    return total, named, choices


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AsmJsonError(f"cannot read JSON {path}: {exc}") from exc


def _escape_inner(text: str, encoding: str, item_id: str) -> str:
    try:
        codecs.lookup(encoding)
    except LookupError as exc:
        raise AsmJsonError(f"unknown encoding {encoding!r}") from exc
    escaped: list[str] = []
    index = 0
    while index < len(text):
        placeholder = PLACEHOLDER_RE.match(text, index)
        if placeholder:
            escaped.append(placeholder.group(0))
            index = placeholder.end()
            continue
        char = text[index]
        if char in "{}":
            raise AsmJsonError(f"{item_id}: literal braces must use a {{XX}} byte placeholder")
        if char == "\\":
            escaped.append("\\\\")
        elif char == '"':
            escaped.append('\\"')
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\r":
            escaped.append("\\r")
        else:
            try:
                char.encode(encoding, errors="strict")
            except UnicodeEncodeError as exc:
                raise AsmJsonError(
                    f"{item_id}: character {char!r} is not representable in {encoding}"
                ) from exc
            escaped.append(char)
        index += 1
    return "".join(escaped)


def _text_span(token: str, line: int) -> tuple[int, str]:
    if not token.startswith('"'):
        raise AsmJsonError(f"line {line}: expected a quoted text operand")
    escaped = False
    for index in range(1, len(token)):
        char = token[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return index, token[index + 1 :]
    raise AsmJsonError(f"line {line}: unterminated quoted text operand")


def _replace_text(lines: list[str], line_number: int, operand_index: int, text: str,
                  encoding: str, item_id: str) -> None:
    if line_number < 1 or line_number > len(lines):
        raise AsmJsonError(f"{item_id}: source line {line_number} is out of range")
    body, ending = _line_parts(lines[line_number - 1])
    match = MNEMONIC_RE.match(body)
    if not match:
        raise AsmJsonError(f"{item_id}: expected instruction at source line {line_number}")
    operands = _split_operands(body, match)
    if operand_index < 0 or operand_index >= len(operands):
        raise AsmJsonError(f"{item_id}: source operand {operand_index} is out of range")
    operand = operands[operand_index]
    _closing, suffix = _text_span(operand.token, line_number)
    token = '"' + _escape_inner(text, encoding, item_id) + '"' + suffix
    lines[line_number - 1] = body[:operand.start] + token + body[operand.end:] + ending


def _read_utf8_preserving_newlines(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return stream.read()


def _load_source_meta(json_path: Path, source: Path) -> dict[str, Any]:
    meta_path = Path(str(json_path) + ".meta.json")
    metadata = _load_json(meta_path)
    if not isinstance(metadata, dict) or metadata.get("format") != FORMAT:
        raise AsmJsonError(f"unsupported or missing metadata: {meta_path}")
    if metadata.get("source_file") != source.name:
        raise AsmJsonError(f"{meta_path}: source file name does not match {source.name}")
    if metadata.get("source_sha256") != sha256(source.read_bytes()):
        raise AsmJsonError(f"{source}: source SHA-256 differs from extraction metadata")
    return metadata


def _message_value(item: dict[str, Any], item_id: str) -> str:
    value = item.get("message")
    if value is None:
        value = item.get("pre_jp")
    if not isinstance(value, str):
        raise AsmJsonError(f"{item_id}: message/pre_jp must be a string")
    return value


def _inject_one(source: Path, json_path: Path, out_path: Path, encoding: str) -> int:
    metadata = _load_source_meta(json_path, source)
    rows = _load_json(json_path)
    if not isinstance(rows, list):
        raise AsmJsonError(f"{json_path}: JSON root must be an array")
    by_id: dict[str, dict[str, Any]] = {}
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise AsmJsonError(f"{json_path}: every item must have a string id")
        if item["id"] in by_id:
            raise AsmJsonError(f"{json_path}: duplicate id {item['id']!r}")
        by_id[item["id"]] = item

    originals = metadata.get("entries")
    if not isinstance(originals, list):
        raise AsmJsonError(f"{json_path}: malformed entries metadata")
    expected = {entry.get("id") for entry in originals if isinstance(entry, dict)}
    if set(by_id) != expected:
        missing = sorted(expected - set(by_id))
        extra = sorted(set(by_id) - expected)
        raise AsmJsonError(f"{json_path}: item id mismatch; missing={missing[:5]}, extra={extra[:5]}")

    try:
        codec = codecs.lookup(encoding).name
    except LookupError as exc:
        raise AsmJsonError(f"unknown encoding {encoding!r}") from exc
    lines = _read_utf8_preserving_newlines(source).splitlines(keepends=True)
    changed = 0
    for entry in originals:
        item_id = entry["id"]
        item = by_id[item_id]
        message = _message_value(item, item_id)
        original_message = entry.get("original_message")
        if item.get("pre_jp") != original_message or not isinstance(original_message, str):
            raise AsmJsonError(f"{item_id}: pre_jp was modified; restore the extracted source text")
        parts = entry.get("parts")
        if not isinstance(parts, list) or not parts:
            raise AsmJsonError(f"{item_id}: malformed source parts metadata")
        values = message.split("\n")
        if len(values) != len(parts):
            raise AsmJsonError(
                f"{item_id}: translated message has {len(values)} line(s), source needs {len(parts)}; "
                "keep the extracted newline count"
            )
        name_source = entry.get("name_source")
        original_name = name_source.get("original") if isinstance(name_source, dict) else None
        new_name = item.get("name", original_name)
        if new_name is not None and not isinstance(new_name, str):
            raise AsmJsonError(f"{item_id}: name must be a string")
        if name_source is None and "name" in item:
            raise AsmJsonError(f"{item_id}: this source message has no speaker name")
        if isinstance(name_source, dict) and not new_name:
            raise AsmJsonError(f"{item_id}: speaker name cannot be empty")
        if isinstance(name_source, dict) and new_name != original_name:
            _escape_inner(new_name, codec, item_id)

        entry_changed = message != original_message or new_name != original_name
        check_line_length = entry.get("kind") == "text" and len(values) == 3
        if not entry_changed and not check_line_length:
            continue
        for dialogue_line, (part, value) in enumerate(zip(parts, values), 1):
            if not isinstance(part, dict):
                raise AsmJsonError(f"{item_id}: malformed source part")
            indent = INDENT if part.get("leading_ideographic_space") else ""
            original_part = part.get("original")
            if not isinstance(original_part, str):
                raise AsmJsonError(f"{item_id}: malformed original source part")
            original_raw = indent + original_part
            if not entry_changed:
                value = original_raw
            elif indent:
                value = indent + value.removeprefix(indent)
            if check_line_length and len(value) > THREE_LINE_CHAR_LIMIT:
                print(
                    f"排版警告 {json_path} [{item_id}] 第 {dialogue_line}/3 行有 {len(value)} 字，"
                    f"超过 {THREE_LINE_CHAR_LIMIT} 字（含全角空格），自动换行后可能超过三行。",
                    file=sys.stderr,
                )
            if value == original_raw:
                continue
            _escape_inner(value, codec, item_id)
            _replace_text(lines, int(part["line"]), int(part["operand"]), value, codec, item_id)
        if isinstance(name_source, dict) and new_name != original_name:
            _replace_text(lines, int(name_source["line"]), int(name_source["operand"]),
                          new_name, codec, item_id)
        if entry_changed:
            changed += 1

    _write_new_or_same(out_path, "".join(lines).encode("utf-8"))
    print(f"{source.name} -> {out_path} ({len(rows)} 条，改动 {changed} 条)")
    return changed


def _copy_manifests(source_root: Path, output_root: Path,
                    source_asm_name: str | None = None,
                    output_asm_name: str | None = None) -> None:
    for name in (".toga_asm_meta.json", ".dat_tool.json"):
        source = source_root / name
        if source.is_file():
            data = source.read_bytes()
            if name == ".toga_asm_meta.json" and source_asm_name and output_asm_name:
                if source_asm_name != output_asm_name:
                    document = json.loads(data.decode("utf-8"))
                    scripts = document.get("scripts") if isinstance(document, dict) else None
                    if not isinstance(scripts, dict) or source_asm_name not in scripts:
                        raise AsmJsonError(f"{source}: missing provenance for {source_asm_name}")
                    scripts[output_asm_name] = scripts[source_asm_name]
                    data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            _write_new_or_same(output_root / name, data)


def inject(src: Path, json_src: Path, out: Path, encoding: str) -> tuple[int, int]:
    sources, root = asm_files(src)
    total = changed = 0
    if root is not None:
        for source in sources:
            relative_json = _relative_output(source, root, ".json")
            json_path = json_src / relative_json if json_src.is_dir() else json_src
            if not json_path.is_file():
                raise AsmJsonError(f"matching JSON not found: {json_path}")
            out_path = out / source.relative_to(root)
            changed += _inject_one(source, json_path, out_path, encoding)
            total += 1
        _copy_manifests(root, out)
    else:
        source = sources[0]
        if json_src.is_file():
            json_path = json_src
        else:
            json_path = json_src / (source.name.removesuffix(".asm.txt") + ".json")
        if not json_path.is_file():
            raise AsmJsonError(f"matching JSON not found: {json_path}")
        out_path = out if out.name.endswith(".asm.txt") else out / source.name
        if source.parent == out_path.parent and source.name != out_path.name:
            raise AsmJsonError("a renamed single-file output must use a separate directory")
        _inject_one(source, json_path, out_path, encoding)
        total = 1
        if source.parent != out_path.parent:
            _copy_manifests(source.parent, out_path.parent, source.name, out_path.name)
    return total, changed


def verify(src: Path, encoding: str) -> int:
    sources, root = asm_files(src)
    with tempfile.TemporaryDirectory(prefix="ankh_asm_json_") as temp:
        temp_root = Path(temp)
        json_root, asm_root = temp_root / "json", temp_root / "asm"
        extract(src, json_root, encoding)
        inject(src, json_root, asm_root, encoding)
        mismatches = []
        for source in sources:
            relative = source.relative_to(root) if root is not None else Path(source.name)
            if source.read_bytes() != (asm_root / relative).read_bytes():
                mismatches.append(str(source))
        if mismatches:
            print("逐字节校验失败：", file=sys.stderr)
            for path in mismatches[:20]:
                print(f"  {path}", file=sys.stderr)
            return 1
        print(f"verify 通过：{len(sources)} 个 asm 文件提取后注入，逐字节一致")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ankh SNR 对话/人名/选项/剧情绘制文本 asm <-> JSON 工具")
    subparsers = parser.add_subparsers(dest="command", required=True)

    command = subparsers.add_parser("extract", help="asm.txt -> UTF-8 JSON")
    command.add_argument("--src", required=True, type=Path, help="asm 目录或单个 .asm.txt")
    command.add_argument("-o", "--out", required=True, type=Path, help="JSON 输出目录")
    command.add_argument("--encoding", default=DEFAULT_ENCODING, help="源文本编码，默认 cp932")

    command = subparsers.add_parser("inject", help="JSON -> asm.txt")
    command.add_argument("--src", required=True, type=Path, help="原始 asm 目录或单个 .asm.txt")
    command.add_argument("--json", required=True, type=Path, help="JSON 目录或单个 JSON 文件")
    command.add_argument("-o", "--out", required=True, type=Path, help="新 asm 输出目录或 .asm.txt 文件")
    command.add_argument("--encoding", default=DEFAULT_INJECT_ENCODING, help="译文编码校验，默认 gbk")

    command = subparsers.add_parser("verify", help="检查空注入是否逐字节还原 asm")
    command.add_argument("--src", required=True, type=Path, help="asm 目录或单个 .asm.txt")
    command.add_argument("--encoding", default=DEFAULT_ENCODING, help="源文本编码，默认 cp932")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "extract":
            extract(args.src, args.out, args.encoding)
            return 0
        if args.command == "inject":
            files, _root = asm_files(args.src)
            inject(args.src, args.json, args.out, args.encoding)
            print(f"注入完成：{len(files)} 个 asm 文件")
            return 0
        return verify(args.src, args.encoding)
    except (AsmJsonError, OSError, ValueError) as exc:
        print(f"asm_json: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
