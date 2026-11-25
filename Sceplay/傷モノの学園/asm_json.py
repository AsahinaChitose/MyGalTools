#!/usr/bin/env python3
"""Extract and inject Sceplay text between UTF-8 assembly and translation JSON."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys

from assembler import TOKEN, operands, string_bytes
from opcodelist import DEFAULT_ENCODING, MNEMONICS, script_encoding, write_output


FORMAT = "sceplay-asm-json-v1"
DEFAULT_INJECT_ENCODING = "gbk"
FIELDS = {
    "TEXT": {0: "text"},
    "SET_STRING": {1: "choice"},
    "TEXT_APPEND_TO_STRING": {1: "text"},
    "MESSAGE_BOX": {0: "title", 1: "prompt"},
    "CONFIRM_RESOURCE_PATH": {3: "prompt"},
    # Opcode 3000's three inline strings are reset values for the input fields.
    "SHOW_CHOICES": {5: "input_default", 6: "input_default", 7: "input_default"},
}
RENDERED = {"TEXT", "SET_STRING", "TEXT_APPEND_TO_STRING"}
RENDER_CONTROL = re.compile(r"\\\\(?:[KPRUW]|[GST](?:[0-9]{4}|-[0-9]{3}))", re.IGNORECASE | re.ASCII)
RAW_BYTES = re.compile(r"\{\{[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})*\}\}")
SPEAKER_HEADER = re.compile(
    r"(?P<opening>(?P<marked>//)?＜[ \t　]*)(?P<name>[^＜＞\n]+?)"
    r"(?P<closing>(?P<voice>[ \t　]+[A-Za-z]{2}[0-9]{2}-[0-9]{4})?[ \t　]*＞)"
)
EFFECT_IMAGES = {f'"ef0{number}"' for number in range(4)}
BYTE_LIMITS = {"SET_STRING": 255, "TEXT_APPEND_TO_STRING": 255, "SHOW_CHOICES": 19}


@dataclass(frozen=True)
class Token:
    value: str
    start: int
    end: int
    line: int


def assembly_records(text):
    """Use the assembler's lexer while retaining original operand spans."""
    offset = 1 if text.startswith("\ufeff") else 0
    pending = []
    for line_number, line in enumerate(text[offset:].splitlines(keepends=True), 1):
        cursor = 0
        tokens = []
        while cursor < len(line):
            match = TOKEN.match(line, cursor)
            if match is None:
                raise ValueError(f"line {line_number}: invalid token or unclosed string at column {cursor + 1}")
            value = match[0]
            if value.startswith(";"):
                break
            if not value.isspace():
                tokens.append(Token(value, offset + cursor, offset + match.end(), line_number))
            cursor = match.end()
        offset += len(line)
        if not tokens:
            continue
        if tokens[-1].value == "\\":
            pending.extend(tokens[:-1])
            if not pending:
                raise ValueError(f"line {line_number}: unexpected line continuation")
            continue
        yield pending + tokens
        pending = []
    if pending:
        raise ValueError(f"line {pending[0].line}: dangling line continuation")


def text_parts(token, rendered):
    """Return editable fragments and exact original control clusters."""
    if not token.startswith('"') or not token.endswith('"'):
        raise ValueError("expected a quoted string")
    inner = token[1:-1]
    fragments = [[]]
    controls = []
    pos = 0
    while pos < len(inner):
        control = (RENDER_CONTROL.match(inner, pos) if rendered else None) or RAW_BYTES.match(inner, pos)
        if control is not None:
            if not fragments[-1] and controls:
                controls[-1] += control[0]
            else:
                controls.append(control[0])
                fragments.append([])
            pos = control.end()
            continue
        if inner[pos] == "\\":
            pos += 1
            if pos == len(inner) or inner[pos] not in '\\"{':
                raise ValueError("invalid assembly string escape")
        fragments[-1].append(inner[pos])
        pos += 1
    visible = ["".join(fragment) for fragment in fragments]
    if not any(fragment.strip() for fragment in visible):
        return None
    prefix = controls.pop(0) if not visible[0] else ""
    suffix = controls.pop() if not visible[-1] else ""
    if prefix:
        visible.pop(0)
    if suffix:
        visible.pop()
    return visible, prefix, controls, suffix


def split_speaker(token, fragments, prefix):
    header = SPEAKER_HEADER.match(fragments[0])
    if header is None or not header["name"].strip():
        return None
    body = fragments[0][header.end():]
    if not (header["marked"] or header["voice"] or body.lstrip().startswith(("「", "『"))):
        return None
    if not body.strip() and not any(fragment.strip() for fragment in fragments[1:]):
        return None

    # Span offsets refer to the original escaped operand, including its opening quote.
    body_start = token.index("＞", 1 + len(prefix)) + 1
    name_start = 1 + len(prefix) + len(header["opening"])
    name_end = body_start - len(header["closing"])
    return header["name"], body, {"name_span": [name_start, name_end], "body_start": body_start}


def scan_asm(path, raw, encoding=None, *, include_english_options=False, split_speakers=True):
    text = raw.decode("utf-8")
    declared = DEFAULT_ENCODING
    original = []
    metadata_entries = []
    instruction = 0
    for head, *tail in assembly_records(text):
        if head.value == ".encoding":
            if len(tail) != 1:
                raise ValueError(f"line {head.line}: expected .encoding followed by one codec")
            declared = script_encoding(tail[0].value)
            continue
        if head.value.startswith(".") or head.value.endswith(":"):
            continue
        instruction += 1
        mnemonic = head.value.upper()
        fields = FIELDS.get(mnemonic)
        if fields is None:
            continue
        try:
            # Validate the operand separators using the assembler's own grammar.
            args = [token for token in tail if token.value != ","]
            if len(operands([token.value for token in tail])) != len(MNEMONICS[mnemonic].operands):
                raise ValueError(f"wrong number of operands for {mnemonic}")
            for index, kind in fields.items():
                token = args[index]
                if (mnemonic == "SET_STRING" and path.name.casefold() == "a_bc_disp00.asm.txt"
                        and args[0].value in ("str[0]", "0") and token.value in EFFECT_IMAGES):
                    # This branch reads the slot with LOAD_IMAGE_FROM_STRING.
                    continue
                parts = text_parts(token.value, mnemonic in RENDERED)
                if parts is None:
                    continue
                fragments, prefix, interior, suffix = parts
                speaker = split_speaker(token.value, fragments, prefix) if split_speakers and mnemonic == "TEXT" else None
                if speaker is not None:
                    name, fragments[0], speaker_meta = speaker
                value = "\n".join(fragments)
                if (mnemonic == "SET_STRING" and not include_english_options
                        and value.isascii() and re.search(r"[A-Za-z]", value)):
                    continue
                item_id = f"{instruction:06d}.{index}"
                row = {"id": item_id}
                entry = {
                    "id": item_id, "kind": kind, "opcode": mnemonic, "operand": index,
                    "line": token.line, "span": [token.start, token.end], "original_token": token.value,
                    "prefix": prefix, "interior": interior, "suffix": suffix,
                }
                if speaker is not None:
                    row["name"] = name
                    entry["speaker"] = speaker_meta
                row.update(pre_jp=value, message=value)
                original.append(row)
                metadata_entries.append(entry)
        except ValueError as error:
            raise ValueError(f"line {head.line}: {error}") from error
    meta = {
        "format": FORMAT, "source_file": path.name, "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_size": len(raw), "encoding": script_encoding(encoding) if encoding else declared,
        "entries": metadata_entries,
    }
    return original, meta


def escape_fragment(text):
    if any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F or char in "\u2028\u2029" for char in text):
        raise ValueError("translation contains an unsupported control character")
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("{", "\\{")


def restore_body(message, source, meta):
    message = message.replace("\r\n", "\n").replace("\r", "\n")
    fragments = message.split("\n")
    interior = meta["interior"]
    automatic_positions = False
    if interior and len(fragments) == 1:
        # A single translated line still retains all original controls in order.
        original_lengths = list(map(len, source.split("\n")))
        original_length = sum(original_lengths)
        positions = [0]
        previous = 0
        for length in original_lengths[:-1]:
            previous += length
            positions.append(round(previous * len(message) / original_length))
        positions.append(len(message))
        fragments = [message[a:b] for a, b in zip(positions, positions[1:])]
        automatic_positions = True
    elif interior and len(fragments) != len(interior) + 1:
        raise ValueError(f"use {len(interior)} line breaks for the original interior controls, or use one line")
    elif len(fragments) > 1 and not interior:
        if meta["opcode"] in RENDERED:
            interior = [r"\\r"] * (len(fragments) - 1)
        elif meta["kind"] in ("title", "prompt"):
            interior = ["{{0D:0A}}"] * (len(fragments) - 1)
        else:
            raise ValueError("line breaks are not supported in this string field")
    escaped = [escape_fragment(fragment) for fragment in fragments]
    if meta["opcode"] in RENDERED and any(RENDER_CONTROL.search(part) for part in escaped):
        raise ValueError("use plain translation text and line breaks for the original controls")
    body = escaped[0] + "".join(control + part for control, part in zip(interior, escaped[1:]))
    return body, automatic_positions


def restore_token(message, source, meta, encoding, *, name=None):
    original = meta["original_token"]
    speaker = meta.get("speaker")
    if speaker is not None:
        head = original[:speaker["body_start"]]
        if name is not None:
            if name != name.strip() or "＜" in name or "＞" in name:
                raise ValueError("name cannot have surrounding whitespace or speaker brackets")
            escaped_name = escape_fragment(name)
            if RENDER_CONTROL.search(escaped_name):
                raise ValueError("name cannot contain text control codes")
            start, end = speaker["name_span"]
            head = head[:start] + escaped_name + head[end:]
    else:
        head = '"' + meta["prefix"]

    if message == source and speaker is not None:
        # For a name-only edit, copy the entire original message operand suffix.
        token = head + original[speaker["body_start"]:]
        automatic_positions = False
    else:
        body, automatic_positions = restore_body(message, source, meta)
        token = head + body + meta["suffix"] + '"'
    payload = string_bytes(token, encoding, Counter() if encoding == "gbk" else None)
    limit = BYTE_LIMITS.get(meta["opcode"])
    if limit is not None and len(payload) - 1 > limit:
        raise ValueError(f"{meta['opcode']} string uses {len(payload) - 1} bytes, limit {limit} in {encoding}")
    return token, automatic_positions


def inject_bytes(path, raw, rows, meta, encoding):
    if not isinstance(meta, dict) or meta.get("format") != FORMAT:
        raise ValueError("missing or incompatible Sceplay translation metadata")
    if meta.get("source_file") != path.name or meta.get("source_sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("source file name or SHA-256 differs from the extraction metadata")
    if not isinstance(meta.get("encoding"), str):
        raise ValueError("invalid source encoding in metadata")
    # Accept exports from before speaker splitting or English-option filtering.
    for split_speakers, include_english_options in ((True, False), (False, False), (False, True), (True, True)):
        originals, source_meta = scan_asm(path, raw, meta["encoding"], split_speakers=split_speakers,
                                          include_english_options=include_english_options)
        if source_meta == meta:
            break
    else:
        raise ValueError("metadata positions or original control codes do not match the source assembly")
    if not isinstance(rows, list):
        raise ValueError("translation JSON must contain an array")
    by_id = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ValueError("each translation row must have a string id")
        item_id = row["id"]
        if item_id in by_id:
            raise ValueError(f"duplicate translation id {item_id!r}")
        by_id[item_id] = row
    expected = {row["id"] for row in originals}
    if by_id.keys() != expected:
        missing = sorted(expected - by_id.keys())
        extra = sorted(by_id.keys() - expected)
        raise ValueError(f"translation ids differ from the source, missing={missing[:5]}, extra={extra[:5]}")

    text = raw.decode("utf-8")
    changes = []
    repositioned = []
    for original, item_meta in zip(originals, meta["entries"]):
        item_id = original["id"]
        record = by_id[item_id]
        source = original["pre_jp"]
        if record.get("pre_jp") != source:
            raise ValueError(f"{item_id}: pre_jp differs from the extracted text")
        message = record.get("message")
        if message is None or message == "":
            message = source
        if not isinstance(message, str):
            raise ValueError(f"{item_id}: message must be a string")
        name = None
        if "speaker" in item_meta:
            translated_name = record.get("name")
            if translated_name not in (None, "", original["name"]):
                if not isinstance(translated_name, str):
                    raise ValueError(f"{item_id}: name must be a string")
                name = translated_name
        if message == source and name is None:
            continue
        try:
            replacement, automatic = restore_token(message, source, item_meta, encoding, name=name)
        except (ValueError, LookupError) as error:
            raise ValueError(f"{item_id}, line {item_meta['line']}: {error}") from error
        start, end = item_meta["span"]
        changes.append((start, end, replacement))
        if automatic:
            repositioned.append(item_id)
    chunks = []
    cursor = 0
    for start, end, replacement in changes:
        chunks.extend((text[cursor:start], replacement))
        cursor = end
    chunks.append(text[cursor:])
    return "".join(chunks).encode("utf-8"), len(changes), repositioned


def asm_inputs(source):
    if source.is_file() and source.suffix.lower() == ".txt":
        return [source], None
    if source.is_dir():
        files = sorted(path for path in source.rglob("*") if path.is_file()
                       and (path.name.lower().endswith(".asm.txt") or path.name.lower() == "asm.txt"))
        if files:
            return files, source
    raise ValueError(f"{source}: expected an asm text file or directory containing .asm.txt files")


def relative_output(path, root, suffix):
    relative = path.relative_to(root) if root is not None else Path(path.name)
    stem = path.name[:-8] if path.name.lower().endswith(".asm.txt") else path.stem
    return relative.with_name(stem + suffix)


def output_path(output, relative, root, suffix):
    if root is None and output.name.lower().endswith(suffix) and not output.is_dir():
        return output
    return output / relative


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:
        raise ValueError(f"{path}: {error}") from error


def meta_path(json_path):
    return json_path.with_name(json_path.name + ".meta.json")


def commit_outputs(outputs, input_paths):
    protected = {path.resolve() for path in input_paths}
    seen = set()
    pending = []
    for path, content in outputs:
        location = path.resolve()
        if location in protected or location in seen:
            raise ValueError(f"output collides with an input or another output: {path}")
        seen.add(location)
        if path.exists():
            if not path.is_file() or path.read_bytes() != content:
                raise ValueError(f"output exists with different content: {path}")
        else:
            pending.append((path, content))
    for path, content in pending:
        write_output(path, content)


def extract(source, output, encoding):
    files, root = asm_inputs(source)
    outputs = []
    counts = Counter()
    for path in files:
        try:
            rows, meta = scan_asm(path, path.read_bytes(), encoding)
        except (OSError, ValueError, LookupError) as error:
            raise ValueError(f"{path}: {error}") from error
        destination = output_path(output, relative_output(path, root, ".json"), root, ".json")
        outputs.extend(((destination, json_bytes(rows)), (meta_path(destination), json_bytes(meta))))
        counts.update(entry["kind"] for entry in meta["entries"])
    commit_outputs(outputs, files)
    summary = ", ".join(f"{kind}={count}" for kind, count in sorted(counts.items()))
    print(f"Extracted {sum(counts.values())} entries from {len(files)} file(s)" + (f" ({summary})." if summary else "."))


def inject(source, translations, output, encoding):
    files, root = asm_inputs(source)
    codec = script_encoding(encoding)
    if root is not None and not translations.is_dir():
        raise ValueError("directory input requires a JSON directory")
    outputs = []
    json_paths = []
    notices = []
    total = 0
    for path in files:
        translation_path = (translations / relative_output(path, root, ".json")
                            if translations.is_dir() else translations)
        companion = meta_path(translation_path)
        json_paths.extend((translation_path, companion))
        try:
            payload, changed, repositioned = inject_bytes(path, path.read_bytes(), read_json(translation_path),
                                                         read_json(companion), codec)
        except (OSError, ValueError, LookupError) as error:
            raise ValueError(f"{path}: {error}") from error
        destination = output_path(output, path.relative_to(root) if root else Path(path.name), root, ".txt")
        outputs.append((destination, payload))
        total += changed
        if repositioned:
            notices.append(f"{path}: placed original interior controls proportionally for IDs {', '.join(repositioned)}")
    commit_outputs(outputs, files + json_paths)
    for notice in notices:
        print(notice, file=sys.stderr)
    print(f"Injected {total} edited strings into {len(files)} file(s).")


def verify(source, encoding):
    files, _ = asm_inputs(source)
    count = 0
    for path in files:
        try:
            raw = path.read_bytes()
            rows, meta = scan_asm(path, raw, encoding)
            rebuilt, _, _ = inject_bytes(path, raw, json.loads(json_bytes(rows)), json.loads(json_bytes(meta)),
                                         meta["encoding"])
            if rebuilt != raw:
                raise ValueError("unchanged JSON did not produce byte-identical assembly")
            count += len(rows)
        except (OSError, ValueError, LookupError) as error:
            raise ValueError(f"{path}: {error}") from error
    print(f"Verified byte-identical round trips for {len(files)} assembly file(s), {count} entries.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    extract_command = commands.add_parser("extract", help="extract editable strings and metadata")
    inject_command = commands.add_parser("inject", help="apply translations to a copy of the original assembly")
    verify_command = commands.add_parser("verify", help="check unchanged JSON against the original assembly")
    for command in (extract_command, inject_command, verify_command):
        command.add_argument("--src", type=Path, required=True, help="source assembly file or directory")
    for command in (extract_command, inject_command):
        command.add_argument("-o", "--out", type=Path, required=True)
    for command in (extract_command, verify_command):
        command.add_argument("--encoding", help="source codec for metadata (default: the .encoding directive)")
    inject_command.add_argument("--json", type=Path, required=True, help="translation JSON file or directory")
    inject_command.add_argument("--encoding", default=DEFAULT_INJECT_ENCODING,
                                help="check edits in the target script codec (default: gbk)")
    args = parser.parse_args()
    try:
        if args.command == "extract":
            extract(args.src, args.out, args.encoding)
        elif args.command == "inject":
            inject(args.src, args.json, args.out, args.encoding)
        else:
            verify(args.src, args.encoding)
    except (OSError, ValueError, LookupError) as error:
        parser.exit(1, f"asm_json: {error}\n")


if __name__ == "__main__":
    main()
