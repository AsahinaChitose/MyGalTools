#!/usr/bin/env python3
"""Extract RAPNTWN TEXT/CHOICE to UTF-8 JSON or inject it into source ASM."""

from __future__ import annotations

import argparse
from codecs import BOM_UTF8
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

from assembler import PLACEHOLDER, SYMBOL, TOKEN, line_tokens, operands, unquote
from disassembler import ScriptError, script_codec


ASM_SUFFIX = ".asm.txt"
LEFT, RIGHT = "\u3010", "\u3011"
SPEAKER = re.compile(r"^\u3010([^\u3010\u3011]+)\u3011(?=.)")
NARRATION_TAGS = frozenset({
    "\u6deb\u6e26\u7206\u4e73\u5d29",
    "\u7d4c\u7d61\u6deb\u6e26\uff08\u3051\u3044\u3089\u304f\u3044\u3093\u304c\uff09",
    "\u6deb\u6e26\u7363\u5fc3\u7fd4",
})
ASM_SPECIAL = re.compile(r"\\.|" + PLACEHOLDER.pattern)
JSON_SPECIAL = re.compile(r"\\\\|\\\{\{|" + PLACEHOLDER.pattern)
ASM_ESCAPE = re.compile(r'[\\"{}]')


def json_literal(token: str) -> str:
    """Decode ASM escapes, distinguishing literal '{{' and backslashes from byte atoms."""
    def plain(parts: list[str]) -> str:
        return "".join(parts).replace("\\", "\\\\").replace("{{", r"\{{")

    body = token[1:-1]
    literal, output = [], []
    end = 0
    for match in ASM_SPECIAL.finditer(body):
        literal.append(body[end:match.start()])
        if match[0].startswith("\\"):
            literal.append(match[0][1:])
        else:
            output.extend((plain(literal), match[0]))
            literal.clear()
        end = match.end()
    literal.append(body[end:])
    output.append(plain(literal))
    return "".join(output)


def asm_literal(text: str) -> str:
    def plain(part: str) -> str:
        return ASM_ESCAPE.sub(lambda match: "\\" + match[0], part)

    output = ['"']
    end = 0
    for match in JSON_SPECIAL.finditer(text):
        output.append(plain(text[end:match.start()]))
        output.append(match[0] if match[1] else plain(match[0][1:]))
        end = match.end()
    output.extend((plain(text[end:]), '"'))
    return "".join(output)


def controls(text: str) -> list[str]:
    return [match[0].upper() for match in JSON_SPECIAL.finditer(text) if match[1]]


def wrapped_choice(text: str) -> bool:
    if not text.startswith(LEFT):
        return False
    depth = 0
    for pos, char in enumerate(text):
        if char == LEFT:
            depth += 1
        elif char == RIGHT:
            depth -= 1
            if depth == 0:
                return pos == len(text) - 1
    return False


@dataclass(frozen=True)
class Entry:
    id: str
    line: int
    start: int
    end: int
    byte_offset: int
    opcode: str
    target: str | None
    literal: str
    name: str | None
    message: str
    bracketed: bool

    def record(self) -> dict:
        row = {"id": self.id}
        if self.name is not None:
            row["name"] = self.name
        row.update(pre_jp=self.message, message=self.message)
        return row

    def metadata(self, codec: str) -> dict:
        try:
            payload = unquote(self.literal, codec).hex()
        except ScriptError:
            # Translated UTF-8 ASM can contain characters outside its declared codec.
            payload = None
        return {
            "id": self.id, "line": self.line, "asm_byte_offset": self.byte_offset,
            "opcode": self.opcode, "target": self.target, "name": self.name,
            "bracketed_choice": self.bracketed, "original_literal": self.literal,
            "payload_hex": payload, "control_codes": controls(json_literal(self.literal)),
            "terminator_hex": "00",
        }


@dataclass(frozen=True)
class Source:
    data: bytes
    text: str
    bom: bytes
    codec: str
    entries: list[Entry]

    def metadata(self) -> dict:
        return {
            "version": 1, "format": "RAPNTWN_ADB_V1", "layout": "inline",
            "asm_encoding": "utf-8-sig" if self.bom else "utf-8",
            "script_encoding": self.codec, "source_sha256": sha256(self.data).hexdigest(),
            "source_size": len(self.data), "entries": [entry.metadata(self.codec) for entry in self.entries],
        }


def parse_asm(data: bytes, script: str) -> Source:
    bom = BOM_UTF8 if data.startswith(BOM_UTF8) else b""
    text = data[len(bom):].decode("utf-8")
    offset, byte_offset = 0, len(bom)
    codec = "cp932"
    entries = []
    for number, line in enumerate(text.split("\n"), 1):
        head = TOKEN.match(line)
        opcode = head[1] if head else ""
        try:
            if opcode in {".encoding", ".script"}:
                tokens = line_tokens(line)
                if len(tokens) != 2:
                    raise ScriptError(f"invalid {opcode} directive")
                if opcode == ".encoding":
                    codec = script_codec(tokens[1])
                else:
                    script = tokens[1]
            elif opcode in {"TEXT", "CHOICE"}:
                args = operands(line_tokens(line)[1:])
                if len(args) != (1 if opcode == "TEXT" else 2):
                    raise ScriptError(f"incorrect operand count for {opcode}")
                target = args[0] if opcode == "CHOICE" else None
                if target is not None and (not SYMBOL.fullmatch(target) or target == "NONE"):
                    raise ScriptError("CHOICE needs a symbolic jump target")
                token = args[-1]
                unquote(token, "utf-8")  # Check syntax without limiting the UTF-8 editing view.
                col = line.index(token, head.end())
                message = json_literal(token)
                match = SPEAKER.match(message) if opcode == "TEXT" else None
                name = None
                bracketed = opcode == "CHOICE" and wrapped_choice(message)
                if match and match[1] not in NARRATION_TAGS:
                    name = match[1]
                    message = message[match.end():]
                elif bracketed:
                    message = message[1:-1]
                entries.append(Entry(
                    f"{script}#{len(entries) + 1:05d}", number, offset + col, offset + col + len(token),
                    byte_offset + len(line[:col].encode("utf-8")), opcode, target, token, name, message, bracketed,
                ))
        except (ValueError, LookupError) as exc:
            raise ScriptError(f"ASM line {number}: {exc}") from exc
        offset += len(line) + 1
        byte_offset += len(line.encode("utf-8")) + 1
    return Source(data, text, bom, codec, entries)


def inject(source: Source, rows: object, metadata: object, codec: str) -> tuple[bytes, int]:
    if not isinstance(metadata, dict) or metadata.get("source_sha256") != sha256(source.data).hexdigest():
        raise ScriptError("source SHA-256 mismatch; use the original ASM or extract again")
    if metadata != source.metadata():
        raise ScriptError("metadata does not match the source ASM; extract again")
    if not isinstance(rows, list):
        raise ScriptError("expected a JSON array of translation entries")

    expected = {entry.id for entry in source.entries}
    by_id = {}
    for pos, row in enumerate(rows, 1):
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ScriptError(f"JSON entry {pos}: expected an object with a string id")
        key = row["id"]
        if key in by_id:
            raise ScriptError(f"duplicate id: {key}")
        if key not in expected:
            raise ScriptError(f"unexpected id: {key}")
        by_id[key] = row

    output = []
    end = changed = 0
    for entry in source.entries:
        where = f"{entry.id} (ASM line {entry.line})"
        if entry.id not in by_id:
            raise ScriptError(f"missing id: {where}")
        row = by_id[entry.id]
        if row.get("pre_jp") != entry.message:
            raise ScriptError(f"{where}: pre_jp must match the source")
        message = row.get("message", "")
        if not isinstance(message, str):
            raise ScriptError(f"{where}: message must be a string")
        message = message or entry.message
        name = row.get("name", entry.name)
        if "name" in row and (entry.name is None or not isinstance(name, str) or not name
                              or LEFT in name or RIGHT in name):
            raise ScriptError(f"{where}: name must be nonempty and unbracketed, on a named TEXT only")
        if (name, message) == (entry.name, entry.message):
            continue
        if controls(message) != controls(entry.message) or controls(name or "") != controls(entry.name or ""):
            raise ScriptError(f"{where}: retain the original byte placeholders and their order")

        body = message
        if name is not None:
            body = f"{LEFT}{name}{RIGHT}{message}"
        elif entry.bracketed:
            body = f"{LEFT}{message}{RIGHT}"
        replacement = asm_literal(body)
        try:
            unquote(replacement, codec)
        except ScriptError as exc:
            raise ScriptError(f"{where}: {exc}") from exc
        output.extend((source.text[end:entry.start], replacement))
        end = entry.end
        changed += 1
    if not changed:
        return source.data, 0
    output.append(source.text[end:])
    return source.bom + "".join(output).encode("utf-8"), changed


def asm_base(path: Path) -> str:
    return path.name[:-len(ASM_SUFFIX)] if path.name.lower().endswith(ASM_SUFFIX) else path.stem


def meta_path(path: Path) -> Path:
    return path.with_name(path.name + ".meta.json")


def read_json(path: Path) -> object:
    def unique_keys(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ScriptError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_keys)
    except ValueError as exc:
        raise ScriptError(f"{path}: {exc}") from exc


def dump_json(data: object) -> bytes:
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def run(args: argparse.Namespace) -> None:
    batch = args.src.is_dir()
    extracting = args.command == "extract"
    if batch:
        inputs = sorted(p for p in args.src.rglob("*") if p.is_file() and
                        (p.name.lower().endswith(ASM_SUFFIX) or p.name.lower() == "asm.txt"))
        if not inputs:
            raise ScriptError(f"no {ASM_SUFFIX} files in {args.src}")
    elif args.src.is_file() and args.src.suffix.lower() == ".txt":
        inputs = [args.src]
    else:
        raise ScriptError(f"expected an ASM file or directory: {args.src}")

    suffix = ".json" if extracting else ".txt"
    single_output = not batch and not args.out.is_dir() and args.out.suffix.lower() == suffix
    if not single_output and args.out.exists() and not args.out.is_dir():
        raise ScriptError(f"expected an output directory: {args.out}")
    if not extracting:
        codec = script_codec(args.encoding)
        if batch and not args.json.is_dir():
            raise ScriptError(f"directory mode requires a JSON directory: {args.json}")

    outputs = []
    seen = set()
    total = changed = 0
    for path in inputs:
        rel = path.relative_to(args.src) if batch else Path(path.name)
        json_rel = rel.with_name(asm_base(path) + ".json")
        dest = args.out if single_output else args.out / (json_rel if extracting else rel)
        for target in (dest, meta_path(dest)) if extracting else (dest,):
            key = str(target.resolve()).casefold()
            if target.exists() or key in seen:
                raise ScriptError(f"output already exists or is duplicated: {target}")
            seen.add(key)

        try:
            source = parse_asm(path.read_bytes(), asm_base(path))
            if extracting:
                outputs.append((dest, dump_json([entry.record() for entry in source.entries])))
                outputs.append((meta_path(dest), dump_json(source.metadata())))
            else:
                json_path = args.json / json_rel if args.json.is_dir() else args.json
                patched, count = inject(source, read_json(json_path), read_json(meta_path(json_path)), codec)
                outputs.append((dest, patched))
                changed += count
            total += len(source.entries)
        except (ValueError, LookupError, OSError) as exc:
            raise ScriptError(f"{path}: {exc}") from exc

    for target, content in outputs:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(content)
    result = f"{len(inputs)} file(s), {total} text entries"
    if not extracting:
        result += f", {changed} changed"
    print(f"{result} -> {args.out}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    extract_parser = sub.add_parser("extract", help="ASM -> translation JSON and metadata")
    inject_parser = sub.add_parser("inject", help="source ASM + translation JSON -> edited ASM")
    for command in (extract_parser, inject_parser):
        command.add_argument("--src", type=Path, required=True, help="source ASM file or directory")
        command.add_argument("--out", type=Path, required=True, help="new output file or directory")
    inject_parser.add_argument("--json", type=Path, required=True, help="translation JSON file or directory")
    inject_parser.add_argument("--encoding", default="gbk", help="check edited strings for this ADB codec (default: gbk)")
    try:
        run(parser.parse_args())
    except (ScriptError, LookupError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
