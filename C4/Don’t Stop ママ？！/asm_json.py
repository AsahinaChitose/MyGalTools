#!/usr/bin/env python3
"""Extract C4 Mp17 ASM into translation JSON or inject it back into UTF-8 ASM.

  python asm_json.py extract --src mpx_asm --out mpx_json
  python asm_json.py inject --src mpx_asm --json mpx_json --out mpx_asm_cn
  python assembler.py mpx_asm_cn -o mpx_gbk --encoding gbk

Keep each .json.meta.json beside its translation JSON. Edit only name and
message. Empty message or omitted name uses the original. Output paths must
be new. Injection validates the rebuilt MPX with --encoding (default: gbk).
"""

from __future__ import annotations

import argparse
from codecs import BOM_UTF8
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

from assembler import assemble, canonical, parse_assembly, resolve_text
from opcodelist import (
    GRAPHIC_VARIANTS, OPCODES_BY_NAME, PLACEHOLDER, TEXT_CONTROLS,
    FormatError, asm_tokens, codec_name, encode_text, text_tokens,
)


ASM_SUFFIX = ".asm.txt"
CHOICES = {"OFFER_CHOICE", "OFFER_CHOICE_ALT"}
SPEAKER = re.compile(r"^【([^【】]+)】")
ATOM = re.compile(r"\\.|" + PLACEHOLDER.pattern + r"|.")
ARG_COMMANDS = "".join(letter for letter, (_, style) in TEXT_CONTROLS.items() if style == "args")
FLAG_COMMANDS = "".join(letter for letter, (_, style) in TEXT_CONTROLS.items() if style == "none")
GRAPHIC_CODES = "".join(variant for variant in GRAPHIC_VARIANTS if variant != ",")
CONTROL = re.compile(
    rf"%[{ARG_COMMANDS}],[^;\x00\n]*;|%g[{GRAPHIC_CODES}]?,[^;\x00\n]*;"
    rf"|%[{FLAG_COMMANDS}]|[\n\x00_]",
    re.ASCII | re.IGNORECASE,
)
CHOICE_CONTROL = re.compile(r"[\n\x00]")


@dataclass(frozen=True)
class Span:
    start: int
    end: int


@dataclass(frozen=True)
class Fragment:
    line: int
    start: int
    literal: str

    @property
    def body(self) -> str:
        return self.literal[1:-1]

    @property
    def span(self) -> Span:
        return Span(self.start, self.start + len(self.body))


@dataclass(frozen=True)
class Entry:
    name: str | None
    message: str
    spans: tuple[Span, ...]
    indent: str
    after_name: str

    def record(self, key: str) -> dict:
        row = {"id": key}
        if self.name is not None:
            row["name"] = self.name
        return dict(row, pre_jp=self.message, message=self.message)

    def replacement(self, name: str | None, message: str) -> str:
        body = self.indent
        if name is not None:
            body += f"【{name}】{self.after_name}"
        return escape_asm(body + message)


@dataclass(frozen=True)
class TextRun:
    fragments: tuple[Fragment, ...]
    entries: tuple[Entry, ...]
    controls: tuple[dict, ...]


@dataclass(frozen=True)
class PoolText:
    ident: str
    kind: str
    primary: TextRun
    equivalent: tuple[TextRun, ...]
    stale: tuple[tuple[Fragment, ...], ...]
    payload_hex: str | None

    def keyed_entries(self, script: str):
        for index, entry in enumerate(self.primary.entries, 1):
            yield f"{script}#{self.ident[1:]}:{index:03d}", entry


@dataclass(frozen=True)
class Source:
    data: bytes
    text: str
    bom: bytes
    script: str
    codec: str
    records: tuple[PoolText, ...]

    def rows(self) -> list[dict]:
        return [entry.record(key) for record in self.records
                for key, entry in record.keyed_entries(self.script)]

    def metadata(self) -> dict:
        records = []
        for record in self.records:
            if not record.primary.entries:
                continue
            entries = []
            for key, entry in record.keyed_entries(self.script):
                entries.append({
                    "id": key, "name": entry.name, "leading_indent": entry.indent,
                    "indent_after_name": entry.after_name,
                    "character_spans": [[span.start, span.end] for span in entry.spans],
                })
            records.append({
                "pool_id": record.ident, "kind": record.kind,
                "references": [run.fragments[0].line for run in record.equivalent + (record.primary,)]
                + [fragments[0].line for fragments in record.stale],
                "fragments": [{"line": fragment.line, "literal": fragment.literal}
                              for fragment in record.primary.fragments],
                "payload_hex": record.payload_hex, "terminator_hex": "00",
                "controls": list(record.primary.controls), "entries": entries,
            })
        return {
            "version": 1, "format": "C4_Mp17", "layout": "shared_text_pool",
            "source_sha256": sha256(self.data).hexdigest(), "source_size": len(self.data),
            "asm_encoding": "utf-8-sig" if self.bom else "utf-8",
            "script_encoding": self.codec, "records": records,
        }


def escape_asm(text: str) -> str:
    return re.sub(r'[\\"{]', lambda match: "\\" + match[0], text)


def find_fragments(text: str, first_lines: set[int]) -> dict[int, list[Fragment]]:
    fragments = {}
    current = None
    offset = 0
    for line_number, line in enumerate(text.split("\n"), 1):
        fields = asm_tokens(line)
        if line_number in first_lines:
            current = []
            fragments[line_number] = current
        elif fields and fields[0] != "|":
            current = None
        if current is not None and fields:
            literal = fields[-1]
            current.append(Fragment(line_number, offset + line.index('"') + 1, literal))
        offset += len(line) + 1
    return fragments


def span_groups(spans: list[Span]) -> tuple[Span, ...]:
    groups = []
    for span in spans:
        if groups and groups[-1].end == span.start:
            groups[-1] = Span(groups[-1].start, span.end)
        else:
            groups.append(span)
    return tuple(groups)


def read_entry(visible: str, spans: list[Span], kind: str) -> Entry | None:
    body = visible.lstrip("　")
    indent = visible[:len(visible) - len(body)]
    if not body.strip():
        return None
    name = None
    after_name = ""
    if kind == "text" and (speaker := SPEAKER.match(body)):
        name = speaker[1]
        tail = body[speaker.end():]
        body = tail.lstrip("　")
        after_name = tail[:len(tail) - len(body)]
    return Entry(name, body, span_groups(spans), indent, after_name)


def read_run(fragments: list[Fragment], kind: str) -> TextRun:
    # Map each decoded character back to its original quoted ASM span. The
    # placeholders and the escaped newline use sentinels unavailable to prose.
    units, spans, raw = [], [], []
    for fragment in fragments:
        for match in ATOM.finditer(fragment.body):
            atom = match[0]
            if atom.startswith("{{"):
                value = "\0"
            elif atom == r"\n":
                value = "\n"
            else:
                value = atom[-1] if atom.startswith("\\") else atom
            units.append(value)
            raw.append(atom)
            spans.append(Span(fragment.start + match.start(), fragment.start + match.end()))
    stream = "".join(units)
    entries, controls = [], []
    pattern = CHOICE_CONTROL if kind == "choice" else CONTROL
    start = 0
    for match in pattern.finditer(stream):
        if entry := read_entry(stream[start:match.start()], spans[start:match.start()], kind):
            entries.append(entry)
        controls.append({"offset": match.start(), "asm": "".join(raw[match.start():match.end()])})
        start = match.end()
    if entry := read_entry(stream[start:], spans[start:], kind):
        entries.append(entry)
    if kind != "choice" and any("%" in entry.message or "%" in (entry.name or "")
                                for entry in entries):
        raise FormatError(f"line {fragments[0].line}: unrecognized or incomplete C4 % command")
    return TextRun(tuple(fragments), tuple(entries), tuple(controls))


def parse_source(data: bytes, script: str) -> Source:
    bom = BOM_UTF8 if data.startswith(BOM_UTF8) else b""
    text = data[len(bom):].decode("utf-8")
    listing = parse_assembly(text)
    source_codec = codec_name(listing.header.get(".encoding", "cp932"))
    first_lines = {use.line for uses in listing.text_uses.values() for use in uses}
    fragments = find_fragments(text, first_lines)
    choices = {operand for op in listing.code if op.name in CHOICES
               for field, operand in zip(OPCODES_BY_NAME[op.name][1].operands, op.operands)
               if field == "text"}
    dialogue = {operand for op in listing.code if op.name not in CHOICES
                for field, operand in zip(OPCODES_BY_NAME[op.name][1].operands, op.operands)
                if field == "text"}
    records = []
    for ident, uses in listing.text_uses.items():
        if ident not in listing.text_order:
            raise FormatError(f"line {uses[0].line}: undefined pool ID {ident}")
        payload, primary_line = resolve_text(ident, uses, listing.text_order[ident], source_codec)
        if payload and ident in choices and ident in dialogue:
            raise FormatError(f"{ident}: nonempty text is shared by a choice and dialogue")
        kind = "choice" if ident in choices else "text"
        primary = read_run(fragments[primary_line], kind)
        equivalents, stale = [], []
        for use in uses:
            if use.line == primary_line:
                continue
            if canonical(use.chunks) == payload:
                other = read_run(fragments[use.line], kind)
                if [e.record("") for e in other.entries] != [e.record("") for e in primary.entries]:
                    raise FormatError(f"{ident}: inconsistent text fragments on line {use.line}")
                equivalents.append(other)
            else:
                stale.append(tuple(fragments[use.line]))
        try:
            payload_hex = encode_text(payload, source_codec).hex()
        except UnicodeEncodeError:
            payload_hex = None  # A translated UTF-8 ASM can still declare CP932.
        records.append(PoolText(ident, kind, primary, tuple(equivalents), tuple(stale), payload_hex))
    missing = listing.text_order.keys() - listing.text_uses.keys()
    if missing:
        raise FormatError("missing text for pool IDs: " + ", ".join(sorted(missing)))
    return Source(data, text, bom, script, source_codec, tuple(records))


def read_json(path: Path):
    def unique_keys(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise FormatError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_bytes().decode("utf-8-sig"), object_pairs_hook=unique_keys)
    except (FormatError, ValueError) as error:
        raise FormatError(f"{path}: {error}") from error


def index_rows(source: Source, rows: object) -> dict:
    if not isinstance(rows, list):
        raise FormatError("expected an array of translation entries")
    expected = {row["id"] for row in source.rows()}
    indexed = {}
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise FormatError(f"JSON entry {number}: expected an object with a string id")
        key = row["id"]
        if key in indexed:
            raise FormatError(f"duplicate id: {key}")
        if key not in expected:
            raise FormatError(f"unknown id: {key}")
        indexed[key] = row
    missing = expected - indexed.keys()
    if missing:
        raise FormatError(f"missing id: {min(missing)} ({len(missing)} missing in total)")
    return indexed


def entry_edit(key: str, entry: Entry, row: dict, kind: str,
               encoding: str) -> tuple[str | None, str] | None:
    if row.get("pre_jp") != entry.message:
        raise FormatError(f"{key}: pre_jp must match the source")
    message = row.get("message", "")
    if not isinstance(message, str):
        raise FormatError(f"{key}: message must be a string")
    message = message or entry.message
    name = row.get("name", entry.name)
    if "name" in row and (entry.name is None or not isinstance(name, str)
                          or not name.strip() or "【" in name or "】" in name):
        raise FormatError(f"{key}: name must be nonempty, unbracketed, and on a named entry")
    if (name, message) == (entry.name, entry.message):
        return None
    if kind != "choice" and any(char in (name or "") + message for char in "%_"):
        raise FormatError(f"{key}: ASCII % and _ are C4 commands; use full-width ％ or ＿ in prose")
    if message != entry.message:
        if message.startswith("\u3000"):
            raise FormatError(f"{key}: leading full-width spaces are restored from the ASM")
        if name is None and not message.strip():
            raise FormatError(f"{key}: message must contain visible text")
        if kind == "text" and name is None and SPEAKER.match(message):
            raise FormatError(f"{key}: leading speaker markup is reserved for named entries")
    try:
        chunks = text_tokens('"' + entry.replacement(name, message) + '"')
        encode_text(chunks, encoding, Counter() if encoding == "gbk" else None)
    except (FormatError, UnicodeEncodeError) as error:
        raise FormatError(f"{key}: {error}") from error
    return name, message


def run_edits(run: TextRun, edits: dict[int, tuple[str | None, str]]) -> dict[Span, str]:
    replacements = {}
    for index, (name, message) in edits.items():
        entry = run.entries[index]
        replacements[entry.spans[0]] = entry.replacement(name, message)
        replacements.update((span, "") for span in entry.spans[1:])
    return replacements


def splice(text: str, replacements: dict[Span, str], offset: int = 0) -> str:
    parts = []
    end = 0
    for span in sorted(replacements, key=lambda s: s.start):
        start = span.start - offset
        if start < end:
            raise FormatError("overlapping ASM text edits")
        parts.extend((text[end:start], replacements[span]))
        end = span.end - offset
    parts.append(text[end:])
    return "".join(parts)


def inject(source: Source, rows: object, metadata: object, encoding: str) -> tuple[bytes, int]:
    if not isinstance(metadata, dict) or metadata.get("source_sha256") != sha256(source.data).hexdigest():
        raise FormatError("source SHA-256 mismatch; use the matching ASM or extract again")
    if metadata != source.metadata():
        raise FormatError("metadata does not match the source ASM; extract again")
    indexed = index_rows(source, rows)
    replacements, changed = {}, 0
    for record in source.records:
        edits = {}
        for index, (key, entry) in enumerate(record.keyed_entries(source.script)):
            if edit := entry_edit(key, entry, indexed[key], record.kind, encoding):
                edits[index] = edit
        if not edits:
            continue
        changed += len(edits)
        primary_edits = run_edits(record.primary, edits)
        replacements.update(primary_edits)
        for run in record.equivalent:
            replacements.update(run_edits(run, edits))
        if record.stale:
            # An older inline reference may still match the pool's baseline. Copy
            # the edited canonical stream into it so every reference agrees.
            canonical_body = "".join(
                splice(fragment.body, {span: value for span, value in primary_edits.items()
                                       if fragment.start <= span.start < fragment.span.end}, fragment.start)
                for fragment in record.primary.fragments
            )
            for first, *continuations in record.stale:
                replacements[first.span] = canonical_body
                replacements.update((fragment.span, "") for fragment in continuations)
    result = splice(source.text, replacements) if replacements else source.text
    assemble(parse_assembly(result), encoding)
    return (source.bom + result.encode("utf-8") if replacements else source.data), changed


def asm_base(path: Path) -> str:
    return path.name[:-len(ASM_SUFFIX)] if path.name.lower().endswith(ASM_SUFFIX) else path.stem


def meta_path(path: Path) -> Path:
    return path.with_name(path.name + ".meta.json")


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def pending_output(outputs: dict[Path, bytes], path: Path, data: bytes) -> None:
    path = path.resolve()
    if path.exists() or path in outputs:
        raise FormatError(f"output already exists or occurs twice: {path}")
    outputs[path] = data


def run(args: argparse.Namespace) -> None:
    batch = args.src.is_dir()
    if batch:
        paths = sorted(p for p in args.src.rglob("*") if p.is_file() and p.name.lower().endswith(ASM_SUFFIX))
    else:
        paths = [args.src] if args.src.is_file() else []
    if not paths:
        raise FormatError(f"{args.src}: no {ASM_SUFFIX} inputs")
    extracting = args.command == "extract"
    if batch and args.out.exists() and not args.out.is_dir():
        raise FormatError("batch output must be a directory")
    if batch and not extracting and not args.json.is_dir():
        raise FormatError("batch injection requires a JSON directory")
    encoding = None if extracting else codec_name(args.encoding)
    outputs = {}
    total = changed = 0
    for path in paths:
        relative = path.relative_to(args.src) if batch else Path(path.name)
        json_relative = relative.with_name(asm_base(path) + ".json")
        try:
            script = json_relative.with_suffix("").as_posix()
            source = parse_source(path.read_bytes(), script)
            total += sum(len(record.primary.entries) for record in source.records)
            if extracting:
                target = args.out / json_relative if batch or args.out.is_dir() else args.out
                pending_output(outputs, target, json_bytes(source.rows()))
                pending_output(outputs, meta_path(target), json_bytes(source.metadata()))
            else:
                json_path = args.json / json_relative if args.json.is_dir() else args.json
                data, count = inject(source, read_json(json_path), read_json(meta_path(json_path)), encoding)
                target = args.out / relative if batch or args.out.is_dir() else args.out
                pending_output(outputs, target, data)
                changed += count
        except (FormatError, UnicodeError, OSError) as error:
            raise FormatError(f"{path}: {error}") from error
    for path, data in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    summary = f"{len(paths)} file(s), {total} text entries"
    if not extracting:
        summary += f", {changed} changed"
    print(f"{summary} -> {args.out}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    extract = commands.add_parser("extract", help="ASM -> translation JSON and metadata")
    inject_parser = commands.add_parser("inject", help="source ASM + translation JSON -> edited ASM")
    for command in (extract, inject_parser):
        command.add_argument("--src", type=Path, required=True, help="source ASM file or directory")
        command.add_argument("--out", type=Path, required=True, help="new output file or directory")
    inject_parser.add_argument("--json", type=Path, required=True, help="translation JSON file or directory")
    inject_parser.add_argument("--encoding", default="gbk", help="target MPX encoding for validation (default: gbk)")
    try:
        run(parser.parse_args(argv))
    except (FormatError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
