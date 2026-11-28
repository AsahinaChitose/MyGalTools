"""Extract HITOMI dialogue to UTF-8 JSON and inject translations into its ASM."""

import argparse
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

import opcodelist as vm
from assembler import assemble, read_assembly


FORMAT = "hitomi.asm_json.v1"
ASM_SUFFIX = ".asm.txt"
SPACE = "　"
COLUMNS = 26
MESSAGE_OPS = {"MESSAGE", "CONDITIONAL_MESSAGE"}
TEXT_HEAD = re.compile(r"^\s*\|\s+TEXT\s+")
NAME_HEAD = re.compile(r"^\s*;\s*NAME(?:\s+|$)")
PLACEHOLDER = re.compile(r"\{\{([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})?)\}\}")


def json_units(text):
    cursor = 0
    units = []
    for match in PLACEHOLDER.finditer(text):
        units.extend(text[cursor:match.start()])
        units.append(bytes.fromhex(match[1].replace(":", "")))
        cursor = match.end()
    units.extend(text[cursor:])
    return units


def visible_text(units):
    return "".join(vm.quote([unit])[1:-1] if isinstance(unit, bytes) else unit for unit in units)


def control_units(units):
    return [unit for unit in units if isinstance(unit, bytes) or unit == "\n"]


def strip_layout(units):
    indent = 0
    while indent < len(units) and units[indent] == SPACE:
        indent += 1
    output, breaks = [], []
    pos = indent
    while pos < len(units):
        if units[pos] != SPACE:
            output.append(units[pos])
            pos += 1
            continue
        end = pos + 1
        while end < len(units) and units[end] == SPACE:
            end += 1
        if end - pos >= 2:
            # An original run of three carries one space in addition to the wrap.
            breaks.append(len(output) + indent)
            pos += 2
        output.extend(units[pos:end])
        pos = end
    return output, indent, breaks


def apply_layout(units, indent):
    output = [SPACE] * indent
    width = indent
    for unit in units:
        if unit == "\n":
            output.append(unit)
            width = 0
            continue
        if width == COLUMNS:
            output.extend((SPACE, SPACE))
            width = 0
        output.append(unit)
        width += 1
    return output


@dataclass(frozen=True)
class Entry:
    id: str
    line: int
    record_line: int
    span: tuple[int, int]
    literal: str
    name: str
    original: str
    indent: int
    breaks: list[int]
    controls: list[str | bytes]

    def row(self):
        result = {"id": self.id}
        if self.name:
            result["name"] = self.name
        result.update(pre_jp=self.original, message=self.original)
        return result

    def metadata(self):
        return {
            "id": self.id,
            "kind": "text",
            "asm_line": self.line,
            "message_line": self.record_line,
            "text_span": list(self.span),
            "name": self.name,
            "original_literal": self.literal,
            "leading_fullwidth_spaces": self.indent,
            "wrap_after_character": self.breaks,
            "controls": [visible_text([unit]) for unit in self.controls],
        }

    def replacement(self, translation, encoding):
        translation = translation.replace("\r\n", "\n").replace("\r", "\n").lstrip(SPACE)
        if not translation:
            return self.literal
        if SPACE * 2 in translation:
            raise vm.FormatError("message 中有连续两个全角空格。请删去手工排版空格，注入时会自动折行")
        units = json_units(translation)
        if control_units(units) != self.controls:
            raise vm.FormatError("原有换行控制或字节占位符发生变化")
        for unit in units:
            if isinstance(unit, str) and unit not in (SPACE, "\n") and not unit.isprintable():
                raise vm.FormatError(f"message 含有控制字符 U+{ord(unit):04X}")
            vm.message_unit(unit, encoding)
        return vm.quote(apply_layout(units, self.indent))


def stem_of(path):
    return path.name[:-len(ASM_SUFFIX)] if path.name.lower().endswith(ASM_SUFFIX) else path.stem


class Source:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        self.text_encoding = "utf-8-sig" if self.data.startswith(b"\xef\xbb\xbf") else "utf-8"
        text = self.data.decode(self.text_encoding)
        self.lines = text.splitlines(keepends=True)
        self.document = read_assembly(text)
        self.entries = self.extract()

    def speaker(self, line_no):
        if line_no < 2:
            return ""
        line = self.lines[line_no - 2]
        match = NAME_HEAD.match(line)
        if not match:
            return ""
        fields = vm.tokenize(line[match.end():])
        if len(fields) != 1:
            raise vm.FormatError(f"第 {line_no - 1} 行的 NAME 应含一个带引号的名字")
        units = vm.unquote(fields[0])
        return visible_text(units).strip(" \t" + SPACE)

    def extract(self):
        entries = []
        script = Path(self.document.script).stem if self.document.script else stem_of(self.path)
        for statement in self.document.statements:
            if statement.tokens[0] not in MESSAGE_OPS:
                continue
            for row in statement.rows:
                fields = row.tokens
                if fields[0] != "TEXT":
                    continue
                if not (len(fields) == 2 or len(fields) == 3 and fields[2].startswith("form=")):
                    raise vm.FormatError(f"第 {row.line} 行的 TEXT 操作数不合法")
                token = fields[1]
                line = self.lines[row.line - 1]
                prefix = TEXT_HEAD.match(line)
                if not prefix or not line.startswith(token, prefix.end()):
                    raise vm.FormatError(f"第 {row.line} 行定位 TEXT 字符串失败")
                start = prefix.end()
                end = start + len(token)
                if len(fields) == 3:
                    rest = line[end:]
                    end += len(rest) - len(rest.lstrip()) + len(fields[2])
                units = vm.unquote(token)
                clean, indent, breaks = strip_layout(units)
                entries.append(Entry(
                    f"{script}.text.{len(entries) + 1:05d}", row.line, statement.line,
                    (start, end), token, self.speaker(row.line), visible_text(clean), indent, breaks,
                    control_units(clean),
                ))
        return entries

    def rows(self):
        return [entry.row() for entry in self.entries]

    def metadata(self):
        return {
            "format": FORMAT,
            "engine": "Ikura GDL / HITOMI",
            "source": {
                "file": self.path.name,
                "script": self.document.script,
                "sha256": sha256(self.data).hexdigest(),
                "size": len(self.data),
                "encoding": self.document.encoding,
            },
            "wrap_columns": COLUMNS,
            "entries": [entry.metadata() for entry in self.entries],
        }

    def check_metadata(self, metadata):
        if not isinstance(metadata, dict) or metadata.get("format") != FORMAT:
            raise vm.FormatError("meta 版本或格式不符")
        baseline = metadata.get("source")
        if not isinstance(baseline, dict) or baseline.get("sha256") != sha256(self.data).hexdigest():
            raise vm.FormatError("源 ASM 的 SHA-256 与 meta 不符，请使用提取时的 ASM")

    def inject(self, rows, encoding):
        if not isinstance(rows, list):
            raise vm.FormatError("翻译 JSON 须为数组")
        by_id = {entry.id: entry for entry in self.entries}
        modified = list(self.lines)
        seen, changed = set(), {}
        for index, row in enumerate(rows, 1):
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise vm.FormatError(f"第 {index} 条记录缺少字符串 id")
            identifier = row["id"]
            if identifier in seen or identifier not in by_id:
                raise vm.FormatError(f"重复或未知的 id {identifier!r}")
            seen.add(identifier)
            entry = by_id[identifier]
            if row.get("pre_jp") != entry.original:
                raise vm.FormatError(f"{identifier}: pre_jp 与源 ASM 不符")
            translation = row.get("message")
            if translation is not None and not isinstance(translation, str):
                raise vm.FormatError(f"{identifier}: message 须为字符串")
            if not translation or translation == entry.original:
                continue
            try:
                literal = entry.replacement(translation, encoding)
            except vm.FormatError as error:
                raise vm.FormatError(f"{identifier}（ASM 第 {entry.line} 行）: {error}") from None
            if literal == entry.literal:
                continue
            start, end = entry.span
            source_line = self.lines[entry.line - 1]
            modified[entry.line - 1] = source_line[:start] + literal + source_line[end:]
            changed[entry.line] = identifier
            changed[entry.record_line] = identifier
        if not changed:
            return self.data, 0
        text = "".join(modified)
        try:
            assemble(text, encoding)
        except vm.FormatError as error:
            context = re.match(r"line (\d+):", str(error))
            if context and int(context[1]) in changed:
                raise vm.FormatError(f"{changed[int(context[1])]}: {error}") from None
            raise
        count = sum(old != new for old, new in zip(self.lines, modified))
        return text.encode(self.text_encoding), count


def asm_files(path):
    if path.is_file():
        return [(path, Path(path.name))]
    if path.is_dir():
        files = [(member, member.relative_to(path)) for member in sorted(path.rglob("*"))
                 if member.is_file() and (member.name.lower() == "asm.txt"
                                           or member.name.lower().endswith(ASM_SUFFIX))]
        if files:
            return files
    raise vm.FormatError(f"找不到 ASM 文件 {path}")


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def meta_path(path):
    return path.with_name(path.name + ".meta.json")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:
        raise vm.FormatError(f"{path}: {error}") from None


def run(args):
    inputs = asm_files(args.src)
    injecting = args.command == "inject"
    if injecting:
        json_dir = args.json.is_dir()
        if not json_dir and len(inputs) != 1:
            raise vm.FormatError("多文件注入时 --json 须指定目录")
        if not json_dir and not args.json.is_file():
            raise vm.FormatError(f"找不到翻译 JSON {args.json}")
        encoding = vm.encoding_name(args.encoding)
    stats = Counter()
    source_paths = {path.resolve() for path, _ in inputs}
    pending = []
    for path, relative in inputs:
        try:
            source = Source(path)
            stats["脚本"] += 1
            stats["正文"] += len(source.entries)
            stats["带名牌"] += sum(bool(entry.name) for entry in source.entries)
            stats["带句首缩进"] += sum(bool(entry.indent) for entry in source.entries)
            stats["原排版换行组"] += sum(len(entry.breaks) for entry in source.entries)
            stats["含显式控制"] += sum(bool(entry.controls) for entry in source.entries)
            relative_json = relative.with_name(stem_of(relative) + ".json")
            if args.command == "extract":
                target = args.out / relative_json
                pending.extend(((target, json_bytes(source.rows())),
                                (meta_path(target), json_bytes(source.metadata()))))
            elif args.command == "verify":
                rows = json.loads(json_bytes(source.rows()))
                if source.inject(rows, source.document.encoding)[0] != source.data:
                    raise vm.FormatError("ASM → JSON → ASM 未逐字节还原")
            elif injecting:
                json_path = args.json / relative_json if json_dir else args.json
                data = source.data
                if json_path.exists():
                    stats["匹配 JSON"] += 1
                    sidecar = meta_path(json_path)
                    if sidecar.exists():
                        source.check_metadata(load_json(sidecar))
                    else:
                        stats["仅核对 id 和 pre_jp（无 meta）"] += 1
                    data, count = source.inject(load_json(json_path), encoding)
                    stats["注入正文"] += count
                pending.append((args.out / relative, data))
        except (OSError, ValueError) as error:
            raise vm.FormatError(f"{path}: {error}") from None
    if injecting and not stats["匹配 JSON"]:
        raise vm.FormatError("找不到与源 ASM 对应的翻译 JSON")
    output_paths = set()
    for target, _ in pending:
        resolved = target.resolve()
        if resolved in source_paths or resolved in output_paths:
            raise vm.FormatError(f"输出覆盖源文件或与另一输出重名: {target}")
        output_paths.add(resolved)
    for target, data in pending:
        vm.write_atomic(target, data)
    print("，".join(f"{key} {value}" for key, value in stats.items()))
    if args.command == "verify":
        print("ASM → JSON → ASM 逐字节一致。")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command, description in (
        ("extract", "提取 UTF-8 翻译 JSON 及元数据"), ("inject", "把译文回注到独立的 ASM 目录"),
        ("verify", "验证未改译文时的逐字节往返"), ("report", "统计正文和原排版"),
    ):
        sub = commands.add_parser(command, help=description)
        sub.add_argument("--src", type=Path, required=True, help="源 ASM 文件或目录")
        if command in ("extract", "inject"):
            sub.add_argument("--out", type=Path, required=True, help="输出目录")
        if command == "inject":
            sub.add_argument("--json", type=Path, required=True, help="翻译 JSON 文件或目录")
            sub.add_argument("--encoding", default="gbk", help="目标汇编编码，默认 gbk")
    try:
        run(parser.parse_args(argv))
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
