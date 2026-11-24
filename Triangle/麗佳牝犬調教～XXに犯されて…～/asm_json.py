"""Convert RSA UTF-8 assembly listings to and from GalTransl JSON."""

import argparse
from collections import Counter
from dataclasses import dataclass
from itertools import combinations
import json
from pathlib import Path
import re
import sys
import unicodedata

from assembler import TOKEN, tokenize
from disassembler import NAME_INDEX
from opcodelist import (
    CODE_FORMAT, DEFAULT_ENCODING, ESCAPES, MHU_FORMAT, PLACEHOLDER, FormatError,
    codec_name, number, segment_kind, unquote_bytes, unquote_lines, write_output,
)


ASM_SUFFIX = ".asm.txt"
MAX_COLUMNS = 50  # 25 full-width characters
MAX_LINES = 3
INDENT = "\u3000"
LITERAL_ITEM = re.compile(r"\\.|" + PLACEHOLDER.pattern)


def decode_literal(token, *, multiline=False):
    """Read visible Unicode without interpreting opaque ASM byte placeholders."""
    if not (token.startswith('"') and token.endswith('"')):
        raise FormatError("需要双引号包围的字符串")

    def unescape(match):
        atom = match[0]
        if atom.startswith("{{"):
            return atom
        if atom == r"\n" and multiline:
            return "\n"
        if atom[1] in ESCAPES:
            return atom[1]
        raise FormatError(f"无效的字符串转义 {atom!r}")

    return LITERAL_ITEM.sub(unescape, token[1:-1])


def normalize_breaks(text, *, legacy=False):
    parts = text.split("\n")
    result = [parts[0]]
    for previous, following in zip(parts, parts[1:]):
        if not previous or not following:
            result.extend(("\n", following))
            continue
        last = previous[-1]
        same_mark = last in "…―" and following.lstrip(" " + INDENT).startswith(last)
        soft_break = not legacy and (same_mark or last == "”")
        if unicodedata.category(last).startswith("P") and not soft_break:
            result.extend(("\n", following))
        else:
            result.append(following.removeprefix(INDENT))
    return "".join(result)


def text_units(text, opaque):
    """Yield visible characters or indivisible byte placeholders."""
    cursor = 0
    for match in PLACEHOLDER.finditer(text) if opaque else ():
        yield from text[cursor:match.start()]
        yield match[0]
        cursor = match.end()
    yield from text[cursor:]


def unit_width(unit):
    if len(unit) > 1:  # An opaque placeholder, with one column per byte.
        return (len(unit) - 3) // 3
    if unicodedata.combining(unit):
        return 0
    return 2 if unicodedata.east_asian_width(unit) in "FAW" else 1


def line_width(text, opaque):
    return sum(unit_width(unit) for unit in text_units(text, opaque))


def has_overlong_line(text, opaque):
    return any(line_width(line, opaque) > MAX_COLUMNS for line in text.split("\n"))


def asm_literal(text, opaque):
    return '"' + "".join(ESCAPES.get(unit, unit) for unit in text_units(text, opaque)) + '"'


def message_parts(text, dialogue):
    parts = text.split("\n")
    if dialogue:
        for index in range(1, len(parts)):
            if not parts[index].startswith(INDENT):
                parts[index] = INDENT + parts[index]
    return parts


def wrap_message(text, dialogue, encoding, opaque):
    """Indent dialogue continuations and wrap each explicit line separately."""
    wrapped = []
    for part in message_parts(text, dialogue):
        line = []
        width = 0
        for unit in text_units(part, opaque):
            columns = unit_width(unit)
            if line and width + columns > MAX_COLUMNS:
                wrapped.append("".join(line))
                line = [INDENT] if dialogue else []
                width = 2 if dialogue else 0
            if not line and segment_kind(unquote_bytes(asm_literal(unit, opaque), encoding)) != "LINE":
                # A LINE starting with an ASCII subcode would be interpreted as an instruction.
                line.append(" ")
                width = 1
            if width + columns > MAX_COLUMNS:
                raise FormatError("单个文本单元超出一行宽度")
            line.append(unit)
            width += columns
        wrapped.append("".join(line))
    return wrapped


def reflow_message(text, dialogue, encoding, opaque):
    """Fit within three lines while preserving as many explicit breaks as possible."""
    parts = text.split("\n")
    if dialogue:
        # When a break is moved, its old continuation indent must not become inline text.
        parts[1:] = [part.removeprefix(INDENT) for part in parts[1:]]
    joined = wrap_message("".join(parts), dialogue, encoding, opaque)
    if len(joined) > MAX_LINES:
        return None

    # Exclude the all-breaks case, which the caller already tested.
    max_breaks = min(MAX_LINES - 1, len(parts) - 2)
    for count in range(max_breaks, 0, -1):
        for breaks in combinations(range(1, len(parts)), count):
            boundaries = (0, *breaks, len(parts))
            lines = ["".join(parts[start:end]) for start, end in zip(boundaries, boundaries[1:])]
            wrapped = wrap_message("\n".join(lines), dialogue, encoding, opaque)
            if len(wrapped) <= MAX_LINES:
                return wrapped
    return joined


@dataclass(frozen=True)
class Entry:
    id: str
    kind: str
    line: int
    span: tuple[int, int]
    original: str
    speaker: str = ""
    prefix: str = ""
    suffix: str = ""
    controls: tuple[str, ...] = ()

    def row(self):
        row = {"id": self.id}
        if self.speaker:
            row["name"] = self.speaker
        row.update(pre_jp=self.original, message=self.original)
        return row

    def replacement(self, text, encoding, *, layout_warnings=None):
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if any(char != "\n" and unicodedata.category(char) == "Cc" for char in text):
            raise FormatError("译文含有控制字符")
        if self.controls and tuple(m[0] for m in PLACEHOLDER.finditer(text)) != self.controls:
            raise FormatError("字节占位符缺失、新增或顺序改变")
        if self.kind == "line":
            dialogue = self.original.lstrip().startswith(("「", "『", "（"))
            parts = wrap_message(text, dialogue, encoding, self.controls)
            if len(parts) > MAX_LINES:
                detail = [f"{self.id}（ASM 第 {self.line + 1} 行）保留原换行时需 {len(parts)} 行"]
                for index, part in enumerate(message_parts(text, dialogue), 1):
                    width = line_width(part, self.controls)
                    overflow = "，超宽" if width > MAX_COLUMNS else ""
                    detail.append(f"  第 {index} 行（{width / 2:g} 全角字宽{overflow}）{part}")
                parts = reflow_message(text, dialogue, encoding, self.controls)
                if parts is None:
                    detail.append(f"  请缩短译文，使其能排在 {MAX_LINES} 行内。")
                    raise FormatError("\n".join(detail))
                detail.append(f"  已调整换行，回注为 {len(parts)} 行。")
                if layout_warnings is not None:
                    layout_warnings.append("\n".join(detail))
            token = '"' + r"\n".join(asm_literal(part, self.controls)[1:-1] for part in parts) + '"'
            unquote_lines(token, encoding)
            return token
        if "\n" in text:
            raise FormatError("选项和人名只允许单行")
        token = asm_literal(self.prefix + text + self.suffix, self.controls)
        encoded = unquote_bytes(token, encoding)
        if self.kind == "name" and (b"," in encoded or encoded.lstrip(b" \t").startswith(b"//")):
            raise FormatError("MHU 姓名字段不能含半角逗号或用 // 开头")
        return token


def stem_of(path):
    return path.name[:-len(ASM_SUFFIX)] if path.name.lower().endswith(ASM_SUFFIX) else path.stem


class Source:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        self.lines = self.data.decode("utf-8-sig").split("\n")
        self.encoding = DEFAULT_ENCODING
        self.entries = self.parse()

    def parse(self):
        entries = []
        format_ = None
        context = speaker = ""
        counts = Counter()
        for line_index, line in enumerate(self.lines):
            try:
                tokens = tokenize(line)
                if not tokens:
                    continue
                command, *args = tokens
                if format_ is None:
                    format_ = tuple(tokens)
                    if format_ not in (CODE_FORMAT, MHU_FORMAT):
                        raise FormatError("需要 RSA_SD 或 RSA_MHU 的 ASM 文件头")
                    continue
                if command == ".encoding":
                    self.encoding = codec_name(args[0])
                    continue
                if format_ == CODE_FORMAT:
                    if command in ("MESSAGE", "CHOICES"):
                        context, speaker = command, ""
                    elif command == ".end":
                        context = ""
                    elif context == "MESSAGE" and command == "NAME":
                        span = list(TOKEN.finditer(line))[1].span()
                        index = NAME_INDEX.match(unquote_bytes(args[0], self.encoding))
                        comment = line[span[1]:].lstrip()
                        speaker = (comment[1:].strip() if comment.startswith(";") and index
                                   and int(index[1]) & 0xFF else "")
                    if (context, command) not in (("MESSAGE", "LINE"), ("CHOICES", "OPTION")):
                        continue
                    field = 1
                    kind = command.lower()
                    counts[kind] += 1
                    entry_id = f"{stem_of(self.path)}.{kind}.{counts[kind]:05d}"
                else:
                    if command == ".section":
                        context = decode_literal(args[0]).lstrip(" \t")
                    elif command == ".end_section":
                        context = ""
                    if context != "//NameStr" or command != "NAME":
                        continue
                    field, kind = 2, "name"
                    entry_id = f"{stem_of(self.path)}.N{number(args[0], 16)}"

                span = list(TOKEN.finditer(line))[field].span()
                token = tokens[field]
                text = decode_literal(token, multiline=kind == "line")
                prefix = suffix = ""
                if kind == "line":
                    text = normalize_breaks(text)
                elif kind == "name":
                    name = text.strip(" \u3000")
                    if not name:
                        continue
                    prefix = text[:len(text) - len(text.lstrip(" \u3000"))]
                    suffix = text[len(text.rstrip(" \u3000")):]
                    text = name
                controls = tuple(m[0] for m in LITERAL_ITEM.finditer(token) if m[0].startswith("{{"))
                entries.append(Entry(entry_id, kind, line_index, span, text,
                                     speaker if kind == "line" else "", prefix, suffix, controls))
            except (FormatError, IndexError) as exc:
                raise FormatError(f"{self.path}:{line_index + 1}: {exc}") from exc
        if format_ is None:
            raise FormatError(f"{self.path}: 缺少 ASM 文件头")
        return entries

    def inject(self, rows, encoding, *, keep_original_layout=False, layout_warnings=None):
        if not isinstance(rows, list):
            raise FormatError("翻译 JSON 的根节点必须是数组")
        by_id = {entry.id: entry for entry in self.entries}
        updated = self.lines.copy()
        seen = set()
        changes = Counter()
        for row in rows:
            entry_id = row.get("id") if isinstance(row, dict) else None
            if not isinstance(entry_id, str) or entry_id not in by_id:
                raise FormatError(f"未知或无效的翻译 ID {entry_id!r}")
            if entry_id in seen:
                raise FormatError(f"{entry_id}: ID 重复")
            seen.add(entry_id)
            entry = by_id[entry_id]
            line = self.lines[entry.line]
            start, end = entry.span
            original = row.get("pre_jp", entry.original)
            if original != entry.original:
                # Accept the exact extraction from older versions of this script.
                if entry.kind != "line" or original != normalize_breaks(
                    decode_literal(line[start:end], multiline=True), legacy=True,
                ):
                    raise FormatError(f"{entry_id}: pre_jp 与源 ASM 不符")
            translation = row.get("message")
            if translation is not None and not isinstance(translation, str):
                raise FormatError(f"{entry_id}: message 必须是字符串")
            if not translation:
                continue
            if translation in (entry.original, original):
                if (keep_original_layout or entry.kind != "line" or "\n" not in entry.original
                        or not has_overlong_line(entry.original, entry.controls)):
                    continue
                translation = entry.original
            try:
                token = entry.replacement(translation, encoding, layout_warnings=layout_warnings)
            except FormatError as exc:
                raise FormatError(f"{entry_id}: {exc}") from exc
            if token != line[start:end]:
                updated[entry.line] = line[:start] + token + line[end:]
                changes[entry.kind] += 1
        if not changes:
            return self.data, changes
        encoding = "utf-8-sig" if self.data.startswith(b"\xef\xbb\xbf") else "utf-8"
        return "\n".join(updated).encode(encoding), changes


def asm_files(path):
    if path.is_file():
        return [path]
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.is_file() and
                       (p.name.lower() == "asm.txt" or p.name.lower().endswith(ASM_SUFFIX)))
        if files:
            return files
    raise FormatError(f"找不到 ASM 文件 {path}")


def run(args):
    sources = [Source(path) for path in asm_files(args.src)]
    if args.cmd in ("extract", "verify", "report"):
        for source in sources:
            counts = Counter(entry.kind for entry in source.entries)
            counts["speaker"] = sum(bool(entry.speaker) for entry in source.entries)
            if args.cmd == "extract":
                dest = args.out / (stem_of(source.path) + ".json")
                rows = [entry.row() for entry in source.entries]
                write_output(dest, (json.dumps(rows, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            elif args.cmd == "verify":
                rows = json.loads(json.dumps([entry.row() for entry in source.entries]))
                if source.inject(rows, source.encoding, keep_original_layout=True)[0] != source.data:
                    raise FormatError(f"{source.path}: ASM 往返字节不一致")
            print(f"{source.path.name}  {dict(counts)}")
        if args.cmd == "verify":
            print("ASM → JSON → ASM 逐字节一致。")
        return

    json_dir = args.json.is_dir()
    if len(sources) > 1 and not json_dir:
        raise FormatError("处理多个 ASM 时，--json 必须指向目录")
    input_paths = {source.path.resolve() for source in sources}
    pending = []
    layout_warnings = []
    matched = False
    for source in sources:
        dest = args.out / source.path.name
        if dest.resolve() in input_paths:
            raise FormatError("请为回注指定独立的 ASM 输出目录")
        json_path = args.json / (stem_of(source.path) + ".json") if json_dir else args.json
        if json_dir and not json_path.exists():
            pending.append((dest, source.data, Counter()))
            continue
        matched = True
        try:
            rows = json.loads(json_path.read_text(encoding="utf-8-sig"))
            data, changes = source.inject(
                rows, codec_name(args.encoding or source.encoding),
                keep_original_layout=args.keep_original_layout,
                layout_warnings=layout_warnings,
            )
        except (OSError, ValueError) as exc:
            raise FormatError(f"{json_path}: {exc}") from exc
        pending.append((dest, data, changes))
    if not matched:
        raise FormatError(f"{args.json} 中找不到与输入 ASM 对应的 JSON")
    for dest, data, changes in pending:
        write_output(dest, data)
        print(f"{dest.name}  回注 {sum(changes.values())} 条 {dict(changes)}")
    if any(source_entry.kind == "line" for source in sources for source_entry in source.entries):
        report_path = args.out / "layout_warnings.txt"
        summary = f"每行最多 {MAX_COLUMNS // 2} 全角字宽，最多 {MAX_LINES} 行。调整原有换行 {len(layout_warnings)} 条。"
        report = "\n\n".join([summary, *layout_warnings]) + "\n"
        write_output(report_path, report.encode("utf-8"))
        if layout_warnings:
            print(report, end="", file=sys.stderr)
        print(f"{summary} 报告路径 {report_path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="cmd", required=True)
    for name, help_text in (
        ("extract", "提取 UTF-8 翻译 JSON"), ("inject", "将翻译 JSON 回注到 ASM"),
        ("verify", "验证未翻译文本的 ASM 往返"), ("report", "统计提取条目"),
    ):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("--src", type=Path, required=True, help="源 ASM 文件或目录")
        if name in ("extract", "inject"):
            sub.add_argument("--out", type=Path, required=True, help="输出目录")
        if name == "inject":
            sub.add_argument("--json", type=Path, required=True, help="翻译 JSON 文件或目录")
            sub.add_argument("--encoding", help="用于校验回注字段的目标编码，默认为 ASM 声明")
            sub.add_argument("--keep-original-layout", action="store_true",
                             help="逐字保留未翻译条目的原始排版")
    try:
        run(parser.parse_args(argv))
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
