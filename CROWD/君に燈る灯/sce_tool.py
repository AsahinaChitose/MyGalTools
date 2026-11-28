#!/usr/bin/env python3
"""Extract and reinject readable text for this game's encrypted Crowd .sce script."""
from __future__ import annotations

import argparse
import codecs
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "1.0"
FORMAT_ID = "kimitomo-crowd-text-v1"
KEY = b"crowd script yeah "
DEFAULT_ENCODING = "cp932"

# Dispatcher strings are text commands, compared case-insensitively; not opcodes.
COMMANDS = frozenset(x.casefold() for x in (
    "RT ED SSt SS Recs Rece Face FS FC FSet FAdd FSub FMul FDiv FExc FInc FDec "
    "FRnd GSC JP JPZ JZ JNZ JMI JMZ JSP JSPZ JSZ JSNZ JSMI JSMZ GS G R SR SP "
    "SL SD SC TE T W KW OP MV CF CMaskD CMask CB CMC CMD CM CMA CMCC EL EW V "
    "MC Ng CFill CFAdd CFSub CFD CFL SHD MOS CGF MP MPS MM MF MPause WP WPD "
    "WPL WStop WOStop WLStop EOF"
).split())

@dataclass(frozen=True)
class Token:
    start: int
    end: int
    value_start: int
    value_end: int
    value: str
    quoted: bool
    gap: str


def xor_crypt(data: bytes) -> bytes:
    """The game's symmetric rolling XOR transform (IDA: sub_4078D0/407790)."""
    out = bytearray(len(data))
    state = 0
    counter = 0
    key_len = len(KEY)
    for offset, byte in enumerate(data):
        key_pos = (state + offset) % key_len
        mask = KEY[key_pos] | (state & (counter & 0xFF))
        out[offset] = byte ^ mask
        if key_pos == 0:
            state = KEY[(state + counter) % key_len]
            counter += 1
    return bytes(out)


def _decode_script(data: bytes, encoding: str) -> str:
    codecs.lookup(encoding)
    clear = xor_crypt(data)
    try:
        text = clear.decode(encoding, errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"明文不能严格按 {encoding} 解码：字节偏移 0x{exc.start:X}") from exc
    if text.encode(encoding, errors="strict") != clear:
        raise ValueError(f"明文按 {encoding} 编码后不能逐字节还原；拒绝继续以免破坏脚本")
    if "\x00" in text:
        raise ValueError("解密文本含 NUL；当前文本解析器不会猜测其语义")
    return text


def _lex(text: str) -> list[Token]:
    """Tokenize the text DSL while retaining exact source character spans."""
    tokens: list[Token] = []
    pos = 0
    previous_end = 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        start = pos
        gap = text[previous_end:start]
        if text[pos] == '"':
            value_start = pos + 1
            pos += 1
            while pos < len(text):
                if text[pos] == "@" and pos + 1 < len(text) and text[pos + 1] == '"':
                    pos += 2
                    continue
                if text[pos] == '"':
                    break
                pos += 1
            if pos >= len(text):
                raise ValueError(f"未闭合的引号字符串，明文字符偏移 0x{start:X}")
            value_end = pos
            raw_value = text[value_start:value_end]
            value = raw_value.replace('@"', '"')
            pos += 1
            tokens.append(Token(start, pos, value_start, value_end, value, True, gap))
        else:
            while pos < len(text) and not text[pos].isspace() and text[pos] != '"':
                pos += 1
            if pos == start:
                raise ValueError(f"无法解析明文字符偏移 0x{pos:X}")
            value_end = pos
            tokens.append(Token(start, pos, start, value_end, text[start:pos], False, gap))
        previous_end = pos
    return tokens


def _indexed_markers(tokens: list[Token]) -> list[tuple[int, int]]:
    """Find this sample's two-space-separated, monotonically numbered text rows."""
    markers: list[tuple[int, int]] = []
    for token_index, token in enumerate(tokens):
        if token.quoted or token.gap != "  " or not re.fullmatch(r"[0-9]+", token.value):
            continue
        markers.append((token_index, int(token.value)))
    if not markers:
        raise ValueError("未找到本作的双空格文本序号；样本格式与已验证的 kimitomo.sce 不符")
    for expected, (token_index, value) in enumerate(markers):
        if value != expected:
            raise ValueError(
                "文本序号不连续或遇到歧义：期望 %d，实际 %d（token %d）；停止以避免漏提/错位"
                % (expected, value, token_index)
            )
        if token_index == 0 or tokens[token_index - 1].quoted:
            raise ValueError(f"文本序号 {value} 前没有可解析的裸文本 token")
    return markers


_SPEAKER_RE = re.compile(
    r"^(?P<prefix>(?:w[0-9a-z]{5,})?@!)(?P<name>[^@\s]+)(?P<suffix>@n)(?P<body>.*)$",
    re.IGNORECASE,
)
_EFFECT_RE = re.compile(r"^(?P<prefix>wse[0-9a-z]+@\?)(?P<body>.*)$", re.IGNORECASE)
# @n is two bytes even before ASCII text. @nw and @nk are separate commands.
_CONTROL_RE = re.compile(r"@n(?![wk])|@[A-Za-z!?][A-Za-z0-9_]*")


def _byte_offsets(text: str, encoding: str) -> list[int]:
    result = [0]
    size = 0
    for char in text:
        size += len(char.encode(encoding, errors="strict"))
        result.append(size)
    return result


def _choice_number(tokens: list[Token], quote_index: int) -> int | None:
    previous = tokens[quote_index - 1] if quote_index else None
    if previous is None or previous.quoted:
        return None
    word = previous.value.casefold()
    if word == "sp":
        return 1
    if word != "*":
        return None
    option = 1
    cursor = quote_index - 2
    while cursor >= 0:
        token = tokens[cursor]
        if token.quoted:
            option += 1
        elif token.value == "*":
            pass
        elif token.value.casefold() == "sp":
            return option
        else:
            return None
        cursor -= 1
    return None


def extract_text(data: bytes, source_name: str, encoding: str = DEFAULT_ENCODING
                 ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    text = _decode_script(data, encoding)
    tokens = _lex(text)
    markers = _indexed_markers(tokens)
    byte_offsets = _byte_offsets(text, encoding)
    found: list[tuple[int, dict[str, Any], dict[str, Any]]] = []

    previous_marker_token = -1
    for marker_token_index, marker_value in markers:
        interval = tokens[previous_marker_token + 1:marker_token_index]
        candidates = [t for t in interval if not t.quoted and any(ord(ch) > 127 for ch in t.value)]
        if not candidates:
            raise ValueError(f"文本序号 {marker_value} 前未找到可确认的日文正文")
        first = candidates[0]
        last = tokens[marker_token_index - 1]
        if first.start >= last.end:
            raise ValueError(f"文本序号 {marker_value} 的正文边界异常")
        payload = text[first.start:last.end]
        speaker = _SPEAKER_RE.match(payload)
        effect = None if speaker else _EFFECT_RE.match(payload)
        name: str | None = None
        prefix = ""
        suffix = ""
        if speaker:
            prefix = speaker.group("prefix")
            name = speaker.group("name")
            suffix = speaker.group("suffix")
            message = speaker.group("body")
        elif effect:
            prefix = effect.group("prefix")
            message = effect.group("body")
        else:
            message = payload

        entry_id = f"{source_name}#{marker_value:05d}:text"
        entry: dict[str, Any] = {"id": entry_id}
        if name is not None:
            entry["name"] = name
        entry["pre_jp"] = message
        entry["message"] = message
        meta_record: dict[str, Any] = {
            "id": entry_id,
            "record_type": "indexed_text",
            "ordinal": marker_value,
            "char_start": first.start,
            "char_end": last.end,
            "byte_start": byte_offsets[first.start],
            "byte_end": byte_offsets[last.end],
            "original_pre_jp": message,
            "original_payload": payload,
            "control_prefix": prefix,
            "speaker_suffix": suffix,
            "original_name": name,
            "control_signature": _CONTROL_RE.findall(message),
        }
        found.append((first.start, entry, meta_record))
        previous_marker_token = marker_token_index

    title_index = 0
    choice_index = 0
    quoted_count = 0
    for i, token in enumerate(tokens):
        if not token.quoted:
            continue
        previous = tokens[i - 1] if i else None
        prev_word = previous.value.casefold() if previous and not previous.quoted else ""
        if prev_word == "ss":
            kind = "title"
            serial = title_index
            title_index += 1
        elif prev_word in {"sp", "*"}:
            option = _choice_number(tokens, i)
            if option is None:
                raise ValueError(f"无法确定 choice 字符串的选项序号，token {i}")
            kind = f"choice-{option}"
            serial = choice_index
            choice_index += 1
        else:
            raise ValueError(
                f"发现未分类的带引号字符串（token {i}，前一 token={previous.value if previous else ''!r}）；"
                "请先在格式分析中确认其语义"
            )
        quoted_count += 1
        entry_id = f"{source_name}#{kind.split('-')[0]}:{serial:04d}"
        entry = {"id": entry_id, "kind": kind, "pre_jp": token.value, "message": token.value}
        meta_record = {
            "id": entry_id,
            "record_type": "quoted_text",
            "kind": kind,
            "char_start": token.value_start,
            "char_end": token.value_end,
            "byte_start": byte_offsets[token.value_start],
            "byte_end": byte_offsets[token.value_end],
            "original_pre_jp": token.value,
            "original_payload": text[token.value_start:token.value_end],
            "control_signature": _CONTROL_RE.findall(token.value),
            "quote_escape": "@\\\"",
        }
        found.append((token.start, entry, meta_record))

    found.sort(key=lambda row: row[0])
    ids = [entry["id"] for _, entry, _ in found]
    if len(set(ids)) != len(ids):
        raise ValueError("生成了重复记录 ID")
    entries = [entry for _, entry, _ in found]
    meta = {
        "format": FORMAT_ID,
        "tool_version": TOOL_VERSION,
        "source_name": source_name,
        "source_size": len(data),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "source_encoding": encoding,
        "cleartext_size": len(text.encode(encoding)),
        "indexed_text_count": len(markers),
        "quoted_text_count": quoted_count,
        "record_count": len(entries),
        "records": [record for _, _, record in found],
    }
    return entries, meta


def _json_text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是字符串")
    return value


def _effective_message(item: dict[str, Any], record: dict[str, Any]) -> str:
    pre_jp = _json_text(item.get("pre_jp"), f"{record['id']}.pre_jp")
    if pre_jp != record["original_pre_jp"]:
        raise ValueError(f"{record['id']} 的 pre_jp 被改动；请保留原文，只编辑 message")
    message_value = item.get("message", pre_jp)
    if message_value is None or message_value == "":
        message_value = pre_jp
    return _json_text(message_value, f"{record['id']}.message")


def _validate_control_codes(record: dict[str, Any], original: str, translated: str,
                            allow_control_change: bool) -> None:
    old = [token for token in _CONTROL_RE.findall(original) if token != "@n"]
    new = [token for token in _CONTROL_RE.findall(translated) if token != "@n"]
    if old != new and not allow_control_change:
        raise ValueError(
            f"{record['id']} 的控制标记有变化（{old!r} → {new!r}）；"
            "默认拒绝可能损坏脚本的改动。检查后可用 --allow-control-change 覆盖"
        )


def _escape_quoted(value: str) -> str:
    return value.replace('"', '@"')


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    try:
        temp.write_bytes(data)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def _write_json(path: Path, obj: Any) -> None:
    payload = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _atomic_write(path, payload)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _inject_one(source_path: Path, json_path: Path, output_path: Path,
                target_encoding: str | None, allow_control_change: bool) -> bytes:
    meta_path = json_path.with_name(json_path.name + ".meta.json")
    if not meta_path.is_file():
        raise ValueError(f"缺少元数据 sidecar：{meta_path}")
    meta = _read_json(meta_path)
    if not isinstance(meta, dict) or meta.get("format") != FORMAT_ID:
        raise ValueError(f"不支持的 meta 格式：{meta_path}")
    source_data = source_path.read_bytes()
    source_sha = hashlib.sha256(source_data).hexdigest()
    if len(source_data) != meta.get("source_size") or source_sha != meta.get("source_sha256"):
        raise ValueError("输入脚本与提取时记录的大小/SHA-256 不一致；拒绝套用过期偏移")
    source_encoding = meta.get("source_encoding", DEFAULT_ENCODING)
    text = _decode_script(source_data, source_encoding)
    output_encoding = target_encoding or source_encoding
    codecs.lookup(output_encoding)

    document = _read_json(json_path)
    if not isinstance(document, list) or any(not isinstance(item, dict) for item in document):
        raise ValueError("翻译 JSON 须为对象数组")
    by_id: dict[str, dict[str, Any]] = {}
    for item in document:
        entry_id = item.get("id")
        if not isinstance(entry_id, str) or entry_id in by_id:
            raise ValueError("JSON 中存在缺失或重复的 id")
        by_id[entry_id] = item
    records = meta.get("records")
    if not isinstance(records, list):
        raise ValueError("meta.records 缺失或格式错误")
    record_ids = [record.get("id") for record in records if isinstance(record, dict)]
    if len(record_ids) != len(records) or set(record_ids) != set(by_id) or len(record_ids) != len(by_id):
        missing = sorted(set(record_ids) - set(by_id))
        extra = sorted(set(by_id) - set(record_ids))
        raise ValueError(f"JSON/meta ID 不匹配；缺失={missing[:5]} 多余={extra[:5]}")

    edits: list[tuple[int, int, str, str]] = []
    no_edits = True
    for record in records:
        item = by_id[record["id"]]
        translated = _effective_message(item, record)
        _validate_control_codes(record, record["original_pre_jp"], translated, allow_control_change)
        if "\x00" in translated or "\r" in translated or "\n" in translated:
            raise ValueError(f"{record['id']} 含 NUL/CR/LF；本作可编辑正文中未确认这些字符的语义")
        if record["record_type"] == "indexed_text":
            if '"' in translated:
                raise ValueError(f"{record['id']} 的裸文本不能含 ASCII 双引号；请使用日文/中文引号或先确认转义规则")
            if translated != translated.strip():
                raise ValueError(f"{record['id']} 有首尾空白，可能改变 token 边界")
            control_prefix = record.get("control_prefix", "")
            original_name = record.get("original_name")
            if original_name is not None:
                name = item.get("name", original_name)
                if name is None or name == "":
                    name = original_name
                name = _json_text(name, f"{record['id']}.name")
                if "@" in name or any(c.isspace() for c in name):
                    raise ValueError(f"{record['id']}.name 含不支持的 @ 或空白")
                replacement = control_prefix + name + record.get("speaker_suffix", "") + translated
                if name != original_name:
                    no_edits = False
            else:
                if item.get("name") not in (None, ""):
                    raise ValueError(f"{record['id']} 原本没有 speaker 标记，不能直接新增 name 字段")
                replacement = control_prefix + translated
        elif record["record_type"] == "quoted_text":
            replacement = _escape_quoted(translated)
        else:
            raise ValueError(f"未知记录类型：{record.get('record_type')!r}")
        if translated != record["original_pre_jp"]:
            no_edits = False
        try:
            replacement.encode(output_encoding, errors="strict")
        except UnicodeEncodeError as exc:
            bad = replacement[exc.start:exc.end]
            raise ValueError(
                f"{record['id']} 含 {output_encoding} 不可编码字符："
                + " ".join(f"U+{ord(ch):04X} {ch!r}" for ch in bad)
            ) from exc
        start, end = record.get("char_start"), record.get("char_end")
        if not isinstance(start, int) or not isinstance(end, int) or not (0 <= start <= end <= len(text)):
            raise ValueError(f"{record['id']} 的偏移越界或格式错误")
        if text[start:end] == replacement:
            pass
        edits.append((start, end, replacement, record["id"]))

    edits.sort(key=lambda row: row[0])
    pieces: list[str] = []
    cursor = 0
    for start, end, replacement, entry_id in edits:
        if start < cursor:
            raise ValueError(f"记录区域重叠：{entry_id}")
        pieces.append(text[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(text[cursor:])
    edited_text = "".join(pieces)
    try:
        clear_output = edited_text.encode(output_encoding, errors="strict")
    except UnicodeEncodeError as exc:
        char = edited_text[exc.start:exc.end]
        raise ValueError(
            f"未修改的脚本文本中仍有 {output_encoding} 不可编码字符："
            + " ".join(f"U+{ord(ch):04X} {ch!r}" for ch in char)
            + "；没有写出文件"
        ) from exc

    verified_tokens = _lex(clear_output.decode(output_encoding, errors="strict"))
    verified_markers = _indexed_markers(verified_tokens)
    if len(verified_markers) != meta.get("indexed_text_count"):
        raise ValueError("注入后文本序号数量改变；没有写出文件")
    verified_quotes = [token for token in verified_tokens if token.quoted]
    if len(verified_quotes) != meta.get("quoted_text_count"):
        raise ValueError("注入后引号字符串数量改变；没有写出文件")
    encrypted = xor_crypt(clear_output)
    if xor_crypt(encrypted) != clear_output:
        raise ValueError("加密回验失败")
    if no_edits and output_encoding == source_encoding and encrypted != source_data:
        raise ValueError("空注入未能逐字节还原源文件；没有写出文件")
    if source_path.resolve() == output_path.resolve():
        raise ValueError("拒绝覆盖输入脚本；请使用独立输出文件/目录")
    return encrypted


def _is_dir_output(path: Path, input_is_dir: bool) -> bool:
    return input_is_dir or path.exists() and path.is_dir() or not path.suffix or str(path).endswith(("/", "\\"))


def _sce_files(path: Path) -> list[Path]:
    if path.is_file():
        if path.suffix.casefold() != ".sce":
            raise ValueError(f"输入不是 .sce 文件：{path}")
        return [path]
    if path.is_dir():
        files = sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.casefold() == ".sce")
        if not files:
            raise ValueError(f"目录中未找到 .sce 文件：{path}")
        return files
    raise FileNotFoundError(path)


def command_extract(args: argparse.Namespace) -> int:
    input_path = args.input
    files = _sce_files(input_path)
    is_directory = input_path.is_dir()
    if args.output is None:
        output_root = input_path.parent / f"{input_path.name}_json" if is_directory else None
    else:
        output_root = args.output if _is_dir_output(args.output, is_directory) else None
    pending: list[tuple[Path, list[dict[str, Any]], dict[str, Any], Path]] = []
    for source in files:
        if output_root is None:
            json_path = args.output if args.output else source.with_suffix(".json")
        else:
            relative = source.relative_to(input_path) if is_directory else Path(source.name)
            json_path = output_root / relative.with_suffix(".json")
        meta_path = json_path.with_name(json_path.name + ".meta.json")
        if source.resolve() in {json_path.resolve(), meta_path.resolve()}:
            raise ValueError(f"拒绝覆盖源脚本：{source}")
        entries, meta = extract_text(source.read_bytes(), source.name, args.encoding)
        pending.append((json_path, entries, meta, source))
    for json_path, entries, meta, source in pending:
        _write_json(json_path, entries)
        _write_json(json_path.with_name(json_path.name + ".meta.json"), meta)
        print(f"{source} -> {json_path} ({len(entries)} 条：{meta['indexed_text_count']} 正文、{meta['quoted_text_count']} 标题/选项)")
    return 0


def command_inject(args: argparse.Namespace) -> int:
    source_path = args.input
    files = _sce_files(source_path)
    is_directory = source_path.is_dir()
    if is_directory and not args.translations.is_dir():
        raise ValueError("目录注入时第二个参数必须是对应的 JSON 目录")
    if not is_directory and not args.translations.is_file():
        raise ValueError(f"翻译 JSON 不存在：{args.translations}")
    if args.output is None:
        output_root = source_path.parent / f"{source_path.name}_translated" if is_directory else None
    else:
        output_root = args.output if _is_dir_output(args.output, is_directory) else None
    pending: list[tuple[Path, bytes]] = []
    for source in files:
        relative = source.relative_to(source_path) if is_directory else Path(source.name)
        json_path = (args.translations / relative.with_suffix(".json")) if is_directory else args.translations
        if not json_path.is_file():
            raise FileNotFoundError(f"缺少翻译 JSON：{json_path}")
        if output_root is None:
            output_path = args.output if args.output else source.with_name(source.stem + "_cn" + source.suffix)
        else:
            output_path = output_root / relative
        result = _inject_one(
            source, json_path, output_path, args.encoding, args.allow_control_change
        )
        pending.append((output_path, result))
    for output_path, result in pending:
        _atomic_write(output_path, result)
    print("注入完毕")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="本作 Crowd .sce 文本提取/注入工具（UTF-8 JSON to encrypted script）"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract = subparsers.add_parser("extract", help="提取可编辑文本并生成 .meta.json")
    extract.add_argument("input", type=Path, help=".sce 文件或包含 .sce 的目录")
    extract.add_argument("-o", "--output", type=Path, help="JSON 文件或输出目录")
    extract.add_argument("--encoding", default=DEFAULT_ENCODING, help="脚本明文编码（默认 cp932）")
    extract.set_defaults(func=command_extract)

    inject = subparsers.add_parser("inject", help="依据 sidecar 偏移注入翻译并重新加密")
    inject.add_argument("input", type=Path, help="原始 .sce 文件或目录（须与提取时 SHA-256 一致）")
    inject.add_argument("translations", type=Path, help="翻译 JSON 文件或目录")
    inject.add_argument("-o", "--output", type=Path, help="重建 .sce 文件或输出目录；不覆盖源文件")
    inject.add_argument("--encoding", help="输出脚本编码；缺省沿用 meta 中的编码")
    inject.add_argument("--allow-control-change", action="store_true", help="允许改动除 @n 以外的控制标记（@n 默认可改）")
    inject.set_defaults(func=command_inject)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, LookupError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"sce_tool: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())