#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""《君に燈る灯》kimitomo.exe 音乐鉴赏 / 回想文本提取与等长注入工具。

已核实的原始 EXE 文件偏移为 0x69340..0x69C04；end-exclusive 范围为
0x69340..0x69C05。用户标注的 0x69C00 正好落在最后一条回想标题中间，
所以只延伸到该条字符串 NUL 终止符 0x69C04，不包含相邻资源。

注入策略：每条记录只覆写原始 payload 的字节长度；超长译文按目标编码、
完整字符边界截断，较短译文以 0x00 补足。原终止符、其他字节和 EXE 总长
保持不变。注入结果写入独立文件，绝不覆盖源 EXE。

用法：
    python kimitomo_exe_text.py extract exe/kimitomo.exe -o kimitomo_exe_text.json
    python kimitomo_exe_text.py inject exe/kimitomo.exe kimitomo_exe_text.json -o exe_cn/kimitomo.exe --encoding gbk
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

TOOL_VERSION = "1.2.0"
SAMPLE_SHA256 = "514a39315aad8dad9cc41df0c9528429f3acf618cad953f5ae8643dba1ce51ab"
USER_RANGE_START = 0x69340
USER_RANGE_END = 0x69C00
RANGE_START = 0x69340
RANGE_END = 0x69C05  # exclusive；包含 0x69C04 的最后一条字符串 NUL
DEFAULT_ENCODING = "cp932"
DEFAULT_INJECT_ENCODING = "gbk"

MUSIC_RE = re.compile(r"^[0-9０-９]{1,2}：『.*』@n@n", re.DOTALL)
RECOLLECTION_TITLE_RE = re.compile(r"^[0-9]{2}：【.*】@n$", re.DOTALL)
RECOLLECTION_PREVIEW_PREFIX = "@s014"
CONTROL_RE = re.compile(r"@[A-Za-z][A-Za-z0-9]*")


class ExeTextError(Exception):
    """输入、格式或注入数据不符合预期。"""


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    def contains_file_range(self, start: int, end: int) -> bool:
        return self.raw_offset <= start < end <= self.raw_offset + self.raw_size

    def file_offset_to_rva(self, offset: int) -> int:
        if not (self.raw_offset <= offset < self.raw_offset + self.raw_size):
            raise ExeTextError(f"文件偏移 0x{offset:X} 不在区段 {self.name} 的原始数据中")
        return self.virtual_address + offset - self.raw_offset


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_pe(data: bytes) -> tuple[int, int, list[Section]]:
    """读取 PE32/PE32+ 的 ImageBase 和节表，用于目标偏移映射验证。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ExeTextError("输入不是有效的 MZ/PE 文件")
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ExeTextError("PE 签名或 PE 头越界")
    machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
    section_count = int.from_bytes(data[pe_offset + 6:pe_offset + 8], "little")
    optional_size = int.from_bytes(data[pe_offset + 20:pe_offset + 22], "little")
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 32:
        raise ExeTextError("PE Optional Header 越界或不完整")
    magic = int.from_bytes(data[optional:optional + 2], "little")
    if magic == 0x10B:
        image_base = int.from_bytes(data[optional + 28:optional + 32], "little")
    elif magic == 0x20B:
        image_base = int.from_bytes(data[optional + 24:optional + 32], "little")
    else:
        raise ExeTextError(f"不支持的 PE Optional Header 魔数 0x{magic:X}")
    table = optional + optional_size
    if table + section_count * 40 > len(data):
        raise ExeTextError("PE 节表越界")
    sections: list[Section] = []
    for i in range(section_count):
        off = table + i * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = int.from_bytes(data[off + 8:off + 12], "little")
        virtual_address = int.from_bytes(data[off + 12:off + 16], "little")
        raw_size = int.from_bytes(data[off + 16:off + 20], "little")
        raw_offset = int.from_bytes(data[off + 20:off + 24], "little")
        if raw_offset + raw_size > len(data):
            raise ExeTextError(f"PE 区段 {name} 的原始范围超出文件")
        sections.append(Section(name, virtual_address, virtual_size, raw_offset, raw_size))
    return machine, image_base, sections


def section_for_range(sections: list[Section], start: int, end: int) -> Section:
    matches = [section for section in sections if section.contains_file_range(start, end)]
    if len(matches) != 1:
        raise ExeTextError(
            f"目标范围 0x{start:X}..0x{end:X} 必须完整落在一个 PE 节内；匹配数={len(matches)}"
        )
    return matches[0]


def iter_c_strings(data: bytes, start: int, end: int) -> Iterator[tuple[int, bytes, int]]:
    """遍历范围内 NUL 结尾字符串，返回 (起点, 内容字节, NUL偏移)。"""
    if start < 0 or end <= start or end > len(data):
        raise ExeTextError(f"非法或越界的提取范围 0x{start:X}..0x{end:X}")
    pos = start
    while pos < end:
        if data[pos] == 0:
            pos += 1
            continue
        nul = data.find(b"\0", pos, end)
        if nul < 0:
            raise ExeTextError(
                f"0x{pos:X} 处字符串在范围 0x{end:X} 前没有 NUL 终止符；拒绝截断提取"
            )
        yield pos, data[pos:nul], nul
        pos = nul + 1


def classify(text: str) -> str | None:
    if MUSIC_RE.match(text):
        return "music_entry"
    if text.startswith(RECOLLECTION_PREVIEW_PREFIX):
        return "recollection_preview"
    if RECOLLECTION_TITLE_RE.match(text):
        return "recollection_title"
    return None


def hexoff(value: int) -> str:
    return f"0x{value:06X}"


def extract(exe_path: Path, output_path: Path, encoding: str) -> tuple[int, int]:
    try:
        data = exe_path.read_bytes()
    except OSError as exc:
        raise ExeTextError(f"无法读取 EXE：{exe_path}: {exc}") from exc
    source_hash = sha256(data)
    try:
        source_resolved = exe_path.resolve()
        output_resolved = output_path.resolve()
    except OSError as exc:
        raise ExeTextError(f"无法解析输入/输出路径：{exc}") from exc
    if source_resolved == output_resolved or (output_path.exists() and output_path.samefile(exe_path)):
        raise ExeTextError("输出路径不能与原始 EXE 相同；原文件保持只读")

    machine, image_base, sections = parse_pe(data)
    section = section_for_range(sections, RANGE_START, RANGE_END)
    if section.name != ".data":
        raise ExeTextError(f"目标数据位于 {section.name}，与已分析样本的 .data 不一致")
    rva_start = section.file_offset_to_rva(RANGE_START)
    rva_end = section.file_offset_to_rva(RANGE_END - 1) + 1

    entries: list[dict[str, object]] = []
    meta_records: list[dict[str, object]] = []
    ignored: list[dict[str, str]] = []
    counts = {"music_entry": 0, "recollection_preview": 0, "recollection_title": 0}

    for offset, raw, nul_offset in iter_c_strings(data, RANGE_START, RANGE_END):
        try:
            text = raw.decode(encoding, errors="strict")
        except (LookupError, UnicodeDecodeError) as exc:
            raise ExeTextError(f"0x{offset:X} 字符串不能严格按 {encoding} 解码：{exc}") from exc
        kind = classify(text)
        if kind is None:
            ignored.append({"offset": hexoff(offset), "text": text})
            continue

        record_id = f"exe#{hexoff(offset)}"
        rva = section.file_offset_to_rva(offset)
        entries.append({"id": record_id, "kind": kind, "pre_jp": text, "message": text})
        meta_records.append({
            "id": record_id,
            "kind": kind,
            "file_offset": hexoff(offset),
            "rva": hexoff(rva),
            "va": hexoff(image_base + rva),
            "byte_length": len(raw),  # payload 长度，不含 NUL
            "terminator_offset": hexoff(nul_offset),
            "terminator": "00",
            "encoding": encoding,
            "raw_hex": raw.hex(" "),
            "raw_sha256": sha256(raw),
            "control_tokens": CONTROL_RE.findall(text),
        })
        counts[kind] += 1

    expected_counts = {"music_entry": 18, "recollection_preview": 7, "recollection_title": 7}
    if counts != expected_counts:
        print(f"警告：样本预期分类数量 {expected_counts}，当前为 {counts}；请核对 EXE 版本。", file=sys.stderr)
    if source_hash != SAMPLE_SHA256:
        print(f"警告：源 SHA-256 与已分析样本不一致：{source_hash}", file=sys.stderr)

    meta = {
        "tool": "kimitomo_exe_text.py",
        "tool_version": TOOL_VERSION,
        "game": "君に燈る灯",
        "purpose": "音乐鉴赏与回想文本提取/等长注入",
        "source_file": str(exe_path.resolve()),
        "source_size": len(data),
        "source_sha256": source_hash,
        "sample_sha256_match": source_hash == SAMPLE_SHA256,
        "encoding": encoding,
        "json_encoding": "UTF-8",
        "pe": {
            "machine": f"0x{machine:04X}",
            "image_base": hexoff(image_base),
            "section": section.name,
            "section_file_range": [hexoff(section.raw_offset), hexoff(section.raw_offset + section.raw_size)],
            "section_rva": hexoff(section.virtual_address),
            "section_virtual_size": hexoff(section.virtual_size),
        },
        "range": {
            "user_reported_file_offsets_end_exclusive_assumed": [hexoff(USER_RANGE_START), hexoff(USER_RANGE_END)],
            "effective_file_offsets_end_exclusive": [hexoff(RANGE_START), hexoff(RANGE_END)],
            "extension_reason": "最后一条标题从 0x69BEC 开始，NUL 终止符位于 0x69C04。",
            "rva": [hexoff(rva_start), hexoff(rva_end)],
            "va": [hexoff(image_base + rva_start), hexoff(image_base + rva_end)],
        },
        "counts": {**counts, "total": len(entries), "ignored_strings": len(ignored)},
        "ignored_strings": ignored,
        "records": meta_records,
        "notes": [
            "主 JSON 保留原始控制串；注入时要求控制串名称及顺序与原文相同。",
            "每条注入槽位长度等于原始 payload 长度，不含 NUL 终止符；译文短则 00 填充，长则在字符边界截断。",
            "message 缺失/空值或等于 pre_jp 时原字节保持不动；原终止 NUL、间隔和其他数据不修改。",
            "注入接受本 sidecar 对应的源 EXE，或可验证为同一原版的已知补丁版。",
        ],
    }
    meta_path = Path(str(output_path) + ".meta.json")
    if meta_path.resolve() == source_resolved or (meta_path.exists() and meta_path.samefile(exe_path)):
        raise ExeTextError("meta 输出路径不能与原始 EXE 相同；原文件保持只读")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(json.dumps(entries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ExeTextError(f"无法写入 JSON 输出：{exc}") from exc

    print(
        f"提取 {len(entries)} 条 -> {output_path}；sidecar -> {meta_path}\n"
        f"音乐 {counts['music_entry']}，回想预览 {counts['recollection_preview']}，"
        f"回想标题 {counts['recollection_title']}；编码 {encoding}；源 SHA-256 {source_hash}"
    )
    return len(entries), len(ignored)


def load_json(path: Path, description: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExeTextError(f"无法读取{description} JSON {path}: {exc}") from exc


def encode_translated(text: str, original_text: str, byte_limit: int, encoding: str,
                      record_id: str) -> tuple[bytes, bool]:
    """按字节上限编码；保留所有控制串，普通文字超长时在字符边界截断。"""
    if "\0" in text:
        raise ExeTextError(f"{record_id}: message 含 NUL，不能注入 C 字符串")
    if "\r" in text or "\n" in text:
        raise ExeTextError(f"{record_id}: 不允许字面 CR/LF；换行请使用原有控制串 @n")
    original_controls = CONTROL_RE.findall(original_text)
    new_controls = CONTROL_RE.findall(text)
    if new_controls != original_controls:
        raise ExeTextError(
            f"{record_id}: 控制串必须原样、同序保留；原文={original_controls}，译文={new_controls}"
        )

    def encoded(value: str) -> bytes:
        try:
            return value.encode(encoding, errors="strict")
        except (LookupError, UnicodeEncodeError) as exc:
            raise ExeTextError(f"{record_id}: 字符无法用 {encoding} 编码：{exc}") from exc

    matches = list(CONTROL_RE.finditer(text))
    control_bytes = [encoded(match.group()) for match in matches]
    reserved = sum(map(len, control_bytes))
    if reserved > byte_limit:
        raise ExeTextError(f"{record_id}: 原控制串本身已超过 {byte_limit} 字节槽位")

    remaining_text_bytes = byte_limit - reserved
    out = bytearray()
    cursor = 0
    control_index = 0
    stopped_text = False

    def append_plain(plain: str) -> None:
        nonlocal remaining_text_bytes, stopped_text
        for char in plain:
            char_bytes = encoded(char)
            if not stopped_text and len(char_bytes) <= remaining_text_bytes:
                out.extend(char_bytes)
                remaining_text_bytes -= len(char_bytes)
            else:
                # 普通文本按前缀截断，但后续控制串仍保留。
                stopped_text = True

    for match in matches:
        append_plain(text[cursor:match.start()])
        out.extend(control_bytes[control_index])
        control_index += 1
        cursor = match.end()
    append_plain(text[cursor:])

    was_truncated = stopped_text
    if len(out) > byte_limit:
        raise ExeTextError(f"{record_id}: 内部错误，编码后长度超过槽位")
    return bytes(out) + b"\0" * (byte_limit - len(out)), was_truncated


def validate_patched_source(source: bytes, source_hash: str, expected_hash: str) -> None:
    """Check the original sample hash after undoing known edits in a temporary copy."""
    mismatch = f"源 EXE SHA-256 与提取 sidecar 不符：当前 {source_hash}，meta {expected_hash!r}"
    if expected_hash != SAMPLE_SHA256:
        raise ExeTextError(mismatch)

    try:
        from patch_exe import PatchError, validate_build
    except ImportError as exc:
        raise ExeTextError(f"{mismatch}\n校验补丁版需要 patch_exe.py：{exc}") from exc

    try:
        canonical_hash = validate_build(source)
    except PatchError as exc:
        raise ExeTextError(f"{mismatch}\n已知补丁还原校验失败：{exc}") from exc
    if canonical_hash != expected_hash:
        raise ExeTextError(f"{mismatch}\n已知补丁还原后的 SHA-256：{canonical_hash}")


def inject(exe_path: Path, json_path: Path, output_path: Path, meta_path: Path,
           encoding: str) -> tuple[int, int, int]:
    try:
        source = exe_path.read_bytes()
    except OSError as exc:
        raise ExeTextError(f"无法读取源 EXE {exe_path}: {exc}") from exc
    payload = load_json(json_path, "翻译")
    meta = load_json(meta_path, "meta")
    if not isinstance(payload, list) or not isinstance(meta, dict):
        raise ExeTextError("翻译 JSON 必须是数组，meta JSON 必须是对象")

    source_hash = sha256(source)
    expected_hash = meta.get("source_sha256")
    if not isinstance(expected_hash, str):
        raise ExeTextError("meta 缺少有效的 source_sha256")
    if meta.get("source_size") != len(source):
        raise ExeTextError("源 EXE 大小与提取 sidecar 不符")
    is_patched_source = source_hash != expected_hash
    if is_patched_source:
        validate_patched_source(source, source_hash, expected_hash)
    _machine, image_base, sections = parse_pe(source)
    source_section = section_for_range(sections, RANGE_START, RANGE_END)
    if source_section.name != ".data":
        raise ExeTextError("当前 EXE 的目标范围不在预期 .data 区段")
    original_encoding = meta.get("encoding")
    if not isinstance(original_encoding, str):
        raise ExeTextError("meta 缺少原始文本编码")
    meta_records = meta.get("records")
    if not isinstance(meta_records, list) or not meta_records:
        raise ExeTextError("meta 中没有可注入记录")

    by_id: dict[str, dict[str, object]] = {}
    for rec in meta_records:
        if not isinstance(rec, dict) or not isinstance(rec.get("id"), str):
            raise ExeTextError("meta records 中存在非法记录")
        if rec["id"] in by_id:
            raise ExeTextError(f"meta 中 ID 重复：{rec['id']}")
        by_id[rec["id"]] = rec

    entries_by_id: dict[str, dict[str, object]] = {}
    for entry in payload:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise ExeTextError("翻译 JSON 中存在非法记录或缺少 id")
        record_id = entry["id"]
        if record_id in entries_by_id:
            raise ExeTextError(f"翻译 JSON 中 ID 重复：{record_id}")
        entries_by_id[record_id] = entry
    if set(entries_by_id) != set(by_id):
        missing = sorted(set(by_id) - set(entries_by_id))
        extra = sorted(set(entries_by_id) - set(by_id))
        raise ExeTextError(f"JSON 与 meta 的记录集合不匹配；缺少={missing}，多出={extra}")

    # 防止别名/链接指向源文件；输入永不覆盖。
    try:
        source_resolved = exe_path.resolve()
        output_resolved = output_path.resolve()
        meta_resolved = meta_path.resolve()
    except OSError as exc:
        raise ExeTextError(f"无法解析输入/输出路径：{exc}") from exc
    if output_resolved == source_resolved or (output_path.exists() and output_path.samefile(exe_path)):
        raise ExeTextError("输出路径不能与源 EXE 相同；原文件保持只读")
    if output_resolved in {json_path.resolve(), meta_resolved}:
        raise ExeTextError("输出 EXE 不能覆盖翻译 JSON 或 meta sidecar")
    for protected_path in (json_path, meta_path):
        if output_path.exists() and protected_path.exists() and output_path.samefile(protected_path):
            raise ExeTextError("输出 EXE 不能覆盖翻译 JSON 或 meta sidecar")
    if meta_resolved == source_resolved or (meta_path.exists() and meta_path.samefile(exe_path)):
        raise ExeTextError("meta 路径不能与源 EXE 相同")

    output = bytearray(source)
    seen_ranges: list[tuple[int, int, str]] = []
    unchanged = 0
    changed = 0
    truncated = 0
    warnings: list[str] = []

    for record_id, entry in entries_by_id.items():
        rec = by_id[record_id]
        try:
            offset = int(str(rec["file_offset"]), 0)
            length = int(rec["byte_length"])
            terminator_offset = int(str(rec["terminator_offset"]), 0)
            raw = bytes.fromhex(str(rec["raw_hex"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ExeTextError(f"{record_id}: meta 偏移/原始字节字段非法：{exc}") from exc
        if length < 0 or len(raw) != length or terminator_offset != offset + length:
            raise ExeTextError(f"{record_id}: meta 长度或终止符位置不一致")
        if offset < RANGE_START or terminator_offset >= RANGE_END or terminator_offset >= len(source):
            raise ExeTextError(f"{record_id}: 记录不在已核实文本区间内或越界")
        if record_id != f"exe#{hexoff(offset)}":
            raise ExeTextError(f"{record_id}: ID 与文件偏移不对应")
        expected_rva = source_section.file_offset_to_rva(offset)
        if rec.get("rva") != hexoff(expected_rva) or rec.get("va") != hexoff(image_base + expected_rva):
            raise ExeTextError(f"{record_id}: meta 中的 RVA/VA 与当前 PE 映射不符")
        if source[offset:offset + length] != raw or source[terminator_offset] != 0:
            raise ExeTextError(f"{record_id}: EXE 原字节与 meta 不符；拒绝写入")
        if sha256(raw) != rec.get("raw_sha256"):
            raise ExeTextError(f"{record_id}: meta 原始字节 SHA-256 不符")
        for old_start, old_end, old_id in seen_ranges:
            if offset < old_end and old_start < offset + length + 1:
                raise ExeTextError(f"{record_id} 与 {old_id} 的注入范围重叠")
        seen_ranges.append((offset, offset + length + 1, record_id))

        try:
            original_text = raw.decode(original_encoding, errors="strict")
        except (LookupError, UnicodeDecodeError) as exc:
            raise ExeTextError(f"{record_id}: meta 原文无法按 {original_encoding} 解码：{exc}") from exc
        expected_kind = classify(original_text)
        if rec.get("kind") != expected_kind:
            raise ExeTextError(f"{record_id}: meta kind 与原始文本不符")
        pre_jp = entry.get("pre_jp")
        if pre_jp != original_text:
            raise ExeTextError(f"{record_id}: pre_jp 被修改或与源 EXE 不符")
        value = entry.get("message")
        text = pre_jp if value is None or value == "" else value
        if not isinstance(text, str):
            raise ExeTextError(f"{record_id}: message 必须是字符串")
        if text == original_text:
            unchanged += 1
            continue  # 未修改文本原字节回写，避免无谓转码

        encoded, was_truncated = encode_translated(text, original_text, length, encoding, record_id)
        if was_truncated:
            truncated += 1
            warnings.append(f"{record_id}: 译文超过原始 {length} 字节，已在字符边界截断")
        output[offset:offset + length] = encoded
        changed += 1

    if len(output) != len(source):
        raise ExeTextError("内部错误：重建 EXE 长度发生变化")
    # 除已登记 payload 字节外，所有字节必须保持不变。
    masked = bytearray(source)
    for start, end, _record_id in seen_ranges:
        masked[start:end - 1] = output[start:end - 1]
    if masked != output:
        raise ExeTextError("内部错误：目标文本区之外出现未授权字节变化")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_bytes(output)
    except OSError as exc:
        raise ExeTextError(f"无法写入输出 EXE {output_path}: {exc}") from exc
    if unchanged and encoding.lower() != original_encoding.lower():
        warnings.append(
            f"有 {unchanged} 条未修改文本保留源编码 {original_encoding} 字节；"
            f"其余修改文本使用 {encoding}，输出可能为混合编码。请完成全部翻译或确认运行时代码页。"
        )
    for warning in warnings:
        print(f"警告：{warning}", file=sys.stderr)
    print(
        f"注入完成：修改 {changed} 条，原样保留 {unchanged} 条，截断 {truncated} 条\n"
        f"输出：{output_path}（{len(output)} bytes；源 SHA-256 {source_hash}；"
        f"输出 SHA-256 {sha256(bytes(output))}；编码 {encoding}）"
    )
    if is_patched_source:
        print("源 EXE 校验通过：还原已知补丁后与 sidecar 的原始 SHA-256 一致。")
    return changed, unchanged, truncated


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="提取/注入《君に燈る灯》EXE 中的音乐鉴赏与回想文本")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_extract = subparsers.add_parser("extract", help="提取目标文本为可编辑 UTF-8 JSON")
    p_extract.add_argument("exe", type=Path, help="游戏主程序，例如 exe/kimitomo.exe")
    p_extract.add_argument("-o", "--output", type=Path, default=Path("kimitomo_exe_text.json"),
                           help="输出 JSON 文件（默认 kimitomo_exe_text.json；自动生成 .meta.json）")
    p_extract.add_argument("--encoding", default=DEFAULT_ENCODING,
                           help=f"EXE 原文本编码（默认 {DEFAULT_ENCODING}）")

    p_inject = subparsers.add_parser("inject", help="按原始字符串字节长度等长注入翻译")
    p_inject.add_argument("exe", type=Path, help="提取时的源 EXE，或本作已识别的 GBK/语音补丁版")
    p_inject.add_argument("json", type=Path, help="extract 生成并完成翻译的 JSON")
    p_inject.add_argument("-o", "--output", type=Path,
                          help="输出 EXE（默认写入同级 exe_cn 目录；不会覆盖输入）")
    p_inject.add_argument("--meta", type=Path,
                          help="提取 sidecar；默认 <JSON文件名>.meta.json")
    p_inject.add_argument("--encoding", default=DEFAULT_INJECT_ENCODING,
                          help=f"译文编码（默认 {DEFAULT_INJECT_ENCODING}；可指定 cp932）")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "extract":
            extract(args.exe, args.output, args.encoding)
        elif args.command == "inject":
            output_path = args.output
            if output_path is None:
                output_path = args.exe.parent.with_name(args.exe.parent.name + "_cn") / args.exe.name
            meta_path = args.meta or Path(str(args.json) + ".meta.json")
            inject(args.exe, args.json, output_path, meta_path, args.encoding)
        else:
            raise ExeTextError(f"未知命令：{args.command}")
    except ExeTextError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
