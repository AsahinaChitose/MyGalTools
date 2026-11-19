#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exe_text.py —— wwadv.exe 内嵌菜单/界面文本的提取与等长注入。

目标区域（文件偏移，按用户给的 "4:XXXX" 换算）：

    0x488B4 .. 0x4B090     菜单/设置/回想/章节标题等主文本区

用户给的三段 ``4:88B0..4:9900``、``4:9930..4:A160``、``4:ADE0..4:AEA0``
都落在这段里；0x488B4 之前是字体/指针数据，0x4B090 之后是指针表，
都不是文本，工具不会去碰。

这些区域是“NUL 结尾字符串 + 若干 0x00 填充”的连续槽位。注入时只替换字符串
内容，并用 0x00 补齐到原槽位长度——exe 总长度与所有偏移保持不变。

注意：
- 原版 exe 是 CP932；打了 GBK 补丁后界面文字应按 GBK 写回，所以
  ``inject`` 默认 ``--encoding cp932``（原样回写）；改成中文后用 ``--encoding gbk``。
- 槽位按“字符串 + NUL + 随后的零填充”计算容量，译文超过容量-1 字节会
  截断（``--strict`` 改为报错）。
- 形如 ``cg.pd`` / ``xxx`` 的文件名、含 ``%d``/``%s`` 的格式串会打上标签，
  翻译时请勿改动。
- 默认只导出含日文假名/汉字的条目；纯英文、数字、标点、空白及其组合
  （``voice.pb``、``VOICE HDD``、``A-``、``    `` 等）会被跳过，``--all`` 可关闭该过滤。
- 系统/调试提示区 ``0x4A174..0x4AC0C``（「このバージョンのWindowsNTでは実行できません」
  到「CPU 判定不能」）默认整段跳过，``--no-exclude`` 可关闭。

用法::

    python exe_text.py extract exe/wwadv1.exe -o exe_text.json
    python exe_text.py inject  exe/wwadv1.exe exe_text.json -o wwadv_cn.exe
    python exe_text.py scan    exe/wwadv1.exe
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ENCODING_EXTRACT = "cp932"
ENCODING_INJECT = "cp932"

DEFAULT_RANGES = [
    # 文本块实测范围：0x488B4（"しらんがな"）.. 0x4B090（D3D8.DLL 之后）
    # 覆盖用户给的 4:88B0..4:9900 / 4:9930..4:A160 / 4:ADE0..4:AEA0 三段；
    # 0x488B4 之前是字体/指针数据，0x4B090 之后是指针表，都不是文本。
    (0x488B4, 0x4B090),
]

EXCLUDE_OFFSETS = {0x4A1A4}   # GBK.py 写入的字体探测串（GBK 的“中”），不参与翻译

# 系统/调试提示区：从「このバージョンのWindowsNTでは実行できません」到
# 「CPU 判定不能」，正常情况下不会显示，翻译无意义，默认整段跳过。
EXCLUDE_RANGES = [
    (0x4A174, 0x4AC0C),
]

FORMAT_RE = re.compile(r"%[-+ #0-9.*]*[diouxXeEfgGcs%]")
FILENAME_RE = re.compile(r"^[A-Za-z0-9_\-]+(\.[A-Za-z0-9]{1,5})$")


class ExeTextError(Exception):
    pass


def merge_ranges(ranges):
    """合并重叠区间，返回按起点排序的列表。"""
    out = []
    for start, end in sorted(ranges):
        if start >= end:
            raise ExeTextError("区间非法: 0x%X..0x%X" % (start, end))
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def align_left(data: bytes, pos: int) -> int:
    """把起点退到所在字符串的开头（上一个 NUL 之后）。"""
    while pos > 0 and data[pos - 1] != 0:
        pos -= 1
    return pos


def iter_slots(data: bytes, start: int, end: int):
    """遍历区间内的槽位，返回 (offset, capacity, raw_bytes)。"""
    pos = align_left(data, start)
    while pos < end:
        while pos < end and data[pos] == 0:
            pos += 1
        if pos >= end:
            break
        nul = data.find(b"\x00", pos, end)
        if nul < 0:
            break            # 区间末尾把字符串截断了，丢弃
        raw = data[pos:nul]
        # 容量 = 字符串 + NUL + 紧随的零填充（直到下一个非零字节）
        cap_end = nul + 1
        while cap_end < len(data) and data[cap_end] == 0:
            cap_end += 1
        cap = cap_end - pos
        yield pos, cap, raw
        pos += cap


def decode_text(raw: bytes, encoding: str):
    """严格解码；失败返回 None。"""
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    for ch in text:
        code = ord(ch)
        if code < 0x20 or 0xE000 <= code <= 0xF8FF:
            return None
    return text


def has_japanese(text: str) -> bool:
    """是否含日文假名/汉字（纯英文、数字、标点、空白的条目会被跳过）。"""
    for ch in text:
        code = ord(ch)
        if 0x3040 <= code <= 0x30FF:          # 平假名 / 片假名
            return True
        if 0x3400 <= code <= 0x4DBF or 0x4E00 <= code <= 0x9FFF:   # 汉字
            return True
        if 0xFF61 <= code <= 0xFF9F:          # 半角片假名
            return True
        if code in (0x3005, 0x3006, 0x3007):  # 々 〆 〇
            return True
    return False


def classify(text: str):
    tags = []
    if FORMAT_RE.search(text):
        tags.append("format")
    if FILENAME_RE.match(text):
        tags.append("filename")
    if all(ord(c) < 0x80 for c in text):
        tags.append("ascii")
    return tags


def cmd_extract(args) -> int:
    exe = Path(args.exe)
    data = exe.read_bytes()
    ranges = merge_ranges(args.ranges or DEFAULT_RANGES)
    encoding = args.encoding or ENCODING_EXTRACT
    entries = []
    seen = set()
    skipped_jp = 0
    skipped_sys = 0
    for start, end in ranges:
        if end > len(data):
            raise ExeTextError("区间 0x%X..0x%X 超出文件（%d 字节）" % (start, end, len(data)))
        for off, cap, raw in iter_slots(data, start, end):
            if off in EXCLUDE_OFFSETS:
                continue
            if off in seen:
                continue
            text = decode_text(raw, encoding)
            if text is None:
                continue
            seen.add(off)
            if not args.no_exclude and any(lo <= off < hi for lo, hi in EXCLUDE_RANGES):
                skipped_sys += 1
                continue
            if not args.all and not has_japanese(text):
                skipped_jp += 1
                continue
            item = {
                "offset": "0x%X" % off,
                "length": len(raw),
                "capacity": cap,
                "text": text,
            }
            tags = classify(text)
            if tags:
                item["tags"] = tags
            entries.append(item)
    entries.sort(key=lambda e: int(e["offset"], 16))
    payload = {
        "exe": str(exe),
        "ranges": ["0x%X-0x%X" % (a, b) for a, b in ranges],
        "encoding": encoding,
        "count": len(entries),
        "skipped_non_japanese": skipped_jp,
        "skipped_system": skipped_sys,
        "entries": entries,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print("提取: %d 条 -> %s（区间 %s，跳过非日文 %d 条）"
          % (len(entries), out, ", ".join(payload["ranges"]), skipped_jp + skipped_sys))
    return 0


def encode_limited(text: str, limit: int, encoding: str, strict: bool, where: str,
                   sub_char: str | None = None) -> bytes:
    out = bytearray()
    for ch in text:
        try:
            b = ch.encode(encoding)
        except UnicodeEncodeError:
            if sub_char is None:
                raise ExeTextError("%s: 字符 %r 无法用 %s 编码（可用 --on-unencodable sub 替换）"
                                   % (where, ch, encoding))
            print("警告: %s 的字符 %r 不在 %s 中，已替换为 %r" % (where, ch, encoding, sub_char),
                  file=sys.stderr)
            b = sub_char.encode(encoding, "replace")
        if len(out) + len(b) > limit:
            if strict:
                raise ExeTextError("%s: 译文超出槽位（%d 字节上限）" % (where, limit))
            print("警告: %s 超出槽位，已在 %d 字节处截断" % (where, len(out)), file=sys.stderr)
            break
        out += b
    return bytes(out)


def cmd_inject(args) -> int:
    exe = Path(args.exe)
    data = bytearray(exe.read_bytes())
    payload = json.loads(Path(args.json).read_text(encoding="utf-8-sig"))
    entries = payload.get("entries", payload if isinstance(payload, list) else [])
    encoding = args.encoding or (ENCODING_INJECT if not args.keep_encoding else payload.get("encoding", ENCODING_INJECT))

    ranges = merge_ranges(DEFAULT_RANGES)
    slots = {}
    for start, end in ranges:
        for off, cap, _raw in iter_slots(bytes(data), start, end):
            slots[off] = cap

    changed = 0
    skipped = 0
    for entry in entries:
        off = int(entry["offset"], 16) if isinstance(entry["offset"], str) else int(entry["offset"])
        cap = slots.get(off)
        if cap is None:
            raise ExeTextError("0x%X 不是当前文本区里的槽位起点" % off)
        text = str(entry.get("text", ""))
        limit = cap - 1
        enc = encode_limited(text, limit, encoding, args.strict, "0x%X" % off, args.sub_char)
        old = bytes(data[off:off + cap])
        new = enc + b"\x00" * (cap - len(enc))
        if new != old:
            data[off:off + cap] = new
            changed += 1
        else:
            skipped += 1

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(data))
    if len(data) != len(exe.read_bytes()):
        raise ExeTextError("内部错误：输出长度变化")
    print("注入: %d 条（改动 %d，未变 %d）-> %s（%d 字节，长度不变）"
          % (len(entries), changed, skipped, out, len(data)))
    return 0


def cmd_scan(args) -> int:
    exe = Path(args.exe)
    data = exe.read_bytes()
    ranges = merge_ranges(args.ranges or DEFAULT_RANGES)
    total = 0
    for start, end in ranges:
        items = list(iter_slots(data, start, end))
        ok = 0
        for off, cap, raw in items:
            if decode_text(raw, args.encoding or ENCODING_EXTRACT) is not None:
                ok += 1
        print("区间 0x%X..0x%X: %d 个槽位，可解码 %d 个" % (start, end, len(items), ok))
        total += ok
    print("合计可解码槽位: %d" % total)
    return 0


def parse_range(text: str):
    a, _, b = text.partition("-")
    return int(a, 0), int(b, 0)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(description="wwadv.exe 内嵌文本提取/等长注入")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="提取文本到 JSON")
    p.add_argument("exe")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--encoding", help="解码编码，默认 cp932")
    p.add_argument("--range", dest="ranges", action="append", type=parse_range,
                   help="start-end（可多次，默认内置一段）")
    p.add_argument("--all", action="store_true",
                   help="连纯英文/数字/标点/空白的条目一起导出（默认只导出含日文假名或汉字的）")
    p.add_argument("--no-exclude", action="store_true",
                   help="????/?????????????? WindowsNT..CPU ???? ????")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="等长注入回 exe")
    p.add_argument("exe")
    p.add_argument("json")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--encoding", help="写入编码：默认 cp932（原样回写）；转中文后用 gbk")
    p.add_argument("--keep-encoding", action="store_true",
                   help="沿用 JSON 里的编码（默认用 gbk）")
    p.add_argument("--strict", action="store_true", help="超长时报错而不是截断")
    p.add_argument("--on-unencodable", choices=("error", "sub"), default="error",
                   help="遇到目标编码没有的字符：error 报错 / sub 替换")
    p.add_argument("--sub-char", default="?", help="--on-unencodable sub 时使用的替换字符")
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("scan", help="统计各区间槽位")
    p.add_argument("exe")
    p.add_argument("--encoding")
    p.add_argument("--range", dest="ranges", action="append", type=parse_range)
    p.set_defaults(func=cmd_scan)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except ExeTextError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
