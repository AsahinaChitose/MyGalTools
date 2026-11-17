#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kusari.exe 内嵌文本提取 / 等长注入

目标区域：0x92B20 .. 0x935E4（.rdata 中一段道具名/说明文本，CP932）
这段是连续的 NUL 结尾字符串，每个字符串后面有若干 0x00 填充。
注入时只替换字符串内容，并用 0x00 补齐到原槽位长度，exe 总长度与所有
偏移不变，不会破坏程序。

用法:
    python exe_text_tool.py extract exe\\kusari.exe -o exe_text.json
    python exe_text_tool.py inject  exe\\kusari.exe exe_text.json -o kusari.new.exe
    python exe_text_tool.py inject  exe\\kusari.exe exe_text.json -o kusari.new.exe --map subs_cn_jp.json

译文可以写简体中文，注入时用 subs_cn_jp.json 逐字替换成日繁槽位字符。
槽位放不下时默认在 CP932 字符边界截断并警告；--strict 改为直接报错。
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

DEFAULT_START = 0x92B20
DEFAULT_END = 0x935E4
ENCODING = "cp932"
DEFAULT_MAP = "subs_cn_jp.json"


class ExeTextError(Exception):
    pass


def find_map(path_arg):
    if path_arg:
        p = Path(path_arg)
        if not p.exists():
            raise ExeTextError("映射文件不存在: %s" % p)
        return p
    for p in (Path.cwd() / DEFAULT_MAP, Path(__file__).resolve().parent / DEFAULT_MAP):
        if p.exists():
            return p
    return None


def load_map(path):
    if path is None:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ExeTextError("%s 必须是 {简体: 日繁槽位}" % path)
    return {k: v for k, v in data.items()
            if isinstance(k, str) and isinstance(v, str) and len(k) == 1 and len(v) == 1}


def iter_slots(data: bytes, start: int, end: int):
    """按 NUL 切分，返回 [(offset, capacity, raw_bytes)]；槽位之间必须是 0。"""
    out = []
    pos = start
    while pos < end:
        while pos < end and data[pos] == 0:
            pos += 1
        if pos >= end:
            break
        nul = data.find(b"\x00", pos, end)
        if nul < 0:
            nul = end
        raw = data[pos:nul]
        nxt = nul + 1
        while nxt < end and data[nxt] == 0:
            nxt += 1
        # 槽位 = 字符串 + NUL + 后面的零填充
        cap = nxt - pos
        if nxt >= end:
            cap = end - pos
        # 校验中间没有非零字节
        if any(b != 0 for b in data[nul + 1:pos + cap]):
            # 保守：只保留到 NUL
            cap = nul + 1 - pos
        out.append((pos, cap, raw))
        pos += cap
    return out


def cmd_extract(args) -> int:
    exe = Path(args.exe)
    data = exe.read_bytes()
    start, end = args.start, args.end
    if not (0 <= start < end <= len(data)):
        raise ExeTextError("范围越界: 0x%X..0x%X（文件 %d 字节）" % (start, end, len(data)))
    entries = []
    for off, cap, raw in iter_slots(data, start, end):
        try:
            text = raw.decode(ENCODING)
        except UnicodeDecodeError as e:
            print("警告: 0x%X 不是合法 CP932（%s），跳过" % (off, e), file=sys.stderr)
            continue
        entries.append({
            "offset": "0x%X" % off,
            "length": len(raw),
            "capacity": cap,
            "text": text,
        })
    out = {
        "exe": str(exe),
        "range": ["0x%X" % start, "0x%X" % end],
        "encoding": ENCODING,
        "entries": entries,
    }
    dst = Path(args.output)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print("提取: %d 条 -> %s" % (len(entries), dst))
    return 0


def encode_limited(text: str, limit: int, strict: bool, where: str):
    """编码为 CP932；超过 limit 时在字符边界截断（strict 则报错）。"""
    out = bytearray()
    for ch in text:
        try:
            b = ch.encode(ENCODING)
        except UnicodeEncodeError:
            raise ExeTextError("%s: 字符 %r 不在 CP932 中" % (where, ch))
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
    if isinstance(payload, dict):
        entries = payload.get("entries", [])
        rng = payload.get("range")
        start = int(rng[0], 16) if rng else DEFAULT_START
        end = int(rng[1], 16) if rng else DEFAULT_END
    else:
        entries = payload
        start, end = DEFAULT_START, DEFAULT_END
    mapping = load_map(find_map(args.map))
    if mapping:
        print("映射: %d 条" % len(mapping))
    # 重新计算每个条目的槽位（以文件中实际边界为准，防止 JSON 被改坏）
    slots = {off: cap for off, cap, _raw in iter_slots(data, start, end)}
    changed = 0
    for e in entries:
        off = int(e["offset"], 16) if isinstance(e["offset"], str) else int(e["offset"])
        cap = slots.get(off)
        if cap is None:
            raise ExeTextError("0x%X 不在文本区/不是字符串起点" % off)
        text = str(e.get("text", ""))
        if mapping:
            text = "".join(mapping.get(ch, ch) for ch in text)
        limit = cap - 1  # 至少留 1 个 NUL
        enc = encode_limited(text, limit, args.strict, "0x%X" % off)
        old = bytes(data[off:off + cap])
        new = enc + b"\x00" * (cap - len(enc))
        if new != old:
            data[off:off + cap] = new
            changed += 1
    out = Path(args.output)
    out.write_bytes(bytes(data))
    if len(data) != len(exe.read_bytes()):
        raise ExeTextError("内部错误：输出长度变化")
    print("注入: %d 条（实际改动 %d 条）-> %s（长度 %d 不变）" %
          (len(entries), changed, out, len(data)))
    return 0


def cmd_scan(args) -> int:
    exe = Path(args.exe)
    data = exe.read_bytes()
    # 粗略找出“连续 CP932 文本 + 零填充”的区域，便于确认还有没有其它文本块
    regions = []
    i = 0
    n = len(data)
    while i < n:
        # 尝试解码一个 NUL 结尾串
        j = data.find(b"\x00", i)
        if j < 0:
            break
        raw = data[i:j]
        ok = False
        if len(raw) >= 4:
            try:
                s = raw.decode(ENCODING)
                jp = sum(1 for ch in s if 0x3040 <= ord(ch) <= 0x30FF or 0x4E00 <= ord(ch) <= 0x9FFF)
                ok = jp >= 2
            except UnicodeDecodeError:
                ok = False
        if ok:
            regions.append(i)
            i = j + 1
        else:
            i += 1
    # 合并邻近地址
    groups = []
    for a in regions:
        if groups and a - groups[-1][1] <= 0x200:
            groups[-1][1] = a
        else:
            groups.append([a, a])
    print("疑似文本串 %d 条，聚集为 %d 个区域：" % (len(regions), len(groups)))
    for a, _b in groups[:50]:
        print("  0x%X" % a)
    return 0


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="kusari.exe 内嵌文本提取/等长注入")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="提取文本到 JSON")
    p.add_argument("exe")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--start", type=lambda s: int(s, 0), default=DEFAULT_START)
    p.add_argument("--end", type=lambda s: int(s, 0), default=DEFAULT_END)
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="等长注入回 exe")
    p.add_argument("exe")
    p.add_argument("json")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--map", help="默认使用 subs_cn_jp.json")
    p.add_argument("--strict", action="store_true", help="译文超长时报错而不是截断")
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("scan", help="粗略扫描其它文本区域")
    p.add_argument("exe")
    p.set_defaults(func=cmd_scan)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except ExeTextError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
