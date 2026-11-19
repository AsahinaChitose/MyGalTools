#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patch_dfm.py -- 把 Konna.exe 窗体资源里的 SHIFTJIS_CHARSET 全部改成 GB2312_CHARSET

只做这一件事，不动任何文字、字体或其它属性。

背景
----
游戏里「コメント」「設定」等文字是编译进 exe 的 Delphi 窗体资源（.rsrc 里以 TPF0
开头的二进制 DFM）。DFM 是长度前缀流，字符集属性按 vaIdent 保存：

    07 10 'SHIFTJIS_CHARSET'      ; 07=vaIdent, 10=字符串长度 16

直接把文本改成 'GB2312_CHARSET'（14 字节）却不改长度字节、不搬移后面的数据，
DFM 解析就会错位，进游戏报错。本工具把整段标识替换成：

    07 0E 'GB2312_CHARSET'        ; 长度 14，后面的数据整体前移 2 字节

每个窗体因此短 2 字节/处，用 0 补齐到原资源大小，.rsrc 目录和文件大小都不变。

菜单文字请自行按原长度（等长）改成 GBK 字节即可；本工具不会碰它们。

用法
----
    python patch_dfm.py gbk.exe                 # 原地改（先备份 gbk.exe.dfm.bak）
    python patch_dfm.py gbk.exe -o gbk_chs.exe  # 输出到新文件
    python patch_dfm.py gbk.exe --check         # 只查看当前状态
    python patch_dfm.py gbk.exe --restore       # 从 .dfm.bak 还原
    python patch_dfm.py gbk.exe --dry-run
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

OLD_IDENT = b"\x07\x10SHIFTJIS_CHARSET"          # vaIdent + len16 + 名字（18 字节）
NEW_IDENT = b"\x07\x0EGB2312_CHARSET"            # vaIdent + len14 + 名字（16 字节）


class DfmError(Exception):
    pass


# ---------------------------------------------------------------- PE

def parse_pe(raw: bytes):
    if raw[:2] != b"MZ":
        raise DfmError("不是 MZ 文件")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    optsz = struct.unpack_from("<H", raw, pe + 20)[0]
    secs = []
    for i in range(nsec):
        o = pe + 24 + optsz + i * 40
        name = raw[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, ra = struct.unpack_from("<IIII", raw, o + 8)
        secs.append({"name": name, "va": va, "vsize": vs, "rawsize": rs, "rawptr": ra})
    return {"pe": pe, "sections": secs}


def rva_to_off(pe, rva: int) -> int:
    for s in pe["sections"]:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["rawptr"] + (rva - s["va"])
    raise DfmError("RVA 0x%X 不在任何段内" % rva)


def resource_entries(raw: bytes, pe):
    rsrc = next((s for s in pe["sections"] if s["name"] == ".rsrc"), None)
    if rsrc is None:
        raise DfmError("没有 .rsrc 段")
    base = rsrc["rawptr"]

    def u16(o):
        return struct.unpack_from("<H", raw, o)[0]

    def u32(o):
        return struct.unpack_from("<I", raw, o)[0]

    out = []

    def walk(rel):
        o = base + rel
        n_named = u16(o + 12)
        n_id = u16(o + 14)
        for i in range(n_named + n_id):
            e = o + 16 + i * 8
            name_id = u32(e)
            off_field = u32(e + 4)
            nm = None
            if name_id & 0x80000000:
                so = base + (name_id & 0x7FFFFFFF)
                n = u16(so)
                nm = raw[so + 2:so + 2 + 2 * n].decode("utf-16-le", "replace")
            tgt = off_field & 0x7FFFFFFF
            if off_field & 0x80000000:
                walk(tgt)
            else:
                de = base + tgt
                out.append((nm, rva_to_off(pe, u32(de)), u32(de + 4)))

    walk(0)
    return out


def find_forms(raw: bytes, pe):
    forms = []
    for name, off, size in resource_entries(raw, pe):
        if size >= 4 and raw[off:off + 4] == b"TPF0":
            forms.append((name, off, size))
    return forms


# ---------------------------------------------------------------- 替换

def replace_in_form(data: bytes) -> tuple:
    """把窗体流里的 SHIFTJIS_CHARSET 标识换成 GB2312_CHARSET，末尾补 0。"""
    out = bytearray()
    pos = 0
    count = 0
    while True:
        i = data.find(OLD_IDENT, pos)
        if i < 0:
            out += data[pos:]
            break
        out += data[pos:i]
        out += NEW_IDENT
        count += 1
        pos = i + len(OLD_IDENT)
    if len(out) > len(data):
        raise DfmError("替换后反而变长，异常")
    out += b"\x00" * (len(data) - len(out))
    return bytes(out), count


def count_idents(data: bytes, ident: bytes) -> int:
    n = 0
    pos = 0
    while True:
        i = data.find(ident, pos)
        if i < 0:
            return n
        n += 1
        pos = i + len(ident)


def inspect(raw: bytes):
    pe = parse_pe(raw)
    forms = find_forms(raw, pe)
    info = []
    for name, off, size in forms:
        data = raw[off:off + size]
        cls = ""
        if size > 5:
            n = data[4]
            cls = data[5:5 + n].decode("latin1", "replace")
        info.append((cls or name, off, size,
                     count_idents(data, OLD_IDENT),
                     count_idents(data, NEW_IDENT)))
    return pe, info


# ---------------------------------------------------------------- 命令

def cmd_check(args) -> int:
    with open(args.exe, "rb") as f:
        raw = f.read()
    _, info = inspect(raw)
    print("窗体资源 %d 个：" % len(info))
    total_old = total_new = 0
    for name, off, size, old, new in info:
        total_old += old
        total_new += new
        print("  %-14s @%X size=%-5d SHIFTJIS=%d  GB2312=%d"
              % (name or "?", off, size, old, new))
    print("合计：SHIFTJIS_CHARSET=%d，GB2312_CHARSET=%d" % (total_old, total_new))
    return 0


def cmd_patch(args) -> int:
    with open(args.exe, "rb") as f:
        raw = f.read()
    pe, info = inspect(raw)
    if not info:
        raise DfmError("没有找到 TPF0 窗体资源")
    old_total = sum(x[3] for x in info)
    new_total = sum(x[4] for x in info)
    if old_total == 0 and new_total:
        print("已经全部是 GB2312_CHARSET：%s" % args.exe)
        return 0

    out = bytearray(raw)
    changed = 0
    for name, off, size, old, new in info:
        if not old:
            continue
        newdata, cnt = replace_in_form(raw[off:off + size])
        out[off:off + size] = newdata
        changed += cnt
    if changed == 0:
        print("没有需要替换的 SHIFTJIS_CHARSET：%s" % args.exe)
        return 0

    if args.dry_run:
        print("dry-run：将替换 %d 处 SHIFTJIS_CHARSET -> GB2312_CHARSET" % changed)
        return 0

    dst = os.path.abspath(args.output) if args.output else os.path.abspath(args.exe)
    if args.output and os.path.exists(dst) and not args.force:
        raise DfmError("输出已存在：%s（--force 覆盖）" % dst)
    if not args.output:
        bak = dst + ".dfm.bak"
        if not os.path.exists(bak):
            with open(bak, "wb") as f:
                f.write(raw)
            print("已备份：%s" % bak)
    with open(dst, "wb") as f:
        f.write(bytes(out))
    print("已写入：%s（替换 %d 处）" % (dst, changed))
    remaining = sum(count_idents(bytes(out)[off:off + size], OLD_IDENT)
                    for name, off, size, _o, _n in info)
    print("复查：剩余 SHIFTJIS_CHARSET = %d" % remaining)
    return 0


def cmd_restore(args) -> int:
    exe = os.path.abspath(args.exe)
    bak = exe + ".dfm.bak"
    if not os.path.isfile(bak):
        raise DfmError("找不到备份：%s" % bak)
    with open(bak, "rb") as f:
        raw = f.read()
    with open(exe, "wb") as f:
        f.write(raw)
    print("已还原：%s（来自 %s）" % (exe, bak))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="只把 Konna.exe 窗体里的 SHIFTJIS_CHARSET 替换为 GB2312_CHARSET")
    p.add_argument("exe", help="目标 exe")
    p.add_argument("-o", "--output", help="输出文件（默认原地改，先备份 .dfm.bak）")
    p.add_argument("--check", action="store_true", help="只查看当前字符集状态")
    p.add_argument("--restore", action="store_true", help="从 .dfm.bak 还原")
    p.add_argument("--dry-run", action="store_true", help="只统计不写入")
    p.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    return p


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    try:
        if args.check:
            return cmd_check(args)
        if args.restore:
            return cmd_restore(args)
        return cmd_patch(args)
    except (DfmError, OSError) as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
