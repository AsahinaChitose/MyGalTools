#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
disassembler.py -- GsWIN SC (SCW) 剧本 反汇编器

    python disassembler.py <脚本文件或目录> [-o <输出目录或文件>] [--encoding cp932]

输入: pak_tool.py 解包出来的 SCW 脚本文件（例如 A102 / A139 / START，无扩展名）。
输出: UTF-8 的 asm.txt（文件名默认 <原名>.asm.txt）。

当前覆盖范围（诚实标注）:
  * 容器头 (0x68)            完全解析，字段化输出
  * 文本池 (Elem 块)         完全解析；每条字符串按原始字节偏移成槽，可安全改写
  * 记录表 (nrec*20)         完全解析为「名字 + u32」
  * 代码块 (Size 块)         **原样保留**：VM 操作数的完整语义尚未确认，
                             按 CLAUDE.md 0.4 的原则以 .byte 数据定义完整保留，
                             不做猜测性反汇编。opcodelist.py 中已记录已确认的
                             opcode 值与定长指令长度，供后续阶段补齐。

文本字符串槽 (slot) 的语义: 文本池是按字节偏移引用的（kind=16 直接偏移 /
kind=32 索引×128）。因此本工具按「原偏移 + 原槽长」输出，改写后若超出原槽长
会报错，避免破坏代码区引用。
"""

import argparse
import hashlib
import os
import struct
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import opcodelist as OPC

SCW_MAGIC = b"GsWIN SC File\x00"
SCW_HDR = 0x68
REC_SIZE = 20


# ---------------------------------------------------------------------------
# 文本转义
# ---------------------------------------------------------------------------
_CTRL = {0x0D: "{{0D}}", 0x0A: "{{0A}}", 0x09: "{{09}}"}


def escape_str(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o in _CTRL:
            out.append(_CTRL[o])
        elif o < 0x20 or o == 0x7F:
            out.append("{{%02X}}" % o)
        else:
            out.append(ch)
    return "".join(out)


def unescape_text(s, encoding):
    """反解 asm 中的字符串字面量 -> bytes"""
    out = bytearray()
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == '"':
                out += b'"'
                i += 2
                continue
            if nxt == "\\":
                out += b"\\"
                i += 2
                continue
            raise ValueError("非法转义 \\%s" % nxt)
        if ch == "{" and s.startswith("{{", i):
            j = s.find("}}", i)
            if j < 0:
                raise ValueError("占位符未闭合")
            hexs = s[i + 2:j]
            out += bytes(int(hexs[k:k + 2], 16) for k in range(0, len(hexs), 2))
            i = j + 2
            continue
        # 普通字符：按目标编码编码，一次可能 1 或 2 字节
        out += ch.encode(encoding)
        i += 1
    return bytes(out)


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def parse_scw(blob):
    if len(blob) < SCW_HDR or blob[:len(SCW_MAGIC)] != SCW_MAGIC:
        raise ValueError("不是 GsWIN SC 脚本")
    version = blob[0x50]
    pad1 = blob[0x51:0x54]
    name_count, total, code_size, text_size, rec_count = struct.unpack_from(
        "<IIIII", blob, 0x54)
    if SCW_HDR + code_size + text_size + rec_count * REC_SIZE != len(blob):
        raise ValueError("分块长度与头部不符")
    off = SCW_HDR
    code = blob[off:off + code_size]
    off += code_size
    text = blob[off:off + text_size]
    off += text_size
    recs = blob[off:off + rec_count * REC_SIZE]
    return {
        "version": version, "pad1": pad1, "title": blob[0x10:0x50],
        "name_count": name_count,
        "total": total, "code": code, "text": text, "recs": recs,
        "rec_count": rec_count,
    }


def split_text_slots(text):
    """文本池 -> [(offset, raw_bytes)]，按 NUL 切分；空槽也保留。"""
    slots = []
    i = 0
    n = len(text)
    while i < n:
        j = text.find(b"\x00", i)
        if j < 0:
            slots.append((i, text[i:]))
            break
        slots.append((i, text[i:j]))
        i = j + 1
    return slots


# ---------------------------------------------------------------------------
# 反汇编主流程
# ---------------------------------------------------------------------------
def disassemble(path, out_path, encoding):
    blob = open(path, "rb").read()
    scw = parse_scw(blob)
    name = os.path.basename(path)
    sha = hashlib.sha256(blob).hexdigest()

    L = []
    add = L.append
    add("; ============================================================")
    add("; GsWIN SC 剧本 反汇编")
    add("; 文件: %s" % name)
    add("; SHA-256: %s" % sha)
    add("; 字节数: %d" % len(blob))
    add("; 编码: %s" % encoding)
    add("; ============================================================")
    add("")
    add(".scw")
    add('.encoding    "%s"' % encoding)
    add('.magic       "GsWIN SC File"')
    add(".version     %d" % scw["version"])
    add(".pad1        %02X %02X %02X" % tuple(scw["pad1"]))
    title_raw = scw["title"]
    if title_raw.strip(b"\x00"):
        try:
            ts = title_raw.split(b"\x00")[0].decode(encoding)
            if ts.encode(encoding) == title_raw.split(b"\x00")[0]:
                add('.title       "%s"' % escape_str(ts))
            else:
                raise UnicodeDecodeError(encoding, title_raw, 0, 1, "往返不一致")
        except (UnicodeDecodeError, UnicodeEncodeError):
            add(".title_raw   %s" % " ".join("%02X" % b for b in title_raw))
    add(".name_count  %d" % scw["name_count"])
    add(".total       %d" % scw["total"])
    add(".rec_count   %d" % scw["rec_count"])
    add("")

    # ---- 文本池 ----
    slots = split_text_slots(scw["text"])
    code = scw["code"]
    # 扫描代码区里的文本引用: 4 字节对齐的 8 字节值操作数
    #   u16 kind=16, u16 sub=0x100, u32 offset (指向字符串起点)
    starts = set(off for off, _ in slots)
    refs = {}
    for off in range(0, len(code) - 8, 4):
        kind, sub = struct.unpack_from("<HH", code, off)
        if kind != 16 or sub != 0x100:
            continue
        val = struct.unpack_from("<I", code, off + 4)[0]
        if val in starts:
            refs[off] = val
    add("; ---------- 文本池 (%d 字节, %d 条字符串, %d 处引用) ----------"
        % (len(scw["text"]), len(slots), len(refs)))
    add("; 文本可自由变长/变短: 汇编时会重建文本池并自动回写全部引用偏移")
    add(".text")
    add(".elem_size   %d" % len(scw["text"]))
    add(".refs        %d" % len(refs))
    for idx, (off, raw) in enumerate(slots):
        try:
            s = raw.decode(encoding)
            if s.encode(encoding) != raw:
                raise UnicodeDecodeError(encoding, raw, 0, 1, "往返不一致")
            add('.text %5d "%s"' % (off, escape_str(s)))
        except (UnicodeDecodeError, UnicodeEncodeError):
            add(".raw  %5d %s" % (off, " ".join("%02X" % b for b in raw)))
    canon = b"".join(raw + b"\x00" for _, raw in slots)
    if len(canon) < len(scw["text"]):
        tail = scw["text"][len(canon):]
        add(".text_tail  " + " ".join("%02X" % b for b in tail))
    elif len(canon) > len(scw["text"]):
        add(".text_no_nul")
    add("")

    # ---- 记录表 ----
    if scw["rec_count"]:
        add("; ---------- 记录表 (%d 条 x %d 字节) ----------" % (scw["rec_count"], REC_SIZE))
        add(".records")
        for k in range(scw["rec_count"]):
            o = k * REC_SIZE
            nm = scw["recs"][o:o + 16].split(b"\x00")[0]
            val = struct.unpack_from("<I", scw["recs"], o + 16)[0]
            add('.rec %-16s 0x%08X' % ('"%s"' % nm.decode(encoding, "replace"), val))
        add("")

    # ---- 代码区 ----
    add("; ---------- 代码区 (%d 字节) ----------" % len(scw["code"]))
    add("; 说明: VM 操作数语义尚未全部确认, 按 CLAUDE.md 0.4 原样保留为数据定义,")
    add(";       不输出猜测性的伪指令。opcodelist.py 记录了已确认的 opcode 与长度。")
    add(".code")
    add(".code_size   %d" % len(scw["code"]))
    text_by_off = {off: raw for off, raw in slots}
    for i in range(0, len(scw["code"]), 16):
        chunk = scw["code"][i:i + 16]
        for o in range(i, min(i + 16, len(scw["code"])), 4):
            if o in refs:
                try:
                    s = text_by_off[refs[o]].decode(encoding)
                    add('; 引用 @0x%04X -> "%s"' % (o, escape_str(s[:40])))
                except Exception:
                    add("; 引用 @0x%04X -> 偏移 %d" % (o, refs[o]))
        add(".byte " + ", ".join("0x%02X" % b for b in chunk))
    add("")

    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L))
    return {"text_slots": len(slots), "code_size": len(scw["code"]),
            "recs": scw["rec_count"], "size": len(blob)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="GsWIN SC 剧本反汇编器")
    ap.add_argument("input", help="脚本文件或目录")
    ap.add_argument("-o", "--output", default=None, help="输出文件或目录")
    ap.add_argument("--encoding", default="cp932", help="文本编码 (默认 cp932)")
    args = ap.parse_args(argv)

    if os.path.isdir(args.input):
        files = [os.path.join(args.input, f) for f in sorted(os.listdir(args.input))
                 if os.path.isfile(os.path.join(args.input, f))]
        outdir = args.output or args.input
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        ok = fail = 0
        for fp in files:
            try:
                disassemble(fp, os.path.join(outdir, os.path.basename(fp) + ".asm.txt"),
                            args.encoding)
                ok += 1
            except Exception as e:
                fail += 1
                print("跳过 %s: %s" % (os.path.basename(fp), e))
        print("完成: %d 个脚本 -> %s (失败 %d)" % (ok, outdir, fail))
        return 0

    out = args.output or (args.input + ".asm.txt")
    if os.path.isdir(out):
        out = os.path.join(out, os.path.basename(args.input) + ".asm.txt")
    info = disassemble(args.input, out, args.encoding)
    print("反汇编完成: %s" % out)
    print("  文本槽 %d 个, 代码区 %d 字节, 记录 %d 条"
          % (info["text_slots"], info["code_size"], info["recs"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
