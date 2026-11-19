#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
assembler.py -- GsWIN SC (SCW) 剧本 汇编器

    python assembler.py <asm.txt 或目录> [-o <输出文件/目录>] [--encoding gbk]

读取 disassembler.py 生成的 asm.txt，重建 SCW 脚本二进制。
文本可任意增删字节：重建文本池后按 vm_analysis.md §3 的三类引用回写偏移。

引用类（vm_analysis.md §3）:
  1. 值操作数        u16 kind=16, u16 sub=0x100, u32 offset
  2. 消息表记录      0x00100000 +8(文本) / +12(标签)
  3. 原生字段        opcodelist.TEXT_RAW_FIELDS 列出的 opcode 字段

回写采用「先按原始字节收集全部引用点，再一次性写入」的方式，
避免新旧偏移互相映射（old->new 后再被当成 old 二次映射）。
"""

import argparse
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


def encode_segment(s, encoding, fallback):
    """把一段文本编码成字节；主编码失败时退回 fallback，返回 (bytes, 是否回退)"""
    try:
        return s.encode(encoding), 0
    except UnicodeEncodeError:
        if fallback:
            return s.encode(fallback), 1
        raise


def unescape(s, encoding, fallback="cp932"):
    out = bytearray()
    buf = []
    fb = 0

    def flush():
        nonlocal fb
        if buf:
            data, f = encode_segment("".join(buf), encoding, fallback)
            out.extend(data)
            fb += f
            buf.clear()

    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == '"':
                buf.append('"')
                i += 2
                continue
            if nxt == "\\":
                buf.append("\\")
                i += 2
                continue
            raise ValueError("非法转义 \\%s" % nxt)
        if s.startswith("{{", i):
            j = s.find("}}", i)
            if j < 0:
                raise ValueError("占位符未闭合")
            hx = s[i + 2:j]
            flush()
            out += bytes(int(hx[k:k + 2], 16) for k in range(0, len(hx), 2))
            i = j + 2
            continue
        buf.append(ch)
        i += 1
    flush()
    return bytes(out), fb


def parse_asm(path, encoding, fallback="cp932"):
    hdr = {"magic": b"GsWIN SC File", "version": 2, "pad1": b"\x00\x01\xFF",
           "name_count": 0, "total": None, "rec_count": 0, "encoding": "cp932",
           "title": b""}
    text_items = []      # (old_offset, bytes)
    recs = []
    code = bytearray()
    code_size = None
    fallback_used = 0
    tail = b""
    no_nul = False

    for lineno, line in enumerate(open(path, encoding="utf-8-sig"), 1):
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        try:
            if s in (".scw", ".text", ".records", ".code"):
                continue
            if s.startswith(".encoding"):
                hdr["encoding"] = s.split(None, 1)[1].strip().strip('"')
            elif s.startswith(".magic"):
                hdr["magic"] = s.split(None, 1)[1].strip().strip('"').encode("ascii")
            elif s.startswith(".version"):
                hdr["version"] = int(s.split()[1], 0)
            elif s.startswith(".title_raw"):
                hdr["title"] = bytes(int(x, 16) for x in s.split()[1:])
            elif s.startswith(".title"):
                lit = s.split(None, 1)[1].strip()
                if not (lit.startswith('"') and lit.endswith('"')):
                    raise ValueError("标题未加引号")
                hdr["title"], f = unescape(lit[1:-1], encoding, fallback)
                fallback_used += f
            elif s.startswith(".pad1"):
                hdr["pad1"] = bytes(int(x, 16) for x in s.split()[1:4])
            elif s.startswith(".name_count"):
                hdr["name_count"] = int(s.split()[1], 0)
            elif s.startswith(".total"):
                hdr["total"] = int(s.split()[1], 0)
            elif s.startswith(".rec_count"):
                hdr["rec_count"] = int(s.split()[1], 0)
            elif s.startswith(".code_size"):
                code_size = int(s.split()[1], 0)
            elif s.startswith(".text_tail"):
                tail = bytes(int(x, 16) for x in s.split()[1:])
            elif s.startswith(".text_no_nul"):
                no_nul = True
            elif s.startswith(".elem_size") or s.startswith(".refs"):
                pass
            elif s.startswith(".text"):
                parts = s.split(None, 2)
                off = int(parts[1], 0)
                lit = parts[2] if len(parts) > 2 else '""'
                if not (lit.startswith('"') and lit.endswith('"')):
                    raise ValueError("字符串未加引号")
                data, f = unescape(lit[1:-1], encoding, fallback)
                fallback_used += f
                text_items.append((off, data))
            elif s.startswith(".raw"):
                parts = s.split()
                off = int(parts[1], 0)
                text_items.append((off, bytes(int(x, 16) for x in parts[2:])))
            elif s.startswith(".rec"):
                parts = s.split(None, 2)
                recs.append((parts[1].strip('"'), int(parts[2], 0)))
            elif s.startswith(".byte"):
                for tok in s.split(None, 1)[1].split(","):
                    tok = tok.strip()
                    if tok:
                        code.append(int(tok, 0))
            else:
                raise ValueError("未知指令: %s" % s)
        except Exception as e:
            raise ValueError("%s:%d: %s" % (os.path.basename(path), lineno, e))

    if code_size is not None and len(code) != code_size:
        raise ValueError("代码区长度不符: 声明 %d, 实际 %d" % (code_size, len(code)))
    if hdr["rec_count"] and len(recs) != hdr["rec_count"]:
        raise ValueError("记录数不符: 声明 %d, 实际 %d" % (hdr["rec_count"], len(recs)))

    # ---- 重建文本池 ----
    text_items.sort(key=lambda x: x[0])
    text = bytearray()
    old2new = {}
    for k, (off, data) in enumerate(text_items):
        if off in old2new:
            raise ValueError("文本偏移 0x%X 重复" % off)
        old2new[off] = len(text)
        text += data
        if not (no_nul and k == len(text_items) - 1):
            text += b"\x00"
    text += tail
    text_size = len(text)

    # ---- 收集引用点（基于原始代码字节） ----
    orig = bytes(code)
    sites = []
    seen = set()

    def add_site(pos):
        if pos in seen or pos + 4 > len(orig):
            return
        seen.add(pos)
        v = struct.unpack_from("<I", orig, pos)[0]
        if v in old2new:
            sites.append((pos, v))

    for off in range(0, len(orig) - 8, 4):
        kind, sub = struct.unpack_from("<HH", orig, off)
        if kind == OPC.VALUE_OPERAND_KIND and sub == OPC.VALUE_OPERAND_SUB:
            add_site(off + 4)

    for off in range(0, len(orig) - 16, 4):
        if struct.unpack_from("<I", orig, off)[0] == 0x00100000:
            add_site(off + 8)
            add_site(off + 12)

    for off in range(0, len(orig) - 4, 4):
        ent = OPC.OPCODES.get(struct.unpack_from("<I", orig, off)[0])
        if not ent or not ent["text_fields"]:
            continue
        for fld in ent["text_fields"]:
            add_site(off + fld)

    for pos, val in sites:
        struct.pack_into("<I", code, pos, old2new[val])
    patched = len(sites)

    # ---- 自检: 所有引用点必须落在新字符串起点 ----
    valid = set(old2new.values())
    for pos, _ in sites:
        v = struct.unpack_from("<I", code, pos)[0]
        if v not in valid:
            raise ValueError("重定位自检失败: 0x%X 处的引用 %d 不在字符串起点" % (pos, v))

    # ---- 记录表 ----
    recbuf = bytearray()
    for nm, val in recs:
        nb = nm.encode(encoding)
        if len(nb) > 16:
            raise ValueError("记录名超过 16 字节: %s" % nm)
        recbuf += nb.ljust(16, b"\x00")
        recbuf += struct.pack("<I", val)

    total = len(code) + text_size + len(recbuf)

    out = bytearray()
    out += hdr["magic"].ljust(16, b"\x00")[:16]
    out += (hdr["title"] or b"")[:64].ljust(64, b"\x00")
    out.append(hdr["version"] & 0xFF)
    out += hdr["pad1"].ljust(3, b"\x00")[:3]
    out += struct.pack("<IIIII", hdr["name_count"], total, len(code),
                       text_size, len(recs))
    out += code
    out += text
    out += recbuf
    return bytes(out), patched, fallback_used


def main(argv=None):
    ap = argparse.ArgumentParser(description="GsWIN SC 剧本汇编器")
    ap.add_argument("input", help="asm.txt 或目录")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--encoding", default="gbk", help="写回脚本的字符串编码 (默认 gbk)")
    ap.add_argument("--fallback", default="cp932",
                    help="主编码失败时的回退编码（默认 cp932，便于中日混排中间态）")
    ap.add_argument("--verify", default=None, help="与原始脚本逐字节比对")
    args = ap.parse_args(argv)

    def one(src, dst):
        blob, patched, fb = parse_asm(src, args.encoding, args.fallback)
        with open(dst, "wb") as f:
            f.write(blob)
        return blob, patched, fb

    if os.path.isdir(args.input):
        files = [f for f in sorted(os.listdir(args.input)) if f.lower().endswith(".asm.txt")]
        outdir = args.output or args.input
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        ok = 0
        for f in files:
            src = os.path.join(args.input, f)
            dst = os.path.join(outdir, f[:-len(".asm.txt")])
            try:
                one(src, dst)
                ok += 1
            except Exception as e:
                print("失败 %s: %s" % (f, e))
        print("完成: %d/%d 个脚本 -> %s" % (ok, len(files), outdir))
        return 0 if ok == len(files) else 1

    dst = args.output or (args.input[:-len(".asm.txt")]
                          if args.input.lower().endswith(".asm.txt") else args.input)
    if os.path.isdir(dst):
        base = os.path.basename(args.input)
        if base.lower().endswith(".asm.txt"):
            base = base[:-len(".asm.txt")]
        dst = os.path.join(dst, base)
    blob, patched, fb = one(args.input, dst)
    print("汇编完成: %s (%d 字节, 重定位引用 %d 处, 编码回退 %d 条)"
          % (dst, len(blob), patched, fb))
    if args.verify:
        orig = open(args.verify, "rb").read()
        if orig == blob:
            print("校验: 与原始脚本逐字节一致")
        else:
            print("校验: 不一致 (原 %d 字节 / 新 %d 字节)" % (len(orig), len(blob)))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
