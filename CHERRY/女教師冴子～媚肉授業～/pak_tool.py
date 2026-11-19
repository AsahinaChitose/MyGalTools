#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pak_tool.py -- CHERRY PACK 3.0 (.pak) 解包 / 封包 / 校验工具

逆向来源: exe/Saeko.exe (IDA Pro 9.1，伪代码见 exe/Saeko_pseudo.c)
    CGsPackFile::Open        0x0041CAB0  读 0x1C 头 + count*0x18 条目表
    CGsPackFile::Find        0x0041CC90  按 16 字节名字查找
    CGsPackFile::GetSize     0x0041CCF0  取条目 size
    CGsPackFile::Seek        0x0041CD20  定位 data_off + entry.offset
    CGsEncode::Decode        0x0041A8B0  LZSS 解码
    CGsEncode::Encode        0x0041A640  LZSS 编码
    CGsEncode::InitTree      0x0041A380 / InsertNode 0x0041A3B0 / DeleteNode 0x0041A530
    CGameScript::Load        0x0040B530  SCW 头部校验 + 分块 XOR 解密

================================================================ 容器层
0x00  char magic[16]   "CHERRY PACK 3.0\\0"
0x10  u32 zero
0x14  u32 count        条目数
0x18  u32 data_off     数据区偏移 = 0x1C + count*0x18
0x1C  entry[count]，每条 0x18:
        0x00 char name[16]    ASCII，NUL 填充
        0x10 u32 offset       相对 data_off
        0x14 u32 size         打包后字节数
条目载荷按条目顺序紧密排列，无对齐、无额外校验和。
容器本身 **不压缩、不加密**。

================================================================ 条目 1: SCW 脚本
0x00  char magic[16]  "GsWIN SC File\\0"
0x10  ...            全 0
0x50  u8  version     固定 2
0x54  u32 v29         （调试/名字表计数）
0x58  u32 total       = 0x68 + Size + Elem + nrec*20
0x5C  u32 Size        明文块长度（脚本字节码）
0x60  u32 Elem        加密块长度（文本池）
0x64  u32 nrec        加密记录数，每条 20 字节（标签/名字表）
0x68  byte[Size]           明文
      byte[Elem]           XOR 加密: b[i] ^= i & 0xFF
      byte[nrec*20]        XOR 加密: b[i] ^= i & 0xFF
（索引 i 在每个块内从 0 重新计数）

================================================================ 条目 2: GRP 图像
0x00  u32 packed_size  0 = 未压缩；否则 LZSS 数据长度
0x04  u32 raw_size
0x08  u16 0xFFFF       固定标识
0x0A  u16 0
0x0C  u32 0
0x10  u32 width
0x14  u32 height
0x18  u32 bpp          8 / 24 / 32
0x1C  u32 0
0x20  u32 0
0x24  u32 0
0x28  byte[packed_size]   LZSS 压缩的像素数据（packed_size=0 时为原始像素）
raw_size = w*h*bpp/8，8bpp 时为 1024 字节调色板 + w*h 索引
调色板/像素字节序: BGRA(32bpp) / BGR(24bpp) / 调色板每项 BGRA

================================================================ LZSS
窗口 4096、最大匹配 18、阈值 2（长度 >=3 才编码为匹配）、标志位 LSB 优先。
匹配项两字节: c1 = pos & 0xFF, c2 = ((pos >> 4) & 0xF0) | (len - 3)。
编码器为 Okumura 式二叉树匹配，窗口初值 0x00，预置 18 字节，
本工具重压缩结果与原文件 **逐字节相同**。

================================================================ 用法
    python pak_tool.py list    SCW.pak
    python pak_tool.py unpack  SCW.pak out_scw             # 自动解密/解压
    python pak_tool.py pack    out_scw SCW_new.pak         # 自动加密/压缩
    python pak_tool.py pack    out_scw SCW_new.pak --reuse # 未改动条目直接复用源载荷(秒级)
    python pak_tool.py verify  GRP.pak --sample 10         # 抽样 解码->重编码 校验
    python pak_tool.py roundtrip GRP.pak                   # 解包->重包 全字节比对
    python pak_tool.py unpack  SCW.pak out --raw           # 保留原始载荷(不解密)
"""

from __future__ import print_function

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MAGIC = b"CHERRY PACK 3.0\x00"
HDR_SIZE = 0x1C
ENTRY_SIZE = 0x18
NAME_LEN = 16

SCW_MAGIC = b"GsWIN SC File\x00"
SCW_HDR_SIZE = 0x68
SCW_VERSION = 2
SCW_REC_SIZE = 20

IMG_HDR_SIZE = 0x28
IMG_MARK = b"\xFF\xFF"

N = 4096
F = 18
NIL = N
THRESHOLD = 2


# ---------------------------------------------------------------------------
# LZSS (与 CGsEncode 逐指令对应)
# ---------------------------------------------------------------------------
def lzss_decode(src):
    """CGsEncode::Decode (0x0041A8B0)。"""
    win = bytearray(N)
    out = bytearray()
    n = len(src)
    r = N - F
    pos = 0
    flags = 0
    while True:
        flags >>= 1
        if not (flags & 0x100):
            if pos >= n:
                return bytes(out)
            flags = src[pos] | 0xFF00
            pos += 1
        if flags & 1:
            if pos >= n:
                return bytes(out)
            c = src[pos]
            pos += 1
            out.append(c)
            win[r] = c
            r = (r + 1) & 0xFFF
        else:
            if pos >= n:
                break
            c1 = src[pos]
            if pos + 1 >= n:
                break
            c2 = src[pos + 1]
            pos += 2
            off = ((c2 & 0xF0) << 4) | c1
            for i in range((c2 & 0x0F) + 3):
                b = win[(off + i) & 0xFFF]
                out.append(b)
                win[r] = b
                r = (r + 1) & 0xFFF
    return bytes(out)


def lzss_encode(data):
    """CGsEncode::Encode (0x0041A640)。输出与原实现逐字节一致。"""
    n = len(data)
    if n == 0:
        return b""

    text = bytearray(N + F - 1)
    lson = [NIL] * (N + 1)
    rson = [NIL] * (N + 257)
    dad = [NIL] * (N + 1)

    out = bytearray()
    code = bytearray(17)
    code[0] = 0
    code_ptr = 1
    mask = 1
    s = 0
    r = N - F

    length = 0
    while length < F and length < n:
        text[r + length] = data[length]
        length += 1

    match_pos = 0
    match_len = 0

    def insert(rr):
        nonlocal match_pos, match_len
        cmp = 1
        p = N + 1 + text[rr]
        rson[rr] = NIL
        lson[rr] = NIL
        match_len = 0
        while True:
            if cmp >= 0:
                q = rson[p]
                if q != NIL:
                    p = q
                else:
                    rson[p] = rr
                    dad[rr] = p
                    return
            else:
                q = lson[p]
                if q != NIL:
                    p = q
                else:
                    lson[p] = rr
                    dad[rr] = p
                    return
            i = 1
            while i < F:
                cmp = text[rr + i] - text[p + i]
                if cmp:
                    break
                i += 1
            if i > match_len:
                match_pos = p
                match_len = i
                if i >= F:
                    break
        dad[rr] = dad[p]
        lson[rr] = lson[p]
        rson[rr] = rson[p]
        dad[lson[p]] = rr
        dad[rson[p]] = rr
        q = dad[p]
        if rson[q] == p:
            rson[q] = rr
        else:
            lson[q] = rr
        dad[p] = NIL

    def delete(p):
        if dad[p] == NIL:
            return
        q = lson[p]
        if rson[p] != NIL:
            if q == NIL:
                q = rson[p]
            else:
                t = rson[q]
                if t != NIL:
                    while True:
                        q = t
                        t = rson[q]
                        if t == NIL:
                            break
                    rson[dad[q]] = lson[q]
                    dad[lson[q]] = dad[q]
                    lson[q] = lson[p]
                    dad[lson[p]] = q
                rson[q] = rson[p]
                dad[rson[p]] = q
        dad[q] = dad[p]
        d = dad[p]
        if rson[d] == p:
            rson[d] = q
        else:
            lson[d] = q
        dad[p] = NIL

    for i in range(r - 1, r - F - 1, -1):
        insert(i)
    insert(r)

    ip = length
    left = length
    total = 0
    while True:
        if match_len > left:
            match_len = left
        if match_len >= THRESHOLD + 1:
            code[code_ptr] = match_pos & 0xFF
            code_ptr += 1
            code[code_ptr] = ((match_len - 3) | ((match_pos >> 4) & 0xF0)) & 0xFF
            total = code_ptr + 1
        else:
            match_len = 1
            code[0] = (code[0] | mask) & 0xFF
            code[code_ptr] = text[r]
            total = code_ptr + 1

        old_mask = mask
        mask = (mask << 1) & 0xFF
        if old_mask == 0x80:
            out += code[:total]
            code[0] = 0
            mask = 1
            total = 1

        last = match_len
        j = 0
        while j < last:
            if ip >= n:
                break
            c = data[ip]
            ip += 1
            delete(s)
            text[s] = c
            if s < F - 1:
                text[s + N] = c
            s = (s + 1) & 0xFFF
            r = (r + 1) & 0xFFF
            insert(r)
            j += 1

        if j < last:
            for _ in range(last - j):
                delete(s)
                s = (s + 1) & 0xFFF
                r = (r + 1) & 0xFFF
                final = (left == 1)
                left -= 1
                if not final:
                    insert(r)

        if left <= 0:
            break
        code_ptr = total

    if total > 1:
        out += code[:total]
    return bytes(out)


# ---------------------------------------------------------------------------
# SCW 脚本层
# ---------------------------------------------------------------------------
def scw_xor(data):
    """b[i] ^= i & 0xFF（加解密同一个函数）。"""
    return bytes((b ^ (i & 0xFF)) for i, b in enumerate(data))


def scw_split(payload):
    """拆成 (hdr, blk1, blk2, blk3)；结构不符时抛 ValueError。"""
    if len(payload) < SCW_HDR_SIZE or payload[:len(SCW_MAGIC)] != SCW_MAGIC:
        raise ValueError("不是 GsWIN SC 脚本")
    if payload[0x50] != SCW_VERSION:
        raise ValueError("SCW 版本 %d != %d" % (payload[0x50], SCW_VERSION))
    v29, total, size, elem, nrec = struct.unpack_from("<IIIII", payload, 0x54)
    if SCW_HDR_SIZE + size + elem + nrec * SCW_REC_SIZE != len(payload):
        raise ValueError("SCW 分块长度不符")
    p = SCW_HDR_SIZE
    b1 = payload[p:p + size]
    p += size
    b2 = payload[p:p + elem]
    p += elem
    b3 = payload[p:p + nrec * SCW_REC_SIZE]
    return payload[:SCW_HDR_SIZE], b1, b2, b3


# ---------------------------------------------------------------------------
# 条目分类 / 解包 / 封包
# ---------------------------------------------------------------------------
class Entry(object):
    __slots__ = ("name", "offset", "size", "payload", "kind", "meta")

    def __init__(self, name, offset, size, payload):
        self.name = name
        self.offset = offset
        self.size = size
        self.payload = payload
        self.kind = "raw"
        self.meta = {}


def classify(payload):
    """返回 (kind, meta)。kind: scw / img / raw"""
    try:
        hdr, b1, b2, b3 = scw_split(payload)
        size = len(b1)
        return "scw", {"hdr": hdr, "size": size, "elem": len(b2),
                       "nrec": len(b3) // SCW_REC_SIZE}
    except ValueError:
        pass
    if len(payload) >= IMG_HDR_SIZE and payload[8:10] == IMG_MARK:
        packed, raw = struct.unpack_from("<II", payload, 0)
        w, h, bpp = struct.unpack_from("<III", payload, 0x10)
        body = len(payload) - IMG_HDR_SIZE
        if packed == 0:
            ok = raw == body
        else:
            ok = packed == body
        if ok and bpp in (8, 16, 24, 32):
            expect = {8: w * h + 1024, 16: 2 * w * h,
                      24: 3 * w * h, 32: 4 * w * h}[bpp]
            if expect == raw:
                return "img", {"packed": packed, "raw": raw, "w": w, "h": h,
                               "bpp": bpp, "header": payload[:IMG_HDR_SIZE]}
    return "raw", {}


def unpack_payload(payload):
    """返回 (kind, data, meta)。data 为解密/解压后的内容。"""
    kind, meta = classify(payload)
    if kind == "scw":
        hdr, b1, b2, b3 = scw_split(payload)
        return kind, hdr + b1 + scw_xor(b2) + scw_xor(b3), meta
    if kind == "img":
        if meta["packed"] == 0:
            body = payload[IMG_HDR_SIZE:]
        else:
            body = lzss_decode(payload[IMG_HDR_SIZE:])
            if len(body) != meta["raw"]:
                raise ValueError("LZSS 解压长度不符: %d != %d"
                                 % (len(body), meta["raw"]))
        return kind, body, meta
    return kind, payload, meta


def pack_payload(kind, data, meta, compress=True):
    """把解包后的内容重新组装为条目载荷。"""
    if kind == "scw":
        # 汇编器已经写好头部（total / elem），这里按文件自身的头分块并加密
        hdr = data[:SCW_HDR_SIZE]
        v29, total, size, elem, nrec = struct.unpack_from("<IIIII", data, 0x54)
        body = data[SCW_HDR_SIZE:]
        if SCW_HDR_SIZE + size + elem + nrec * SCW_REC_SIZE != len(data):
            raise ValueError("SCW 分块长度与头部不符 (头部 %d+%d+%d*20, 实际 %d)"
                             % (size, elem, nrec, len(data) - SCW_HDR_SIZE))
        b1 = body[:size]
        b2 = body[size:size + elem]
        b3 = body[size + elem:size + elem + nrec * SCW_REC_SIZE]
        return bytes(hdr) + b1 + scw_xor(b2) + scw_xor(b3)

    if kind != "img":
        return data

    raw = len(data)
    hdr = bytearray(meta["header"])
    if compress:
        body = lzss_encode(data)
        if len(body) >= raw:
            body = data
            packed = 0
        else:
            packed = len(body)
    else:
        body = data
        packed = 0
    struct.pack_into("<II", hdr, 0, packed, raw)
    return bytes(hdr) + body


# ---------------------------------------------------------------------------
# 容器读写
# ---------------------------------------------------------------------------
def read_pak(path):
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < HDR_SIZE or blob[:len(MAGIC)] != MAGIC:
        raise ValueError("不是 CHERRY PACK 3.0 文件: %s" % path)
    zero, count, data_off = struct.unpack_from("<III", blob, 0x10)
    if HDR_SIZE + count * ENTRY_SIZE != data_off:
        raise ValueError("条目表与 data_off 不一致: 0x%X vs 0x%X"
                         % (HDR_SIZE + count * ENTRY_SIZE, data_off))
    entries = []
    end = data_off
    for i in range(count):
        o = HDR_SIZE + i * ENTRY_SIZE
        name = blob[o:o + NAME_LEN].split(b"\x00")[0].decode("cp932", "replace")
        off, size = struct.unpack_from("<II", blob, o + NAME_LEN)
        if data_off + off + size > len(blob):
            raise ValueError("条目 %s 越界 (off=0x%X size=0x%X)"
                             % (name, off, size))
        entries.append(Entry(name, off, size,
                             blob[data_off + off:data_off + off + size]))
        end = max(end, data_off + off + size)
    return {"count": count, "data_off": data_off, "entries": entries,
            "trailing": blob[end:], "size": len(blob)}


def build_pak(entries, compress=True, trailing=b""):
    count = len(entries)
    data_off = HDR_SIZE + count * ENTRY_SIZE
    table = bytearray()
    body = bytearray()
    off = 0
    for e in entries:
        payload = pack_payload(e.kind, e.payload, e.meta, compress)
        nm = e.name.encode("cp932")
        if len(nm) > NAME_LEN:
            raise ValueError("条目名超过 16 字节: %s" % e.name)
        table += nm.ljust(NAME_LEN, b"\x00")
        table += struct.pack("<II", off, len(payload))
        body += payload
        off += len(payload)
    return (MAGIC + struct.pack("<III", 0, count, data_off)
            + bytes(table) + bytes(body) + bytes(trailing))


def safe_name(name):
    bad = '<>:"/\\|?*'
    out = "".join("_" if c in bad else c for c in name)
    out = out.strip().strip(".")
    return out or "_unnamed"


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
def cmd_list(args):
    pak = read_pak(args.pak)
    print("%-18s %10s %10s  %s" % ("name", "offset", "size", "kind"))
    for e in pak["entries"]:
        kind, meta = classify(e.payload)
        extra = ""
        if kind == "img":
            extra = "  %dx%d %dbpp%s" % (meta["w"], meta["h"], meta["bpp"],
                                         "" if meta["packed"] else " stored")
        elif kind == "scw":
            extra = "  code=%d text=%d rec=%d" % (meta["size"], meta["elem"], meta["nrec"])
        print("%-18s 0x%08X %10d  %s%s" % (e.name, e.offset, e.size, kind, extra))
    print("-- %d entries, %d bytes, data_off=0x%X"
          % (pak["count"], pak["size"], pak["data_off"]))


def cmd_unpack(args):
    pak = read_pak(args.pak)
    outdir = args.outdir
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    with open(args.pak, "rb") as f:
        src_sha = hashlib.sha256(f.read()).hexdigest()
    manifest = {"source": os.path.abspath(args.pak), "sha256": src_sha,
                "count": pak["count"], "raw": bool(args.raw), "entries": [],
                "trailing": pak["trailing"].hex()}
    used = set()
    for e in pak["entries"]:
        if args.raw:
            kind, meta = classify(e.payload)
            data = e.payload
        else:
            kind, data, meta = unpack_payload(e.payload)
        ext = ""  # 与 GARbro 一致：解包文件不带扩展名（A102 / A139 / START …）
        fn = safe_name(e.name)
        base = fn
        k = 2
        while fn.lower() in used:
            fn = "%s_%d" % (base, k)
            k += 1
        used.add(fn.lower())
        with open(os.path.join(outdir, fn + ext), "wb") as f:
            f.write(data)
        item = {"name": e.name, "file": fn + ext, "kind": kind,
                "size": len(data), "crc32": zlib.crc32(data) & 0xFFFFFFFF}
        if args.raw:
            item["orig_kind"] = kind
            item["kind"] = "raw"
            manifest["entries"].append(item)
            continue
        if kind == "scw":
            item["header"] = meta["hdr"].hex()
            item.update({"code": meta["size"], "elem": meta["elem"], "nrec": meta["nrec"]})
        elif kind == "img":
            item["header"] = meta["header"].hex()
            item.update({"w": meta["w"], "h": meta["h"], "bpp": meta["bpp"],
                         "raw": meta["raw"], "packed": meta["packed"]})
        manifest["entries"].append(item)
    with open(os.path.join(outdir, args.manifest), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    print("解包完成: %d 条目 -> %s  (清单 %s)"
          % (len(manifest["entries"]), outdir, args.manifest))


def cmd_pack(args):
    with open(os.path.join(args.indir, args.manifest), "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # --reuse: 内容未改动的条目直接复用原 pak 里的载荷，免去重新压缩
    src = None
    if args.reuse:
        sp = manifest.get("source") or args.source
        if sp and os.path.exists(sp):
            src = {e.name: e.payload for e in read_pak(sp)["entries"]}
            print("复用源封包: %s (%d 条目)" % (sp, len(src)))
        else:
            print("警告: 找不到源封包，--reuse 无效")

    entries = []
    reused = 0
    for item in manifest["entries"]:
        with open(os.path.join(args.indir, item["file"]), "rb") as f:
            data = f.read()
        if src is not None and item["name"] in src and \
                (zlib.crc32(data) & 0xFFFFFFFF) == item["crc32"]:
            e = Entry(item["name"], 0, len(src[item["name"]]), src[item["name"]])
            e.kind = "raw"
            entries.append(e)
            reused += 1
            continue
        e = Entry(item["name"], 0, len(data), data)
        e.kind = item["kind"]
        if e.kind == "scw":
            e.meta = {"header": bytes.fromhex(item["header"]), "size": item["code"],
                      "elem": item["elem"], "nrec": item["nrec"]}
        elif e.kind == "img":
            e.meta = {"header": bytes.fromhex(item["header"])}
        if len(data) != item["size"] and e.kind != "img":
            print("提示: %s 长度 %d -> %d" % (item["file"], item["size"], len(data)))
        entries.append(e)
    blob = build_pak(entries, compress=not args.store,
                     trailing=bytes.fromhex(manifest.get("trailing") or ""))
    with open(args.pak, "wb") as f:
        f.write(blob)
    print("封包完成: %d 条目 (复用 %d), %d 字节 -> %s"
          % (len(entries), reused, len(blob), args.pak))
    if not args.no_verify:
        pak2 = read_pak(args.pak)
        bad = 0
        for a, b in zip(entries, pak2["entries"]):
            if pack_payload(a.kind, a.payload, a.meta, not args.store) != b.payload:
                bad += 1
        print("自检: 回读 %d 条目, 载荷不一致 %d" % (len(pak2["entries"]), bad))


def verify_entry(e, compress=True):
    kind, data, meta = unpack_payload(e.payload)
    if kind == "scw":
        back = pack_payload(kind, data, meta, compress)
        return (back == e.payload), ("xor-ok" if back == e.payload else "xor-mismatch")
    if kind != "img":
        return True, "skip"
    if meta["packed"] == 0:
        return True, "stored"
    re = lzss_encode(data)
    orig = e.payload[IMG_HDR_SIZE:]
    if re == orig:
        return True, "bit-exact"
    if lzss_decode(re) == data:
        return True, "recompress-ok(%d->%d)" % (len(orig), len(re))
    return False, "decode-mismatch"


def cmd_verify(args):
    pak = read_pak(args.pak)
    ok = bad = 0
    entries = pak["entries"]
    if not args.all:
        step = max(1, len(entries) // max(1, args.sample))
        entries = entries[::step][:args.sample]
    for e in entries:
        good, msg = verify_entry(e)
        if good:
            ok += 1
            if args.verbose:
                print("  OK   %-16s %s" % (e.name, msg))
        else:
            bad += 1
            print("  FAIL %-16s %s" % (e.name, msg))
    print("校验: %d 条目, OK %d, FAIL %d" % (len(entries), ok, bad))
    return 0 if bad == 0 else 1


def cmd_roundtrip(args):
    pak = read_pak(args.pak)
    entries = []
    for e in pak["entries"]:
        kind, data, meta = unpack_payload(e.payload)
        n = Entry(e.name, 0, len(data), data)
        n.kind = kind
        n.meta = meta
        entries.append(n)
    blob = build_pak(entries, compress=not args.store, trailing=pak["trailing"])
    with open(args.pak, "rb") as f:
        orig = f.read()
    if blob == orig:
        print("round-trip 完全一致: %d 字节, SHA-256 %s"
              % (len(blob), hashlib.sha256(blob).hexdigest()))
        return 0
    diff = 0
    for e, n in zip(pak["entries"], entries):
        if e.payload != pack_payload(n.kind, n.payload, n.meta, not args.store):
            diff += 1
    print("round-trip 不一致: orig=%d new=%d, 载荷不同条目=%d"
          % (len(orig), len(blob), diff))
    if args.out:
        with open(args.out, "wb") as f:
            f.write(blob)
        print("已写出: %s" % args.out)
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="CHERRY PACK 3.0 (.pak) 解包/封包工具")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("list", help="列出条目")
    p.add_argument("pak")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("unpack", help="解包（自动解密/解压）")
    p.add_argument("pak")
    p.add_argument("outdir")
    p.add_argument("--manifest", default="pak_manifest.json")
    p.add_argument("--raw", action="store_true", help="保留原始载荷，不解密/解压")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("pack", help="封包（自动加密/压缩）")
    p.add_argument("indir")
    p.add_argument("pak")
    p.add_argument("--manifest", default="pak_manifest.json")
    p.add_argument("--store", action="store_true", help="图像不压缩，按原样存储")
    p.add_argument("--reuse", action="store_true",
                   help="内容未改动的条目直接复用源 pak 载荷（免重压缩，速度极快）")
    p.add_argument("--source", default=None, help="配合 --reuse 指定源 pak")
    p.add_argument("--no-verify", action="store_true")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("verify", help="解密/解压 -> 重新加密/压缩 一致性校验")
    p.add_argument("pak")
    p.add_argument("--all", action="store_true")
    p.add_argument("--sample", type=int, default=8)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("roundtrip", help="解包->重包，与原文件逐字节比较")
    p.add_argument("pak")
    p.add_argument("--store", action="store_true")
    p.add_argument("--out")
    p.set_defaults(func=cmd_roundtrip)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    try:
        return args.func(args) or 0
    except (ValueError, IOError) as e:
        print("错误: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
