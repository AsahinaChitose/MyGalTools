#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAC / xlvns PAK 通用解包 / 封包工具
适用：SCRIPT.PAK、GPARTS.PAK 以及同格式（"LAC\\0" 头）的封包

用法:
    python pak_tool.py list   <pak> [--encoding cp932]
    python pak_tool.py unpack <pak> [-o 输出目录] [--encoding cp932]
    python pak_tool.py pack   <解包目录> [-o 新PAK] [--store]
    python pak_tool.py verify <pak> [--encoding cp932]

封包结构（小端）:
    +0x00  char[4]  "LAC\\0"
    +0x04  uint32   条目数
    目录项 40 字节:
        +0x00 char[31] 文件名（逐字节取反，0x00 填充/结尾）
        +0x1F uint8    压缩标志：1=LZSS，0=原样
        +0x20 uint32   存储大小
        +0x24 uint32   数据偏移
    数据区紧随目录。

LZSS（kusari.exe sub_418120）:
    4096 环形窗口，初值 0，写指针 0xFEE；
    控制字节 LSB-first，1=原样字节，0=回溯；
    回溯 2 字节: off=((b1&0xF0)<<4)|b0（12 位环形绝对下标），
                 len=(b1&0x0F)+3（3..18）。
压缩条目以 uint32 解压长度开头。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import time
from array import array
from pathlib import Path

MAGIC = b"LAC\x00"
HEADER_SIZE = 8
ENTRY_SIZE = 40
NAME_FIELD = 31
FLAG_OFF = 31
SIZE_OFF = 32
OFFSET_OFF = 36

RING_SIZE = 4096
RING_MASK = 4095
RING_START = 0xFEE
MIN_MATCH = 3
MAX_MATCH = 18
MAX_CHAIN = 96

DEFAULT_ENCODING = "cp932"


class PakError(Exception):
    pass


# ---------------------------------------------------------------------------
# LZSS
# ---------------------------------------------------------------------------
def lzss_decompress(payload: bytes) -> bytes:
    if len(payload) < 4:
        raise PakError("压缩数据不足 4 字节")
    out_size = struct.unpack_from("<I", payload, 0)[0]
    src = payload[4:]
    n = len(src)
    ring = bytearray(RING_SIZE)
    w = RING_START
    out = bytearray()
    bb = 0
    i = 0
    try:
        while len(out) < out_size:
            bb >>= 1
            if not (bb & 0x100):
                bb = src[i] | 0xFF00
                i += 1
            if bb & 1:
                c = src[i]
                i += 1
                out.append(c)
                ring[w] = c
                w = (w + 1) & RING_MASK
            else:
                b0 = src[i]
                b1 = src[i + 1]
                i += 2
                off = ((b1 & 0xF0) << 4) | b0
                ln = (b1 & 0x0F) + MIN_MATCH
                for k in range(ln):
                    c = ring[(off + k) & RING_MASK]
                    out.append(c)
                    ring[w] = c
                    w = (w + 1) & RING_MASK
    except IndexError:
        raise PakError("压缩流提前结束（偏移 %d）" % i)
    return bytes(out[:out_size])


def lzss_compress(data: bytes, max_chain: int = MAX_CHAIN) -> bytes:
    n = len(data)
    out = bytearray(struct.pack("<I", n))
    if n == 0:
        return bytes(out)
    head = array("i", [-1]) * 65536
    prev = array("i", [-1]) * n

    def hash3(p):
        return ((data[p] * 251 + data[p + 1]) * 251 + data[p + 2]) & 0xFFFF

    def insert(p):
        if p + 2 < n:
            h = hash3(p)
            prev[p] = head[h]
            head[h] = p

    pending = bytearray()
    flags = 0
    bit = 0

    def flush_group():
        nonlocal flags, bit
        if bit:
            out.append(flags)
            out.extend(pending)
            pending.clear()
            flags = 0
            bit = 0

    i = 0
    while i < n:
        best_len = 0
        best_pos = -1
        maxlen = MAX_MATCH if n - i > MAX_MATCH else n - i
        if n - i >= MIN_MATCH:
            cand = head[hash3(i)]
            limit = i - 4095
            chain = 0
            while cand >= 0 and cand >= limit and chain < max_chain:
                if best_len < maxlen and data[cand + best_len] == data[i + best_len]:
                    l = 0
                    while l < maxlen and data[cand + l] == data[i + l]:
                        l += 1
                    if l > best_len:
                        best_len = l
                        best_pos = cand
                        if l >= maxlen:
                            break
                cand = prev[cand]
                chain += 1
        if best_len >= MIN_MATCH:
            off = (RING_START + best_pos) & RING_MASK
            pending.append(off & 0xFF)
            pending.append(((off >> 4) & 0xF0) | (best_len - MIN_MATCH))
            step = best_len
        else:
            flags |= 1 << bit
            pending.append(data[i])
            step = 1
        for k in range(step):
            insert(i + k)
        i += step
        bit += 1
        if bit == 8:
            flush_group()
    flush_group()
    return bytes(out)


# ---------------------------------------------------------------------------
# 目录
# ---------------------------------------------------------------------------
def decode_name(raw: bytes, xor: bool, encoding: str) -> str:
    end = raw.find(0)
    if end < 0:
        end = len(raw)
    b = raw[:end]
    if xor:
        b = bytes(x ^ 0xFF for x in b)
    return b.decode(encoding, errors="replace")


def encode_name(name: str, xor: bool, encoding: str) -> bytes:
    b = name.encode(encoding)
    if not b:
        raise PakError("文件名为空")
    if len(b) > NAME_FIELD:
        raise PakError("文件名过长（>%d 字节）: %s" % (NAME_FIELD, name))
    if xor:
        b = bytes(x ^ 0xFF for x in b)
        if 0 in b:
            raise PakError("文件名含不可编码字符: %s" % name)
    out = b + b"\x00" * (NAME_FIELD - len(b))
    return out


def _printable_score(b: bytes) -> int:
    return sum(1 for x in b if 0x20 <= x < 0x7F or x >= 0x80)


def detect_name_xor(blob: bytes, count: int, encoding: str) -> bool:
    """通过前几个目录项判断文件名是否逐字节取反。"""
    sx = sr = 0
    for i in range(min(count, 8)):
        raw = blob[HEADER_SIZE + i * ENTRY_SIZE: HEADER_SIZE + i * ENTRY_SIZE + NAME_FIELD]
        end = raw.find(0)
        if end < 0:
            end = NAME_FIELD
        sx += _printable_score(bytes(x ^ 0xFF for x in raw[:end]))
        sr += _printable_score(raw[:end])
    return sx >= sr


class Entry:
    __slots__ = ("index", "name", "flag", "size", "offset")

    def __init__(self, index, name, flag, size, offset):
        self.index = index
        self.name = name
        self.flag = flag
        self.size = size
        self.offset = offset


def read_pak(path: Path, encoding: str = DEFAULT_ENCODING):
    blob = path.read_bytes()
    if len(blob) < HEADER_SIZE:
        raise PakError("文件太小: %s" % path)
    if blob[:4] != MAGIC:
        raise PakError("不是 LAC PAK（魔数 %r）: %s" % (blob[:4], path))
    count = struct.unpack_from("<I", blob, 4)[0]
    if count == 0 or HEADER_SIZE + count * ENTRY_SIZE > len(blob):
        raise PakError("目录长度非法（条目数 %d）" % count)
    xor = detect_name_xor(blob, count, encoding)
    entries = []
    for i in range(count):
        o = HEADER_SIZE + i * ENTRY_SIZE
        name = decode_name(blob[o:o + NAME_FIELD], xor, encoding)
        flag = blob[o + FLAG_OFF]
        size, off = struct.unpack_from("<II", blob, o + SIZE_OFF)
        if off + size > len(blob):
            raise PakError("条目 %d (%s) 数据越界" % (i, name))
        entries.append(Entry(i, name, flag, size, off))
    return blob, entries, xor


def entry_data(blob: bytes, e: Entry) -> bytes:
    raw = blob[e.offset:e.offset + e.size]
    return lzss_decompress(raw) if e.flag else raw


# ---------------------------------------------------------------------------
# 命令
# ---------------------------------------------------------------------------
def cmd_list(args) -> int:
    blob, entries, xor = read_pak(Path(args.pak), args.encoding)
    print("PAK: %s" % args.pak)
    print("magic=%r entries=%d size=%d name_xor=%s" % (blob[:4], len(entries), len(blob), xor))
    print("%-5s %-32s %-4s %12s %12s %12s" % ("#", "name", "flag", "packed", "offset", "unpacked"))
    tp = tu = 0
    for e in entries:
        try:
            u = len(entry_data(blob, e))
        except PakError:
            u = -1
        tp += e.size
        tu += max(u, 0)
        print("%-5d %-32s %-4d %12d %12d %12d" % (e.index, e.name, e.flag, e.size, e.offset, u))
    print("-" * 80)
    print("packed=%d unpacked=%d ratio=%.4f" % (tp, tu, tp / tu if tu else 0))
    return 0


def cmd_unpack(args) -> int:
    pak = Path(args.pak)
    blob, entries, xor = read_pak(pak, args.encoding)
    outdir = Path(args.out) if args.out else pak.parent / (pak.stem + "_unpacked")
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "format": "LAC",
        "magic": "LAC\\u0000",
        "encoding": args.encoding,
        "name_xor": xor,
        "source": str(pak),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "entries": [],
    }
    t0 = time.time()
    total = 0
    for e in entries:
        data = entry_data(blob, e)
        dst = outdir / e.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        total += len(data)
        manifest["entries"].append({
            "name": e.name,
            "flag": e.flag,
            "packed_size": e.size,
            "offset": e.offset,
            "unpacked_size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        if args.verbose:
            print("  %-32s %10d -> %10d" % (e.name, e.size, len(data)))
    (outdir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print("解包完成: %d 个文件, %d 字节 -> %s（耗时 %.1fs）" %
          (len(entries), total, outdir, time.time() - t0))
    return 0


def cmd_pack(args) -> int:
    indir = Path(args.dir)
    if not indir.is_dir():
        raise PakError("不是目录: %s" % indir)
    manifest = {}
    mf = indir / "manifest.json"
    if mf.exists():
        manifest = json.loads(mf.read_text(encoding="utf-8"))
    encoding = args.encoding or manifest.get("encoding") or DEFAULT_ENCODING
    xor = args.name_xor if args.name_xor is not None else manifest.get("name_xor", True)

    files = {p.name: p for p in indir.iterdir() if p.is_file() and p.name != "manifest.json"}
    order = []
    meta = {}
    for ent in manifest.get("entries", []):
        if ent["name"] in files:
            order.append(ent["name"])
            meta[ent["name"]] = ent
        else:
            print("警告: manifest 中 %s 不存在，跳过" % ent["name"])
    for name in sorted(files):
        if name not in meta:
            order.append(name)
    if not order:
        raise PakError("目录中没有可打包文件")

    payloads = []
    records = []
    total_u = 0
    t0 = time.time()
    for name in order:
        data = files[name].read_bytes()
        old = meta.get(name)
        flag = 0 if (args.store or (old and old.get("flag") == 0)) else 1
        payload = lzss_compress(data) if flag else data
        payloads.append(payload)
        records.append((name, flag, len(payload)))
        total_u += len(data)
    count = len(order)
    off = HEADER_SIZE + count * ENTRY_SIZE
    directory = bytearray()
    for name, flag, psize in records:
        directory += encode_name(name, xor, encoding)
        directory.append(flag)
        directory += struct.pack("<II", psize, off)
        off += psize
    out = bytearray(MAGIC)
    out += struct.pack("<I", count)
    out += directory
    for p in payloads:
        out += p
    dst = Path(args.out) if args.out else indir.parent / (indir.name + ".PAK")
    dst.write_bytes(out)
    print("封包完成: %d 个文件, %d -> %d 字节 -> %s（耗时 %.1fs）" %
          (count, total_u, len(out), dst, time.time() - t0))
    return 0


def cmd_verify(args) -> int:
    blob, entries, xor = read_pak(Path(args.pak), args.encoding)
    bad = 0
    total = 0
    t0 = time.time()
    for e in entries:
        try:
            data = entry_data(blob, e)
            total += len(data)
        except PakError as ex:
            print("失败 %s: %s" % (e.name, ex))
            bad += 1
    print("校验: %d/%d 通过, 解压总量 %d 字节（耗时 %.1fs）" %
          (len(entries) - bad, len(entries), total, time.time() - t0))
    return 1 if bad else 0


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="LAC/xlvns PAK 通用解包工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="列出目录")
    p.add_argument("pak")
    p.add_argument("--encoding", default=DEFAULT_ENCODING)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("unpack", help="解包并自动解压")
    p.add_argument("pak")
    p.add_argument("-o", "--out")
    p.add_argument("--encoding", default=DEFAULT_ENCODING)
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("pack", help="从解包目录重新封包")
    p.add_argument("dir")
    p.add_argument("-o", "--out")
    p.add_argument("--encoding", default=None)
    p.add_argument("--store", action="store_true", help="全部不压缩")
    p.add_argument("--name-xor", dest="name_xor", default=None, type=lambda s: s.lower() != "false")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("verify", help="校验所有条目可解压")
    p.add_argument("pak")
    p.add_argument("--encoding", default=DEFAULT_ENCODING)
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except PakError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
