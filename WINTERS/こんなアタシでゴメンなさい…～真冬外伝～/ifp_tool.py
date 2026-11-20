#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ifp_tool.py -- IAGS_IFP_01 封包解包 / 封包工具（真冬外伝 / IAGS 引擎）

格式来源
--------
本工具的结构来自 exe 逆向（IDA 9.1，见 exe/pseudocode.c 的 sub_48EF90 /
sub_48B330 / sub_48B798 / sub_4030AC）与 SCR.IFP / GRP.IFP 样本实测：

  文件结构
    0x00  char[16]  "IAGS_IFP_01" + 5 个空格      ; 魔数
    0x10  TOC 段，共 header_size 字节，每 16 字节一个槽位（本样本 2048 槽）
          槽 0 同时是 TOC 描述符：{type=1, type2=0, offset=0x10, size=header_size, size2=0}
          其余槽 16 字节，小端：
            +0x00 u16 type    ; 0=空槽 1=TOC 自身 11=BMP 12=PNG 13=未出现 21=脚本块
            +0x02 u16 type2   ; 第二个载荷的类型，0 表示没有
            +0x04 u32 offset  ; 载荷在文件中的绝对偏移
            +0x08 u32 size    ; 第一个载荷的字节数
            +0x0C u32 size2   ; 第二个载荷的字节数（offset2 = offset + size）
    0x10 + header_size  数据区（本样本 0x8010），各条目按 index 升序首尾相接，无对齐填充

  注意：exe 是从文件偏移 16 处读入 0x8000 字节到缓冲区 word_55980C（sub_4030AC），
  之后一律按 16 字节步长访问 word_55980C[8*idx] / dword_559810[4*idx] ...
  因此在引擎眼里 0x10 处那 16 字节就是第 0 条记录，而不是独立的
  “版本 / 条目大小 / 头部大小 / 保留”字段。本工具按同样的模型解析：
  header_size 取自槽 0 的 size，数据区 = 槽 0 的 offset + size。

  引用位置：槽序号 index 就是运行时的资源号 / 脚本号
  （sub_48B330 用 word_55980C[8*idx]、dword_559810[4*idx] ... 访问，
   stride=16 与上面的结构一致；sub_48B798 用同样的方式取脚本块）。
  因此重封包时必须保留每个条目的 index，不能只按顺序排列。

压缩 / 加密
-----------
对当前两个封包逐块签名核对：SCR.IFP 全部 31 块以 "IAGS_ISD_01 " 开头，
GRP.IFP 全部 139 块以 "BM"（BMP，27 块）或 "\\x89PNG"（PNG，112 块）开头，
BMP 的 bfSize 字段都等于所在块长度，PNG 块以 IEND 结束 —— 容器层没有压缩、
没有加密、没有异或或长度混淆。因此本工具的 codec 固定为 "raw"；
若将来遇到非明文载荷，unpack 会直接报错并给出槽号/偏移/签名，而不是猜测后静默处理。

用法
----
  python ifp_tool.py list    SCR.IFP
  python ifp_tool.py unpack  SCR.IFP -o unpacked_SCR
  python ifp_tool.py pack    unpacked_SCR -o SCR.rebuild.IFP
  python ifp_tool.py verify  SCR.IFP            # 解包->重封包，逐字节比对
  python ifp_tool.py diagnose GRP.IFP           # 只打印每块签名/尺寸，不解包

依赖：仅 Python 3 标准库。
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile

MAGIC_PREFIX = b"IAGS_IFP_01"
MAGIC_FIELD = b"IAGS_IFP_01" + b"\x20" * 5   # 16 字节，空格补齐
TOC_OFF = 0x10
ENTRY_FMT = "<HHIII"
ENTRY_SIZE = 16

TYPE_TOC = 1
TYPE_BMP = 11
TYPE_PNG = 12
TYPE_UNKNOWN13 = 13
TYPE_SCRIPT = 21

TYPE_EXT = {TYPE_BMP: ".bmp", TYPE_PNG: ".png", TYPE_SCRIPT: "", TYPE_UNKNOWN13: ".bin"}

PNG_SIG = b"\x89PNG\r\n\x1a\n"


class IfpError(Exception):
    pass


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def payload_signature(blob):
    """识别载荷自身的文件签名，仅用于诊断与严格性校验。"""
    if not blob:
        return "empty"
    if blob[:2] == b"BM":
        return "bmp"
    if blob[:8] == PNG_SIG:
        return "png"
    if blob[:2] == b"\xff\xd8":
        return "jpeg"
    if blob[:12] == b"IAGS_ISD_01 ":
        return "isd"
    if blob[:2] == b"\x1f\x8b":
        return "gzip"
    if blob[:1] == b"\x78" and len(blob) > 2 and (blob[1] in (0x01, 0x5E, 0x9C, 0xDA)):
        return "zlib?"
    return "unknown"


class Entry(object):
    __slots__ = ("index", "type", "type2", "offset", "size", "size2")

    def __init__(self, index, type_, type2, offset, size, size2):
        self.index = index
        self.type = type_
        self.type2 = type2
        self.offset = offset
        self.size = size
        self.size2 = size2

    def __repr__(self):
        return "Entry(idx=%d type=%d type2=%d off=0x%X size=0x%X size2=0x%X)" % (
            self.index, self.type, self.type2, self.offset, self.size, self.size2)


class IfpFile(object):
    """解析后的 IAGS_IFP_01 封包（只读视图 + 数据切片）。"""

    def __init__(self, data, name="<memory>"):
        self.data = data
        self.name = name
        if len(data) < TOC_OFF + ENTRY_SIZE:
            raise IfpError("%s: 文件太短，不可能是 IAGS_IFP_01" % name)
        if data[:len(MAGIC_PREFIX)] != MAGIC_PREFIX:
            raise IfpError("%s: 魔数不匹配：%r" % (name, data[:16]))
        if data[:16] != MAGIC_FIELD:
            # 只容忍尾部补齐差异；记录但不致命
            sys.stderr.write("警告: %s 的魔数区不是 'IAGS_IFP_01' + 5 空格: %r\n" % (name, data[:16]))
        self.entry0 = Entry(0, *struct.unpack_from(ENTRY_FMT, data, TOC_OFF))
        if self.entry0.type != TYPE_TOC:
            raise IfpError("%s: 槽 0 的 type=%d，不是 1（TOC 描述符），需要重新分析" % (
                name, self.entry0.type))
        if self.entry0.offset != TOC_OFF:
            raise IfpError("%s: 槽 0 的 offset=0x%X，不是 0x%X" % (name, self.entry0.offset, TOC_OFF))
        self.header_size = self.entry0.size
        if self.header_size < 2 * ENTRY_SIZE or (self.header_size % ENTRY_SIZE) != 0:
            raise IfpError("%s: TOC 大小 0x%X 不合理（不是 16 的整数倍）" % (name, self.header_size))
        self.data_start = self.entry0.offset + self.header_size
        if self.data_start > len(data):
            raise IfpError("%s: 数据起点 0x%X 超出文件大小 0x%X" % (name, self.data_start, len(data)))
        self.slot_count = self.header_size // ENTRY_SIZE
        self.entries = []
        self._read_toc()

    def _read_toc(self):
        for i in range(self.slot_count):
            off = TOC_OFF + i * ENTRY_SIZE
            type_, type2, offset, size, size2 = struct.unpack_from(ENTRY_FMT, self.data, off)
            if not (type_ or type2 or offset or size or size2):
                continue
            self.entries.append(Entry(i, type_, type2, offset, size, size2))

    # ---- 结构校验 -------------------------------------------------------
    def check_layout(self):
        """返回 (warnings, gaps)。要求数据区无空洞、覆盖到文件末尾。"""
        warnings = []
        gaps = []
        real = [e for e in self.entries if e.type != TYPE_TOC]
        pos = self.data_start
        for e in sorted(real, key=lambda x: x.offset):
            if e.offset > pos:
                gaps.append((pos, e.offset - pos))
            elif e.offset < pos:
                warnings.append("槽 %d 与前一条目重叠：offset=0x%X < 已用 0x%X" % (e.index, e.offset, pos))
            pos = max(pos, e.offset + e.size + e.size2)
        if pos != len(self.data):
            gaps.append((pos, len(self.data) - pos))
        for e in real:
            if e.offset + e.size + e.size2 > len(self.data):
                warnings.append("槽 %d 越界：end=0x%X > 文件 0x%X" % (
                    e.index, e.offset + e.size + e.size2, len(self.data)))
        return warnings, gaps

    def block(self, entry):
        return self.data[entry.offset:entry.offset + entry.size]

    def block2(self, entry):
        if not entry.size2:
            return b""
        return self.data[entry.offset + entry.size:entry.offset + entry.size + entry.size2]


# ---------------------------------------------------------------------------
# 命令实现
# ---------------------------------------------------------------------------

def load_ifp(path):
    with open(path, "rb") as f:
        return IfpFile(f.read(), os.path.basename(path))


def cmd_list(args):
    ifp = load_ifp(args.ifp)
    print("文件            : %s" % args.ifp)
    print("大小            : %d (0x%X)" % (len(ifp.data), len(ifp.data)))
    print("SHA-256         : %s" % sha256_bytes(ifp.data))
    print("槽 0 描述符     : type=%d type2=%d offset=0x%X size=0x%X size2=%d" % (
        ifp.entry0.type, ifp.entry0.type2, ifp.entry0.offset, ifp.entry0.size, ifp.entry0.size2))
    print("TOC 槽位        : %d（数据起点 0x%X）" % (ifp.slot_count, ifp.data_start))
    print("已用条目        : %d" % len(ifp.entries))
    print()
    print("%-6s %-5s %-6s %-12s %-12s %-12s %s" % (
        "index", "type", "type2", "offset", "size", "size2", "载荷签名"))
    for e in ifp.entries:
        sig = "-"
        if e.type != TYPE_TOC:
            sig = payload_signature(ifp.block(e))
            if e.size2:
                sig += " + " + payload_signature(ifp.block2(e))
        print("%-6d %-5d %-6d 0x%010X 0x%010X 0x%010X %s" % (
            e.index, e.type, e.type2, e.offset, e.size, e.size2, sig))
    warnings, gaps = ifp.check_layout()
    for w in warnings:
        print("警告: " + w)
    for (off, ln) in gaps:
        print("空洞: 0x%X 起 %d 字节未被任何条目覆盖" % (off, ln))
    return 0


def cmd_diagnose(args):
    ifp = load_ifp(args.ifp)
    stats = {}
    for e in ifp.entries:
        if e.type == TYPE_TOC:
            continue
        sig = payload_signature(ifp.block(e))
        stats.setdefault((e.type, sig), 0)
        stats[(e.type, sig)] += 1
        if e.size2:
            sig2 = payload_signature(ifp.block2(e))
            stats.setdefault((e.type2, sig2), 0)
            stats[(e.type2, sig2)] += 1
    print("块签名统计（type, 签名）-> 数量：")
    for k in sorted(stats):
        print("  %-18s %d" % (str(k), stats[k]))
    warnings, gaps = ifp.check_layout()
    print("布局警告: %d 条，空洞: %d 处" % (len(warnings), len(gaps)))
    for w in warnings:
        print("  " + w)
    for (off, ln) in gaps:
        print("  空洞 0x%X +%d" % (off, ln))
    return 0


def entry_filename(stem, index, type_, suffix="", offset=0):
    """GARbro 风格命名：<封装名>#<5 位序号><后缀><扩展名>。

    默认序号用真实槽号（= 运行时资源号 / 脚本号）。
    offset=1 时改用 GARbro 的顺序号（槽号 - 1，因为它把 TOC 描述符槽也数进去了）。
    脚本块不带扩展名，图片按类型带 .bmp / .png。
    """
    return "%s#%05d%s%s" % (stem, index - offset, suffix, TYPE_EXT.get(type_, ""))


def cmd_unpack(args):
    ifp = load_ifp(args.ifp)
    outdir = args.output or (os.path.splitext(os.path.basename(args.ifp))[0] + "_unpacked")
    if os.path.exists(outdir) and os.listdir(outdir) and not args.force:
        raise IfpError("输出目录 %s 非空；加 --force 覆盖" % outdir)
    os.makedirs(outdir, exist_ok=True)

    warnings, gaps = ifp.check_layout()
    if gaps and not args.allow_gaps:
        raise IfpError("封包存在未被条目覆盖的区域：%r（加 --allow-gaps 会把这些字节写成 _gap_*.bin）" % (gaps,))

    manifest = {
        "format": "IAGS_IFP_01",
        "source": os.path.basename(args.ifp),
        "source_size": len(ifp.data),
        "source_sha256": sha256_bytes(ifp.data),
        "toc": {
            "offset": ifp.entry0.offset,
            "header_size": ifp.header_size,
            "slots": ifp.slot_count,
            "entry_size": ENTRY_SIZE,
            "slot0": {
                "type": ifp.entry0.type,
                "type2": ifp.entry0.type2,
                "offset": ifp.entry0.offset,
                "size": ifp.entry0.size,
                "size2": ifp.entry0.size2,
            },
        },
        "codec": "raw",
        "compression": "none",
        "encryption": "none",
        "entries": [],
    }

    stem = os.path.splitext(os.path.basename(args.ifp))[0]
    num_off = 1 if args.garbro else 0

    for e in ifp.entries:
        if e.type == TYPE_TOC:
            continue
        rec = {
            "index": e.index,
            "type": e.type,
            "type2": e.type2,
            "size": e.size,
            "sha256": sha256_bytes(ifp.block(e)),
        }
        name = entry_filename(stem, e.index, e.type, offset=num_off)
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(ifp.block(e))
        rec["file"] = name
        if e.size2:
            name2 = entry_filename(stem, e.index, e.type2, "_b", offset=num_off)
            with open(os.path.join(outdir, name2), "wb") as f:
                f.write(ifp.block2(e))
            rec["size2"] = e.size2
            rec["sha256_2"] = sha256_bytes(ifp.block2(e))
            rec["file2"] = name2
        manifest["entries"].append(rec)

    gaps_out = []
    for n, (off, ln) in enumerate(gaps):
        gname = "_gap_%02d_0x%08X.bin" % (n, off)
        with open(os.path.join(outdir, gname), "wb") as f:
            f.write(ifp.data[off:off + ln])
        gaps_out.append({"offset": off, "size": ln, "file": gname})
    if gaps_out:
        manifest["gaps"] = gaps_out

    with open(os.path.join(outdir, "ifp_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print("已解包 %s -> %s" % (args.ifp, outdir))
    print("  条目 %d 个（含 %d 个双载荷）" % (
        len(manifest["entries"]),
        sum(1 for r in manifest["entries"] if r.get("file2"))))
    if gaps_out:
        print("  未覆盖区域 %d 处已另存为 _gap_*.bin" % len(gaps_out))
    for w in warnings:
        print("  警告: " + w)
    return 0


def cmd_pack(args):
    src = args.input
    if os.path.isdir(src):
        manifest_path = os.path.join(src, "ifp_manifest.json")
    else:
        manifest_path = src
        src = os.path.dirname(os.path.abspath(manifest_path)) or "."
    if not os.path.isfile(manifest_path):
        raise IfpError("找不到 ifp_manifest.json：%s" % manifest_path)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    if manifest.get("codec", "raw") != "raw":
        raise IfpError("manifest 声明的 codec=%r，本工具只实现 raw；"
                       "遇到压缩/加密封包需要先补 codec 实现" % manifest.get("codec"))

    toc_info = manifest["toc"]
    header_size = int(toc_info["header_size"])
    if header_size < 2 * ENTRY_SIZE or header_size % ENTRY_SIZE:
        raise IfpError("manifest 的 TOC 大小 0x%X 不合法" % header_size)

    records = sorted(manifest["entries"], key=lambda r: int(r["index"]))
    if len(records) > header_size // ENTRY_SIZE:
        raise IfpError("条目数 %d 超出 TOC 容量 %d" % (len(records), header_size // ENTRY_SIZE))

    toc = bytearray(header_size)
    struct.pack_into(ENTRY_FMT, toc, 0, TYPE_TOC, 0, TOC_OFF, header_size, 0)

    data_parts = []
    pos = TOC_OFF + header_size
    for r in records:
        idx = int(r["index"])
        if idx <= 0 or idx >= header_size // ENTRY_SIZE:
            raise IfpError("条目 index=%d 超出槽位范围 1..%d" % (idx, header_size // ENTRY_SIZE - 1))
        t1 = int(r["type"])
        t2 = int(r.get("type2", 0))
        p1 = os.path.join(src, r["file"])
        if not os.path.isfile(p1):
            raise IfpError("缺少载荷文件：%s（槽 %d）" % (p1, idx))
        b1 = open(p1, "rb").read()
        b2 = b""
        if r.get("file2") or int(r.get("size2", 0)):
            p2 = os.path.join(src, r["file2"])
            if not os.path.isfile(p2):
                raise IfpError("缺少第二载荷文件：%s（槽 %d）" % (p2, idx))
            b2 = open(p2, "rb").read()
        struct.pack_into(ENTRY_FMT, toc, idx * ENTRY_SIZE, t1, t2, pos, len(b1), len(b2))
        data_parts.append(b1)
        data_parts.append(b2)
        pos += len(b1) + len(b2)

    out = args.output
    with open(out, "wb") as f:
        f.write(MAGIC_FIELD)
        f.write(toc)
        for part in data_parts:
            f.write(part)

    total = TOC_OFF + header_size + sum(len(p) for p in data_parts)
    print("已封包 %d 个条目 -> %s（%d 字节）" % (len(records), out, total))
    if manifest.get("source_sha256"):
        got = sha256_file(out)
        if got == manifest["source_sha256"]:
            print("  与原封包逐字节一致：SHA-256 %s" % got)
        else:
            print("  注意：与原封包不一致")
            print("    原始 : %s" % manifest["source_sha256"])
            print("    重建 : %s" % got)
    return 0


def cmd_verify(args):
    ifp_path = args.ifp
    original = sha256_file(ifp_path)
    tmp = tempfile.mkdtemp(prefix="ifp_verify_")
    try:
        outdir = os.path.join(tmp, "unpacked")
        cmd_unpack(argparse.Namespace(ifp=ifp_path, output=outdir, force=True,
                                      allow_gaps=False, garbro=False))
        rebuild = os.path.join(tmp, "rebuild.ifp")
        cmd_pack(argparse.Namespace(input=outdir, output=rebuild))
        rebuilt = sha256_file(rebuild)
        same = (rebuilt == original)
        size_o = os.path.getsize(ifp_path)
        size_r = os.path.getsize(rebuild)
        print()
        print("round-trip 结果: %s" % ("逐字节一致" if same else "不一致"))
        print("  原始  %10d 字节  %s" % (size_o, original))
        print("  重建  %10d 字节  %s" % (size_r, rebuilt))
        return 0 if same else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build_parser():
    p = argparse.ArgumentParser(
        description="IAGS_IFP_01 封包工具（真冬外伝 / IAGS 引擎）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python ifp_tool.py list SCR.IFP\n"
               "  python ifp_tool.py unpack GRP.IFP -o grp_unpacked\n"
               "  python ifp_tool.py pack grp_unpacked -o GRP.rebuild.IFP\n"
               "  python ifp_tool.py verify SCR.IFP\n")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="列出 TOC 条目")
    sp.add_argument("ifp")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("diagnose", help="统计块签名与布局，不解包")
    sp.add_argument("ifp")
    sp.set_defaults(func=cmd_diagnose)

    sp = sub.add_parser("unpack", help="解包到目录（含 ifp_manifest.json）")
    sp.add_argument("ifp")
    sp.add_argument("-o", "--output")
    sp.add_argument("--force", action="store_true", help="允许写入非空输出目录")
    sp.add_argument("--allow-gaps", action="store_true",
                    help="允许未被条目覆盖的区域，另存为 _gap_*.bin")
    sp.add_argument("--garbro", action="store_true",
                    help="文件名用 GARbro 的顺序号（槽号-1）而不是真实槽号")
    sp.set_defaults(func=cmd_unpack)

    sp = sub.add_parser("pack", help="从解包目录重新封包")
    sp.add_argument("input", help="解包目录或 ifp_manifest.json")
    sp.add_argument("-o", "--output", required=True)
    sp.set_defaults(func=cmd_pack)

    sp = sub.add_parser("verify", help="解包->重封包并逐字节比对")
    sp.add_argument("ifp")
    sp.set_defaults(func=cmd_verify)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except IfpError as e:
        sys.stderr.write("错误: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
