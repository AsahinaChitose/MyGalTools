#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ifx_tool.py -- Konna.exe (こんなアタシでも…) 的 .ifx 封包解包 / 封包工具

格式（依据 Konna.exe 静态分析 + 样本逐字节验证）
------------------------------------------------
.ifx 文件 = 固定 0x10000 字节目录区 + 从 0x10000 开始的数据区

目录区（0x10000）：
    +0x00  64 字节文件头（不以常规结构解析，原样保留）
           实测两个样本均为：u32 0x65, u32 0, u32 0x10000, 其余 0
    +0x20  2047 条记录，每条 32 字节，每条记录由两个 16 字节槽位组成：

        槽位（16 字节，小端）：
            +0  u16 type    资源类型：2=BMP, 3=JPEG, 11/12/13=脚本
            +2  u16 flag    标志（脚本包为 0xFFFF，图片包为 0）
            +4  u32 offset  数据区偏移（相对文件开头）
            +8  u32 size    长度
            +12 u32 extra   附加字段（脚本包为 0xFFFFFFFF，图片包为 0）

        记录 i 的主槽位（A）对应游戏内编号 id = i + 1；
        游戏读取图片时用 A.offset/A.size + 记录 B 槽位的 type；
        未使用槽位的 offset 等于当时写入游标（0 表示纯填充）。

数据区：所有非空槽位按记录顺序、A 后 B 依次连续存放，无压缩、无加密。
    GRP.ifx 中的块是标准 JPEG / BMP 原始字节；SCR.ifx 中的块是脚本 VM 字节码。

用法
----
    python ifx_tool.py list    <archive.ifx>
    python ifx_tool.py unpack  <archive.ifx> [-o <目录>]
    python ifx_tool.py pack    <目录> [-o <archive.ifx>]
    python ifx_tool.py verify  <archive.ifx> [--work <临时目录>] [--keep]

解包产物：
    <目录>/manifest.json    文件头、2047 条记录的类型/标志/附加字段与文件映射
    <目录>/entries/0000_A.bin, 0000_B.bin ...   每个非空槽位一个文件

重新封包时按 manifest 顺序写回数据区并重算 offset/size，
未改动的输入可做到与源文件 SHA-256 完全一致（verify 会自动检查）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MAGIC_EXPECTED = 0x65
HEADER_SIZE = 0x20          # 文件头长度
RECORD_SIZE = 0x20          # 32 字节记录 = 2 个 16 字节槽位
SLOT_SIZE = 0x10
DIRECTORY_SIZE = 0x10000    # 目录区固定大小，也是数据区起始偏移
RECORD_COUNT = (DIRECTORY_SIZE - HEADER_SIZE) // RECORD_SIZE  # 2047
SLOT_NAMES = ("A", "B")

# 资源类型
TYPE_NONE = 0
TYPE_BMP = 2
TYPE_JPEG = 3

TYPE_NAMES = {
    0: "empty",
    2: "bmp",
    3: "jpeg",
    11: "script/11",
    12: "script/12",
    13: "script/13",
}


def _utf8_stdout() -> None:
    """控制台按本机编码输出；被重定向/管道时用 UTF-8，保证中文不乱码。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            if getattr(stream, "isatty", lambda: False)():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # pragma: no cover - 老版本解释器
            pass


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_type(data: bytes) -> int:
    """按文件头推断资源类型，仅用于新增条目时补全 type。"""
    if data[:2] == b"BM":
        return TYPE_BMP
    if data[:3] == b"\xff\xd8\xff":
        return TYPE_JPEG
    return TYPE_NONE


@dataclass
class Slot:
    type: int
    flag: int
    offset: int
    size: int
    extra: int
    path: Optional[str] = None   # 解包后对应的相对文件路径
    zero: bool = False           # 原本是否为 16 字节全零填充

    @property
    def empty(self) -> bool:
        return self.size == 0

    def to_json(self) -> Dict:
        d = {
            "type": self.type,
            "flag": self.flag,
            "extra": self.extra,
            "offset": self.offset,
            "size": self.size,
        }
        if self.path:
            d["file"] = self.path
        if self.empty:
            d["padding"] = "zero" if self.zero else "running"
        return d


@dataclass
class Record:
    index: int
    slots: List[Slot] = field(default_factory=list)

    @property
    def id(self) -> int:
        return self.index + 1

    def to_json(self) -> Dict:
        return {
            "index": self.index,
            "id": self.id,
            "A": self.slots[0].to_json(),
            "B": self.slots[1].to_json(),
        }


class IfxError(Exception):
    pass


def read_archive(path: str) -> Tuple[bytes, bytes, List[Record], bytes]:
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < DIRECTORY_SIZE:
        raise IfxError("文件小于 0x10000 字节，不是有效的 .ifx：%s" % path)
    header = raw[:HEADER_SIZE]
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic != MAGIC_EXPECTED:
        raise IfxError("文件头魔数不符（期望 0x%X，实际 0x%X）：%s"
                       % (MAGIC_EXPECTED, magic, path))
    records: List[Record] = []
    for i in range(RECORD_COUNT):
        base = HEADER_SIZE + i * RECORD_SIZE
        rec = Record(index=i)
        for h in range(2):
            t, fl, off, size, extra = struct.unpack_from("<HHIII", raw, base + h * SLOT_SIZE)
            zero = raw[base + h * SLOT_SIZE: base + (h + 1) * SLOT_SIZE] == b"\x00" * SLOT_SIZE
            if size and off + size > len(raw):
                raise IfxError("记录 %d%s 越界：offset=0x%X size=0x%X 超出文件长度 0x%X"
                               % (i, SLOT_NAMES[h], off, size, len(raw)))
            rec.slots.append(Slot(t, fl, off, size, extra, zero=zero))
        records.append(rec)
    data = raw[DIRECTORY_SIZE:]
    return header, data, records, raw


def check_layout(records: List[Record]) -> List[str]:
    """返回数据区布局告警：空洞 / 重叠 / 未使用尾部。"""
    warnings: List[str] = []
    cursor = 0
    for rec in records:
        for h, slot in enumerate(rec.slots):
            if not slot.size:
                continue
            expect = DIRECTORY_SIZE + cursor
            if slot.offset != expect:
                if slot.offset > expect:
                    warnings.append("记录 %d%s 前有 %d 字节无法归属的数据（偏移 0x%X）"
                                    % (rec.index, SLOT_NAMES[h], slot.offset - expect, expect))
                else:
                    warnings.append("记录 %d%s 与前一块重叠（偏移 0x%X < 期望 0x%X）"
                                    % (rec.index, SLOT_NAMES[h], slot.offset, expect))
            cursor = max(cursor, slot.offset + slot.size - DIRECTORY_SIZE)
    return warnings


def cmd_list(args: argparse.Namespace) -> int:
    header, _data, records, raw = read_archive(args.archive)
    df = struct.unpack_from("<8I", header, 0)
    print("文件: %s" % os.path.abspath(args.archive))
    print("大小: %d 字节 (0x%X)   SHA-256: %s" % (len(raw), len(raw), sha256_file(args.archive)))
    print("文件头: " + " ".join("%08X" % x for x in df))
    used = sum(1 for r in records for s in r.slots if s.size)
    print("记录: %d 条 × 2 槽位，非空槽位 %d 个" % (len(records), used))
    print()
    print("%-5s %-4s %-3s %-6s %10s %10s  %s" % ("id", "槽", "type", "flag", "offset", "size", "类型"))
    print("-" * 72)
    for rec in records:
        for h, slot in enumerate(rec.slots):
            if not slot.size and not slot.type:
                continue
            print("%-5d %-4s %-3d 0x%04X %10X %10X  %s%s" % (
                rec.id, SLOT_NAMES[h], slot.type, slot.flag, slot.offset, slot.size,
                TYPE_NAMES.get(slot.type, "?"),
                "" if slot.empty else ""))
    warns = check_layout(records)
    if warns:
        print("\n布局告警:")
        for w in warns[:20]:
            print("  - " + w)
        if len(warns) > 20:
            print("  ... 共 %d 条" % len(warns))
    return 0


def _slot_extension(blob: bytes) -> str:
    """GARbro 风格：按内容给扩展名（脚本 0x65 头 -> .ifx，图片 -> .bmp/.jpg）。"""
    if blob[:4] == b"\x65\x00\x00\x00":
        return ".ifx"
    if blob[:2] == b"BM":
        return ".bmp"
    if blob[:3] == b"\xff\xd8\xff":
        return ".jpg"
    return ""


def _slot_name(stem: str, record_index: int, half: int, blob: bytes) -> str:
    """GARbro 命名：<stem>#<5 位槽位号><扩展名>；槽位号 = 2*记录号 + 槽位(A=0,B=1)。"""
    return "%s#%05d%s" % (stem, record_index * 2 + half, _slot_extension(blob))


def cmd_unpack(args: argparse.Namespace) -> int:
    src = os.path.abspath(args.archive)
    outdir = os.path.abspath(args.output or (os.path.splitext(src)[0] + "_unpacked"))
    header, data, records, raw = read_archive(src)
    os.makedirs(outdir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(src))[0]

    used_names = set()
    for rec in records:
        for h, slot in enumerate(rec.slots):
            if not slot.size:
                continue
            blob = data[slot.offset - DIRECTORY_SIZE: slot.offset - DIRECTORY_SIZE + slot.size]
            if len(blob) != slot.size:
                raise IfxError("读取记录 %d%s 数据失败" % (rec.index, SLOT_NAMES[h]))
            name = _slot_name(stem, rec.index, h, blob)
            while name in used_names:  # 理论不会发生，防御性处理
                name = "_" + name
            used_names.add(name)
            with open(os.path.join(outdir, name), "wb") as f:
                f.write(blob)
            slot.path = name

    manifest = {
        "format": "IFX",
        "format_note": "0x10000 字节目录区 + 数据区；2047 条记录，每条 2 个 16 字节槽位",
        "source": os.path.basename(src),
        "source_size": len(raw),
        "source_sha256": sha256_file(src),
        "header_hex": header.hex(),
        "data_offset": DIRECTORY_SIZE,
        "record_count": RECORD_COUNT,
        "compression": "none",
        "encryption": "none",
        "layout_warnings": check_layout(records),
        "records": [r.to_json() for r in records],
    }
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)

    # 便于 diff / 检索的扁平清单
    with open(os.path.join(outdir, "entries.tsv"), "w", encoding="utf-8", newline="") as f:
        f.write("id\tslot\ttype\tflag\textra\toffset\tsize\tfile\n")
        for rec in records:
            for h, slot in enumerate(rec.slots):
                if not slot.size:
                    continue
                f.write("%d\t%s\t%d\t0x%04X\t0x%08X\t0x%X\t%d\t%s\n" % (
                    rec.id, SLOT_NAMES[h], slot.type, slot.flag, slot.extra,
                    slot.offset, slot.size, slot.path or ""))

    used = sum(1 for r in records for s in r.slots if s.size)
    types: Dict[int, int] = {}
    for r in records:
        for s in r.slots:
            if s.size:
                types[s.type] = types.get(s.type, 0) + 1
    print("已解包: %s" % src)
    print("输出目录: %s" % outdir)
    print("槽位: %d 个非空；类型统计: %s" % (
        used, ", ".join("%s=%d" % (TYPE_NAMES.get(k, k), v) for k, v in sorted(types.items()))))
    warns = manifest["layout_warnings"]
    if warns:
        print("布局告警 %d 条（scripts 包中空槽位 offset 惯例差异属正常）" % len(warns))
    print("压缩: 无    加密: 无    （块内即原始 JPEG/BMP/脚本字节码）")
    return 0


def _load_manifest(path: str) -> Dict:
    mpath = os.path.join(path, "manifest.json")
    if not os.path.isfile(mpath):
        raise IfxError("目录中缺少 manifest.json：%s" % path)
    with open(mpath, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_pack(args: argparse.Namespace) -> int:
    srcdir = os.path.abspath(args.directory)
    manifest = _load_manifest(srcdir)
    default_name = manifest.get("source") or (os.path.basename(srcdir.rstrip("\\/")) + ".ifx")
    out = os.path.abspath(args.output or default_name)
    if os.path.exists(out) and not args.force:
        raise IfxError("输出文件已存在，拒绝覆盖：%s\n如确认覆盖请加 --force" % out)
    header = bytes.fromhex(manifest["header_hex"])
    if len(header) != HEADER_SIZE:
        raise IfxError("manifest 中的 header_hex 长度异常")
    records_json = manifest["records"]
    if len(records_json) != RECORD_COUNT:
        raise IfxError("manifest 记录数 %d，应为 %d" % (len(records_json), RECORD_COUNT))

    # 读取每个槽位的数据（manifest 中的 file 字段；文件被删除即视为清空）
    payloads: Dict[Tuple[int, int], bytes] = {}
    meta: Dict[Tuple[int, int], Dict] = {}
    for rj in records_json:
        i = rj["index"]
        for h, key in enumerate(SLOT_NAMES):
            sj = rj[key]
            meta[(i, h)] = sj
            rel = sj.get("file")
            if not rel:
                continue
            fpath = os.path.join(srcdir, rel.replace("/", os.sep))
            if not os.path.isfile(fpath):
                print("警告: 记录 %d%s 的数据文件不存在，按空槽位处理: %s" % (i, key, rel))
                continue
            with open(fpath, "rb") as f:
                payloads[(i, h)] = f.read()

    directory = bytearray(header)
    chunks: List[bytes] = []
    cursor = 0  # 相对数据区起始的游标
    for i in range(RECORD_COUNT):
        for h in range(2):
            sj = meta[(i, h)]
            blob = payloads.get((i, h))
            if blob:
                t = int(sj.get("type") or 0)
                if t == 0:
                    t = detect_type(blob)
                    if t == 0:
                        raise IfxError("记录 %d%s 新增数据无法推断 type，请在 manifest 中填写 type" % (i, SLOT_NAMES[h]))
                    print("提示: 记录 %d%s 未指定 type，按文件头推断为 %d" % (i, SLOT_NAMES[h], t))
                directory += struct.pack("<HHIII", t, int(sj.get("flag") or 0),
                                         DIRECTORY_SIZE + cursor, len(blob), int(sj.get("extra") or 0))
                chunks.append(blob)
                cursor += len(blob)
            else:
                pad = sj.get("padding")
                if pad not in ("zero", "running"):
                    pad = "zero" if not any([sj.get("type"), sj.get("flag"), sj.get("extra")]) else "running"
                if pad == "zero":
                    directory += b"\x00" * SLOT_SIZE
                else:
                    directory += struct.pack("<HHIII", int(sj.get("type") or 0),
                                             int(sj.get("flag") or 0),
                                             DIRECTORY_SIZE + cursor, 0,
                                             int(sj.get("extra") or 0))

    if len(directory) != DIRECTORY_SIZE:
        raise IfxError("目录区长度异常: %d" % len(directory))

    tmp = out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(directory)
        for blob in chunks:
            f.write(blob)
    os.replace(tmp, out)

    size = os.path.getsize(out)
    print("已封包: %s" % out)
    print("输出大小: %d 字节 (0x%X)，槽位 %d 个，数据区 0x%X 字节" % (
        size, size, len(chunks), size - DIRECTORY_SIZE))
    src_hash = manifest.get("source_sha256")
    if src_hash:
        new_hash = sha256_file(out)
        same = "一致" if new_hash == src_hash else "不同"
        print("SHA-256: %s（与解包来源%s）" % (new_hash, same))
        if new_hash != src_hash:
            print("  提示: 若你修改过条目内容或大小，此处不同属预期；未改动时应完全一致。")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    src = os.path.abspath(args.archive)
    work = os.path.abspath(args.work) if args.work else tempfile.mkdtemp(prefix="ifx_verify_")
    outdir = os.path.join(work, os.path.splitext(os.path.basename(src))[0] + "_unpacked")
    rebuild = os.path.join(work, os.path.splitext(os.path.basename(src))[0] + ".rebuild.ifx")
    try:
        cmd_unpack(argparse.Namespace(archive=src, output=outdir))
        print()
        cmd_pack(argparse.Namespace(directory=outdir, output=rebuild))
        a, b = sha256_file(src), sha256_file(rebuild)
        print()
        if a == b:
            print("[通过] 解包→封包 round-trip 逐字节一致")
            print("  %s" % a)
        else:
            print("[失败] round-trip 不一致")
            print("  原始: %s" % a)
            print("  重建: %s" % b)
            return 1
        return 0
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("工作目录保留: %s" % work)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Konna.exe .ifx 封包解包/封包工具（GRP.ifx 图片、SCR.ifx 脚本）")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("list", help="列出目录条目")
    q.add_argument("archive")
    q.set_defaults(func=cmd_list)

    q = sub.add_parser("unpack", help="解包为 manifest.json + entries/")
    q.add_argument("archive")
    q.add_argument("-o", "--output", help="输出目录（默认 <archive>_unpacked）")
    q.set_defaults(func=cmd_unpack)

    q = sub.add_parser("pack", help="从解包目录重新封包")
    q.add_argument("directory", help="含 manifest.json 的解包目录")
    q.add_argument("-o", "--output", help="输出 .ifx（默认与解包来源同名）")
    q.add_argument("-f", "--force", action="store_true", help="允许覆盖已存在的输出文件")
    q.set_defaults(func=cmd_pack)

    q = sub.add_parser("verify", help="解包→重封包并比对 SHA-256")
    q.add_argument("archive")
    q.add_argument("--work", help="临时工作目录")
    q.add_argument("--keep", action="store_true", help="保留临时工作目录")
    q.set_defaults(func=cmd_verify)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    _utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except IfxError as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
