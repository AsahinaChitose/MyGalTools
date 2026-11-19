#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""disassembler.py -- こんなアタシでも… 脚本（SCR.ifx）与文本库（MSG.dat）的反汇编器

用法：
    python disassembler.py <脚本文件或目录> [-o <输出目录或文件>] [--encoding utf-16-le] [--msg MSG.dat]

输入可以是：
    * SCR.ifx 封包（自动遍历其中 type 11/12/13 的脚本）
    * 一个目录（里面是从 SCR.ifx 解出的脚本块，可带 SCR#00000.ifx 这种 GARbro 命名）
    * 单个脚本块文件

输出：UTF-8 的 asm.txt（每个脚本一个），文本以 MSG.dat 为源内联在 MSG 指令处。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import opcodelist as OPC
import ifx_tool

REC_SIZE = 20
MSG_METADATA_SIZE = 0xC3500      # MSG.dat 前 800000 字节：100000 条 (start,count)
MSG_SLOT_SIZE = 64               # 文本槽 64 字节 = 32 个 UTF-16 单元
MSG_MAX_UNITS = MSG_SLOT_SIZE // 2 - 0   # 槽位容量（含结尾 0 之外可放 31~32 字）
MSG_SOFT_UNITS = 24              # 引擎逐行读取上限（sub_46D990 中 0x18）

SCRIPT_TYPES = (11, 12, 13)


# ---------------------------------------------------------------- 编码与转义

def _utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if getattr(stream, "isatty", lambda: False)():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def display_width(text: str) -> float:
    """按全角=1、半角=0.5 计算显示宽度（与引擎换行口径一致）。"""
    import unicodedata
    return sum(1.0 if unicodedata.east_asian_width(ch) in ("W", "F", "A") else 0.5
               for ch in text)


def escape_text(text: str) -> str:
    out = []
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\u%04X" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def unescape_text(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(text):
            raise ValueError("字符串以反斜杠结尾")
        nxt = text[i + 1]
        if nxt == "n":
            out.append("\n")
            i += 2
        elif nxt == "r":
            out.append("\r")
            i += 2
        elif nxt == "t":
            out.append("\t")
            i += 2
        elif nxt == '"':
            out.append('"')
            i += 2
        elif nxt == "\\":
            out.append("\\")
            i += 2
        elif nxt == "u" and i + 5 < len(text) + 1:
            hexpart = text[i + 2:i + 6]
            if len(hexpart) != 4 or re.fullmatch(r"[0-9A-Fa-f]{4}", hexpart) is None:
                raise ValueError("非法的 \\u 转义: %r" % text[i:i + 6])
            out.append(chr(int(hexpart, 16)))
            i += 6
        else:
            raise ValueError("未知转义 \\%s" % nxt)
    return "".join(out)


# ---------------------------------------------------------------- 脚本记录

Record = Tuple[int, int, int, int, int, int, int, int]   # cmd,P1,P2,P3,P4,P5,flags,P6


def parse_records(blob: bytes) -> List[Record]:
    if len(blob) % REC_SIZE:
        raise ValueError("脚本长度 %d 不是 20 的整数倍" % len(blob))
    recs = []
    for off in range(0, len(blob), REC_SIZE):
        cmd, _pad, p1, p2, p3, p4, p5, flags, p6 = struct.unpack_from("<HHIHHHHHH", blob, off)
        recs.append((cmd, p1, p2, p3, p4, p5, flags, p6))
    return recs


def pack_records(recs: Sequence[Record]) -> bytes:
    out = bytearray()
    for cmd, p1, p2, p3, p4, p5, flags, p6 in recs:
        out += struct.pack("<HHIHHHHHH", cmd, 0, p1, p2, p3, p4, p5, flags, p6)
    return bytes(out)


def infer_vmtype(recs: Sequence[Record]) -> int:
    """按跳转目标推断脚本槽位类型（1/2/3），用于没有目录信息的散装脚本。"""
    n = len(recs)
    targets = []
    for cmd, p1, p2, p3, p4, p5, flags, p6 in recs:
        spec = OPC.OPCODES.get(cmd)
        if spec and spec["kind"] == "jump":
            if cmd in (201, 211):
                targets.append(p1)
            elif cmd in (202, 203, 204, 205, 206, 207, 212, 213, 214, 215, 216, 217):
                targets.append(p3)
    best = 3
    best_score = -1
    for vt in (1, 2, 3):
        base = OPC.record_base(vt)
        score = sum(1 for t in targets if base <= t < base + n)
        if score > best_score:
            best, best_score = vt, score
    return best


# ---------------------------------------------------------------- MSG.dat

class MsgDb:
    """MSG.dat = 0xC3500 字节的 (start,count) 表 + 64 字节槽位文本池。"""

    def __init__(self, path: Optional[str] = None, fallback_encoding: str = "utf-16-le"):
        self.path = path
        self.header = b""
        self.entries: Dict[int, Tuple[int, int]] = {}   # msg id -> (start, count)
        self.lines: Dict[int, List[str]] = {}           # msg id -> [line...]
        self.order: List[int] = []                       # 按 start 排序的 msg id
        self.fallback_encoding = fallback_encoding
        if path:
            self.load(path)

    def _decode_line(self, seg: bytes) -> str:
        text = seg.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        if text.count("\ufffd") * 2 > len(text):  # UTF-16 解码失败，退回备用编码
            try:
                text = seg.split(b"\x00", 1)[0].decode(self.fallback_encoding, errors="replace")
            except LookupError:
                pass
        return text

    def load(self, path: str) -> None:
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) < MSG_METADATA_SIZE:
            raise ValueError("MSG.dat 小于 0xC3500 字节：%s" % path)
        self.path = path
        self.header = raw[:MSG_METADATA_SIZE]
        pool = raw[MSG_METADATA_SIZE:]
        slots = len(pool) // MSG_SLOT_SIZE
        for idx in range(MSG_METADATA_SIZE // 8):
            start, count = struct.unpack_from("<II", self.header, idx * 8)
            if count == 0:
                continue
            msg_id = idx + 1
            self.entries[msg_id] = (start, count)
            lines = []
            for k in range(count):
                off = (start - 1 + k) * MSG_SLOT_SIZE
                seg = pool[off:off + MSG_SLOT_SIZE]
                if len(seg) < MSG_SLOT_SIZE:
                    lines.append("")
                    continue
                text = self._decode_line(seg)
                lines.append(text)
            self.lines[msg_id] = lines
        self.order = sorted(self.entries, key=lambda m: self.entries[m][0])

    def exists(self, msg_id: int) -> bool:
        return msg_id in self.entries

    def text(self, msg_id: int) -> Optional[List[str]]:
        return self.lines.get(msg_id)

    def set_text(self, msg_id: int, lines: List[str]) -> None:
        old = self.lines.get(msg_id)
        if old is None:
            # 新消息：追加到末尾（不改变已有消息的相对顺序）
            self.lines[msg_id] = list(lines)
            self.order.append(msg_id)
        else:
            self.lines[msg_id] = list(lines)

    def build(self) -> bytes:
        """重建 MSG.dat：按消息原有 start 顺序重排文本池，未改动的表项原样保留。"""
        table = bytearray(self.header)
        pool = bytearray()
        cursor = 1
        placed = set()
        for msg_id in self.order:
            lines = self.lines.get(msg_id)
            if not lines:
                continue
            placed.add(msg_id)
            count = len(lines)
            table[8 * (msg_id - 1):8 * (msg_id - 1) + 8] = struct.pack("<II", cursor, count)
            for line in lines:
                units = len(line.encode("utf-16-le")) // 2
                if units >= MSG_SLOT_SIZE // 2:
                    raise ValueError("消息 %d 的行超过 32 个字符：%r" % (msg_id, line))
                slot = line.encode("utf-16-le")
                pool += slot + b"\x00" * (MSG_SLOT_SIZE - len(slot))
            cursor += count
        for msg_id, lines in self.lines.items():
            if msg_id in placed or not lines:
                continue
            count = len(lines)
            table[8 * (msg_id - 1):8 * (msg_id - 1) + 8] = struct.pack("<II", cursor, count)
            for line in lines:
                slot = line.encode("utf-16-le")
                if len(slot) >= MSG_SLOT_SIZE:
                    raise ValueError("消息 %d 的行超过 32 个字符：%r" % (msg_id, line))
                pool += slot + b"\x00" * (MSG_SLOT_SIZE - len(slot))
            cursor += count
        return bytes(table) + bytes(pool)


# ---------------------------------------------------------------- 脚本来源

@dataclass
class ScriptFile:
    name: str                 # 输出文件名主干
    path: str                 # 原始路径
    blob: bytes
    type_value: int           # SCR 目录里的 type（11/12/13），散装时为 0
    record_index: int = -1    # 在 .ifx 目录里的记录号（-1 表示未知）
    half: int = 0


def _looks_like_script(blob: bytes) -> bool:
    if not blob or len(blob) % REC_SIZE:
        return False
    if blob[:2] == b"BM" or blob[:3] == b"\xff\xd8\xff":
        return False
    return True


def collect_scripts(target: str) -> Tuple[List[ScriptFile], Optional[str]]:
    """返回 (脚本列表, 来源 .ifx 路径或 None)。"""
    target = os.path.abspath(target)
    if os.path.isdir(target):
        files = []
        for name in sorted(os.listdir(target)):
            full = os.path.join(target, name)
            if not os.path.isfile(full):
                continue
            with open(full, "rb") as f:
                blob = f.read()
            if not _looks_like_script(blob):
                continue
            stem = name
            m = re.search(r"#(\d+)", name)
            rec = int(m.group(1)) // 2 if m else -1
            files.append(ScriptFile(name=name + ".asm.txt", path=full, blob=blob,
                                    type_value=0, record_index=rec))
        return files, None
    if target.lower().endswith(".ifx") and os.path.getsize(target) >= ifx_tool.DIRECTORY_SIZE:
        with open(target, "rb") as f:
            magic = struct.unpack("<I", f.read(4))[0]
        if magic != 0x65:
            raise ValueError("不是 .ifx 封包（魔数 0x%X）：%s" % (magic, target))
        header, data, records, raw = ifx_tool.read_archive(target)
        out = []
        stem = os.path.splitext(os.path.basename(target))[0]
        for rec in records:
            for h, slot in enumerate(rec.slots):
                if not slot.size or slot.type not in SCRIPT_TYPES:
                    continue
                blob = data[slot.offset - ifx_tool.DIRECTORY_SIZE:
                            slot.offset - ifx_tool.DIRECTORY_SIZE + slot.size]
                name = ifx_tool._slot_name(stem, rec.index, h, blob) + ".asm.txt"
                out.append(ScriptFile(name=name, path=target, blob=blob,
                                      type_value=slot.type, record_index=rec.index, half=h))
        return out, target
    with open(target, "rb") as f:
        blob = f.read()
    if not _looks_like_script(blob):
        raise ValueError("不是脚本文件：%s" % target)
    return [ScriptFile(name=os.path.basename(target) + ".asm.txt", path=target,
                       blob=blob, type_value=0)], None


def find_msg_db(script_paths: Sequence[str], explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return os.path.abspath(explicit)
    seen = set()
    for p in script_paths:
        d = os.path.dirname(os.path.abspath(p))
        for _ in range(4):
            if d in seen:
                break
            seen.add(d)
            for cand in ("MSG.dat", "MSG.DAT", "msg.dat"):
                full = os.path.join(d, cand)
                if os.path.isfile(full):
                    return full
            nd = os.path.dirname(d)
            if nd == d:
                break
            d = nd
    return None


# ---------------------------------------------------------------- 反汇编

def _fmt_jump_target(rec_index_abs: int, base: int, n: int) -> str:
    if base <= rec_index_abs < base + n:
        return "loc_%05d" % (rec_index_abs - base)
    return str(rec_index_abs)


def disassemble_script(script: ScriptFile, msgdb: Optional[MsgDb],
                        emitted_text: Dict[int, str]) -> str:
    recs = parse_records(script.blob)
    n = len(recs)
    if script.type_value:
        vmtype = OPC.SCRIPT_TYPE_TO_VMTYPE[script.type_value]
    else:
        vmtype = infer_vmtype(recs)
    base = OPC.record_base(vmtype)

    # 找出所有跳转目标，用于生成标签
    labels = set()
    for cmd, p1, p2, p3, p4, p5, flags, p6 in recs:
        spec = OPC.OPCODES.get(cmd)
        if not spec or spec["kind"] != "jump":
            continue
        if cmd in (201, 211, 271, 272):
            target = p1
            if cmd in (271, 272):
                continue
        else:
            target = p3
        if base <= target < base + n:
            labels.add(target - base)

    out: List[str] = []
    out.append("; Konna script disassembly")
    out.append("; file       : %s" % script.name)
    out.append("; script type: %s (VM slot %d, base record %d)"
               % (script.type_value or "?", vmtype, base))
    out.append("; records    : %d" % n)
    out.append("; encoding   : utf-8")
    out.append("; msgdb      : %s" % (msgdb.path if msgdb else "未找到（MSG 指令不带文本）"))
    out.append("")
    out.append(".vmtype %d" % vmtype)
    out.append("")
    out.append("loc_%05d:" % 0)
    for k, rec in enumerate(recs):
        cmd, p1, p2, p3, p4, p5, flags, p6 = rec
        if k in labels:
            out.append("")
            out.append("loc_%05d:" % k)
        values = {"P1": p1, "P2": p2, "P3": p3, "P4": p4, "P5": p5, "P6": p6}
        spec = OPC.OPCODES.get(cmd)
        if spec is None:
            out.append("    RAW 0x%04X, 0x%08X, 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X"
                       % (cmd, p1, p2, p3, p4, p5, flags, p6))
            continue
        mnemonic = spec["mnemonic"]
        ops = []
        for name in spec["operands"]:
            if spec["kind"] == "jump" and not (cmd in (271, 272)):
                pos = spec["operands"].index(name)
                target_pos = 2 if cmd in (202, 203, 204, 205, 206, 207,
                                          212, 213, 214, 215, 216, 217) else 0
                if pos == target_pos:
                    ops.append(_fmt_jump_target(values[name], base, n))
                    continue
            ops.append(str(values[name]))
        line = "    %s" % mnemonic
        if ops:
            line += " " + ", ".join(ops)
        if flags and spec["kind"] != "end":
            line += ", flags=0x%04X" % flags
        if spec["kind"] == "text" and msgdb is not None:
            text = msgdb.text(p1)
            if text is not None:
                if p1 in emitted_text:
                    line += "   ; text defined in %s" % emitted_text[p1]
                else:
                    escaped = escape_text("\n".join(text))
                    line += '   "%s"' % escaped
                    if any(display_width(l) > MSG_SOFT_UNITS for l in text):
                        line += "   ; 警告: 该消息有行超过 %d 字，游戏会截断" % MSG_SOFT_UNITS
                    emitted_text[p1] = script.name
            else:
                line += "   ; 警告: MSG.dat 中不存在消息 %d" % p1
        out.append(line)
    out.append("")
    return "\n".join(out) + "\n"


def cmd_disassemble(args: argparse.Namespace) -> int:
    scripts, archive = collect_scripts(args.target)
    if not scripts:
        raise SystemExit("没有找到脚本")
    msg_path = find_msg_db([s.path for s in scripts], args.msg)
    msgdb = MsgDb(msg_path, args.encoding) if msg_path else None
    if msgdb is None:
        print("警告: 未找到 MSG.dat，MSG 指令将不带文本。可用 --msg 指定。")

    out = args.output
    if out is None:
        out = "asm_" + os.path.splitext(os.path.basename(os.path.abspath(args.target)))[0]
    single = len(scripts) == 1 and not os.path.isdir(args.target)
    if single and (out.lower().endswith(".txt") or out.lower().endswith(".asm")):
        outdir = os.path.dirname(os.path.abspath(out)) or "."
        os.makedirs(outdir, exist_ok=True)
        targets = [(scripts[0], os.path.abspath(out))]
    else:
        outdir = os.path.abspath(out)
        os.makedirs(outdir, exist_ok=True)
        targets = [(s, os.path.join(outdir, s.name)) for s in scripts]

    emitted: Dict[int, str] = {}
    total_cmds = 0
    for script, path in targets:
        text = disassemble_script(script, msgdb, emitted)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        total_cmds += len(text.splitlines())
    print("已反汇编 %d 个脚本 -> %s" % (len(targets), outdir))
    print("文本引用: %d 条消息" % len(emitted))
    if msgdb:
        print("文本库: %s（%d 条消息）" % (msgdb.path, len(msgdb.entries)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="こんなアタシでも… 脚本反汇编器（SCR.ifx + MSG.dat）")
    p.add_argument("target", help="SCR.ifx / 脚本目录 / 单个脚本文件")
    p.add_argument("-o", "--output", help="输出目录或 asm 文件（默认 asm_<名字>/）")
    p.add_argument("--encoding", default="utf-16-le", help="文本编码（默认 utf-16-le；本作文本库为 UTF-16LE）")
    p.add_argument("--msg", help="MSG.dat 路径（默认自动查找）")
    p.set_defaults(func=cmd_disassemble)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    _utf8_stdout()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, ifx_tool.IfxError) as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
