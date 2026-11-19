#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""assembler.py -- こんなアタシでも… 脚本汇编器

用法：
    python assembler.py <asm.txt 或目录> [-o <输出文件/目录>] [--encoding utf-16-le] [--ifx SCR.ifx] [--msg MSG.dat]

* 单个 asm.txt：重建一个脚本块，-o 指定输出文件。
* 目录：按文件名里的 #槽位号 对应回 SCR.ifx 的槽位，重建 SCR.ifx 与 MSG.dat。
  未在 asm 中出现的条目/消息保持模板原样。

asm 语法见 disassembler.py 的注释；文本只在一个 MSG 指令上内联定义，其余引用省略。
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
from typing import Dict, List, Optional, Sequence, Tuple

import opcodelist as OPC
import ifx_tool
from disassembler import (MSG_SOFT_UNITS, MsgDb, Record, REC_SIZE, display_width, escape_text, find_msg_db,
                          parse_records, pack_records, unescape_text, _utf8_stdout)


# ---------------------------------------------------------------- asm 解析

def _strip_comment(line: str) -> str:
    """去掉引号外的 ; 注释。"""
    out = []
    in_quote = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quote = False
            i += 1
            continue
        if ch == '"':
            in_quote = True
            out.append(ch)
            i += 1
            continue
        if ch == ";":
            break
        out.append(ch)
        i += 1
    return "".join(out).strip()


def _split_operands(text: str) -> List[str]:
    parts = []
    cur = []
    in_quote = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(text):
                cur.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quote = False
            i += 1
            continue
        if ch == '"':
            in_quote = True
            cur.append(ch)
            i += 1
            continue
        if ch == ",":
            parts.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _parse_number(tok: str) -> int:
    tok = tok.strip()
    if re.fullmatch(r"0[xX][0-9A-Fa-f]+", tok):
        return int(tok, 16)
    if re.fullmatch(r"-?\d+", tok):
        return int(tok, 10)
    raise ValueError("非法数字: %r" % tok)


class AsmError(Exception):
    pass


def parse_asm(path: str) -> Tuple[int, int, List[Record], Dict[int, List[str]], str]:
    """返回 (vmtype, base, records, texts, source_note)。"""
    with open(path, "r", encoding="utf-8-sig") as f:
        lines = f.read().splitlines()

    vmtype = 0
    records: List[Record] = []
    labels: Dict[str, int] = {}
    pending: List[Tuple[int, str, str, Optional[str], int]] = []  # (index, mnemonic, operands, text, flags)
    texts: Dict[int, List[str]] = {}

    for lineno, raw in enumerate(lines, 1):
        line = _strip_comment(raw)
        if not line:
            continue
        if line.startswith("."):
            m = re.match(r"\.vmtype\s+(\d+)", line)
            if m:
                vmtype = int(m.group(1))
                if vmtype not in (1, 2, 3):
                    raise AsmError("%s:%d 非法的 .vmtype" % (path, lineno))
                continue
            raise AsmError("%s:%d 未知伪指令 %r" % (path, lineno, line))
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):$", line)
        if m:
            label = m.group(1)
            if label in labels:
                raise AsmError("%s:%d 重复标签 %s" % (path, lineno, label))
            labels[label] = len(records) + len(pending)
            continue
        if line.endswith(":"):
            raise AsmError("%s:%d 非法标签: %s" % (path, lineno, line))

        name, _, rest = line.partition(" ")
        rest = rest.strip()
        text_value = None
        # 取出末尾的引号字符串（文本）
        if rest.endswith('"'):
            # 找到未转义的起始引号
            idx = len(rest) - 1
            in_esc = False
            start = -1
            j = 0
            while j < len(rest):
                if rest[j] == "\\":
                    j += 2
                    continue
                if rest[j] == '"':
                    start = j
                    break
                j += 1
            if start < 0:
                raise AsmError("%s:%d 引号不配对" % (path, lineno))
            text_value = unescape_text(rest[start + 1:-1])
            rest = rest[:start].strip()
            if rest.endswith(","):
                rest = rest[:-1].strip()

        flags = 0
        m = re.search(r"(?:^|,)\s*flags=0x([0-9A-Fa-f]+)\s*$", rest)
        if m:
            flags = int(m.group(1), 16)
            rest = rest[:m.start()].strip()
            if rest.endswith(","):
                rest = rest[:-1].strip()

        pending.append((len(records) + len(pending), name, rest, text_value, flags))

    base = OPC.record_base(vmtype) if vmtype else 0

    for idx, mnemonic, opstr, text_value, flags in pending:
        opcode = OPC.MNEMONIC_TO_OPCODE.get(mnemonic)
        if opcode is None and mnemonic.startswith("OP_"):
            try:
                opcode = int(mnemonic[3:], 16)
            except ValueError:
                opcode = None
        if mnemonic == "RAW":
            vals = [_parse_number(x) for x in _split_operands(opstr)]
            if len(vals) != 8:
                raise AsmError("%s:%d RAW 需要 8 个值" % (path, 1))
            records.append((vals[0] & 0xFFFF, vals[1] & 0xFFFFFFFF, vals[2] & 0xFFFF,
                            vals[3] & 0xFFFF, vals[4] & 0xFFFF, vals[5] & 0xFFFF,
                            vals[6] & 0xFFFF, vals[7] & 0xFFFF))
            continue
        if opcode is None:
            raise AsmError("%s: 未知助记符 %s" % (path, mnemonic))
        spec = OPC.OPCODES[opcode]
        if spec["kind"] == "end":
            records.append((OPC.END_MARKER, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                            0xFFFF, 0xFFFF, 0x0000))
            continue
        toks = _split_operands(opstr)
        if len(toks) != len(spec["operands"]):
            raise AsmError("%s: %s 需要 %d 个操作数，实际 %d 个：%s"
                           % (path, mnemonic, len(spec["operands"]), len(toks), opstr))
        fields = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0, "P6": 0}
        for name, tok in zip(spec["operands"], toks):
            if tok in labels:
                value = base + labels[tok]
            else:
                value = _parse_number(tok)
            fields[name] = value & 0xFFFFFFFF
        if spec["kind"] == "text":
            msg_id = fields["P1"]
            if text_value is not None:
                lines = text_value.split("\n")
                if msg_id in texts and texts[msg_id] != lines:
                    raise AsmError("%s: 消息 %d 的文本重复定义且不一致" % (path, msg_id))
                texts[msg_id] = lines
        records.append((opcode, fields["P1"], fields["P2"], fields["P3"],
                        fields["P4"], fields["P5"], flags, fields["P6"]))

    return vmtype, base, records, texts, os.path.basename(path)


# ---------------------------------------------------------------- 重建封包

def rebuild_ifx(template_path: str, replacements: Dict[Tuple[int, int], bytes],
                out_path: str) -> None:
    header, data, records, raw = ifx_tool.read_archive(template_path)
    table = bytearray(header)
    chunks: List[bytes] = []
    cursor = 0
    for rec in records:
        for h, slot in enumerate(rec.slots):
            repl = replacements.get((rec.index, h))
            if repl is not None:
                blob = repl
                t, fl, extra = slot.type, slot.flag, slot.extra
            else:
                blob = data[slot.offset - ifx_tool.DIRECTORY_SIZE:
                            slot.offset - ifx_tool.DIRECTORY_SIZE + slot.size] if slot.size else b""
                t, fl, extra = slot.type, slot.flag, slot.extra
            if blob:
                table += struct.pack("<HHIII", t, fl, ifx_tool.DIRECTORY_SIZE + cursor,
                                     len(blob), extra)
                chunks.append(blob)
                cursor += len(blob)
            else:
                pad = "zero" if slot.zero else "running"
                if pad == "zero":
                    table += b"\x00" * ifx_tool.SLOT_SIZE
                else:
                    table += struct.pack("<HHIII", t, fl, ifx_tool.DIRECTORY_SIZE + cursor, 0, extra)
    assert len(table) == ifx_tool.DIRECTORY_SIZE, len(table)
    with open(out_path, "wb") as f:
        f.write(bytes(table))
        for blob in chunks:
            f.write(blob)


def _entry_key(name: str) -> Optional[Tuple[int, int]]:
    m = re.search(r"#(\d+)", name)
    if not m:
        return None
    idx = int(m.group(1))
    return (idx // 2, idx % 2)


# ---------------------------------------------------------------- 主流程

def cmd_assemble(args: argparse.Namespace) -> int:
    target = os.path.abspath(args.target)
    if os.path.isdir(target):
        asm_files = []
        for name in sorted(os.listdir(target)):
            if name.lower().endswith(".asm.txt"):
                asm_files.append(os.path.join(target, name))
        if not asm_files:
            raise AsmError("目录中没有 *.asm.txt：%s" % target)
    else:
        asm_files = [target]

    all_records: Dict[str, List[Record]] = {}
    all_texts: Dict[int, List[str]] = {}
    vmtypes: Dict[str, int] = {}
    for path in asm_files:
        vmtype, base, records, texts, note = parse_asm(path)
        all_records[os.path.basename(path)] = records
        vmtypes[os.path.basename(path)] = vmtype
        for msg_id, lines in texts.items():
            if msg_id in all_texts and all_texts[msg_id] != lines:
                raise AsmError("消息 %d 在多个 asm 中定义且不一致" % msg_id)
            all_texts[msg_id] = lines

    out = args.output
    single = len(asm_files) == 1 and not os.path.isdir(target)
    if single and out and not out.lower().endswith(os.sep) and os.path.splitext(out)[1]:
        # 单文件 -> 单个脚本块
        records = all_records[os.path.basename(asm_files[0])]
        blob = pack_records(records)
        with open(out, "wb") as f:
            f.write(blob)
        print("已汇编脚本: %s（%d 条记录，%d 字节）" % (out, len(records), len(blob)))
        if all_texts:
            print("提示: 单文件模式不改写 MSG.dat；如需文本请用目录模式。")
        return 0

    outdir = os.path.abspath(out or "build")
    os.makedirs(outdir, exist_ok=True)

    # 1) MSG.dat
    msg_template = args.msg or find_msg_db([asm_files[0]], None)
    if all_texts and msg_template:
        db = MsgDb(msg_template, args.encoding)
        long_lines = 0
        for msg_id, lines in all_texts.items():
            for ln in lines:
                if display_width(ln) > MSG_SOFT_UNITS:
                    long_lines += 1
                    print("警告: 消息 %d 的一行有 %g 个全角字符（>%d，游戏会截断）：%r"
                          % (msg_id, display_width(ln), MSG_SOFT_UNITS, ln))
            if not db.exists(msg_id):
                print("警告: MSG.dat 模板中没有消息 %d，将追加到文本池末尾" % msg_id)
            db.set_text(msg_id, lines)
        msg_out = os.path.join(outdir, "MSG.dat")
        with open(msg_out, "wb") as f:
            f.write(db.build())
        print("已重建 %s（%d 条消息，%d 字节）" % (msg_out, len(db.lines), os.path.getsize(msg_out)))
    elif all_texts:
        print("警告: 未找到 MSG.dat 模板，跳过文本重建（--msg 可指定）")

    # 2) SCR.ifx
    ifx_template = args.ifx
    if not ifx_template:
        search_dirs = [os.path.dirname(asm_files[0]), os.getcwd()]
        d = os.path.dirname(asm_files[0])
        for _ in range(3):
            nd = os.path.dirname(d)
            if nd == d:
                break
            d = nd
            search_dirs.append(d)
        for d in search_dirs:
            p = os.path.join(d, "SCR.ifx")
            if os.path.isfile(p):
                ifx_template = p
                break
    if ifx_template:
        replacements = {}
        for name, records in all_records.items():
            key = _entry_key(name)
            if key is None:
                print("警告: %s 文件名没有 #槽位号，无法放回封包" % name)
                continue
            replacements[key] = pack_records(records)
        ifx_out = os.path.join(outdir, os.path.basename(ifx_template))
        rebuild_ifx(ifx_template, replacements, ifx_out)
        print("已重建 %s（%d 个槽位被替换）" % (ifx_out, len(replacements)))
    else:
        print("提示: 未找到 SCR.ifx 模板，仅输出脚本块。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="こんなアタシでも… 脚本汇编器")
    p.add_argument("target", help="asm.txt 或包含 *.asm.txt 的目录")
    p.add_argument("-o", "--output", help="输出文件（单脚本）或输出目录（多脚本）")
    p.add_argument("--encoding", default="utf-16-le", help="文本编码（默认 utf-16-le；本作文本库为 UTF-16LE）")
    p.add_argument("--ifx", help="SCR.ifx 模板路径（目录模式默认自动查找）")
    p.add_argument("--msg", help="MSG.dat 模板路径（默认自动查找）")
    p.set_defaults(func=cmd_assemble)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    _utf8_stdout()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, AsmError, ifx_tool.IfxError) as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
