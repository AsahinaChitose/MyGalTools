#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDT 脚本反汇编器  ——  鎖－クサリ－ (Kusari)

用法:
    python disassembler.py <脚本文件或目录> [-o <输出目录或文件>] [--encoding cp932]

输出为语义化汇编文本 (.asm.txt)：文件头/入口表/指令/内联 Shift-JIS 文本，
所有跳转目标使用标签，绝不输出原始十六进制转储。
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

import opcodelist as oc

MAGIC = b"L\x00F\x00"
HEADER_SIZE = oc.CODE_OFFSET
DISASM_ENCODING = oc.ENCODING


class DisasmError(Exception):
    pass


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def parse_sdt(path: Path):
    data = path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise DisasmError("文件太小，不是 SDT 脚本: %s" % path)
    if data[:4] != MAGIC:
        raise DisasmError("魔数不是 L\\0F\\0: %s" % path)
    total = struct.unpack_from("<I", data, 4)[0]
    if total != len(data):
        raise DisasmError("头部长度 0x%X 与文件大小 0x%X 不一致: %s" % (total, len(data), path))
    table = list(struct.unpack_from("<256I", data, 8))
    code = data[HEADER_SIZE:]
    return table, code


def read_variant(code: bytes, pos: int):
    """返回 (kind, value, size)，kind 为 reg/imm/str。"""
    t = code[pos]
    if t == 2:
        ln = code[pos + 1]
        s = code[pos + 2:pos + 2 + ln]
        if len(s) != ln:
            raise DisasmError("字符串越界 @0x%X" % pos)
        return "str", s, 2 + ln
    if t == 0:
        v = struct.unpack_from("<I", code, pos + 1)[0]
        return "reg", v, 5
    if t == 1:
        v = struct.unpack_from("<I", code, pos + 1)[0]
        return "imm", v, 5
    raise DisasmError("未知变体类型 %d @0x%X" % (t, pos))


def parse_insn(code: bytes, pc: int):
    if pc + 2 > len(code):
        raise DisasmError("指令越界 @0x%X" % pc)
    op = code[pc] | (code[pc + 1] << 8)
    info = oc.get_opcode(op)
    if info is None:
        raise DisasmError("未定义操作码 0x%04X @0x%X" % (op, pc))
    ops = info["ops"]
    out = []
    p = pc + 2
    for kind in ops:
        if kind == "imm8":
            out.append(("imm8", code[p]))
            p += 1
        elif kind == "imm16":
            out.append(("imm16", struct.unpack_from("<H", code, p)[0]))
            p += 2
        elif kind == "imm32":
            out.append(("imm32", struct.unpack_from("<I", code, p)[0]))
            p += 4
        elif kind == "label32":
            out.append(("label", struct.unpack_from("<I", code, p)[0]))
            p += 4
        elif kind == "reg8":
            out.append(("reg", code[p]))
            p += 1
        elif kind == "cond":
            out.append(("cond", code[p]))
            p += 1
        elif kind == "str8":
            ln = code[p]
            s = code[p + 1:p + 1 + ln]
            if len(s) != ln:
                raise DisasmError("字符串越界 @0x%X" % p)
            out.append(("str", s))
            p += 1 + ln
        elif kind == "str16":
            ln = struct.unpack_from("<H", code, p)[0]
            s = code[p + 2:p + 2 + ln]
            if len(s) != ln:
                raise DisasmError("字符串越界 @0x%X" % p)
            out.append(("str", s))
            p += 2 + ln
        elif kind == "variant":
            k, v, sz = read_variant(code, p)
            out.append(("variant", k, v))
            p += sz
        elif kind == "cmp":
            reg = code[p]
            cond = code[p + 1]
            k, v, sz = read_variant(code, p + 2)
            out.append(("cmp", reg, cond, k, v))
            p += 2 + sz
        elif kind == "callargs":
            n = struct.unpack_from("<h", code, p)[0]
            if n < 0:
                raise DisasmError("CALLX 参数长度非法 @0x%X" % pc)
            start = p + 2
            end = start + n
            if end > len(code):
                raise DisasmError("CALLX 参数越界 @0x%X" % pc)
            args = []
            q = start
            while q < end:
                t = code[q]
                if t == 0:
                    v = struct.unpack_from("<I", code, q + 1)[0]
                    # 5 字节: type 0 + imm32
                    if q + 5 > end:
                        raise DisasmError("CALLX 参数越界 @0x%X" % q)
                    args.append((0, v))
                    q += 5
                else:
                    args.append((t, code[q + 1]))
                    q += 2
            out.append(("callargs", args))
            p = end
        else:
            raise DisasmError("未知操作数类型 %r @0x%X" % (kind, pc))
    return op, out, p - pc


# ---------------------------------------------------------------------------
# 文本输出
# ---------------------------------------------------------------------------
def fmt_operand(opnd):
    kind = opnd[0]
    if kind in ("imm8", "imm16", "imm32", "reg", "cond", "label"):
        value = opnd[1]
    if kind == "imm8":
        return "0x%02X" % value
    if kind == "imm16":
        return "0x%04X" % value
    if kind == "imm32":
        return "0x%X" % value
    if kind == "reg":
        return "R%d" % value
    if kind == "cond":
        return oc.COND_NAMES.get(value, "0x%X" % value)
    if kind == "label":
        return "loc_%08X" % value
    if kind == "str":
        return '"%s"' % oc.decode_string(opnd[1], DISASM_ENCODING)
    if kind == "variant":
        vk, vv = opnd[1], opnd[2]
        if vk == "reg":
            return "R%d" % vv
        if vk == "str":
            return '"%s"' % oc.decode_string(vv, DISASM_ENCODING)
        return "0x%X" % vv
    if kind == "cmp":
        reg, cond, vk, vv = opnd[1], opnd[2], opnd[3], opnd[4]
        sub = "R%d" % vv if vk == "reg" else ('"%s"' % oc.decode_string(vv, DISASM_ENCODING) if vk == "str" else "0x%X" % vv)
        return "%s, %s, %s" % ("R%d" % reg, oc.COND_NAMES.get(cond, "0x%X" % cond), sub)
    if kind == "callargs":
        return ", ".join("0x%02X:0x%X" % (t, v) for t, v in opnd[1])
    raise DisasmError("未知操作数 %r" % (opnd,))


def insn_text(op, info, operands):
    parts = [info["mnemonic"]]
    if operands:
        parts.append(", ".join(fmt_operand(o) for o in operands))
    return "    " + " ".join(parts[:1]) + (" " + parts[1] if len(parts) > 1 else "")


def find_targets(code: bytes):
    """返回所有跳转目标 PC 集合。"""
    targets = set()
    pc = 0
    while pc < len(code):
        op, operands, size = parse_insn(code, pc)
        for item in operands:
            if item[0] == "label":
                targets.add(item[1])
        pc += size
    return targets


def disassemble(path: Path, encoding: str) -> str:
    global DISASM_ENCODING
    DISASM_ENCODING = encoding
    table, code = parse_sdt(path)
    targets = find_targets(code)
    lines = []
    lines.append("; ============================================================")
    lines.append("; SDT script disassembly")
    lines.append("; source       : %s" % path.name)
    lines.append("; encoding     : %s" % encoding)
    lines.append("; original size: 0x%X (%d bytes)" % (len(code) + HEADER_SIZE, len(code) + HEADER_SIZE))
    lines.append("; entry table  : 256 dwords")
    lines.append("; ============================================================")
    lines.append("")
    lines.append(".sdt")
    lines.append('.encoding "%s"' % encoding)
    lines.append(".original_size 0x%X" % (len(code) + HEADER_SIZE))
    for i, v in enumerate(table):
        if v:
            lines.append(".entry %d, 0x%08X" % (i, v))
    lines.append("")
    lines.append(".code")

    pc = 0
    prev_was_label = False
    while pc < len(code):
        op, operands, size = parse_insn(code, pc)
        info = oc.get_opcode(op)
        if pc in targets or pc == 0:
            if pc != 0:
                lines.append("")
            lines.append("loc_%08X:" % pc)
            prev_was_label = True
        lines.append(insn_text(op, info, operands))
        pc += size
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 批处理
# ---------------------------------------------------------------------------
def iter_inputs(src: Path):
    if src.is_dir():
        for p in sorted(src.iterdir()):
            if p.is_file() and p.suffix.lower() == ".sdt":
                yield p
    else:
        yield src


def output_for(src_file: Path, out_arg: str | None) -> Path:
    if out_arg:
        out = Path(out_arg)
        if src_file.is_dir() or (out.exists() and out.is_dir()) or str(out_arg).endswith(("\\", "/")):
            out.mkdir(parents=True, exist_ok=True)
            return out / (src_file.name + ".asm.txt")
        return out
    return src_file.with_name(src_file.name + ".asm.txt")


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="SDT 脚本反汇编器（kusari / cp932）")
    ap.add_argument("input", nargs="+", help="SDT 脚本文件或目录（可传多个）")
    ap.add_argument("-o", "--output", help="输出文件或目录")
    ap.add_argument("--encoding", default=oc.ENCODING, help="字符串解码/呈现编码，默认 cp932（可用 shift_jis）")
    ap.add_argument("--asm-encoding", default="utf-8", help="asm.txt 文件自身编码，默认 utf-8")
    args = ap.parse_args(argv)

    srcs = [Path(x) for x in args.input]
    for s in srcs:
        if not s.exists():
            print("错误: 输入不存在: %s" % s, file=sys.stderr)
            return 2

    multi = len(srcs) > 1
    if multi:
        root = Path(args.output) if args.output else Path.cwd() / "asm_out"
        root.mkdir(parents=True, exist_ok=True)
        ok = fail = 0
        for src in srcs:
            if src.is_dir():
                sub = root / src.name
                sub.mkdir(parents=True, exist_ok=True)
                files = list(iter_inputs(src))
                pairs = [(f, sub / (f.name + ".asm.txt")) for f in files]
            else:
                pairs = [(src, root / (src.name + ".asm.txt"))]
            for f, dst in pairs:
                try:
                    text = disassemble(f, args.encoding)
                    dst.write_text(text, encoding=args.asm_encoding)
                    ok += 1
                except DisasmError as e:
                    print("失败 %s: %s" % (f, e), file=sys.stderr)
                    fail += 1
        print("反汇编完成: %d 成功, %d 失败 -> %s" % (ok, fail, root))
        return 1 if fail else 0

    src = srcs[0]
    if src.is_dir():
        outdir = Path(args.output) if args.output else src.with_name(src.name + "_asm")
        outdir.mkdir(parents=True, exist_ok=True)
        files = list(iter_inputs(src))
        ok = fail = 0
        for f in files:
            try:
                text = disassemble(f, args.encoding)
            except DisasmError as e:
                print("失败 %s: %s" % (f.name, e), file=sys.stderr)
                fail += 1
                continue
            dst = outdir / (f.name + ".asm.txt")
            dst.write_text(text, encoding=args.asm_encoding)
            ok += 1
        print("反汇编完成: %d 成功, %d 失败 -> %s" % (ok, fail, outdir))
        return 1 if fail else 0

    try:
        text = disassemble(src, args.encoding)
    except DisasmError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 2
    dst = output_for(src, args.output)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding=args.asm_encoding)
    print("反汇编完成 -> %s" % dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
