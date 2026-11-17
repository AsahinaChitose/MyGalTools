#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDT 脚本汇编器  ——  鎖－クサリ－ (Kusari)

用法:
    python assembler.py <asm.txt 或目录> [-o <输出文件/目录>] [--encoding cp932]

读取 disassembler.py 生成的语义汇编，重建逐字节一致的 .SDT 脚本。
标签、字符串长度、入口表、文件总长都会重新计算。

未指定 -o 时，输出名就是原脚本名（去掉 .asm.txt），例如：
    dis\01010.SDT.asm.txt  ->  dis\01010.SDT
不再追加 .rebuild，可直接交给 pak_tool.py 封包。
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import opcodelist as oc

MAGIC = b"L\x00F\x00"
HEADER_SIZE = oc.CODE_OFFSET


class AsmError(Exception):
    def __init__(self, msg, line=None):
        self.line = line
        super().__init__(msg)


# ---------------------------------------------------------------------------
# 词法
# ---------------------------------------------------------------------------
def strip_comment(line: str) -> str:
    inq = False
    esc = False
    for i, ch in enumerate(line):
        if inq:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                inq = False
        else:
            if ch == '"':
                inq = True
            elif ch == ";":
                return line[:i]
    return line


def split_operands(s: str):
    parts = []
    buf = []
    inq = False
    esc = False
    for ch in s:
        if inq:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                inq = False
        else:
            if ch == '"':
                inq = True
                buf.append(ch)
            elif ch == ",":
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
    tail = "".join(buf).strip()
    if tail != "" or parts:
        parts.append(tail)
    return parts


def parse_int(tok: str) -> int:
    t = tok.strip()
    if not t:
        raise AsmError("缺少数值")
    try:
        return int(t, 0)
    except ValueError:
        raise AsmError("非法数值: %s" % tok)


def parse_str(tok: str, line_no=None) -> bytes:
    t = tok.strip()
    if not (t.startswith('"') and t.endswith('"') and len(t) >= 2):
        raise AsmError("期望字符串: %s" % tok, line_no)
    try:
        return oc.encode_string(t[1:-1], CURRENT_ENCODING)
    except ValueError as e:
        raise AsmError("字符串编码失败: %s" % e, line_no)


CURRENT_ENCODING = oc.ENCODING


def parse_reg(tok: str) -> int:
    t = tok.strip()
    if t[:1] in ("R", "r") and t[1:].isdigit():
        return int(t[1:])
    return parse_int(t)


def parse_cond(tok: str) -> int:
    t = tok.strip().upper()
    if t in oc.COND_VALUES:
        return oc.COND_VALUES[t]
    return parse_int(tok)


def parse_variant(tok: str, line_no=None):
    t = tok.strip()
    if t.startswith('"'):
        return ("str", parse_str(t, line_no))
    if t[:1] in ("R", "r") and t[1:].isdigit():
        return ("reg", int(t[1:]))
    return ("imm", parse_int(tok))


# ---------------------------------------------------------------------------
# 指令
# ---------------------------------------------------------------------------
class Insn:
    __slots__ = ("line", "op", "info", "operands", "size", "pc")

    def __init__(self, line, op, info):
        self.line = line
        self.op = op
        self.info = info
        self.operands = []
        self.size = 0
        self.pc = 0


def parse_insn(mnemonic: str, argtext: str, line_no: int) -> Insn:
    m = mnemonic.upper()
    op = oc.BY_MNEMONIC.get(m)
    if op is None:
        raise AsmError("未知指令: %s" % mnemonic, line_no)
    info = oc.get_opcode(op)
    ins = Insn(line_no, op, info)
    toks = split_operands(argtext) if argtext.strip() else []
    ti = 0
    for kind in info["ops"]:
        if kind == "imm8":
            v = parse_int(toks[ti]); ti += 1
            if not 0 <= v <= 0xFF:
                raise AsmError("imm8 越界: %s" % toks[ti - 1], line_no)
            ins.operands.append(("imm8", v))
        elif kind == "imm16":
            v = parse_int(toks[ti]); ti += 1
            if not 0 <= v <= 0xFFFF:
                raise AsmError("imm16 越界: %s" % toks[ti - 1], line_no)
            ins.operands.append(("imm16", v))
        elif kind == "imm32":
            v = parse_int(toks[ti]) & 0xFFFFFFFF; ti += 1
            ins.operands.append(("imm32", v))
        elif kind == "label32":
            tok = toks[ti]; ti += 1
            ins.operands.append(("label", tok.strip()))
        elif kind == "reg8":
            v = parse_reg(toks[ti]); ti += 1
            if not 0 <= v <= 0xFF:
                raise AsmError("寄存器号越界", line_no)
            ins.operands.append(("reg", v))
        elif kind == "cond":
            ins.operands.append(("cond", parse_cond(toks[ti]))); ti += 1
        elif kind == "str8":
            s = parse_str(toks[ti], line_no); ti += 1
            if len(s) > 0xFF:
                raise AsmError("str8 字符串过长 (%d 字节)" % len(s), line_no)
            ins.operands.append(("str", s))
        elif kind == "str16":
            s = parse_str(toks[ti], line_no); ti += 1
            if len(s) > 0xFFFF:
                raise AsmError("str16 字符串过长", line_no)
            ins.operands.append(("str", s))
        elif kind == "variant":
            k, v = parse_variant(toks[ti], line_no); ti += 1
            if k == "str" and len(v) > 0xFF:
                raise AsmError("变体字符串过长 (%d 字节)" % len(v), line_no)
            ins.operands.append(("variant", k, v))
        elif kind == "cmp":
            reg = parse_reg(toks[ti]); ti += 1
            cond = parse_cond(toks[ti]); ti += 1
            k, v = parse_variant(toks[ti], line_no); ti += 1
            if k == "str" and len(v) > 0xFF:
                raise AsmError("变体字符串过长", line_no)
            ins.operands.append(("cmp", reg, cond, k, v))
        elif kind == "callargs":
            args = []
            while ti < len(toks):
                tok = toks[ti]; ti += 1
                if ":" not in tok:
                    raise AsmError("CALLX 参数应为 类型:值: %s" % tok, line_no)
                ts, vs = tok.split(":", 1)
                t = parse_int(ts)
                v = parse_int(vs)
                args.append((t & 0xFF, v))
            ins.operands.append(("callargs", args))
        else:
            raise AsmError("未知操作数类型 %r" % kind, line_no)
    if ti != len(toks):
        raise AsmError("操作数过多: %s" % argtext, line_no)
    ins.size = operand_size(ins)
    return ins


def operand_size(ins: Insn) -> int:
    sz = 2
    for i, kind in enumerate(ins.info["ops"]):
        o = ins.operands[i]
        if kind in ("imm8", "reg8", "cond"):
            sz += 1
        elif kind == "imm16":
            sz += 2
        elif kind in ("imm32", "label32"):
            sz += 4
        elif kind in ("str8", "str16"):
            sz += (1 if kind == "str8" else 2) + len(o[1])
        elif kind == "variant":
            sz += (2 + len(o[2])) if o[1] == "str" else 5
        elif kind == "cmp":
            sz += 2 + ((2 + len(o[4])) if o[3] == "str" else 5)
        elif kind == "callargs":
            sz += 2
            for t, v in o[1]:
                sz += 5 if t == 0 else 2
        else:
            raise AsmError("内部错误: 未知操作数 %r" % kind)
    return sz


def encode_insn(ins: Insn, labels: dict) -> bytes:
    out = bytearray(struct.pack("<H", ins.op))
    for i, kind in enumerate(ins.info["ops"]):
        o = ins.operands[i]
        if kind in ("imm8", "reg8", "cond"):
            out.append(o[1] & 0xFF)
        elif kind == "imm16":
            out += struct.pack("<H", o[1])
        elif kind == "imm32":
            out += struct.pack("<I", o[1])
        elif kind == "label32":
            name = o[1]
            if name not in labels:
                raise AsmError("未定义的标签: %s" % name, ins.line)
            out += struct.pack("<I", labels[name])
        elif kind in ("str8", "str16"):
            data = o[1]
            if kind == "str8":
                if len(data) > 0xFF:
                    raise AsmError("str8 字符串过长", ins.line)
                out.append(len(data))
            else:
                if len(data) > 0xFFFF:
                    raise AsmError("str16 字符串过长", ins.line)
                out += struct.pack("<H", len(data))
            out += data
        elif kind == "variant":
            vk, vv = o[1], o[2]
            if vk == "str":
                out.append(2)
                out.append(len(vv))
                out += vv
            elif vk == "reg":
                out.append(0)
                out += struct.pack("<I", vv)
            else:
                out.append(1)
                out += struct.pack("<I", vv & 0xFFFFFFFF)
        elif kind == "cmp":
            reg, cond, vk, vv = o[1], o[2], o[3], o[4]
            out.append(reg & 0xFF)
            out.append(cond & 0xFF)
            if vk == "str":
                out.append(2)
                out.append(len(vv))
                out += vv
            elif vk == "reg":
                out.append(0)
                out += struct.pack("<I", vv)
            else:
                out.append(1)
                out += struct.pack("<I", vv & 0xFFFFFFFF)
        elif kind == "callargs":
            args = o[1]
            body = bytearray()
            for t, v in args:
                if t == 0:
                    body.append(0)
                    body += struct.pack("<I", v & 0xFFFFFFFF)
                else:
                    body.append(t & 0xFF)
                    body.append(v & 0xFF)
            out += struct.pack("<h", len(body))
            out += body
        else:
            raise AsmError("内部错误: 未知操作数 %r" % kind)
    return bytes(out)


# ---------------------------------------------------------------------------
# 汇编
# ---------------------------------------------------------------------------
def assemble_text(text: str, encoding: str, source_name="<asm>", force_encoding=False) -> bytes:
    global CURRENT_ENCODING
    CURRENT_ENCODING = encoding
    table = [0] * 256
    insns = []
    labels = {}
    pc = 0
    in_code = False
    orig_size = None
    for no, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("."):
            parts = line.split(None, 1)
            d = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""
            if d == ".sdt":
                continue
            if d == ".encoding":
                enc = arg.strip().strip('"').strip("'")
                if enc and not force_encoding:
                    encoding = enc
                    CURRENT_ENCODING = enc
            elif d == ".original_size":
                orig_size = parse_int(arg)
            elif d == ".entry":
                a, b = [x.strip() for x in arg.split(",")]
                idx = parse_int(a)
                val = parse_int(b) & 0xFFFFFFFF
                if not 0 <= idx < 256:
                    raise AsmError(".entry 下标越界", no)
                table[idx] = val
            elif d == ".code":
                in_code = True
            else:
                raise AsmError("未知伪指令: %s" % d, no)
            continue
        if line.endswith(":"):
            name = line[:-1].strip()
            if not name:
                raise AsmError("空标签", no)
            if name in labels:
                raise AsmError("重复标签: %s" % name, no)
            labels[name] = pc
            continue
        if not in_code:
            raise AsmError("指令出现在 .code 之前", no)
        parts = line.split(None, 1)
        mnemonic = parts[0]
        argtext = parts[1] if len(parts) > 1 else ""
        try:
            ins = parse_insn(mnemonic, argtext, no)
        except IndexError:
            raise AsmError("操作数不足: %s" % line, no)
        ins.pc = pc
        pc += ins.size
        insns.append(ins)
    code = bytearray()
    for ins in insns:
        data = encode_insn(ins, labels)
        if len(data) != ins.size:
            raise AsmError("内部长度不一致 @line %d" % ins.line, ins.line)
        code += data
    if len(code) != pc:
        raise AsmError("内部错误: 代码长度不一致")
    total = HEADER_SIZE + len(code)
    out = bytearray()
    out += MAGIC
    out += struct.pack("<I", total)
    for v in table:
        out += struct.pack("<I", v)
    out += code
    if orig_size is not None and total != orig_size:
        print("提示: 重建长度 0x%X 与 .original_size 0x%X 不同（文本被修改时会如此）" %
              (total, orig_size), file=sys.stderr)
    return bytes(out)


# ---------------------------------------------------------------------------
# 批处理
# ---------------------------------------------------------------------------
def read_asm(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "shift_jis", "cp932", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def iter_inputs(src: Path):
    if src.is_dir():
        for p in sorted(src.iterdir()):
            if p.is_file() and p.name.lower().endswith((".asm.txt", ".asm")):
                yield p
    else:
        yield src


def out_name(src: Path) -> str:
    name = src.name
    for suf in (".asm.txt", ".asm"):
        if name.lower().endswith(suf):
            return name[:-len(suf)]
    return name + ".sdt"


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="SDT 脚本汇编器（kusari / cp932）")
    ap.add_argument("input", nargs="+", help="asm.txt 文件或目录（可传多个）")
    ap.add_argument("-o", "--output", help="输出文件或目录")
    ap.add_argument("--encoding", default=None,
                    help="字符串写入二进制时使用的编码；默认取 .encoding（cp932）")
    args = ap.parse_args(argv)

    srcs = [Path(x) for x in args.input]
    for s in srcs:
        if not s.exists():
            print("错误: 输入不存在: %s" % s, file=sys.stderr)
            return 2

    multi = len(srcs) > 1
    if multi:
        root = Path(args.output) if args.output else Path.cwd() / "rebuild_out"
        root.mkdir(parents=True, exist_ok=True)
        ok = fail = 0
        for src in srcs:
            if src.is_dir():
                sub = root / src.name
                sub.mkdir(parents=True, exist_ok=True)
                pairs = [(f, sub / out_name(f)) for f in iter_inputs(src)]
            else:
                pairs = [(src, root / out_name(src))]
            for f, dst in pairs:
                try:
                    text = read_asm(f)
                    data = assemble_text(text, args.encoding or oc.ENCODING, f.name,
                                         force_encoding=bool(args.encoding))
                except AsmError as e:
                    print("失败 %s:%s: %s" % (f, e.line or "?", e), file=sys.stderr)
                    fail += 1
                    continue
                dst.write_bytes(data)
                ok += 1
        print("汇编完成: %d 成功, %d 失败 -> %s" % (ok, fail, root))
        return 1 if fail else 0

    src = srcs[0]
    if src.is_dir():
        outdir = Path(args.output) if args.output else src.with_name(src.name + "_rebuild")
        outdir.mkdir(parents=True, exist_ok=True)
        ok = fail = 0
        for f in iter_inputs(src):
            try:
                text = read_asm(f)
                data = assemble_text(text, args.encoding or oc.ENCODING, f.name, force_encoding=bool(args.encoding))
            except AsmError as e:
                print("失败 %s:%s: %s" % (f.name, e.line or "?", e), file=sys.stderr)
                fail += 1
                continue
            dst = outdir / out_name(f)
            dst.write_bytes(data)
            ok += 1
        print("汇编完成: %d 成功, %d 失败 -> %s" % (ok, fail, outdir))
        return 1 if fail else 0

    try:
        text = read_asm(src)
        data = assemble_text(text, args.encoding or oc.ENCODING, src.name, force_encoding=bool(args.encoding))
    except AsmError as e:
        print("错误 line %s: %s" % (e.line or "?", e), file=sys.stderr)
        return 2

    if args.output:
        dst = Path(args.output)
        if dst.is_dir() or str(args.output).endswith(("\\", "/")):
            dst.mkdir(parents=True, exist_ok=True)
            dst = dst / out_name(src)
    else:
        dst = src.with_name(out_name(src))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    print("汇编完成 -> %s" % dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
