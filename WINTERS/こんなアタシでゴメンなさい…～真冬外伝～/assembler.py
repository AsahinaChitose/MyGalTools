#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
assembler.py -- IAGS_ISD_01 脚本汇编器（真冬外伝 / IAGS 引擎）

把 disassembler.py 生成的 asm.txt 重新汇编成脚本块，未修改的内容应当与原始
字节逐字节一致（零突变）。

用法：
    python assembler.py <asm.txt 或目录> [-o <输出文件/目录>] [--encoding gbk]

    * 目录会递归处理 *.asm.txt。
    * 输出文件名和原脚本一致（去掉 .asm.txt 就是原名，不再加 .rebuild）：
      `SCR#00101.asm.txt` -> `SCR#00101`，直接拿去封包就行。
    * 不给 -o 时写在 asm 同目录；给 -o 目录就都放进该目录。
    * --encoding 决定正文/名字按什么编码写回；默认取 asm 头部的 .encoding（通常 cp932）。
      想生成 GBK 正文的改版时显式给 --encoding gbk。
"""

import argparse
import os
import re
import struct
import sys

import opcodelist as OL

LABEL_RE = re.compile(r"^\s*(loc_[0-9A-Fa-f]{4,})\s*:\s*(.*)$")
NUM_RE = re.compile(r"^-?(0[xX][0-9A-Fa-f]+|\d+)$")


class AsmError(Exception):
    pass


def parse_int(tok):
    tok = tok.strip()
    if not NUM_RE.match(tok):
        raise ValueError("不是数字: %r" % tok)
    neg = tok.startswith("-")
    body = tok[1:] if neg else tok
    v = int(body, 16) if body.lower().startswith("0x") else int(body, 10)
    return -v if neg else v


def parse_operand(tok, op_index):
    """解析 V[..] / W[..] 包裹，返回 (值, flags 位)。"""
    tok = tok.strip()
    if tok.startswith("W[") and tok.endswith("]"):
        v, bits = parse_operand(tok[2:-1], op_index)
        return v, bits | OL.w_bit(op_index)
    if tok.startswith("V[") and tok.endswith("]"):
        v, bits = parse_operand(tok[2:-1], op_index)
        return v, bits | OL.v_bit(op_index)
    return parse_int(tok), 0


def check_i16(v, what, line_no):
    if not (-32768 <= v <= 32767):
        raise AsmError("第 %d 行：%s = %d 超出 i16 范围" % (line_no, what, v))
    return v


def strip_comment(line):
    out = []
    in_str = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\" and i + 1 < len(line):
                out.append(ch)
                out.append(line[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            out.append(ch)
        else:
            if ch == '"':
                in_str = True
                out.append(ch)
            elif ch == ";":
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out)


def split_args(s):
    """按逗号切分操作数，字符串和方括号内的逗号不算分隔符。"""
    args = []
    buf = []
    depth = 0
    in_str = False
    i = 0
    while i < len(s):
        ch = s[i]
        if in_str:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(s):
                buf.append(s[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
                buf.append(ch)
            elif ch in "[(":
                depth += 1
                buf.append(ch)
            elif ch in "])":
                depth -= 1
                buf.append(ch)
            elif ch == "," and depth == 0:
                args.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        i += 1
    if buf:
        args.append("".join(buf).strip())
    return args


def parse_string(tok, line_no):
    tok = tok.strip()
    if not (len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"'):
        raise AsmError("第 %d 行：期望字符串，得到 %r" % (line_no, tok))
    inner = tok[1:-1]
    return inner


def assemble(text, enc_override, file_name):
    lines = text.splitlines()

    encoding = enc_override
    if encoding is None:
        encoding = "cp932"
        for raw in lines:
            s = strip_comment(raw).strip()
            if s.lower().startswith(".encoding"):
                encoding = s.split(None, 1)[1].strip()
                break

    code = bytearray()
    names = {}
    calls = {}
    voices = []
    texts = {}
    loc_defs = set()
    loc_refs = []

    def add_instr(op, flags, a, b, c, line_no):
        code.extend(struct.pack("<BBhhh", op, flags,
                                check_i16(a, "op1", line_no),
                                check_i16(b, "op2", line_no),
                                check_i16(c, "op3", line_no)))

    for line_no, raw in enumerate(lines, 1):
        s = strip_comment(raw).strip()
        if not s:
            continue
        low = s.lower()
        if low.startswith(".encoding") or low.startswith(".code") or low.startswith(".meta"):
            continue

        # 标签行：loc_XXXX:  [可选指令]
        m = LABEL_RE.match(s)
        if m:
            loc = m.group(1)
            lid = int(loc[4:], 16)
            rest = m.group(2).strip()
            add_instr(0x7F, 0, lid, 0, 0, line_no)
            loc_defs.add(loc.upper())
            if not rest:
                continue
            s = rest

        if s.startswith(".raw"):
            body = s[4:].strip()
            try:
                bs = [int(x.strip(), 16) for x in body.split(",")]
            except ValueError:
                raise AsmError("第 %d 行：.raw 只接受 8 个十六进制字节" % line_no)
            if len(bs) != OL.INSTRUCTION_SIZE:
                raise AsmError("第 %d 行：.raw 需要正好 %d 字节，给了 %d" % (
                    line_no, OL.INSTRUCTION_SIZE, len(bs)))
            code.extend(bytes(b & 0xFF for b in bs))
            continue

        parts = s.split(None, 1)
        mn = parts[0].upper()
        argstr = parts[1].strip() if len(parts) > 1 else ""
        args = split_args(argstr) if argstr else []

        info = None
        for op, inf in OL.OPCODES.items():
            if inf["mnemonic"] == mn:
                info = (op, inf)
                break
        if info is None:
            raise AsmError("第 %d 行：未知助记符 %r" % (line_no, mn))
        op, inf = info
        kind = inf["kind"]

        if kind == "end":
            if args:
                raise AsmError("第 %d 行：END 不带参数" % line_no)
            code.extend(b"\xFF" * OL.INSTRUCTION_SIZE)
            continue

        if kind == "goto":
            if len(args) != 1:
                raise AsmError("第 %d 行：GOTO 需要 1 个标签" % line_no)
            loc = args[0].strip().upper()
            if not loc.startswith("LOC_"):
                raise AsmError("第 %d 行：GOTO 目标应为 loc_XXXX，得到 %r" % (line_no, args[0]))
            loc_refs.append((loc, line_no))
            add_instr(op, 0, int(loc[4:], 16), 0, 0, line_no)
            continue

        if kind == "label":
            raise AsmError("第 %d 行：LOC 请写成 'loc_XXXX:' 标签行" % line_no)

        if kind == "deflab":
            if len(args) != 2:
                raise AsmError("第 %d 行：LABEL 需要 <id>, \"名字\"" % line_no)
            idx = check_i16(parse_int(args[0]), "标签 id", line_no)
            names.setdefault(idx, OL.unescape_text(parse_string(args[1], line_no), encoding))
            add_instr(op, 0, idx, 0, 0, line_no)
            continue

        if kind == "call":
            if len(args) != 3:
                raise AsmError("第 %d 行：%s 需要 <id>, <脚本id>, \"名字\"" % (line_no, mn))
            idx = check_i16(parse_int(args[0]), "调用名下标", line_no)
            script = parse_int(args[1])
            calls.setdefault(idx, OL.unescape_text(parse_string(args[2], line_no), encoding))
            add_instr(op, 0, idx, script, 0, line_no)
            continue

        if kind == "msg":
            if len(args) != 3:
                raise AsmError("第 %d 行：%s 需要 <正文行号>, \"语音\"|-, \"正文\"" % (line_no, mn))
            tid = check_i16(parse_int(args[0]), "正文行号", line_no)
            if tid in texts:
                raise AsmError("第 %d 行：正文行号 %d 重复" % (line_no, tid))
            texts[tid] = OL.unescape_text(parse_string(args[2], line_no), encoding)
            vo = args[1].strip()
            if vo == "-":
                vid = -1
            else:
                # 语音名按出现顺序编号；原文件里允许出现重名（不同 id 同一个文件名），
                # 所以这里不做去重，出现一次占一个 id。
                vbytes = OL.unescape_text(parse_string(vo, line_no), encoding)
                vid = len(voices)
                voices.append(vbytes)
            add_instr(op, 0, tid, vid, 0, line_no)
            continue

        # plain
        vals = []
        flags = 0
        for i, a in enumerate(args):
            if i > 2:
                raise AsmError("第 %d 行：%s 最多 3 个操作数" % (line_no, mn))
            v, bits = parse_operand(a, i)
            vals.append(v)
            flags |= bits
        while len(vals) < 3:
            vals.append(0)
        add_instr(op, flags, vals[0], vals[1], vals[2], line_no)

    # 校验跳转目标
    for loc, line_no in loc_refs:
        if loc not in loc_defs:
            raise AsmError("第 %d 行：跳转目标 %s 没有定义" % (line_no, loc))

    # 重建各表
    def build_table(mapping, chunk_name):
        if not mapping:
            return b""
        ids = sorted(mapping)
        expect = list(range(ids[-1] + 1))
        if ids != expect:
            raise AsmError("%s 表的编号不连续：%r" % (chunk_name, ids))
        return b"".join(mapping[i] + b"\r\n" for i in ids)

    chunk_names = build_table(names, "names")
    chunk_calls = build_table(calls, "calls")
    chunk_voices = b"".join(v + b"\r\n" for v in voices)
    chunk_texts = build_table(texts, "texts")

    chunks = [bytes(code), chunk_names, chunk_calls, chunk_voices, chunk_texts]
    out = bytearray(OL.MAGIC)
    for c in chunks:
        out.extend(struct.pack("<I", len(c)))
        out.extend(c)
    return bytes(out), encoding, chunks


def output_path(src, out_arg, single):
    """asm.txt 去掉 .asm.txt 就是输出名（和反汇编前的脚本同名，方便直接封包）。"""
    base = os.path.basename(src)
    if base.lower().endswith(".asm.txt"):
        base = base[:-len(".asm.txt")]
    elif base.lower().endswith(".txt"):
        base = base[:-4]
    target = base
    if out_arg is None:
        return os.path.join(os.path.dirname(os.path.abspath(src)), target)
    if single and not os.path.isdir(out_arg) and not out_arg.endswith(("\\", "/")):
        return out_arg
    return os.path.join(out_arg, target)


def iter_inputs(path):
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith(".asm.txt"):
                    yield os.path.join(root, fn)
    else:
        yield path


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="IAGS_ISD_01 脚本汇编器（asm.txt -> 脚本块）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python assembler.py asm\\SCR#00101.asm.txt\n"
               "  python assembler.py asm -o rebuild\n"
               "  python assembler.py a.asm.txt -o a.bin --encoding gbk\n"
               "\n"
               "输出名默认与反汇编前的脚本同名（SCR#00101.asm.txt -> SCR#00101），\n"
               "可直接覆盖到解包目录里重新封包。\n")
    ap.add_argument("input", help="asm.txt 文件或目录")
    ap.add_argument("-o", "--output", help="输出目录，或单个输入时的输出文件名")
    ap.add_argument("--encoding", default=None,
                    help="正文写回编码；默认用 asm 头部的 .encoding（通常 cp932）")
    args = ap.parse_args(argv)

    inputs = list(iter_inputs(args.input))
    if not inputs:
        sys.stderr.write("没有找到 asm.txt\n")
        return 1
    single = len(inputs) == 1

    outdir = args.output
    if outdir and single and not os.path.isdir(outdir) and not outdir.endswith(("\\", "/")):
        d = os.path.dirname(os.path.abspath(outdir))
        if d and not os.path.isdir(d):
            os.makedirs(d)
    elif outdir:
        os.makedirs(outdir, exist_ok=True)

    rc = 0
    for src in inputs:
        with open(src, "r", encoding="utf-8") as f:
            text = f.read()
        name = os.path.basename(src)
        try:
            data, used_enc, chunks = assemble(text, args.encoding or "cp932", name)
        except (AsmError, ValueError) as e:
            sys.stderr.write("错误: %s: %s\n" % (name, e))
            rc = 2
            continue
        dst = output_path(src, outdir, single)
        with open(dst, "wb") as f:
            f.write(data)
        print("汇编 %s -> %s（%d 字节，正文编码 %s，chunks=%s）" % (
            src, dst, len(data), used_enc,
            ",".join(str(len(c)) for c in chunks)))
    return rc


if __name__ == "__main__":
    sys.exit(main())
