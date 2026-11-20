#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
disassembler.py -- IAGS_ISD_01 脚本反汇编器（真冬外伝 / IAGS 引擎）

把一个脚本块（SCR.IFP 解包出来的 SCR#NNNNN 之类的文件）反汇编成
可读、可编辑、可无损汇编回原字节的 asm.txt（UTF-8）。

用法：
    python disassembler.py <脚本文件或目录> [-o <输出目录或文件>] [--encoding cp932]

    * 目录会递归处理其中的所有脚本文件（跳过 *.asm.txt / *.rebuild）。
    * 不给 -o 时，在脚本同目录生成 <脚本名>.asm.txt；给 -o 目录则都放进该目录；
      单个输入时 -o 也可以直接给一个以 .txt 结尾的文件名。
    * --encoding 是脚本里正文/名字的字节编码，默认 cp932。asm.txt 本身永远是 UTF-8。

asm 结构：头部注释、.encoding、.code，然后一行一条指令。

记法：
    MSG   0x0000, "V00048", "真冬「ちゅうっ・・・・」"
    LABEL 0x0000, "ST_NEXT"
    CALL  0x0000, 0x0001, "TITLE"
    JNE   0x0003, 0x0001, 0x0002, loc_0003
    GOTO  loc_0003

    loc_0005:                    ← 0x7F 标签定义点
    SET   V[0x0065], 0x0001      ← V[]/W[] 表示间接寻址（见 opcodelist.py）

字符串里不可显示的原始字节写成 {{XX}} / {{XX:XX}}，反斜杠与引号用 \\ 和 \"。
"""

import argparse
import os
import struct
import sys

import opcodelist as OL

SKIP_SUFFIX = (".asm.txt", ".rebuild")


class DisasmError(Exception):
    pass


def parse_container(data, name):
    if len(data) < 12 + 4 * OL.CHUNK_COUNT:
        raise DisasmError("%s: 文件太短，不是 IAGS_ISD_01" % name)
    if data[:12] != OL.MAGIC:
        raise DisasmError("%s: 魔数不匹配：%r" % (name, data[:12]))
    pos = 12
    chunks = []
    for i in range(OL.CHUNK_COUNT):
        if pos + 4 > len(data):
            raise DisasmError("%s: 第 %d 段长度字段越界" % (name, i + 1))
        ln = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if pos + ln > len(data):
            raise DisasmError("%s: 第 %d 段长度 0x%X 超出文件" % (name, i + 1, ln))
        chunks.append(data[pos:pos + ln])
        pos += ln
    if pos != len(data):
        raise DisasmError("%s: 5 段之后还有 %d 字节未解析" % (name, len(data) - pos))
    return chunks


def split_table(blob, chunk_name, file_name):
    """名字/正文表：若干条 \\r\\n 结尾的行。"""
    if not blob:
        return []
    if not blob.endswith(b"\r\n"):
        raise DisasmError("%s 的 %s 段不是以 \\r\\n 结尾，格式与假设不符" % (file_name, chunk_name))
    return blob[:-2].split(b"\r\n")


def _fmt_num(v):
    return "-0x%04X" % (-v) if v < 0 else "0x%04X" % v


def wrap_operand(value, flags, op_index):
    s = _fmt_num(value)
    if flags & OL.v_bit(op_index):
        s = "V[%s]" % s
    if flags & OL.w_bit(op_index):
        s = "W[%s]" % s
    return s


def last_nonzero(op1, op2, op3):
    if op3:
        return 2
    if op2:
        return 1
    return 0


def disassemble(data, file_name, encoding):
    chunks = parse_container(data, file_name)
    code = chunks[OL.CHUNK_CODE]
    if len(code) % OL.INSTRUCTION_SIZE:
        raise DisasmError("%s: 指令流长度 0x%X 不是 %d 的整数倍" % (
            file_name, len(code), OL.INSTRUCTION_SIZE))

    names = split_table(chunks[OL.CHUNK_NAMES], "names", file_name)
    calls = split_table(chunks[OL.CHUNK_CALLS], "calls", file_name)
    voices = split_table(chunks[OL.CHUNK_VOICES], "voices", file_name)
    texts = split_table(chunks[OL.CHUNK_TEXTS], "texts", file_name)

    names_s = [OL.decode_bytes(x, encoding) for x in names]
    calls_s = [OL.decode_bytes(x, encoding) for x in calls]
    voices_s = [OL.decode_bytes(x, encoding) for x in voices]
    texts_s = [OL.decode_bytes(x, encoding) for x in texts]

    out = []
    warn = []

    def w(line=""):
        out.append(line)

    n_ins = len(code) // OL.INSTRUCTION_SIZE

    w("; " + "=" * 74)
    w("; IAGS_ISD_01 脚本块：%s" % file_name)
    w("; 分块字节数：code=%d names=%d calls=%d voices=%d texts=%d" % (
        len(code), len(chunks[OL.CHUNK_NAMES]), len(chunks[OL.CHUNK_CALLS]),
        len(chunks[OL.CHUNK_VOICES]), len(chunks[OL.CHUNK_TEXTS])))
    w("; 指令 %d 条（每条 8 字节）；正文 %d 行；标签名 %d 个；调用名 %d 个；语音 %d 个" % (
        n_ins, len(texts_s), len(names_s), len(calls_s), len(voices_s)))
    w("; 由 disassembler.py 生成。正文在 MSG 行里直接改，改完用 assembler.py 回封。")
    w("; " + "=" * 74)
    w(".encoding %s" % encoding)
    w(".code")

    for k in range(n_ins):
        off = k * OL.INSTRUCTION_SIZE
        op = code[off]
        flags = code[off + 1]
        op1, op2, op3 = struct.unpack_from("<hhh", code, off + 2)
        info = OL.get_opcode(op)
        raw = ", ".join("0x%02X" % b for b in code[off:off + 8])

        if info is None:
            w("    .raw %s   ; 未知 opcode 0x%02X @0x%04X" % (raw, op, off))
            warn.append("%s: 未知 opcode 0x%02X @0x%04X，已按 .raw 原样保留" % (file_name, op, off))
            continue

        kind = info["kind"]
        mn = info["mnemonic"]

        if kind == "end":
            w("    END")
            continue

        if kind == "label":
            if flags or op2 or op3:
                w("    .raw %s   ; 0x7F 带额外字段 @0x%04X" % (raw, off))
                warn.append("%s: 0x7F 标签记录带额外字段 @0x%04X" % (file_name, off))
                continue
            if out and out[-1].strip():
                w()
            w("loc_%04X:" % (op1 & 0xFFFF))
            continue

        if kind == "goto":
            if flags or op2 or op3:
                w("    .raw %s   ; 0x7E 带额外字段 @0x%04X" % (raw, off))
                warn.append("%s: 0x7E 跳转记录带额外字段 @0x%04X" % (file_name, off))
                continue
            w("    %-7s loc_%04X" % (mn, op1 & 0xFFFF))
            continue

        if kind == "deflab":
            if flags or op2 or op3:
                w("    .raw %s   ; 0x4E 带额外字段 @0x%04X" % (raw, off))
                warn.append("%s: 0x4E 标签记录带额外字段 @0x%04X" % (file_name, off))
                continue
            i = op1 & 0xFFFF
            if i >= len(names_s):
                raise DisasmError("%s: 0x4E @0x%04X 的标签名下标 %d 超出 names 表(%d)" % (
                    file_name, off, i, len(names_s)))
            w('    %-7s 0x%04X, "%s"' % (mn, i, OL.escape_text(names_s[i])))
            continue

        if kind == "call":
            if flags or op3:
                w("    .raw %s   ; 0x%02X 带额外字段 @0x%04X" % (raw, op, off))
                warn.append("%s: 0x%02X 调用记录带额外字段 @0x%04X" % (file_name, op, off))
                continue
            i = op1 & 0xFFFF
            if i >= len(calls_s):
                raise DisasmError("%s: 0x%02X @0x%04X 的调用名下标 %d 超出 calls 表(%d)" % (
                    file_name, op, off, i, len(calls_s)))
            w('    %-7s 0x%04X, 0x%04X, "%s"' % (
                mn, i, op2 & 0xFFFF, OL.escape_text(calls_s[i])))
            continue

        if kind == "msg":
            if flags or op3:
                w("    .raw %s   ; 0x%02X 带额外字段 @0x%04X" % (raw, op, off))
                warn.append("%s: 0x%02X 正文记录带额外字段 @0x%04X" % (file_name, op, off))
                continue
            ti = op1 & 0xFFFF
            if ti >= len(texts_s):
                raise DisasmError("%s: 0x%02X @0x%04X 的正文行号 %d 超出 texts 表(%d)" % (
                    file_name, op, off, ti, len(texts_s)))
            vi = op2
            if vi < 0:
                vo = "-"
            else:
                if vi >= len(voices_s):
                    raise DisasmError("%s: 0x%02X @0x%04X 的语音下标 %d 超出 voices 表(%d)" % (
                        file_name, op, off, vi, len(voices_s)))
                vo = '"%s"' % OL.escape_text(voices_s[vi])
            w('    %-7s 0x%04X, %s, "%s"' % (mn, ti, vo, OL.escape_text(texts_s[ti])))
            continue

        # kind == "plain"
        argc = max(info["min_args"], last_nonzero(op1, op2, op3) + 1)
        argv = [op1, op2, op3]
        for i in range(argc, 3):
            if flags & (OL.v_bit(i) | OL.w_bit(i)):
                argc = i + 1
        w("    %-7s %s" % (mn, ", ".join(wrap_operand(argv[i], flags, i) for i in range(argc))))

    w()
    return "\n".join(out) + "\n", warn, n_ins


def is_file_target(p):
    return p.lower().endswith(".txt")


def output_path(src, out_arg, single):
    base = os.path.basename(src)
    target = base + ".asm.txt"
    if out_arg is None:
        return os.path.join(os.path.dirname(os.path.abspath(src)), target)
    if single and is_file_target(out_arg):
        return out_arg
    return os.path.join(out_arg, target)


def iter_inputs(path):
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith(SKIP_SUFFIX):
                    continue
                yield os.path.join(root, fn)
    else:
        yield path


def looks_like_script(path):
    try:
        with open(path, "rb") as f:
            return f.read(12) == OL.MAGIC
    except OSError:
        return False


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="IAGS_ISD_01 脚本反汇编器（输出 UTF-8 的 asm.txt）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python disassembler.py SCR_unpacked\\SCR#00101\n"
               "  python disassembler.py SCR_unpacked -o asm\n"
               "  python disassembler.py SCR#00101 -o out.asm.txt --encoding cp932\n")
    ap.add_argument("input", help="脚本文件或目录")
    ap.add_argument("-o", "--output", help="输出目录，或单个输入时以 .txt 结尾的输出文件名")
    ap.add_argument("--encoding", default="cp932", help="脚本正文编码（默认 cp932）")
    args = ap.parse_args(argv)

    inputs = list(iter_inputs(args.input))
    if os.path.isdir(args.input):
        skipped = [p for p in inputs if not looks_like_script(p)]
        inputs = [p for p in inputs if looks_like_script(p)]
        for p in skipped:
            sys.stderr.write("跳过（不是 IAGS_ISD_01）：%s\n" % p)
    if not inputs:
        sys.stderr.write("没有找到输入文件\n")
        return 1
    single = len(inputs) == 1

    if args.output:
        if single and is_file_target(args.output):
            d = os.path.dirname(os.path.abspath(args.output))
            if d and not os.path.isdir(d):
                os.makedirs(d)
        else:
            os.makedirs(args.output, exist_ok=True)

    all_warn = []
    for src in inputs:
        with open(src, "rb") as f:
            data = f.read()
        name = os.path.basename(src)
        try:
            text, warn, n_ins = disassemble(data, name, args.encoding)
        except DisasmError as e:
            sys.stderr.write("错误: %s\n" % e)
            return 2
        dst = output_path(src, args.output, single)
        with open(dst, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        all_warn.extend(warn)
        print("反汇编 %s -> %s（%d 字节，%d 条指令）" % (src, dst, len(data), n_ins))

    for w in all_warn:
        sys.stderr.write("警告: %s\n" % w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
