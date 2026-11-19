# -*- coding: utf-8 -*-
"""wwadv.id 反汇编器：二进制脚本 -> 语义汇编（asm.txt）。

用法::

    python disassembler.py <脚本文件或目录...> [-o <输出目录或文件>] [--encoding cp932]

- 输入单个文件时，默认在文件同目录生成 ``<basename>.asm.txt``。
- 输入目录时批量处理目录内所有 ``.id`` 文件（目录内无 .id 时处理全部文件）。
- ``--encoding`` 指定文本区字符编码，默认 cp932。

输出结构：
- 代码区逐条反汇编，跳转目标生成 ``loc_`` 标签；
- 文本记录在引用指令后面就地展开，一条显示页 = 一行 ``MESSAGE``，
  选择肢记录 = 每项一行 ``OPTION``；
- 末尾是跳转表 C（场景入口）。
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import opcodelist as oc  # noqa: E402

# 文本流结构常量
T_BR = 0x0001     # 换行
T_PAGE = 0x0002   # 分页
T_TAG = 0x0003    # 语音/说话人标记（后随 2 个参数）
T_WAIT = 0x0006   # 等待式分页（后随 0x0001 再跟 TAG）


# ------------------------------------------------------------------ 容器

def parse_header(data):
    if len(data) < oc.HEADER_WORDS * 4:
        raise ValueError("文件太小，不是 wwadv.id 脚本")
    hdr = list(struct.unpack_from("<8I", data, 0))
    n = len(data) // 4
    t0, t1 = hdr[0], hdr[1]
    if hdr[2] != oc.CODE_START:
        raise ValueError("代码区起始应为 %d，实际 %d" % (oc.CODE_START, hdr[2]))
    if not (oc.CODE_START < t0 <= t1 < hdr[3] <= hdr[4] <= n):
        raise ValueError("文件头区段边界异常: %r" % (hdr,))
    if (4 * t1 - 4 * t0) % 4:
        raise ValueError("文本区长度不是 4 的倍数")
    return hdr


def decrypt_text(data, hdr):
    """文本区按 u16 逐字 XOR 0x0001（加密与解密是同一个运算）。"""
    buf = bytearray(data)
    start, end = 4 * hdr[0], 4 * hdr[1]
    for i in range(start, end, 2):
        buf[i] ^= oc.TEXT_XOR
    return buf


def load_text_codes(data, hdr):
    count = 2 * (hdr[1] - hdr[0])
    return struct.unpack_from("<%dH" % count, data, 4 * hdr[0])


def split_records(text_codes):
    """把文本区切成记录；返回 [(起始 u16 偏移, [codes...]), ...]。"""
    records = []
    i, n = 0, len(text_codes)
    while i < n:
        j = i
        while j < n and text_codes[j] != 0:
            j += 1
        if j >= n:
            raise ValueError("文本区最后一个记录缺少 0x0000 终止符")
        records.append((i, list(text_codes[i:j])))
        i = j + 1
    return records


# ------------------------------------------------------------------ 文本渲染

def _raw(code):
    return "{{%02X:%02X}}" % (code & 0xFF, code >> 8)


def text_tokens(codes, encoding):
    """正文码 -> [(raw, 显示形式)]；换行码 0x0001 显示为 \\n。"""
    out = []
    i, n = 0, len(codes)
    while i < n:
        code = codes[i]
        if code == T_BR:
            out.append(("\\n", "\\n"))
            i += 1
            continue
        nparam = oc.TEXT_CONTROL_PARAMS.get(code)
        if nparam is not None:
            if i + nparam >= n:
                raise ValueError("控制码 0x%04X 缺少 %d 个参数" % (code, nparam))
            out.append((_raw(code), _raw(code)))
            for k in range(1, nparam + 1):
                out.append((_raw(codes[i + k]), _raw(codes[i + k])))
            i += nparam + 1
            continue
        if code in oc.CONTROL_CODES:
            out.append((_raw(code), _raw(code)))
            i += 1
            continue
        try:
            s = bytes((code & 0xFF, code >> 8)).decode(encoding)
        except UnicodeDecodeError:
            out.append((_raw(code), _raw(code)))
            i += 1
            continue
        if (s.encode(encoding, "strict") != bytes((code & 0xFF, code >> 8))
                or any(ch < " " or ch == "\x7f" for ch in s)):
            out.append((_raw(code), _raw(code)))
            i += 1
            continue
        out.append((s, s.replace("\\", "\\\\").replace('"', '\\"')))
        i += 1
    return out


def join_tokens(tokens):
    return "".join(shown for _raw_token, shown in tokens)


def split_pages(codes):
    """消息记录 -> [(分隔符, 标签, 正文码)]；分隔符 ∈ {None, 'page', 'wait'}。"""
    pages = []
    cur_sep = None
    cur_tag = None
    body = []
    pending = None
    started = False
    i, n = 0, len(codes)
    while i < n:
        c = codes[i]
        if c == T_TAG:
            if i + 2 >= n:
                raise ValueError("TAG 标记缺少 2 个参数")
            if started:
                pages.append((cur_sep, cur_tag, body))
            elif body:
                pages.append((None, None, body))
            cur_tag = (codes[i + 1], codes[i + 2])
            cur_sep = pending
            pending = None
            body = []
            started = True
            i += 3
            continue
        if c == T_PAGE:
            if pending is not None:
                raise ValueError("连续出现两个分页标记")
            pending = "page"
            i += 1
            continue
        if c == T_WAIT:
            if pending is not None:
                raise ValueError("连续出现两个分页标记")
            pending = "wait"
            i += 2 if (i + 1 < n and codes[i + 1] == T_BR) else 1
            continue
        body.append(c)
        i += 1

    if started or body:
        pages.append((cur_sep, cur_tag, body))
    return pages


def render_message_record(codes, encoding):
    lines = []
    for sep, tag, body in split_pages(codes):
        shown = join_tokens(text_tokens(body, encoding))
        name = "MESSAGE_WAIT" if sep == "wait" else "MESSAGE"
        tail = ""
        if tag is not None:
            tail = ", 0x%04X, 0x%04X" % tag
        lines.append('        %s "%s"%s' % (name.ljust(13), shown, tail))
    return lines


def render_choice_record(codes, encoding):
    parts = [[]]
    for c in codes:
        if c == T_BR:
            parts.append([])
        else:
            parts[-1].append(c)
    lines = []
    for part in parts:
        shown = join_tokens(text_tokens(part, encoding))
        lines.append('        %s "%s"' % ("OPTION".ljust(13), shown))
    return lines


# ------------------------------------------------------------------ 反汇编

def collect_instructions(words, code_end):
    pcs = []
    pc = oc.CODE_START
    while pc < code_end:
        pcs.append(pc)
        pc += oc.instruction_size(words, pc)
    if pc != code_end:
        raise ValueError("指令流在 0x%X 处越界（代码区结束 0x%X）" % (pc * 4, code_end * 4))
    return pcs


def render_instruction(words, pc):
    spec = oc.OPCODES[words[pc]]
    parts = []
    trefs = []
    for kind, extra, vals in oc.iter_operands(words, pc):
        if kind == "imm":
            parts.append("0x%X" % vals[0])
        elif kind == "desc":
            parts.append("%d:%d" % (vals[0], vals[1]))
        elif kind == "jref":
            parts.append("loc_%06X" % (vals[0] + extra))
        elif kind == "tref":
            parts.append("t_%06X" % vals[0])
            trefs.append(vals[0])
        elif kind == "count":
            parts.append("0x%X" % vals[0])
        elif kind == "str":
            chars = bytes(vals[1:])
            text = chars.decode("cp932", "backslashreplace")
            text = text.replace("\\", "\\\\").replace('"', '\\"')
            parts.append('"%s"' % text)
        else:
            raise ValueError("未知操作数类型 %r" % (kind,))
    return spec["mnemonic"], parts, trefs


def disassemble(data, encoding="cp932", source_name="<mem>"):
    hdr = parse_header(data)
    plain = decrypt_text(data, hdr)
    words = struct.unpack_from("<%dI" % hdr[0], plain, 0)
    text_codes = load_text_codes(plain, hdr)
    records = split_records(text_codes)
    rec_start = {off: idx for idx, (off, _codes) in enumerate(records)}

    pcs = collect_instructions(words, hdr[0])
    pc_set = set(pcs)

    tab_a = struct.unpack_from("<%dI" % (hdr[3] - hdr[1]), plain, 4 * hdr[1])
    tab_b = struct.unpack_from("<%dI" % (hdr[4] - hdr[3]), plain, 4 * hdr[3])
    tab_c = struct.unpack_from("<%dI" % (len(data) // 4 - hdr[4]), plain, 4 * hdr[4])

    labels = {oc.CODE_START}
    for pc in pcs:
        for kind, extra, vals in oc.iter_operands(words, pc):
            if kind == "jref":
                labels.add(vals[0] + extra)
    labels.update(tab_c)
    bad = sorted(v for v in labels if v not in pc_set)
    if bad:
        raise ValueError("以下跳转目标不是指令边界: %s"
                         % ", ".join("0x%X" % (v * 4) for v in bad[:10]))

    out = []
    out.append("; ============================================================")
    out.append("; wwadv.id 语义反汇编")
    out.append("; 源文件: %s（0x%X 字节）" % (source_name, len(data)))
    out.append("; 代码区: dword [%d, %d)   文本区: 0x%X..0x%X（%d 个记录）"
               % (oc.CODE_START, hdr[0], 4 * hdr[0], 4 * hdr[1], len(records)))
    out.append("; 跳转表 A: %d 项（文本页入口，汇编时由代码自动生成）" % len(tab_a))
    out.append("; 跳转表 B: %d 项（CALL 返回地址，汇编时由代码自动生成）" % len(tab_b))
    out.append("; 跳转表 C: %d 项（场景入口，按标签原样保留）" % len(tab_c))
    out.append("; 文本区加密: 每个 u16 与 0x%04X 异或" % oc.TEXT_XOR)
    out.append("; ------------------------------------------------------------")
    out.append("; 文本记录写法（在引用指令后就地展开）：")
    out.append(";   MESSAGE      \"正文\", 语音号, 说话人槽   —— 一条显示页")
    out.append(";   MESSAGE_WAIT \"正文\", 语音号, 说话人槽   —— 等待式分页")
    out.append(";   OPTION       \"选项\"                      —— 选择肢（op 0x17）")
    out.append(";   正文里的 \\n 表示换行；{{XX:YY}} 是原始字节占位符。")
    out.append("; ============================================================")
    out.append(".encoding %s" % encoding)
    out.append(".code_start %d" % oc.CODE_START)
    out.append("")

    emitted = set()

    def emit_text_record(off, codes, is_choice):
        out.append("")
        out.append("t_%06X:" % off)
        if is_choice:
            out.extend(render_choice_record(codes, encoding))
        elif codes:
            out.extend(render_message_record(codes, encoding))
        else:
            out.append("        .pad    2")

    for pc in pcs:
        if pc in labels:
            out.append("")
            out.append("loc_%06X:" % pc)
        mnem, parts, trefs = render_instruction(words, pc)
        if parts:
            out.append("        %s %s" % (mnem.ljust(12), ", ".join(parts)))
        else:
            out.append("        %s" % mnem)
        is_choice = words[pc] == 0x17
        for off in trefs:
            if off not in rec_start:
                raise ValueError("指令 0x%X 引用文本偏移 %d，但该处不是记录起点"
                                 % (pc * 4, off))
            if off in emitted:
                continue
            emitted.add(off)
            emit_text_record(off, records[rec_start[off]][1], is_choice)

    for off, codes in records:
        if off not in emitted:
            emitted.add(off)
            emit_text_record(off, codes, False)

    out.append("")
    out.append("; ---- 跳转表 C（场景入口） ----")
    out.append(".table_c")
    line = "       "
    for i, v in enumerate(tab_c):
        line += " loc_%06X," % v
        if (i + 1) % 8 == 0:
            out.append(line)
            line = "       "
    if line.strip():
        out.append(line)
    out.append("")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------ CLI

def default_output(path):
    base, _ext = os.path.splitext(path)
    return base + ".asm.txt"


def iter_inputs(path):
    if os.path.isdir(path):
        names = sorted(os.listdir(path))
        id_names = [n for n in names if n.lower().endswith(".id")]
        names = id_names or [n for n in names if os.path.isfile(os.path.join(path, n))]
        for n in names:
            yield os.path.join(path, n)
    else:
        yield path


def main(argv=None):
    ap = argparse.ArgumentParser(description="wwadv.id 反汇编器")
    ap.add_argument("inputs", nargs="+", help="脚本文件或目录，可一次给多个（拖放）")
    ap.add_argument("-o", "--output", help="输出文件或输出目录")
    ap.add_argument("--encoding", default="cp932", help="文本区编码（默认 cp932）")
    args = ap.parse_args(argv)

    targets = []
    for raw in args.inputs:
        targets.extend(iter_inputs(raw))
    if not targets:
        print("没有找到输入文件", file=sys.stderr)
        return 2

    for path in targets:
        if args.output and os.path.isdir(args.output):
            out_path = os.path.join(args.output,
                                    os.path.splitext(os.path.basename(path))[0] + ".asm.txt")
        elif args.output and len(targets) == 1 and not os.path.isdir(args.output):
            out_path = args.output
        else:
            out_path = default_output(path)

        with open(path, "rb") as f:
            data = f.read()
        text = disassemble(data, args.encoding, os.path.basename(path))
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8-sig", newline="\n") as f:
            f.write(text)
        print("%s -> %s" % (path, out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
