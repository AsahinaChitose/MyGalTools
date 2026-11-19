# -*- coding: utf-8 -*-
"""wwadv.id 汇编器：语义汇编（asm.txt）-> 二进制脚本。

用法::

    python assembler.py <asm.txt 或目录...> [-o <输出文件/目录>] [--encoding gbk]

- 输入单个 asm.txt 时，默认输出 ``<basename>.rebuild``。
- 输入目录时批量汇编目录内所有 ``*.asm.txt``。
- ``--encoding`` 覆盖汇编头 ``.encoding`` 声明的正文编码（默认从头部读取，缺省 cp932）。

汇编流程与反汇编器互逆：

1. 逐条编码代码区指令，两遍解析 ``loc_`` 标签；
2. 按出现顺序把 ``MESSAGE`` / ``MESSAGE_WAIT`` / ``OPTION`` 记录拼回文本区，
   重算每条记录的 u16 偏移，回填所有 ``t_`` 引用；
3. 由代码自动生成跳转表 A/B，按标签回填跳转表 C；
4. 重算文件头，最后对文本区重新施加 ``u16 XOR 0x0001`` 加密。
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import opcodelist as oc  # noqa: E402

T_BR = 0x0001
T_PAGE = 0x0002
T_TAG = 0x0003
T_WAIT = 0x0006

TEXT_KINDS = ("MESSAGE", "MESSAGE_WAIT", "OPTION")


class AsmError(Exception):
    pass


# ------------------------------------------------------------------ 词法

def split_operands(text):
    """按顶层逗号切分操作数，忽略字符串与 {{}} 内的逗号。"""
    parts, buf, i, in_str = [], [], 0, False
    while i < len(text):
        ch = text[i]
        if in_str:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if text.startswith("{{", i):
            j = text.index("}}", i)
            buf.append(text[i:j + 2])
            i = j + 2
            continue
        if ch == '"':
            in_str = True
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    if in_str:
        raise AsmError("字符串未闭合: %s" % text)
    last = "".join(buf).strip()
    if last or parts:
        parts.append(last)
    return [p for p in parts if p != ""]


def strip_comment(line):
    """去掉行尾 ; 注释（引号内不算）。"""
    in_str = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == ";":
            return line[:i]
        i += 1
    return line


def parse_int(tok):
    tok = tok.strip()
    try:
        if tok.lower().startswith("0x") or tok.lower().startswith("-0x"):
            return int(tok, 16)
        return int(tok, 10)
    except ValueError:
        raise AsmError("无法解析整数: %r" % tok)


def parse_desc(tok):
    if ":" not in tok:
        raise AsmError("值描述符应写作 type:value，得到 %r" % tok)
    a, b = tok.split(":", 1)
    return parse_int(a), parse_int(b)


def unquote(tok):
    tok = tok.strip()
    if len(tok) < 2 or not (tok.startswith('"') and tok.endswith('"')):
        raise AsmError("应为字符串字面量: %r" % tok)
    return tok[1:-1]


def decode_string(text, encoding):
    """把正文转成 u16 codes；``\\n`` 表示换行码 0x0001。"""
    codes = []
    pending = bytearray()

    def flush():
        while len(pending) >= 2:
            codes.append(pending[0] | (pending[1] << 8))
            del pending[:2]

    i = 0
    while i < len(text):
        if text.startswith("{{", i):
            j = text.index("}}", i)
            body = text[i + 2:j]
            if ":" in body:
                a, b = body.split(":", 1)
                pending.append(int(a, 16) & 0xFF)
                pending.append(int(b, 16) & 0xFF)
            else:
                pending.append(int(body, 16) & 0xFF)
            flush()
            i = j + 2
        elif text[i] == "\\":
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if nxt == "n":
                if pending:
                    raise AsmError("换行 \\n 前有半个字符，无法对齐 u16 单元")
                codes.append(T_BR)
            elif nxt == "\\":
                pending += b"\\"
                flush()
            elif nxt == '"':
                pending += b'"'
                flush()
            else:
                raise AsmError("未知转义: \\%s" % nxt)
            i += 2
        else:
            try:
                pending += text[i].encode(encoding)
            except UnicodeEncodeError:
                raise AsmError("字符 %r（U+%04X）无法用 %s 编码"
                               % (text[i], ord(text[i]), encoding))
            flush()
            i += 1
    if pending:
        raise AsmError("字符串结尾有半个字符（字节数为奇数）")
    return codes


# ------------------------------------------------------------------ 解析

def parse_asm(path):
    encoding = None
    code_start = None
    items = []
    table_c = []
    in_table_c = False
    current_text_label = None
    lineno = 0

    with open(path, "r", encoding="utf-8-sig") as f:
        raw_lines = f.read().split("\n")

    for raw in raw_lines:
        lineno += 1
        line = strip_comment(raw).rstrip()
        if not line.strip():
            continue
        stripped = line.strip()

        if stripped.startswith("."):
            parts = stripped.split(None, 1)
            directive = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""
            in_table_c = False
            if directive == ".encoding":
                encoding = arg
            elif directive == ".code_start":
                code_start = parse_int(arg)
            elif directive == ".table_c":
                in_table_c = True
            elif directive == ".pad":
                items.append(("pad", parse_int(arg)))
            elif directive == ".ref":
                if not in_table_c:
                    raise AsmError("第 %d 行: .ref 只能出现在 .table_c 之后" % lineno)
                for tok in arg.split(","):
                    tok = tok.strip()
                    if tok:
                        table_c.append(tok)
            else:
                raise AsmError("第 %d 行: 未知伪指令 %s" % (lineno, directive))
            continue

        if in_table_c and stripped.startswith("loc_"):
            for tok in stripped.split(","):
                tok = tok.strip()
                if tok:
                    table_c.append(tok)
            continue

        if stripped.endswith(":") and " " not in stripped:
            name = stripped[:-1]
            current_text_label = name if name.startswith("t_") else None
            items.append(("label", name))
            continue

        head = stripped.split(None, 1)[0]
        if head in TEXT_KINDS:
            if current_text_label is None:
                raise AsmError("第 %d 行: %s 前缺少 t_ 标签" % (lineno, head))
            tokens = split_operands(stripped.split(None, 1)[1]) if len(stripped.split(None, 1)) > 1 else []
            if not tokens:
                raise AsmError("第 %d 行: %s 缺少文本参数" % (lineno, head))
            body = unquote(tokens[0])
            p1 = p2 = None
            if head != "OPTION":
                if len(tokens) != 3:
                    raise AsmError("第 %d 行: %s 需要 \"正文\", 语音号, 说话人槽 三个参数"
                                   % (lineno, head))
                p1 = parse_int(tokens[1])
                p2 = parse_int(tokens[2])
            items.append(("msg", current_text_label, head, body, p1, p2))
            continue

        current_text_label = None
        parts = stripped.split(None, 1)
        mnemonic = parts[0]
        tokens = split_operands(parts[1]) if len(parts) > 1 else []
        items.append(("instr", mnemonic, tokens, lineno))

    if code_start not in (None, oc.CODE_START):
        raise AsmError("暂不支持非默认代码起点: %r" % code_start)
    return encoding, items, table_c


# ------------------------------------------------------------------ 编码

class Assembler:
    def __init__(self, encoding):
        self.encoding = encoding
        self.labels = {}            # 代码标签 -> dword 偏移
        self.text_labels = {}       # 文本标签 -> u16 偏移
        self.text_stream = []       # [("pad", nbytes) | ("rec", label, entries)]
        self.option_counts = {}     # 选择肢记录的选项数
        self.phase = 1

    # -- 收集文本记录
    def collect_records(self, items):
        byte_off = 0
        cur = None
        for item in items:
            if item[0] == "pad":
                self.text_stream.append(("pad", item[1]))
                byte_off += item[1]
            elif item[0] == "msg":
                _tag, label, kind, body, p1, p2 = item
                if cur is None or cur[1] != label:
                    cur = ("rec", label, [])
                    self.text_stream.append(cur)
                    self.text_labels[label] = byte_off // 2
                cur[2].append((kind, body, p1, p2))
                byte_off += 2          # 估算占位，真正长度在组装时才知道

    def build_text_words(self):
        """按记录重建文本码流，同时修正记录长度与标签偏移。"""
        words = []
        byte_off = 0
        for entry in self.text_stream:
            if entry[0] == "pad":
                words.extend([0] * (entry[1] // 2))
                byte_off += entry[1]
                continue
            _tag, label, entries = entry
            self.text_labels[label] = byte_off // 2
            codes = []
            first = True
            options = 0
            for kind, body, p1, p2 in entries:
                data = decode_string(body, self.encoding)
                if kind == "OPTION":
                    options += 1
                    if not first:
                        codes.append(T_BR)
                    codes.extend(data)
                elif kind == "MESSAGE":
                    if first:
                        if p1 is not None:
                            codes.extend([T_TAG, p1, p2])
                    else:
                        codes.append(T_PAGE)
                        if p1 is not None:
                            codes.extend([T_TAG, p1, p2])
                    codes.extend(data)
                elif kind == "MESSAGE_WAIT":
                    codes.extend([T_WAIT, T_BR, T_TAG, p1 or 0, p2 or 0])
                    codes.extend(data)
                else:
                    raise AsmError("未知文本记录类型 %s" % kind)
                first = False
            self.option_counts[label] = options
            words.extend(codes)
            words.append(0)              # 记录终止符
            byte_off += 2 * (len(codes) + 1)
        return words

    # -- 指令编码
    def encode_instr(self, pc, mnemonic, tokens, lineno):
        code = oc.BY_MNEMONIC.get(mnemonic)
        if code is None:
            raise AsmError("第 %d 行: 未知指令 %s" % (lineno, mnemonic))
        spec = oc.OPCODES[code]
        words, used = self._encode_ops(spec["ops"], tokens, 0, {})
        if used != len(tokens):
            raise AsmError("第 %d 行: %s 操作数数量不匹配（用了 %d/%d 个）"
                           % (lineno, mnemonic, used, len(tokens)))
        words = [code] + words
        if code == 0x17 and tokens and tokens[0].startswith("t_"):
            cnt = self.option_counts.get(tokens[0])
            if cnt is not None:
                if len(words) < 4:
                    raise AsmError("第 %d 行: TEXT 指令缺少选项数操作数" % lineno)
                words[3] = cnt
        return words

    def _encode_ops(self, specs, tokens, used, vars_):
        words = []
        for spec in specs:
            kind = spec[0]
            if kind == "imm":
                words.append(parse_int(tokens[used])); used += 1
            elif kind == "desc":
                t, v = parse_desc(tokens[used]); used += 1
                words += [t, v]
            elif kind == "cond5":
                t, v = parse_desc(tokens[used]); used += 1
                words += [t, v, parse_int(tokens[used])]; used += 1
                t2, v2 = parse_desc(tokens[used]); used += 1
                words += [t2, v2]
            elif kind == "jref":
                words.append(self._resolve_code(tokens[used], spec[1])); used += 1
            elif kind == "tref":
                words.append(self._resolve_text(tokens[used])); used += 1
            elif kind == "count":
                n = parse_int(tokens[used]); used += 1
                vars_[spec[1]] = n
                words.append(n)
            elif kind == "rep":
                for _ in range(vars_[spec[1]]):
                    sub, used = self._encode_ops(spec[2], tokens, used, vars_)
                    words += sub
            elif kind == "group":
                for _ in range(vars_[spec[1]]):
                    k = parse_int(tokens[used]); used += 1
                    words.append(k)
                    for _i in range(k):
                        t, v = parse_desc(tokens[used]); used += 1
                        words += [t, v]
            elif kind == "str":
                s = unquote(tokens[used]); used += 1
                data = s.encode("cp932", "replace")
                words.append(len(data))
                words += list(data)
            else:
                raise AsmError("未知操作数类型 %r" % (kind,))
        return words, used

    def _resolve_code(self, tok, delta):
        tok = tok.strip()
        if tok.startswith("loc_"):
            if tok not in self.labels:
                if self.phase == 1:
                    return 0 - delta
                raise AsmError("未定义代码标签: %s" % tok)
            return self.labels[tok] - delta
        return parse_int(tok) - delta

    def _resolve_text(self, tok):
        tok = tok.strip()
        if tok.startswith("t_"):
            if tok not in self.text_labels:
                raise AsmError("未定义文本标签: %s" % tok)
            return self.text_labels[tok]
        return parse_int(tok)

    # -- 两遍汇编
    def assemble(self, items, table_c_refs):
        self.collect_records(items)
        text_words = self.build_text_words()

        # 第一遍：定位标签
        pc = oc.CODE_START
        for item in items:
            if item[0] == "label":
                if item[1].startswith("loc_"):
                    self.labels[item[1]] = pc
            elif item[0] == "instr":
                _tag, mnemonic, tokens, lineno = item
                words = self.encode_instr(pc, mnemonic, tokens, lineno)
                pc += len(words)
        self.phase = 2

        # 第二遍：生成机器码
        code_words = []
        layout = []
        pc = oc.CODE_START
        for item in items:
            if item[0] != "instr":
                continue
            _tag, mnemonic, tokens, lineno = item
            words = self.encode_instr(pc, mnemonic, tokens, lineno)
            layout.append((pc, words[0]))
            code_words.extend(words)
            pc += len(words)

        text_bytes = b"".join(struct.pack("<H", w) for w in text_words)
        if len(text_bytes) % 4:
            if len(text_bytes) % 4 != 2:
                raise AsmError("文本区长度 %d 无法按 4 字节对齐" % len(text_bytes))
            text_words.append(0)
            text_bytes += struct.pack("<H", 0)

        tab_a = sorted(p for p, op in layout if op in oc.TABLE_A_OPS)
        tab_b = sorted(p + 3 for p, op in layout if op == 0x10)
        tab_c = [self._resolve_code(tok, 0) for tok in table_c_refs]

        hdr = [0] * 8
        hdr[2] = oc.CODE_START
        hdr[0] = oc.CODE_START + len(code_words)
        hdr[1] = hdr[0] + len(text_words) // 2
        hdr[3] = hdr[1] + len(tab_a)
        hdr[4] = hdr[3] + len(tab_b)

        out = bytearray()
        out += struct.pack("<8I", *hdr)
        out += b"".join(struct.pack("<I", w) for w in code_words)
        out += text_bytes
        out += b"".join(struct.pack("<I", v) for v in tab_a)
        out += b"".join(struct.pack("<I", v) for v in tab_b)
        out += b"".join(struct.pack("<I", v) for v in tab_c)
        return out


def encrypt_text(buf, hdr):
    start, end = 4 * hdr[0], 4 * hdr[1]
    for i in range(start, end, 2):
        buf[i] ^= oc.TEXT_XOR
    return buf


# ------------------------------------------------------------------ CLI

def default_output(path):
    base = path[:-8] if path.lower().endswith(".asm.txt") else os.path.splitext(path)[0]
    return base + ".rebuild"


def iter_inputs(path):
    if os.path.isdir(path):
        names = sorted(n for n in os.listdir(path) if n.lower().endswith(".asm.txt"))
        if not names:
            names = sorted(n for n in os.listdir(path) if os.path.isfile(os.path.join(path, n)))
        for n in names:
            yield os.path.join(path, n)
    else:
        yield path


def main(argv=None):
    ap = argparse.ArgumentParser(description="wwadv.id 汇编器")
    ap.add_argument("inputs", nargs="+", help="asm.txt 文件或目录，可一次给多个（拖放）")
    ap.add_argument("-o", "--output", help="输出文件或输出目录")
    ap.add_argument("--encoding", default=None, help="正文编码（默认读取 .encoding，缺省 cp932）")
    args = ap.parse_args(argv)

    targets = []
    for raw in args.inputs:
        targets.extend(iter_inputs(raw))
    if not targets:
        print("没有找到输入文件", file=sys.stderr)
        return 2

    for path in targets:
        try:
            encoding, items, table_c = parse_asm(path)
            if args.encoding:
                encoding = args.encoding
            encoding = encoding or "cp932"
            asm = Assembler(encoding)
            blob = asm.assemble(items, table_c)
            hdr = struct.unpack_from("<8I", blob, 0)
            encrypt_text(blob, hdr)
        except AsmError as exc:
            print("%s: 错误: %s" % (path, exc), file=sys.stderr)
            return 1
        except (ValueError, IndexError) as exc:
            print("%s: 解析失败: %s" % (path, exc), file=sys.stderr)
            return 1

        if args.output and os.path.isdir(args.output):
            base = os.path.basename(path)
            base = base[:-8] if base.lower().endswith(".asm.txt") else os.path.splitext(base)[0]
            out_path = os.path.join(args.output, base + ".rebuild")
        elif args.output and len(targets) == 1 and not os.path.isdir(args.output):
            out_path = args.output
        else:
            out_path = default_output(path)

        with open(out_path, "wb") as f:
            f.write(blob)
        print("%s -> %s（%d 字节）" % (path, out_path, len(blob)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
