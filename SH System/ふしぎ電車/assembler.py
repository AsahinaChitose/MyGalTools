#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
assembler.py -- HIMAURI(SH System) .hst 脚本汇编器

用法:
    python assembler.py <asm.txt 或目录> [-o <输出文件/目录>] [--encoding gbk] [--quiet]

读取 disassembler.py 生成的语义汇编(UTF-8)，重建二进制脚本。
编码优先级：--encoding > asm 头部 .encoding > gbk。
"""

import argparse
import os
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8')
    except Exception:
        pass

import opcodelist as O


class AsmError(Exception):
    pass


# ---------------------------------------------------------------------------
# 词法
# ---------------------------------------------------------------------------
SLASH_MODE = 'cp932'    # gbk 文本里的 ／ 默认写成 CP932 的 81 5E（引擎靠它分段）
                        # 'cr' = 写成 0x0D；None = 原样保留

TOKEN_RE = re.compile(r'''
    (?P<ws>\s+)
  | (?P<num>-?(?:0[xX][0-9a-fA-F]+|\d+))
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>\+=|-=|\*=|/=|%=|&=|\|=|==|!=|<=|>=|&&|\|\||[-+*/%&|<>()\[\],=!])
''', re.VERBOSE)

PREC = {
    '=': 2, '+=': 2, '-=': 2, '*=': 2, '/=': 2, '%=': 2, '&=': 2, '|=': 2,
    '||': 3, '&&': 4, '|': 5, '&': 6,
    '==': 7, '!=': 7,
    '<': 8, '<=': 8, '>': 8, '>=': 8,
    '+': 9, '-': 9,
    '*': 10, '/': 10, '%': 10,
}
ASSIGN_SYMS = {'=', '+=', '-=', '*=', '/=', '%=', '&=', '|='}
RIGHT_ASSOC = ASSIGN_SYMS


def tokenize_expr(s):
    toks = []
    pos = 0
    while pos < len(s):
        m = TOKEN_RE.match(s, pos)
        if not m:
            raise AsmError('无法解析的表达式片段: %r' % s[pos:pos + 20])
        pos = m.end()
        kind = m.lastgroup
        if kind == 'ws':
            continue
        val = m.group()
        if kind == 'num':
            toks.append(('num', int(val, 0)))
        else:
            toks.append((kind, val))
    return toks


class ExprParser:
    def __init__(self, text):
        self.toks = tokenize_expr(text)
        self.i = 0
        self.out = []

    def peek(self, off=0):
        j = self.i + off
        return self.toks[j] if j < len(self.toks) else (None, None)

    def next(self):
        t = self.peek()
        self.i += 1
        return t

    def parse(self):
        self.parse_expr(0)
        if self.i != len(self.toks):
            raise AsmError('表达式有多余内容: %r' % (self.toks[self.i:],))
        return self.out

    def parse_expr(self, min_prec):
        self.parse_unary()
        while True:
            kind, val = self.peek()
            if kind != 'op' or val not in PREC:
                break
            prec = PREC[val]
            if prec < min_prec:
                break
            self.next()
            self.parse_expr(prec if val in RIGHT_ASSOC else prec + 1)
            self.emit_op(val)

    def parse_unary(self):
        kind, val = self.peek()
        if kind == 'op' and val == '-':
            self.next()
            # 负数字面量: -5 直接作为立即数
            if self.peek()[0] == 'num':
                n = self.next()[1]
                self.emit_num(-n)
                return
            self.parse_unary()
            self.out.append(('op', 0x70))
            return
        if kind == 'op' and val == '!':
            self.next()
            self.parse_unary()
            self.out.append(('op', 0x71))
            return
        self.parse_primary()

    def parse_primary(self):
        kind, val = self.next()
        if kind == 'num':
            self.emit_num(val)
            return
        if kind == 'op' and val == '(':
            self.parse_expr(0)
            if self.next() != ('op', ')'):
                raise AsmError('缺少右括号')
            return
        if kind == 'ident':
            up = val.upper()
            if re.fullmatch(r'V[123]', up):
                ty = int(up[1])
                inner = self.parse_bracket_tokens()
                if len(inner) == 1 and inner[0][0] == 'num':
                    self.out.append(('var', ty, inner[0][1]))
                else:
                    sub = ExprParser.from_tokens(inner)
                    self.out.extend(sub)
                    self.out.append(('idxvar', ty))
                return
            if val.lower() in O.UN_FUNCS:
                if self.next() != ('op', '('):
                    raise AsmError('%s 需要括号参数' % val)
                self.parse_expr(0)
                if self.next() != ('op', ')'):
                    raise AsmError('缺少右括号')
                self.out.append(('op', O.UN_FUNCS[val.lower()]))
                return
            if re.fullmatch(r'loc_[0-9A-Fa-f]+', val):
                raise AsmError('表达式里不能出现标签: %s' % val)
            raise AsmError('未知标识符: %s' % val)
        raise AsmError('表达式语法错误: %r' % (val,))

    def parse_index(self):
        inner = self.parse_bracket_tokens()
        if len(inner) != 1 or inner[0][0] != 'num':
            raise AsmError('变量下标必须是常量')
        return inner[0][1]

    def parse_bracket_tokens(self):
        """吃掉 [ ... ]，返回括号内的 token 列表。"""
        if self.next() != ('op', '['):
            raise AsmError('变量缺少下标')
        depth = 1
        start = self.i
        while self.i < len(self.toks):
            k, v = self.toks[self.i]
            if k == 'op' and v == '[':
                depth += 1
            elif k == 'op' and v == ']':
                depth -= 1
                if depth == 0:
                    break
            self.i += 1
        if depth != 0:
            raise AsmError('变量下标缺少 ]')
        inner = self.toks[start:self.i]
        self.i += 1
        return inner

    @classmethod
    def from_tokens(cls, toks):
        obj = cls.__new__(cls)
        obj.toks = list(toks)
        obj.i = 0
        obj.out = []
        obj.parse()
        if obj.i != len(obj.toks):
            raise AsmError('下标表达式有多余内容')
        return obj.out

    def emit_num(self, v):
        self.out.append(('num', v))

    def emit_op(self, sym):
        if sym in ASSIGN_SYMS:
            code = O.SYM_TO_OP[sym]
            self.out.append(('op', code))
        elif sym in O.SYM_TO_OP:
            self.out.append(('op', O.SYM_TO_OP[sym]))
        else:
            raise AsmError('未知运算符: %s' % sym)


# ---------------------------------------------------------------------------
# 编码
# ---------------------------------------------------------------------------
def enc_num(v):
    if 0 <= v <= 7:
        return bytes([v])
    if -5 <= v <= -1:
        return bytes([7 - v])
    if 0 <= v <= 127:
        return bytes([0x0D, v])
    if -32768 <= v <= 32767:
        return bytes([0x0E]) + (v & 0xFFFF).to_bytes(2, 'big')
    if -2 ** 31 <= v <= 2 ** 32 - 1:
        return bytes([0x0F]) + (v & 0xFFFFFFFF).to_bytes(4, 'big')
    raise AsmError('立即数超出 32 位: %d' % v)


def enc_var(ty, idx):
    if not 0 <= ty <= 3:
        raise AsmError('变量类型越界: %d' % ty)
    hi = ty << 4
    if 0 <= idx <= 13:
        return bytes([hi | idx])
    if 0 <= idx <= 255:
        return bytes([hi | 0x0E, idx])
    if 0 <= idx <= 65535:
        return bytes([hi | 0x0F]) + idx.to_bytes(2, 'big')
    raise AsmError('变量下标越界: %d' % idx)


def enc_expr(tokens):
    out = bytearray()
    depth = 0
    for t in tokens:
        if t[0] == 'num':
            out += enc_num(t[1])
            depth += 1
        elif t[0] == 'var':
            out += enc_var(t[1], t[2])
            depth += 1
        elif t[0] == 'idxvar':
            if depth < 1:
                raise AsmError('间接变量引用缺少下标')
            if t[1] not in O.INDEX_VAR_CODE:
                raise AsmError('间接变量类型越界: %d' % t[1])
            out.append(O.INDEX_VAR_CODE[t[1]])
        else:
            code = t[1]
            need = 1 if code in O.UN_OPS else 2
            if depth < need:
                raise AsmError('表达式操作数不足(运算符 0x%02X)' % code)
            depth -= need - 1
            out.append(code)
    if depth != 1:
        raise AsmError('表达式结果不唯一(栈深 %d)' % depth)
    out.append(0xFF)
    return bytes(out)


# ---------------------------------------------------------------------------
# 文本解析
# ---------------------------------------------------------------------------
def strip_comment(line):
    out = []
    q = False
    i = 0
    while i < len(line):
        c = line[i]
        if q:
            if c == '\\' and i + 1 < len(line):
                out.append(c)
                out.append(line[i + 1])
                i += 2
                continue
            if c == '"':
                q = False
            out.append(c)
            i += 1
            continue
        if c == '"':
            q = True
            out.append(c)
            i += 1
            continue
        if c == ';':
            break
        out.append(c)
        i += 1
    return ''.join(out).rstrip()


def split_top(s, sep=','):
    """按顶层逗号切分（忽略括号/方括号花括号和引号内的逗号）。"""
    parts = []
    depth = 0
    q = False
    cur = []
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            cur.append(c)
            if c == '\\' and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                q = False
            i += 1
            continue
        if c == '"':
            q = True
            cur.append(c)
            i += 1
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        if c == sep and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if ''.join(cur).strip():
        parts.append(''.join(cur).strip())
    return parts


def encode_text(s, encoding):
    out = bytearray()
    i = 0
    while i < len(s):
        if s.startswith('{{', i):
            j = s.find('}}', i)
            if j < 0 or j - i not in (4, 7):
                raise AsmError('占位符格式错误: %s' % s[i:i + 10])
            body = s[i + 2:j]
            if len(body) == 2:
                out.append(int(body, 16))
            else:
                raise AsmError('占位符必须是单字节 {{XX}}: {{%s}}' % body)
            i = j + 2
            continue
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            if n == '\\':
                out.append(0x5C)
                i += 2
                continue
            if n == '"':
                out.append(0x22)
                i += 2
                continue
            raise AsmError('未知转义: \\%s' % n)
        out += c.encode(encoding)
        i += 1
    return bytes(out)


def parse_string_operand(text, encoding):
    """返回 ('lit', bytes) 或 ('ref', type, tokens, form)，form: b/w/e"""
    text = text.strip()
    if text.startswith('"'):
        if not text.endswith('"') or len(text) < 2:
            raise AsmError('字符串缺少结束引号')
        return ('lit', encode_text(text[1:-1], encoding))
    m = re.fullmatch(r'S(\d+)w\s*\[(.*)\]', text)
    if m:
        return ('ref', int(m.group(1)), ExprParser(m.group(2)).parse(), 'w')
    m = re.fullmatch(r'S(\d+)\s*\[\((.*)\)\]', text)
    if m:
        return ('ref', int(m.group(1)), ExprParser(m.group(2)).parse(), 'e')
    m = re.fullmatch(r'S(\d+)\s*\[(.*)\]', text)
    if m:
        return ('ref', int(m.group(1)), ExprParser(m.group(2)).parse(), 'b')
    raise AsmError('无法识别的字符串操作数: %s' % text)


def enc_string_operand(op, encoding):
    if op[0] == 'lit':
        raw = op[1]
        if not raw:
            return b'\0'
        if raw[0] < 0x20:
            raise AsmError('字符串首字节 0x%02X < 0x20，引擎会把它当作变量引用' % raw[0])
        if 0 in raw:
            raise AsmError('字符串不能包含 0x00')
        if SLASH_MODE:
            # 引擎靠 CP932 的 ／(81 5E) 分段换行；GBK 正文里的 ／(A1 AD) 它不认，
            # 所以默认把 ／ 写回 CP932 字节（该字节对会被引擎吃掉，不会被绘制）
            norm = (encoding or '').lower().replace('-', '')
            if norm in ('gbk', 'gb2312', 'cp936', 'gb18030'):
                if SLASH_MODE == 'cr':
                    raw = raw.replace('／'.encode(encoding, 'ignore'), b'\x0d')
                else:
                    raw = raw.replace('／'.encode(encoding, 'ignore'), b'\x81\x5e')
        return raw + b'\0'
    ty, toks, form = op[1], op[2], op[3]
    if form == 'b':
        if not (1 <= ty <= 5):
            raise AsmError('S%d[] 形式要求类型 1..5' % ty)
        if len(toks) != 1 or toks[0][0] != 'num' or not 0 <= toks[0][1] <= 255:
            raise AsmError('S%d[] 的下标必须是 0..255 的常量' % ty)
        return bytes([ty, toks[0][1]])
    if form == 'w':
        if not (0 <= ty <= 5):
            raise AsmError('S%dw[] 形式要求类型 0..5' % ty)
        if len(toks) != 1 or toks[0][0] != 'num' or not 0 <= toks[0][1] <= 65535:
            raise AsmError('S%dw[] 的下标必须是 0..65535 的常量' % ty)
        return bytes([ty + 6]) + toks[0][1].to_bytes(2, 'big')
    if not (0 <= ty <= 19):
        raise AsmError('字符串变量类型越界: %d' % ty)
    return bytes([ty + 12]) + enc_expr(toks)


# ---------------------------------------------------------------------------
# 汇编
# ---------------------------------------------------------------------------
class Program:
    def __init__(self):
        self.items = []          # ('label', name) / ('cmd', mnemonic, args_text)
        self.encoding = None
        self.source_name = None  # .source 里记录的原文件名（用于决定输出后缀）
        self.flag = 0
        self.reserved = 0
        self.title = None
        self.data = []           # .byte 字节


def parse_asm(path):
    prog = Program()
    with open(path, encoding='utf-8') as f:
        lines = f.read().splitlines()
    for no, raw in enumerate(lines, 1):
        line = strip_comment(raw).rstrip()
        if not line.strip():
            continue
        s = line.strip()
        if s.startswith('.'):
            m = re.match(r'\.(\w+)\s*(.*)$', s)
            if not m:
                raise AsmError('第 %d 行: 无法识别的伪指令' % no)
            name, rest = m.group(1).lower(), m.group(2).strip()
            if name == 'encoding':
                prog.encoding = rest
            elif name == 'source':
                prog.source_name = parse_string_operand(rest, prog.encoding or 'cp932')[1] \
                    if rest.startswith('"') else rest
                if isinstance(prog.source_name, bytes):
                    prog.source_name = prog.source_name.decode('utf-8', 'replace')
            elif name == 'header':
                parts = split_top(rest)
                if len(parts) < 2:
                    raise AsmError('第 %d 行: .header 需要 flag, reserved' % no)
                prog.flag = int(parts[0], 0)
                prog.reserved = int(parts[1], 0)
            elif name == 'title':
                prog.title = parse_string_operand(rest, prog.encoding or 'cp932')[1]
            elif name == 'byte':
                for p in split_top(rest):
                    prog.data.append(int(p, 0))
            else:
                raise AsmError('第 %d 行: 未知伪指令 .%s' % (no, name))
            continue
        if s.endswith(':'):
            prog.items.append(('label', s[:-1].strip()))
            continue
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$', s)
        if not m:
            raise AsmError('第 %d 行: 无法解析: %s' % (no, s))
        prog.items.append(('cmd', m.group(1).upper(), m.group(2).strip(), no))
    return prog


def split_operands(s):
    """按顶层逗号切分；平衡的 { ... } 作为一个整体。"""
    parts = []
    cur = []
    depth = 0
    q = False
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            cur.append(c)
            if c == '\\' and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                q = False
            i += 1
            continue
        if c == '"':
            q = True
            cur.append(c)
            i += 1
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        if c == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if ''.join(cur).strip():
        parts.append(''.join(cur).strip())
    return parts


def build(prog, encoding):
    title_bytes = (prog.title + b'\0') if prog.title else b''
    header_len = O.HEADER_SIZE + len(title_bytes)
    out = bytearray(header_len)      # 前部留出文件头，保证标签偏移是文件绝对偏移
    patches = []           # (pos, label)
    labels = {}

    def emit_target(label):
        patches.append((len(out), label))
        out.extend(b'\0\0\0')

    ended = False
    for it in prog.items:
        if it[0] == 'label':
            name = it[1]
            if name in labels:
                raise AsmError('重复标签: %s' % name)
            labels[name] = len(out)
            continue
        _, mn, rest, no = it
        if mn == 'END':
            out.append(0xFF)
            ended = True
            continue
        try:
            code = O.by_mnemonic(mn)
        except KeyError:
            raise AsmError('第 %d 行: 未知助记符 %s' % (no, mn))
        info = O.OPCODES[code]
        if info['schema'] is None:
            raise AsmError('第 %d 行: 指令 %s 的操作数格式尚未确认' % (no, mn))
        schema = info['schema']
        parts = split_operands(rest)

        pos = 0
        out.append(code)
        for kind in schema:
            if kind == 'expr':
                if pos >= len(parts):
                    raise AsmError('第 %d 行: %s 缺少表达式操作数' % (no, mn))
                toks = ExprParser(parts[pos]).parse()
                pos += 1
                out.extend(enc_expr(toks))
            elif kind == 'str':
                if pos >= len(parts):
                    raise AsmError('第 %d 行: %s 缺少字符串操作数' % (no, mn))
                op = parse_string_operand(parts[pos], encoding)
                pos += 1
                out.extend(enc_string_operand(op, encoding))
            elif kind == 'target':
                if pos >= len(parts):
                    raise AsmError('第 %d 行: %s 缺少跳转目标' % (no, mn))
                emit_target(parts[pos].strip())
                pos += 1
            elif kind == 'count':
                if pos >= len(parts):
                    raise AsmError('第 %d 行: %s 缺少计数' % (no, mn))
                n = int(parts[pos], 0)
                pos += 1
                out.append(n & 0xFF)
            elif kind == 'switch':
                if pos >= len(parts):
                    raise AsmError('第 %d 行: %s 缺少目标表' % (no, mn))
                b = parts[pos].strip()
                if not (b.startswith('{') and b.endswith('}')):
                    raise AsmError('第 %d 行: %s 目标表需要 { }' % (no, mn))
                inner = b[1:-1].strip()
                tg = split_top(inner) if inner else []
                pos += 1
                out.append(len(tg))
                for t in tg:
                    emit_target(t.strip())
            elif kind == 'params':
                if pos >= len(parts):
                    raise AsmError('第 %d 行: %s 缺少参数表 { }' % (no, mn))
                b = parts[pos].strip()
                if not (b.startswith('{') and b.endswith('}')):
                    raise AsmError('第 %d 行: %s 参数表需要 { }' % (no, mn))
                inner = b[1:-1].strip()
                plist = split_top(inner) if inner else []
                pos += 1
                for p in plist:
                    p = p.strip()
                    if p.startswith('"') or p.startswith('S'):
                        op = parse_string_operand(p, encoding)
                        out.append(1)
                        out.extend(enc_string_operand(op, encoding))
                    else:
                        toks = ExprParser(p).parse()
                        out.append(2)
                        out.extend(enc_expr(toks))
                out.append(0)
            elif kind == 'tagarg':
                if pos >= len(parts):
                    raise AsmError('第 %d 行: %s 缺少查表键' % (no, mn))
                arg = parts[pos].strip()
                pos += 1
                if arg.startswith('"') or re.match(r'^S\d+\s*\[', arg):
                    out.append(1)
                    out.extend(enc_string_operand(parse_string_operand(arg, encoding), encoding))
                else:
                    out.append(0)
                    out.extend(enc_expr(ExprParser(arg).parse()))
            elif kind == 'calladdr':
                if len(parts) < 2:
                    raise AsmError('第 %d 行: %s 需要 { 参数 }, 目标' % (no, mn))
                b = parts[0].strip()
                if not (b.startswith('{') and b.endswith('}')):
                    raise AsmError('第 %d 行: %s 参数表需要 { }' % (no, mn))
                inner = b[1:-1].strip()
                exprs = split_operands(inner) if inner else []
                out.append(len(exprs))
                for e in exprs:
                    out.extend(enc_expr(ExprParser(e).parse()))
                emit_target(parts[1].strip())
                pos = 2
        if pos != len(parts):
            raise AsmError('第 %d 行: %s 有多余操作数: %s' % (no, mn, parts[pos:]))
        if code == 0x00:
            pass

    # 结束符
    if not ended:
        out.append(0xFF)
    for b in prog.data:
        out.append(b & 0xFF)

    for p, label in patches:
        if label not in labels:
            raise AsmError('未定义的标签: %s' % label)
        v = labels[label]
        if v > 0xFFFFFF:
            raise AsmError('标签 %s 超出 24 位' % label)
        out[p:p + 3] = v.to_bytes(3, 'big')
    if os.environ.get('ASM_DEBUG'):
        for k in sorted(labels):
            print('  label %-12s 0x%04X' % (k, labels[k]), file=sys.stderr)

    body = bytes(out[header_len:])
    header = bytearray(O.MAGIC)
    total = header_len + len(body)
    header += total.to_bytes(3, 'big')
    header.append(prog.flag & 0xFF)
    header += (prog.reserved & 0xFFFFFFFF).to_bytes(4, 'big')
    header += title_bytes
    out[0:header_len] = header
    return bytes(out)


def source_name_of(path):
    """读取 asm 头部的 .source，返回原始文件名（没有则 None）。"""
    try:
        with open(path, encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i > 30:
                    break
                s = line.strip()
                if s.startswith('.source'):
                    rest = s[len('.source'):].strip()
                    if rest.startswith('"') and rest.endswith('"') and len(rest) >= 2:
                        return os.path.basename(rest[1:-1])
    except Exception:
        pass
    return None


def default_out_name(path):
    """汇编输出的默认文件名：优先用 .source 记录的原名，否则 <stem>.hst。"""
    name = source_name_of(path)
    if name:
        return name
    base = os.path.basename(path)
    if base.lower().endswith('.asm.txt'):
        base = base[:-len('.asm.txt')]
    else:
        base = os.path.splitext(base)[0]
    return base + '.hst'


def main(argv=None):
    ap = argparse.ArgumentParser(description='HIMAURI .hst 脚本汇编器')
    ap.add_argument('input', help='asm.txt 或目录')
    ap.add_argument('-o', '--out', help='输出文件或目录（目录时沿用原文件名，如 0000.hst）')
    ap.add_argument('--encoding', default=None, help='字符串编码（默认取 .encoding，否则 gbk）')
    ap.add_argument('--slash-newline', action='store_true',
                    help='把 ／ 汇编成 0x0D（默认是把 GBK ／ 写成 CP932 的 81 5E）')
    ap.add_argument('--no-slash', action='store_true',
                    help='保留 GBK 的 ／（A1 AD）原样，不做转换')
    ap.add_argument('--force', action='store_true',
                    help='允许覆盖同目录下已存在的同名文件')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args(argv)
    global SLASH_MODE
    SLASH_MODE = None if args.no_slash else ('cr' if args.slash_newline else 'cp932')

    if os.path.isdir(args.input):
        files = [os.path.join(args.input, f) for f in sorted(os.listdir(args.input))
                 if f.lower().endswith('.asm.txt')]
        if not files:
            print('[-] 目录里没有 .asm.txt: %s' % args.input)
            return 1
        outdir = args.out or args.input
        os.makedirs(outdir, exist_ok=True)
        pairs = [(p, os.path.join(outdir, default_out_name(p))) for p in files]
    else:
        if not os.path.isfile(args.input):
            print('[-] 找不到输入: %s' % args.input)
            return 1
        out = args.out
        if out and os.path.isdir(out):
            out = os.path.join(out, default_out_name(args.input))
        out = out or os.path.join(os.path.dirname(args.input), default_out_name(args.input))
        pairs = [(args.input, out)]

    rc = 0
    for src, dst in pairs:
        try:
            # 同一目录下按原名回写会把原始脚本覆盖掉，默认拒绝，需 --force
            if (os.path.exists(dst) and not args.force
                    and os.path.normcase(os.path.dirname(os.path.abspath(dst)))
                    == os.path.normcase(os.path.dirname(os.path.abspath(src)))):
                raise AsmError('目标已存在: %s（同目录按原名回写会覆盖原文件）\n'
                               '    换一个 -o 输出目录，或加 --force 确认覆盖。' % dst)
            prog = parse_asm(src)
            enc = args.encoding or prog.encoding
            if not enc:
                enc = 'gbk'
            data = build(prog, enc)
            with open(dst, 'wb') as f:
                f.write(data)
            if not args.quiet:
                print('[+] %s -> %s (%d 字节, 编码 %s)' % (src, dst, len(data), enc))
        except UnicodeEncodeError as e:
            ch = e.object[e.start:e.end] if getattr(e, 'object', None) else ''
            print('[-] %s: 文本里有 %r 无法用 %s 编码。'
                  % (src, ch, enc))
            print('    如果这是已翻译的中文，请加 --encoding gbk（或把头部 .encoding 改成 gbk）。')
            rc = 1
        except Exception as e:
            print('[-] %s: %s' % (src, e))
            rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
