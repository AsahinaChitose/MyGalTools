#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
disassembler.py -- HIMAURI(SH System) .hst 脚本反汇编器

用法:
    python disassembler.py <脚本文件或目录> [-o <输出目录或文件>] [--encoding cp932]
                          [--no-verify]

输出语义汇编文本(UTF-8)，标签化所有跳转目标，文本按 --encoding 解码展示。
对目录输入时，为每个 *.hst 生成同目录下 <名字>.asm.txt。
"""

import argparse
import os
import sys
import unicodedata

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8')
    except Exception:
        pass

import opcodelist as O


# ---------------------------------------------------------------------------
# 表达式
# ---------------------------------------------------------------------------
def read_expr(data, pos, limit):
    """解析一个 RPN 表达式，返回 (tokens, 新位置)。tokens: ('num',v) / ('var',t,i) / ('op',code)"""
    toks = []
    while True:
        if pos >= limit:
            raise ValueError('表达式在 0x%X 处越界（缺少 0xFF 结束符）' % pos)
        c = data[pos]
        pos += 1
        if c == O.TOK_END:
            return toks, pos
        if c < 0x40:
            ty, lo = c >> 4, c & 0x0F
            if ty == 0:
                if lo == 0x0D:
                    if pos + 1 > limit:
                        raise ValueError('立即数越界 @0x%X' % pos)
                    v = data[pos]
                    pos += 1
                elif lo == 0x0E:
                    v = int.from_bytes(data[pos:pos + 2], 'big')
                    pos += 2
                elif lo == 0x0F:
                    v = int.from_bytes(data[pos:pos + 4], 'big')
                    pos += 4
                elif lo < 8:
                    v = lo
                else:
                    v = 7 - lo
                if v >= 0x80000000:
                    v -= 0x100000000
                toks.append(('num', v))
            else:
                if lo == 0x0E:
                    idx = data[pos]
                    pos += 1
                elif lo == 0x0F:
                    idx = int.from_bytes(data[pos:pos + 2], 'big')
                    pos += 2
                else:
                    idx = lo
                toks.append(('var', ty, idx))
        else:
            if c in O.INDEX_VAR_OPS:
                toks.append(('idxvar', O.INDEX_VAR_OPS[c]))
            elif c not in O.OP_TO_SYM:
                raise ValueError('未知表达式记号 0x%02X @0x%X' % (c, pos - 1))
            else:
                toks.append(('op', c))


def render_expr(toks):
    """RPN -> 全括号中缀文本。"""
    st = []
    for t in toks:
        if t[0] == 'num':
            st.append(str(t[1]))
        elif t[0] == 'var':
            st.append('V%d[%d]' % (t[1], t[2]))
        elif t[0] == 'idxvar':
            if not st:
                raise ValueError('间接变量引用缺少下标表达式')
            idx = st.pop()
            st.append('V%d[(%s)]' % (t[1], idx))
        else:
            code = t[1]
            sym = O.OP_TO_SYM[code]
            if code in O.ASSIGN_OPS:
                if len(st) < 2:
                    raise ValueError('赋值表达式栈不足')
                rhs = st.pop()
                lhs = st.pop()
                st.append('(%s %s %s)' % (lhs, sym, rhs))
            elif code in O.BIN_OPS:
                if len(st) < 2:
                    raise ValueError('二元运算符栈不足')
                b = st.pop()
                a = st.pop()
                st.append('(%s %s %s)' % (a, sym, b))
            elif code in O.UN_OPS:
                if not st:
                    raise ValueError('一元运算符栈不足')
                a = st.pop()
                st.append('%s(%s)' % (sym, a))
            else:
                raise ValueError('未定义的运算符 0x%02X' % code)
    if len(st) != 1:
        raise ValueError('表达式求值后栈不唯一（%d 个值）' % len(st))
    return st[0]


# ---------------------------------------------------------------------------
# 字符串
# ---------------------------------------------------------------------------
def decode_text(raw, encoding):
    """把字节串转成可读文本；无法安全往返的字节用 {{XX}} 表示。"""
    out = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == 0x5C:      # backslash
            out.append('\\\\')
            i += 1
            continue
        if b == 0x22:      # "
            out.append('\\"')
            i += 1
            continue
        if b in (0x0D, 0x0A):
            out.append('{{%02X}}' % b)
            i += 1
            continue
        if 0x20 <= b < 0x7F:
            out.append(chr(b))
            i += 1
            continue
        # 尝试多字节解码
        done = False
        for ln in (2, 1):
            if i + ln > n:
                continue
            chunk = raw[i:i + ln]
            try:
                ch = chunk.decode(encoding)
            except Exception:
                continue
            if len(ch) != 1:
                continue
            try:
                if ch.encode(encoding) != chunk:
                    continue
            except Exception:
                continue
            if ch.isprintable() or ch in (' ', '\u3000') or unicodedata.category(ch)[0] not in ('C', 'Z'):
                out.append(ch)
                i += ln
                done = True
                break
        if not done:
            out.append('{{%02X}}' % b)
            i += 1
    return ''.join(out)


def read_string(data, pos, limit):
    """读取字符串操作数，返回 (kind_args, 新位置)。
    返回 ('lit', bytes) 或 ('ref', type, index_expr_tokens)。"""
    if pos >= limit:
        raise ValueError('字符串操作数越界 @0x%X' % pos)
    b0 = data[pos]
    if b0 >= 0x20:
        z = data.find(b'\0', pos, limit)
        if z < 0:
            raise ValueError('字符串未以 0 结束 @0x%X' % pos)
        return ('lit', data[pos:z]), z + 1
    pos += 1
    if b0 == 0:
        return ('lit', b''), pos
    if b0 < 6:
        idx = data[pos]
        return ('ref', b0, [('num', idx)], 'b'), pos + 1
    if b0 < 12:
        idx = int.from_bytes(data[pos:pos + 2], 'big')
        return ('ref', b0 - 6, [('num', idx)], 'w'), pos + 2
    toks, pos = read_expr(data, pos, limit)
    return ('ref', b0 - 12, toks, 'e'), pos


# ---------------------------------------------------------------------------
# 反汇编
# ---------------------------------------------------------------------------
class Script:
    def __init__(self, data, encoding, source_name=None):
        self.data = data
        self.encoding = encoding
        self.source_name = source_name
        self.items = []      # (offset, kind, payload)
        self.targets = set()
        self.parse()

    def parse(self):
        d = self.data
        if len(d) < O.HEADER_SIZE or d[:7] != b'Himauri':
            raise ValueError('不是 HimaURI 脚本（缺少 "Himauri" 头）')
        size = (d[8] << 16) | (d[9] << 8) | d[10]
        if size != len(d):
            raise ValueError('头部长度 0x%X 与实际 0x%X 不符' % (size, len(d)))
        self.flag = d[11]
        self.reserved = int.from_bytes(d[12:16], 'big')
        pos = O.HEADER_SIZE
        self.title = None
        if self.flag:
            z = d.find(b'\0', pos)
            if z < 0:
                raise ValueError('标题串未结束')
            self.title = d[pos:z]
            pos = z + 1
        self.code_start = pos
        self.code_end = pos
        while pos < len(d):
            start = pos
            op = d[pos]
            pos += 1
            if op == 0xFF:
                self.items.append((start, 'end', None))
                self.code_end = pos
                break
            info = O.OPCODES.get(op)
            if info is None:
                raise ValueError('未定义的操作码 0x%02X @0x%X' % (op, start))
            if info['schema'] is None:
                raise ValueError('操作码 0x%02X(%s) 的操作数格式尚未确认，位置 0x%X'
                                 % (op, info['mnemonic'], start))
            args, pos = self.read_operands(info, pos)
            self.items.append((start, 'cmd', (op, args)))
        else:
            raise ValueError('指令流未以 0xFF 结束')
        self.code_end = pos
        if pos < len(d):
            self.items.append((pos, 'data', d[pos:]))

    def read_operands(self, info, pos):
        d = self.data
        args = []
        for kind in info['schema']:
            if kind == 'expr':
                toks, pos = read_expr(d, pos, len(d))
                args.append(('expr', toks))
            elif kind == 'str':
                s, pos = read_string(d, pos, len(d))
                args.append(('str', s))
            elif kind == 'target':
                t = int.from_bytes(d[pos:pos + 3], 'big')
                pos += 3
                self.targets.add(t)
                args.append(('target', t))
            elif kind == 'count':
                args.append(('count', d[pos]))
                pos += 1
            elif kind == 'switch':
                n = d[pos]
                pos += 1
                tg = []
                for _ in range(n):
                    t = int.from_bytes(d[pos:pos + 3], 'big')
                    pos += 3
                    self.targets.add(t)
                    tg.append(t)
                args.append(('switch', tg))
            elif kind == 'params':
                plist = []
                while True:
                    tag = d[pos]
                    pos += 1
                    if tag == 0:
                        break
                    if tag == 1:
                        s, pos = read_string(d, pos, len(d))
                        plist.append(('str', s))
                    elif tag == 2:
                        toks, pos = read_expr(d, pos, len(d))
                        plist.append(('expr', toks))
                    else:
                        raise ValueError('未知参数 tag %d @0x%X' % (tag, pos - 1))
                args.append(('params', plist))
            elif kind == 'tagarg':
                tag = d[pos]
                pos += 1
                if tag == 1:
                    s, pos = read_string(d, pos, len(d))
                    args.append(('str', s))
                else:
                    toks, pos = read_expr(d, pos, len(d))
                    args.append(('expr', toks))
            elif kind == 'calladdr':
                n = d[pos]
                pos += 1
                exprs = []
                for _ in range(n):
                    toks, pos = read_expr(d, pos, len(d))
                    exprs.append(toks)
                t = int.from_bytes(d[pos:pos + 3], 'big')
                pos += 3
                self.targets.add(t)
                args.append(('calladdr', (exprs, t)))
            else:
                raise ValueError('内部错误: 未知 schema %r' % kind)
        return args, pos

    # ---------------- 输出 ----------------
    def label(self, off):
        return 'loc_%04X' % off

    def fmt_str(self, s):
        """字符串操作数：字面量 / 变量引用（区分三种编码形式）。"""
        if s[0] == 'lit':
            return '"%s"' % decode_text(s[1], self.encoding)
        ty, toks, form = s[1], s[2], s[3]
        if form == 'e':
            return 'S%d[(%s)]' % (ty, render_expr(toks))
        if form == 'w':
            return 'S%dw[%s]' % (ty, render_expr(toks))
        return 'S%d[%s]' % (ty, render_expr(toks))

    def format_args(self, info, args):
        parts = []
        tail = ''
        for kind, val in args:
            if kind == 'expr':
                parts.append(render_expr(val))
            elif kind == 'str':
                parts.append(self.fmt_str(val))
            elif kind == 'target':
                tail = self.label(val)
            elif kind == 'count':
                parts.append(str(val))
            elif kind == 'switch':
                tail = '{ %s }' % (', '.join(self.label(t) for t in val) if val else '')
            elif kind == 'params':
                inner = []
                for t, v in val:
                    if t == 'str':
                        inner.append(self.fmt_str(v))
                    else:
                        inner.append(render_expr(v))
                tail = '{ %s }' % ', '.join(inner) if inner else '{ }'
            elif kind == 'calladdr':
                exprs, t = val
                tail = '{ %s }, %s' % (', '.join(render_expr(e) for e in exprs), self.label(t))
        if tail:
            parts.append(tail)
        return ', '.join(parts)

    def text(self):
        L = []
        L.append('; HIMAURI(SH System) script disassembly')
        L.append('; generated by disassembler.py v%s' % O.VERSION)
        L.append('; source size: %d bytes' % len(self.data))
        L.append('')
        L.append('.header 0x%02X, 0x%08X' % (self.flag, self.reserved))
        if self.source_name:
            L.append('.source "%s"' % self.source_name)
        L.append('.encoding %s' % self.encoding)
        if self.title is not None:
            L.append('.title "%s"' % decode_text(self.title, self.encoding))
        L.append('')
        for off, kind, payload in self.items:
            if off in self.targets:
                L.append('')
                L.append('%s:' % self.label(off))
            if kind == 'end':
                L.append('    END')
            elif kind == 'data':
                L.append('    ; 尾部数据')
                for i in range(0, len(payload), 16):
                    L.append('    .byte %s' % ', '.join('%d' % b for b in payload[i:i + 16]))
            else:
                op, args = payload
                info = O.OPCODES[op]
                try:
                    rest = self.format_args(info, args)
                except Exception as ex:
                    raise ValueError('0x%X 处 %s 生成失败: %s' % (off, info['mnemonic'], ex))
                L.append('    %-10s %s' % (info['mnemonic'], rest))
        L.append('')
        return '\n'.join(L)


def process_file(path, out_path, encoding):
    data = open(path, 'rb').read()
    sc = Script(data, encoding, os.path.basename(path))
    text = sc.text()
    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    return len(sc.items)


def main(argv=None):
    ap = argparse.ArgumentParser(description='HIMAURI .hst 脚本反汇编器')
    ap.add_argument('input', help='脚本文件或目录')
    ap.add_argument('-o', '--out', help='输出文件或目录')
    ap.add_argument('--encoding', default='cp932', help='文本编码（默认 cp932）')
    ap.add_argument('--no-verify', action='store_true', help='跳过自检')
    args = ap.parse_args(argv)

    inputs = []
    if os.path.isdir(args.input):
        skipped = 0
        for fn in sorted(os.listdir(args.input)):
            if not fn.lower().endswith(('.hst', '.bin', '.sc')):
                continue
            p = os.path.join(args.input, fn)
            with open(p, 'rb') as f:
                if f.read(8) != b'Himauri\0':
                    skipped += 1
                    continue
            inputs.append(p)
        if skipped:
            print('[!] 跳过 %d 个非 HIMAURI 脚本文件' % skipped)
        if not inputs:
            print('[-] 目录中没有可反汇编的脚本: %s' % args.input)
            return 1
        outdir = args.out or args.input
        if os.path.isfile(outdir):
            print('[-] 输出必须是目录: %s' % outdir)
            return 1
        os.makedirs(outdir, exist_ok=True)
        pairs = [(p, os.path.join(outdir, os.path.splitext(os.path.basename(p))[0] + '.asm.txt'))
                 for p in inputs]
    else:
        if not os.path.isfile(args.input):
            print('[-] 找不到输入文件: %s' % args.input)
            return 1
        out = args.out
        if out and os.path.isdir(out):
            out = os.path.join(out, os.path.splitext(os.path.basename(args.input))[0] + '.asm.txt')
        out = out or (os.path.splitext(args.input)[0] + '.asm.txt')
        pairs = [(args.input, out)]

    rc = 0
    for src, dst in pairs:
        try:
            n = process_file(src, dst, args.encoding)
            print('[+] %s -> %s (%d 条指令)' % (src, dst, n))
            if not args.no_verify:
                import subprocess
                here = os.path.dirname(os.path.abspath(__file__))
                rebuild = dst + '.verify'
                r = subprocess.run([sys.executable, os.path.join(here, 'assembler.py'), dst,
                                    '-o', rebuild, '--encoding', args.encoding,
                                    '--quiet'], capture_output=True)
                if r.returncode != 0:
                    print('[-] 自检失败: %s' % r.stderr.decode('utf-8', 'replace').strip())
                    rc = 1
                else:
                    a = open(src, 'rb').read()
                    b = open(rebuild, 'rb').read()
                    if a != b:
                        print('[-] 自检不一致: %s' % src)
                        rc = 1
                try:
                    os.remove(rebuild)
                except OSError:
                    pass
        except Exception as e:
            print('[-] %s: %s' % (src, e))
            rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
