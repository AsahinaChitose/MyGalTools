#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asm_json.py -- HIMAURI 脚本的语义汇编(asm.txt) <-> 翻译 JSON 双向转换

参照 REIMI/asm_json.py 的交互方式，适配本项目 disassembler.py 的 asm 语法：

    CALLSCRIPT 52, { 537, "", "【チヒロの母】／それでは、これにて失礼致します。" }
    CALLSCRIPT 57, { "文明を捨てるべきだ", 1, "機械化を推進するべきだ", 1 }
    CALLSCRIPT 51, { 7, "FD_A01", "眠りと目覚めの狭間で…" }

提取规则（--types 可关掉某一类）：
    MESSAGE  52 的第 3 个参数：正文/旁白。文本形如 "【名字】／正文"，
             【】内抽成 name，紧随其后的 ／ 抽成行首符号，其余为 message。
    CHOICE   57 的奇数位参数：选择肢，每项一条 message。
    TITLE    51 的第 3 个参数：章节标题（第 2 个参数是资源代码，过滤掉）。

过滤（--no-filter 关闭）：
    * 空串、纯空白；
    * 纯资源代码（如 BG_06 / CH_01D / FD_A01，只含 ASCII 字母数字下划线）；
    * 不含假名/汉字的纯符号行（如 "……………………"）。

注入：
    * 以 asm 源文件为模板按 id 定位，只替换字符串本体；
    * 【name】／ 等符号按源文件原结构自动补回（源文件该行是什么结构就补什么）；
    * message 为空时回退 pre_jp；
    * --encoding 指定目标编码时，同步改写 asm 头部的 `.encoding`，并逐条检查可编码性。

用法：
    python asm_json.py extract -s asm -o json_jp
    python asm_json.py inject  -s asm -j json_cn -o asm_cn --encoding gbk
    python asm_json.py stats   -s asm
"""

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8')
    except Exception:
        pass

# ---------------------------------------------------------------------------
# asm 行解析
# ---------------------------------------------------------------------------
CALL_RE = re.compile(r'^(\s*)CALLSCRIPT\s+(\d+)\s*,\s*\{(.*)\}\s*$')
ENC_RE = re.compile(r'^\.encoding\s+(\S+)\s*$')

JP_RE = re.compile(r'[\u3040-\u30ff\u4e00-\u9fff\uff66-\uff9f]')
RESOURCE_RE = re.compile(r'^[A-Za-z0-9_.\-]+$')


def split_args_offsets(body):
    """返回 [(start, end, text)]，start/end 为 body 内的字符区间。"""
    out = []
    cur = ''
    start = 0
    depth = 0
    q = False
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if q:
            cur += c
            if c == '\\' and i + 1 < n:
                cur += body[i + 1]
                i += 2
                continue
            if c == '"':
                q = False
            i += 1
            continue
        if c == '"':
            q = True
            cur += c
            i += 1
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        if c == ',' and depth == 0:
            out.append((start, i, cur))
            cur = ''
            i += 1
            while i < n and body[i] in ' \t':
                i += 1
            start = i
            continue
        cur += c
        i += 1
    if cur or not out:
        out.append((start, n, cur))
    return out


def unquote(s):
    s = s.strip()
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return None
    body = s[1:-1]
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == '\\' and i + 1 < len(body) and body[i + 1] in '\\"':
            out.append(body[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def quote(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def split_text(txt):
    """把 "【名】／正文" 拆成 (name, sep, message)。"""
    name = ''
    rest = txt
    if rest.startswith('【'):
        j = rest.find('】')
        if 0 < j:
            name = rest[1:j]
            rest = rest[j + 1:]
    sep = rest.startswith('／')
    if sep:
        rest = rest[1:]
    return name, sep, rest


def join_text(name, sep, message):
    return ('【%s】' % name if name else '') + ('／' if sep else '') + message


# ---------------------------------------------------------------------------
# 单行宽度检查（游戏文本框每行最多 24 个全角字符）
# ---------------------------------------------------------------------------
LINE_MAX = 24


def _width(ch):
    return 1.0 if unicodedata.east_asian_width(ch) in ('W', 'F') else 0.5


def text_width(s):
    return sum(_width(c) for c in s)


def overlong_lines(text, limit=LINE_MAX):
    """去掉【人名】后按 ／ 分段，返回超过 limit 的 [(段号, 宽度, 段落)]。"""
    t = re.sub(r'【[^】]*】', '', text)
    if t.startswith('／'):      # 名字后面那个分隔符不算一段
        t = t[1:]
    out = []
    for i, seg in enumerate(t.split('／'), 1):
        w = text_width(seg)
        if w > limit:
            out.append((i, w, seg.strip()))
    return out


def has_jp(s):
    return bool(JP_RE.search(s))


def skip_text(name, msg, filtered=True):
    """过滤掉非翻译内容；但有名字（【】）的行即使正文只有标点也保留，
    以免同一角色的称呼在部分行里没被翻译。"""
    if not filtered:
        return False
    text = (name or '') + (msg or '')
    if not text.strip():
        return True
    if RESOURCE_RE.match((msg or '').strip()):
        return True
    if not has_jp(text):
        return True
    return False


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------
def scan_file(path, enable, filtered=True):
    """返回 (entries, skipped)。id 编号只对未被过滤的条目递增，保证提取/注入一致。"""
    stem = stem_of(path)
    entries = []
    skipped = []
    seq = 0
    with open(path, encoding='utf-8') as f:
        lines = f.read().splitlines()
    for li, line in enumerate(lines):
        m = CALL_RE.match(line)
        if not m:
            continue
        sid = int(m.group(2))
        body = m.group(3)
        base = m.start(3)
        parts = split_args_offsets(body)
        cand = []           # (kind, part_index, atext, text, name, sep, msg)
        if sid == 52 and 'MESSAGE' in enable:
            if len(parts) < 3:
                continue
            atext = parts[2][2]
            txt = unquote(atext)
            if txt is None:
                continue
            name, sep, msg = split_text(txt)
            cand.append(('MESSAGE', 2, atext, txt, name, sep, msg))
        elif sid == 57 and 'CHOICE' in enable:
            # 偶数位(0,2,4...)是文本，奇数位是数值
            for i in range(0, len(parts), 2):
                atext = parts[i][2]
                txt = unquote(atext)
                if txt is None:
                    continue
                cand.append(('CHOICE', i, atext, txt, '', False, txt))
        elif sid == 51 and 'TITLE' in enable:
            if len(parts) < 3:
                continue
            atext = parts[2][2]
            txt = unquote(atext)
            if txt is None:
                continue
            cand.append(('TITLE', 2, atext, txt, '', False, txt))
        for kind, pidx, atext, txt, name, sep, msg in cand:
            if skip_text(name, msg, filtered):
                skipped.append((stem, li + 1, kind, txt))
                continue
            q0 = atext.index('"')
            q1 = atext.rindex('"')
            seq += 1
            entries.append({
                'id': '%s#%04d' % (stem, seq),
                'type': kind,
                'line': li,
                'col_start': base + parts[pidx][0] + q0 + 1,
                'col_end': base + parts[pidx][0] + q1,
                'text': txt,
                'name': name,
                'sep': sep,
                'message': msg,
            })
    return entries, skipped


def stem_of(path):
    base = os.path.basename(path)
    for suf in ('.asm.txt', '.txt'):
        if base.lower().endswith(suf):
            return base[:-len(suf)]
    return os.path.splitext(base)[0]


def collect(src, pattern='.asm.txt'):
    if os.path.isdir(src):
        return [os.path.join(src, f) for f in sorted(os.listdir(src))
                if f.lower().endswith(pattern)]
    return [src]


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------
def cmd_extract(args):
    enable = set(args.types.upper().split(','))
    files = collect(args.src)
    if not files:
        print('[-] 没有找到 asm 文件: %s' % args.src)
        return 1
    os.makedirs(args.out, exist_ok=True)
    total = 0
    skipped_total = 0
    per_type = {}
    for path in files:
        entries, skipped = scan_file(path, enable, not args.no_filter)
        stem = stem_of(path)
        data = []
        for e in entries:
            item = {'id': e['id']}
            if e['name']:
                item['name'] = e['name']
            item['pre_jp'] = e['message']
            item['message'] = e['message']
            data.append(item)
            per_type[e['type']] = per_type.get(e['type'], 0) + 1
        with open(os.path.join(args.out, stem + '.json'), 'w', encoding='utf-8', newline='\n') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n')
        if args.meta:
            sha = hashlib.sha256(open(path, 'rb').read()).hexdigest()
            meta = {
                'source': os.path.basename(path),
                'sha256': sha,
                'encoding': args.encoding,
                'filtered': not args.no_filter,
                'entries': [{'id': e['id'], 'type': e['type'], 'line': e['line'] + 1,
                             'pre_jp_full': e['text']} for e in entries],
                'skipped': [{'line': s[1], 'type': s[2], 'text': s[3]} for s in skipped],
            }
            with open(os.path.join(args.out, stem + '.json.meta.json'), 'w',
                      encoding='utf-8', newline='\n') as f:
                json.dump(meta, f, ensure_ascii=False, indent=1)
                f.write('\n')
        total += len(data)
        skipped_total += len(skipped)
        if data:
            print('%s -> %s  (%d)' % (os.path.basename(path), stem + '.json', len(data)))
    print('done: %d files, %d texts, %d filtered out' % (len(files), total, skipped_total))
    for k in sorted(per_type):
        print('  %-8s %d' % (k, per_type[k]))
    return 0


# ---------------------------------------------------------------------------
# inject
# ---------------------------------------------------------------------------
def cmd_inject(args):
    enable = set(args.types.upper().split(','))
    files = collect(args.src)
    if not files:
        print('[-] 没有找到 asm 文件: %s' % args.src)
        return 1
    if not args.in_place:
        os.makedirs(args.out, exist_ok=True)
    total = 0
    changed_files = 0
    missing = 0
    warns = []
    overlong = []
    for path in files:
        stem = stem_of(path)
        jp = os.path.join(args.json, stem + '.json')
        if not os.path.exists(jp):
            print('[跳过] %s（没有 %s.json）' % (os.path.basename(path), stem))
            if not args.in_place:
                text = open(path, encoding='utf-8', newline='').read()
                open(os.path.join(args.out, os.path.basename(path)), 'w',
                     encoding='utf-8', newline='').write(text)
            continue
        entries, _ = scan_file(path, enable, not args.no_filter)
        data = json.load(open(jp, encoding='utf-8-sig'))
        if not isinstance(data, list):
            raise SystemExit('%s 不是 JSON 数组' % jp)
        by_id = {e['id']: e for e in data if isinstance(e, dict) and 'id' in e}
        if not by_id and len(data) == len(entries):
            by_id = {e['id']: d for e, d in zip(entries, data)}

        raw = open(path, encoding='utf-8', newline='').read()
        lines = raw.splitlines(keepends=True)
        changed = False
        repls = {}          # 行号 -> [(start, end, 新正文)]
        for e in entries:
            item = by_id.get(e['id'])
            if item is None:
                missing += 1
                continue
            msg = item.get('message')
            if not msg:
                msg = item.get('pre_jp') or e['message']
            if not isinstance(msg, str):
                raise SystemExit('%s: %s 的 message 不是字符串' % (jp, e['id']))
            name = item.get('name', e['name']) or ''
            if e['type'] == 'MESSAGE':
                new_text = join_text(name, e['sep'], msg)
            else:
                new_text = msg
            if e['type'] != 'TITLE':
                for idx, w, seg in overlong_lines(new_text):
                    overlong.append((stem, e['id'], idx, w, seg))
            if new_text == e['text']:
                continue
            if args.encoding:
                try:
                    new_text.encode(args.encoding)
                except UnicodeEncodeError as ex:
                    bad = new_text[ex.start:ex.end]
                    warns.append((stem, e['id'], bad))
                    continue
            body = new_text.replace('\\', '\\\\').replace('"', '\\"')
            repls.setdefault(e['line'], []).append((e['col_start'], e['col_end'], body))
        # 同一行可能有多条（选择肢），从右往左替换，避免偏移失效
        for li, lst in repls.items():
            line = lines[li]
            for start, end, body in sorted(lst, key=lambda x: x[0], reverse=True):
                line = line[:start] + body + line[end:]
            lines[li] = line
            changed = True
        if changed and args.encoding:
            for i, line in enumerate(lines):
                if ENC_RE.match(line.rstrip('\r\n')):
                    eol = line[len(line.rstrip('\r\n')):]
                    lines[i] = '.encoding %s%s' % (args.encoding, eol)
                    break
        out_text = ''.join(lines)
        if changed:
            changed_files += 1
        if args.in_place:
            bak = path + '.bak'
            if not os.path.exists(bak):
                open(bak, 'w', encoding='utf-8', newline='').write(raw)
            target = path
        else:
            target = os.path.join(args.out, os.path.basename(path))
        open(target, 'w', encoding='utf-8', newline='').write(out_text)
        total += len(entries)
    if missing:
        print('[!] %d 条 JSON 条目在 asm 中找不到对应 id' % missing)
    if warns:
        print('[!] %d 处文本无法用 %s 编码，已跳过（未写入）:' % (len(warns), args.encoding))
        for stem, tid, bad in warns[:20]:
            print('    %s %s: %r' % (stem, tid, bad))
    if overlong:
        print('[!] %d 处单行超过 %d 个全角字符（游戏里超出的字会画到文本框右边）:'
              % (len(overlong), LINE_MAX))
        for stem, tid, idx, w, seg in overlong[:40]:
            print('    %s %s 第%d段 %g 字: %s' % (stem, tid, idx, w, seg))
        if len(overlong) > 40:
            print('    ...（其余 %d 处省略）' % (len(overlong) - 40))
    print('done: %d files, %d texts, %d files changed' % (len(files), total, changed_files))
    return 0


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------
def cmd_stats(args):
    enable = set(args.types.upper().split(','))
    files = collect(args.src)
    total = 0
    skipped = 0
    per = {}
    chars = 0
    over = []
    for path in files:
        entries, sk = scan_file(path, enable, not args.no_filter)
        total += len(entries)
        skipped += len(sk)
        for e in entries:
            per[e['type']] = per.get(e['type'], 0) + 1
            chars += len(e['message'])
            if e['type'] != 'TITLE':
                for idx, w, seg in overlong_lines(e['text']):
                    over.append((os.path.basename(path), e['id'], idx, w, seg))
        if args.verbose and entries:
            print('%s: %d' % (os.path.basename(path), len(entries)))
    print('files: %d  texts: %d  chars: %d  filtered: %d' % (len(files), total, chars, skipped))
    for k in sorted(per):
        print('  %-8s %d' % (k, per[k]))
    if over:
        print('[!] %d 处单行超过 %d 个全角字符:' % (len(over), LINE_MAX))
        for name, tid, idx, w, seg in over[:20]:
            print('    %s %s 第%d段 %g 字: %s' % (name, tid, idx, w, seg))
        if len(over) > 20:
            print('    ...（其余 %d 处省略）' % (len(over) - 20))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='HIMAURI asm.txt <-> 翻译 JSON')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract', help='asm.txt -> JSON')
    p.add_argument('-s', '--src', required=True)
    p.add_argument('-o', '--out', default='json_jp')
    p.add_argument('--types', default='MESSAGE,CHOICE,TITLE')
    p.add_argument('--no-filter', action='store_true')
    p.add_argument('--no-meta', dest='meta', action='store_false')
    p.add_argument('--encoding', default='cp932')
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser('inject', help='JSON -> asm.txt')
    p.add_argument('-s', '--src', required=True)
    p.add_argument('-j', '--json', required=True)
    p.add_argument('-o', '--out', default='asm_cn')
    p.add_argument('--in-place', action='store_true')
    p.add_argument('--encoding', default=None)
    p.add_argument('--types', default='MESSAGE,CHOICE,TITLE')
    p.add_argument('--no-filter', action='store_true')
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser('stats', help='统计可提取文本')
    p.add_argument('-s', '--src', required=True)
    p.add_argument('--types', default='MESSAGE,CHOICE,TITLE')
    p.add_argument('--no-filter', action='store_true')
    p.add_argument('-v', '--verbose', action='store_true')
    p.set_defaults(func=cmd_stats)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
