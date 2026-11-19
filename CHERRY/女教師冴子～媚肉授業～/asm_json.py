#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asm_json.py -- SCW asm.txt <-> JSON 文本互转（翻译工作流）

针对 disassembler.py 生成的 asm.txt。

用法:
    python asm_json.py extract --src asm --out json_jp [--all]
    python asm_json.py inject  --json json_cn --asm asm --out asm_cn [--width 18]
    python asm_json.py report  --src asm -o report.txt

文本结构（本作固定两种）:
    #F【人名】#F{{0A}}正文…       人名行 + 正文
    正文…                          无人名（旁白、选项 ■…、★…）

JSON 每条:
    {
      "id": 0,
      "kind": "message" | "choice" | "label",
      "offsets": [4830],          // 同一文本在 asm 里的全部偏移
      "name": "不良",              // 人名，无人名时为 ""
      "orig_name": "不良",         // 提取时的人名（用于判断是否改过）
      "pre_jp": "おいおい、大変だよ。このセンセイ、腰振ってるぜ。",
      "message": "おいおい、大変だよ。このセンセイ、腰振ってるぜ。",
      "orig": "#F【不良】#F{{0A}}おいおい…"   // 原始字面量（往返用，勿手改）
    }

规则:
  * 提取：剥掉 `#F【…】#F` 人名前缀，**删除所有 {{0A}}/{{0D}}**，pre_jp 与 message 都是单行；
  * 注入：先写 `#F【人名】#F{{0A}}`，再把 message 以 **18 个全角字符** 为上限重新分行、插入 {{0A}}；
  * 人名/正文都没改动时按 `orig` 原样写回，保证 `extract → inject` 的 asm 逐字节不变；
  * 同一 (人名, 正文) 出现多次时合并为一条（选项会存两份），注入时一次写全。
"""

import argparse
import json
import os
import re
import sys
import unicodedata

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ENCODING = "cp932"
DEFAULT_WIDTH = 18

TEXT_RE = re.compile(r'^\.text\s+(\d+)\s+"(.*)"$')
NAME_RE = re.compile(r"^#F【(.*?)】#F(.*)$", re.S)


# ---------------------------------------------------------------------------
# 字面量 <-> 文本
# ---------------------------------------------------------------------------
def unescape_literal(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in ('"', "\\"):
                out.append(nxt)
                i += 2
                continue
            out.append(c)
            i += 1
            continue
        if s.startswith("{{", i):
            j = s.find("}}", i)
            if j < 0:
                out.append(c)
                i += 1
                continue
            hexs = s[i + 2:j]
            try:
                out.append(bytes(int(hexs[k:k + 2], 16) for k in range(0, len(hexs), 2))
                           .decode(ENCODING))
            except Exception:
                out.append(s[i:j + 2])
            i = j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def escape_literal(text):
    out = []
    for ch in text:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("{{0A}}")
        elif ch == "\r":
            out.append("{{0D}}")
        else:
            out.append(ch)
    return "".join(out)


def strip_newlines(s):
    return s.replace("{{0A}}", "").replace("{{0D}}", "").replace("\n", "").replace("\r", "")


def split_name(text):
    """'#F【不良】#F{{0A}}正文' -> ('不良', '正文')；无人名 -> ('', text)"""
    m = NAME_RE.match(text)
    if not m:
        return "", text
    return m.group(1), m.group(2)


# ---------------------------------------------------------------------------
# 折行
# ---------------------------------------------------------------------------
def char_width(ch):
    if ch == "#":           # #F 控制标记不占宽度
        return 0.0
    ea = unicodedata.east_asian_width(ch)
    return 1.0 if ea in ("W", "F") else 0.5


def wrap_text(text, width=DEFAULT_WIDTH):
    text = strip_newlines(text)
    if not text:
        return text
    lines, cur, cur_w = [], [], 0.0
    for ch in text:
        w = char_width(ch)
        if cur_w + w > width + 1e-6 and cur:
            lines.append("".join(cur))
            cur, cur_w = [], 0.0
        cur.append(ch)
        cur_w += w
    if cur:
        lines.append("".join(cur))
    return "{{0A}}".join(lines)


def compose(name, message, width=DEFAULT_WIDTH):
    """name + 18 全角折行后的正文 -> asm 字面量内容"""
    body = wrap_text(message, width)
    if name:
        return "#F【%s】#F{{0A}}%s" % (name, body)
    return body


# ---------------------------------------------------------------------------
# 分类
# ---------------------------------------------------------------------------
def classify(name, text):
    plain = strip_newlines(text)
    if not plain and not name:
        return "empty", False
    if not name and not any(0x0800 <= ord(c) <= 0xFFFF for c in plain):
        return "label", False       # 纯 ASCII 资源名/标签
    if plain.startswith("■") or plain.startswith("★"):
        return "choice", True
    return "message", True


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------
def extract_file(path, include_all):
    lines = open(path, encoding="utf-8-sig").read().split("\n")
    groups = []
    index = {}
    for ln in lines:
        m = TEXT_RE.match(ln.strip())
        if not m:
            continue
        off = int(m.group(1))
        text = unescape_literal(m.group(2))
        name, body = split_name(text)
        kind, translatable = classify(name, body)
        if not translatable and not include_all:
            continue
        key = (name, strip_newlines(body))
        if key in index:
            groups[index[key]]["offsets"].append(off)
        else:
            index[key] = len(groups)
            groups.append({
                "id": len(groups),
                "kind": kind,
                "offsets": [off],
                "name": name,
                "orig_name": name,
                "pre_jp": strip_newlines(body),
                "message": strip_newlines(body),
                "orig": text,
            })
    return groups


def cmd_extract(args):
    src = args.src
    if os.path.isdir(src):
        files = sorted(f for f in os.listdir(src) if f.endswith(".asm.txt"))
        os.makedirs(args.out, exist_ok=True)
        total = 0
        for f in files:
            entries = extract_file(os.path.join(src, f), args.all)
            data = {"file": f, "encoding": ENCODING, "width": DEFAULT_WIDTH, "lines": entries}
            with open(os.path.join(args.out, f[:-len(".asm.txt")] + ".json"), "w",
                      encoding="utf-8") as fp:
                json.dump(data, fp, ensure_ascii=False, indent=1)
            total += len(entries)
        print("提取完成: %d 个脚本, %d 条文本 -> %s" % (len(files), total, args.out))
        return 0

    entries = extract_file(src, args.all)
    base = os.path.basename(src)
    if base.endswith(".asm.txt"):
        base = base[:-len(".asm.txt")]
    out = args.out
    if os.path.isdir(out) or out.endswith(("/", "\\")):
        os.makedirs(out, exist_ok=True)
        out = os.path.join(out, base + ".json")
    data = {"file": os.path.basename(src), "encoding": ENCODING,
            "width": DEFAULT_WIDTH, "lines": entries}
    with open(out, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=1)
    print("提取完成: %d 条文本 -> %s" % (len(entries), out))
    return 0


# ---------------------------------------------------------------------------
# inject
# ---------------------------------------------------------------------------
def inject_file(asm_path, data, width):
    lines = open(asm_path, encoding="utf-8-sig").read().split("\n")
    by_offset = {}
    for e in data["lines"]:
        for off in e["offsets"]:
            by_offset[off] = e

    written = changed = 0
    for i, ln in enumerate(lines):
        m = TEXT_RE.match(ln.strip())
        if not m:
            continue
        off = int(m.group(1))
        e = by_offset.get(off)
        if e is None:
            continue
        if e["message"] == e["pre_jp"] and e["name"] == e["orig_name"]:
            literal = escape_literal(e["orig"])      # 未改动: 原样保留
        else:
            literal = escape_literal(compose(e["name"], e["message"], width))
            changed += 1
        lines[i] = '.text %5d "%s"' % (off, literal)
        written += 1
    return "\n".join(lines), written, changed


def cmd_inject(args):
    js = args.json
    if os.path.isdir(js):
        files = sorted(f for f in os.listdir(js) if f.endswith(".json"))
        os.makedirs(args.out, exist_ok=True)
        for f in files:
            data = json.load(open(os.path.join(js, f), encoding="utf-8"))
            asm_name = data.get("file") or (f[:-5] + ".asm.txt")
            asm_path = os.path.join(args.asm, asm_name)
            if not os.path.exists(asm_path):
                print("跳过 %s: 找不到 %s" % (f, asm_path))
                continue
            text, w, c = inject_file(asm_path, data, args.width)
            with open(os.path.join(args.out, asm_name), "w", encoding="utf-8",
                      newline="\n") as fp:
                fp.write(text)
        print("注入完成 -> %s" % args.out)
        return 0

    data = json.load(open(js, encoding="utf-8"))
    asm_path = args.asm
    if os.path.isdir(asm_path):
        asm_path = os.path.join(asm_path, data["file"])
    text, w, c = inject_file(asm_path, data, args.width)
    out = args.out or asm_path
    if os.path.isdir(out):
        out = os.path.join(out, os.path.basename(asm_path))
    with open(out, "w", encoding="utf-8", newline="\n") as fp:
        fp.write(text)
    print("注入完成: %d 处写入, %d 处改动 -> %s" % (w, c, out))
    return 0


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
def cmd_report(args):
    src = args.src
    files = ([os.path.join(src, f) for f in sorted(os.listdir(src))
              if f.endswith(".asm.txt")] if os.path.isdir(src) else [src])
    out = []
    stats = {}
    for f in files:
        entries = extract_file(f, True)
        cnt = {}
        for e in entries:
            cnt[e["kind"]] = cnt.get(e["kind"], 0) + 1
            stats[e["kind"]] = stats.get(e["kind"], 0) + 1
        out.append("%-24s %s" % (os.path.basename(f),
                                 ", ".join("%s=%d" % kv for kv in sorted(cnt.items()))))
    summary = "总计: " + ", ".join("%s=%d" % kv for kv in sorted(stats.items()))
    txt = summary + "\n" + "\n".join(out)
    if args.output:
        open(args.output, "w", encoding="utf-8").write(txt)
        print("报告 -> %s\n%s" % (args.output, summary))
    else:
        print(txt)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="SCW asm.txt <-> JSON 文本互转")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("extract", help="asm.txt -> JSON（剥人名、删 {{0A}}）")
    p.add_argument("--src", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--all", action="store_true", help="连资源名/标签一并导出")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="JSON -> asm.txt（补人名 {{0A}}、18 全角折行）")
    p.add_argument("--json", required=True)
    p.add_argument("--asm", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--width", type=float, default=DEFAULT_WIDTH)
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("report", help="统计可翻译文本")
    p.add_argument("--src", required=True)
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
