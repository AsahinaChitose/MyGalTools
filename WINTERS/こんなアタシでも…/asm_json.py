#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""asm_json.py -- こんなアタシでも… 的 asm.txt <-> JSON 文本提取 / 注入 / TSV 转换

文本都内联在脚本 asm 里（首次引用处）：

    MSG 5443   "「あっ、遠井君。それじゃまた明日ねーっ」"
    MSG 5444   "【真冬】\\n「あっ、遠野君。それじゃまた明日ねーっ」"

* 带人名的段落：第一行是 ``【真冬】``，提取时把 ``真冬`` 放进 ``name``，
  其余行去掉换行后作为 ``message``。
* 选项段落：``１・絶望する\\n２・絶望しない`` 会拆成**两条独立 message**
  （``kind`` 为 ``choice-1`` / ``choice-2``，``msg`` 相同），注入时再按 msg
  收齐后合并回 ``１・…\\n２・…``（选项行不折行，超过 24 全角会警告）。
* 提取时删除所有换行（以及对话续行开头的排版缩进：只在 「/『/（ 开头的段落里去掉）。
* 注入时按 **每行最多 22 个全角字符** 硬折行（缩进算在这 22 内）：
  - `【name】` 行之后的**第一行正文不缩进**，最多 23 字；
  - 对话行（正文以 `「`/`『`/`（` 开头，带不带人名都算）的**续行**行首补一个全角
    空格缩进，所以续行正文最多 21 字，整行仍是 22；
  - 旁白等非对话段落不加缩进，每行 22 字；
  - 纯按字数切；唯一例外是收尾括号 `」`/`』`/`）`：折完如果只剩它单独一行，
    就并回上一行（该行允许到 23 字），不允许收尾括号独占一行。

用法::

    python asm_json.py extract --src SCR_asm --out json_jp [--txt txt_jp]
    python asm_json.py inject  --src SCR_asm --json json_cn --out asm_cn
    python asm_json.py to-txt  --src json_cn --out txt_cn
    python asm_json.py to-json --src txt_cn  --out json_cn
    python asm_json.py report  --src SCR_asm [-o report.txt]

JSON 结构（按 asm 中出现顺序）::

    [
      {
        "id": "SCR#00200.ifx#00001",
        "msg": 5443,
        "ref": "loc_00003",
        "kind": "text",
        "name": "真冬",                      // 仅带人名时存在
        "pre_jp": "「あっ、遠井君。それじゃまた明日ねーっ」",
        "message": "「あっ、遠井君。それじゃまた明日ねーっ」"
      },
      {
        "id": "SCR#00000.ifx#00402",
        "msg": 401,
        "ref": "loc_00381",
        "kind": "choice-1",                  // 选项：一条 message 一个条目
        "pre_jp": "絶望する",
        "message": "絶望する",
        "width": 5.0
      },
      {
        "id": "SCR#00000.ifx#00403",
        "msg": 401,                          // msg 相同，注入时按 kind 顺序合并
        "ref": "loc_00381",
        "kind": "choice-2",
        "pre_jp": "絶望しない",
        "message": "絶望しない",
        "width": 6.0
      }
    ]

TSV 与 JSON 一一对应：每个选项一行，``to-json`` 按相同 ``msg`` 的连续行还原
``choice-1`` / ``choice-2``。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata

import disassembler

LIMIT = 22                 # 每行显示宽度上限（全角字符，含行首缩进）
LIMIT_MAX = 23             # 收尾括号并回上一行后的单行上限
LIMIT_DISPLAY = 24         # 引擎单行最多读取 24 个 UTF-16 单元（硬上限）
INDENT = "\u3000"          # 全角空格缩进
NAME_RE = re.compile(r"^【([^】]{1,16})】$")
# 选项行：全角数字 + ・ ，例如 “１・絶望する”
CHOICE_RE = re.compile(r"^([１２３４５６７８９])・(.*)$")
FULLWIDTH_DIGITS = "０１２３４５６７８９"

TEXT_RE = re.compile(
    r'^(?P<prefix>\s+MSG2?\s+\d+(?:\s*,\s*flags=0x[0-9A-Fa-f]+)?\s+)'
    r'"(?P<text>(?:[^"\\]|\\.)*)"'
    r'(?P<tail>.*)$'
)

# 换行禁则
NO_LINE_START = set("」』）！？、。…ー")
NO_LINE_END = set("「『（")
# 对话开头（决定续行是否缩进）：原文续行缩进只出现在「/『/（ 开头的段落
OPENERS = set("「『（")
CLOSERS = set("」』）")


class TextError(Exception):
    pass


# ---------------------------------------------------------------- 宽度 / 折行

def char_width(ch: str) -> float:
    return 1.0 if unicodedata.east_asian_width(ch) in ("W", "F", "A") else 0.5


def text_width(text: str) -> float:
    return sum(char_width(ch) for ch in text)


def wrap_text(body: str, limit: int = LIMIT, indent: bool = False):
    """按显示宽度硬折行，每行最多 limit 个全角（缩进算在内）。

    indent=True 时续行加一个全角空格缩进，因此续行正文最多 limit-1；
    纯按字数切，不做禁则移动（保证首行能填满 22）。
    """
    lines = []
    cur = ""
    width = 0.0
    cur_limit = limit
    for ch in body:
        w = char_width(ch)
        if cur and width + w > cur_limit + 1e-6:
            lines.append(cur)
            cur = ""
            width = 0.0
            cur_limit = limit - 1 if indent else limit
        cur += ch
        width += w
    if cur:
        lines.append(cur)
    if indent and len(lines) > 1:
        lines = [lines[0]] + [INDENT + ln for ln in lines[1:]]
    # 收尾括号不单独落行：末行只剩一个 」』） 时，并回上一行（整行最多 23 字）
    if len(lines) >= 2:
        last = lines[-1]
        core = last[1:] if last.startswith(INDENT) else last
        if len(core) == 1 and core in CLOSERS:
            merged = lines[-2] + core
            if text_width(merged) <= LIMIT_MAX + 1e-6:
                lines = lines[:-1]
                lines[-1] = merged
    return lines


def read_asm(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read().split("\n")


def scan_asm(path):
    """返回 (lines, entries)；entry 带 asm 行号与重建所需的 prefix。"""
    lines = read_asm(path)
    entries = []
    label = "loc_00000"
    for idx, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        if s.endswith(":") and " " not in s and not s.startswith("."):
            label = s[:-1]
            continue
        m = TEXT_RE.match(line)
        if not m:
            continue
        raw = disassembler.unescape_text(m.group("text"))
        parts = raw.split("\n")
        name = None
        kind = "text"
        options = None
        body_lines = parts
        if parts and NAME_RE.match(parts[0]):
            name = NAME_RE.match(parts[0]).group(1)
            body_lines = parts[1:]
        elif len(parts) >= 2 and all(CHOICE_RE.match(p) for p in parts):
            # 选项：“１・xxx\n２・yyy”，拆成多条 message，注入时再合回
            kind = "choice"
            options = [CHOICE_RE.match(p).group(2) for p in parts]
        # 续行开头的全角空格是排版缩进：只对对话段落（「/『/（ 开头）去掉
        if body_lines and body_lines[0][:1] in OPENERS:
            body_lines = [body_lines[0]] + [
                ln[1:] if ln.startswith(INDENT) else ln for ln in body_lines[1:]]
        body = "".join(body_lines)
        num = int(re.search(r"MSG2?\s+(\d+)", m.group("prefix")).group(1))
        entries.append({
            "line_no": idx,
            "line": line,
            "prefix": m.group("prefix"),
            "raw": raw,
            "msg": num,
            "ref": label,
            "kind": kind,
            "name": name,
            "pre_jp": options if options is not None else body,
            "orig_text": raw,
        })
    return lines, entries


def asm_files(src):
    if os.path.isdir(src):
        return [os.path.join(src, n) for n in sorted(os.listdir(src))
                if n.lower().endswith(".asm.txt")]
    if os.path.isfile(src):
        return [src]
    return []


# ---------------------------------------------------------------- 注入格式

def build_text(item, entry):
    body = item.get("message", "")
    if not body:
        body = item.get("pre_jp", entry["pre_jp"])
    name = item.get("name") or None
    manual = "\n" in body
    # 对话行：句子以「/『/（ 开头（带人名时正文同样适用），续行加全角缩进
    indent = body[:1] in OPENERS
    if manual:
        segs = body.split("\n")
    else:
        segs = wrap_text(body, LIMIT, indent)
    lines = (["【%s】" % name] if name else []) + list(segs)
    return "\n".join(lines), name, manual


def _choice_index(item):
    """choice-1 / choice-2 …… 的序号，用于把 JSON 条目按选项顺序排好。"""
    m = re.search(r"choice-(\d+)", str(item.get("kind", "")))
    return int(m.group(1)) if m else 0


def build_choice(options):
    """把若干条选项合并回 “１・xxx\\n２・yyy” 的原始形态。"""
    lines = []
    for i, opt in enumerate(options):
        if "\n" in opt:
            raise TextError("选项文本不能包含换行：%r" % opt)
        if i + 1 >= len(FULLWIDTH_DIGITS):
            raise TextError("选项超过 9 个：%r" % (options,))
        lines.append("%s・%s" % (FULLWIDTH_DIGITS[i + 1], opt))
    return "\n".join(lines)


def check_lines(text, ident):
    warns = []
    for ln in text.split("\n"):
        w = text_width(ln)
        if w > LIMIT + 0.01:
            warns.append("%s: 一行 %g 个全角字符（上限 %d）：%r"
                         % (ident, w, LIMIT, ln))
    return warns


# ---------------------------------------------------------------- extract

def cmd_extract(args):
    files = asm_files(args.src)
    if not files:
        raise TextError("没有找到 asm 文件：%s" % args.src)
    os.makedirs(args.out, exist_ok=True)
    if args.txt:
        os.makedirs(args.txt, exist_ok=True)
    total = 0
    for path in files:
        _lines, entries = scan_asm(path)
        stem = os.path.basename(path)
        if stem.endswith(".asm.txt"):
            stem = stem[:-len(".asm.txt")]
        data = []
        seen = set()
        for e in entries:
            if e["msg"] in seen:
                raise TextError("%s: 消息 %d 重复定义" % (path, e["msg"]))
            seen.add(e["msg"])
            if e["kind"] == "choice":
                # 每个选项单独成一条 message，kind = choice-1 / choice-2 ……
                for i, opt in enumerate(e["pre_jp"], 1):
                    item = {
                        "id": "%s#%05d" % (stem, len(data) + 1),
                        "msg": e["msg"],
                        "ref": e["ref"],
                        "kind": "choice-%d" % i,
                        "pre_jp": opt,
                        "message": opt,
                        "width": text_width(opt),
                    }
                    data.append(item)
                continue
            item = {
                "id": "%s#%05d" % (stem, len(data) + 1),
                "msg": e["msg"],
                "ref": e["ref"],
                "kind": "text",
            }
            if e["name"]:
                item["name"] = e["name"]
            item["pre_jp"] = e["pre_jp"]
            item["message"] = e["pre_jp"]
            item["width"] = text_width(e["pre_jp"])
            data.append(item)
        out_path = os.path.join(args.out, stem + ".json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        if args.txt:
            write_txt(os.path.join(args.txt, stem + ".txt"), data)
        total += len(data)
        print("%s -> %s（%d 条）" % (path, out_path, len(data)))
    print("共 %d 条" % total)
    return 0


# ---------------------------------------------------------------- inject

def cmd_inject(args):
    files = asm_files(args.src)
    if not files:
        raise TextError("没有找到 asm 文件：%s" % args.src)
    out_dir = args.out
    if out_dir and not os.path.isdir(out_dir) and len(files) > 1:
        os.makedirs(out_dir, exist_ok=True)
    total = 0
    all_warns = []
    for path in files:
        stem = os.path.basename(path)
        if stem.endswith(".asm.txt"):
            stem = stem[:-len(".asm.txt")]
        json_path = os.path.join(args.json, stem + ".json")
        if not os.path.isfile(json_path):
            raise TextError("找不到对应的 JSON: %s" % json_path)
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        lines, entries = scan_asm(path)
        by_msg = {e["msg"]: e for e in entries}
        groups = {}
        for item in data:
            msg = item.get("msg")
            if msg not in by_msg:
                raise TextError("%s: JSON 里的消息 %r 在 asm 中不存在" % (json_path, msg))
            groups.setdefault(msg, []).append(item)
        if set(groups) != set(by_msg):
            missing = sorted(set(by_msg) - set(groups))[:5]
            extra = sorted(set(groups) - set(by_msg))[:5]
            raise TextError("%s: 消息集合不一致（asm 缺 %s / JSON 多 %s）"
                            % (json_path, missing, extra))
        changed = 0
        for msg, items in groups.items():
            e = by_msg[msg]
            if e["kind"] == "choice":
                items.sort(key=lambda it: _choice_index(it))
                if len(items) != len(e["pre_jp"]):
                    raise TextError("%s: 消息 %d 选项数 %d，原为 %d（不能增删选项）"
                                    % (json_path, msg, len(items), len(e["pre_jp"])))
                body = [str(it.get("message", it.get("pre_jp", ""))) for it in items]
                if body == e["pre_jp"]:
                    continue
                new_raw = build_choice(body)
            else:
                if len(items) != 1:
                    raise TextError("%s: 消息 %d 的 JSON 条目数为 %d（应为 1）"
                                    % (json_path, msg, len(items)))
                item = items[0]
                body = item.get("message")
                if body is None:
                    body = item.get("pre_jp", "")
                if isinstance(body, list):
                    body = "\n".join(body)
                name = item.get("name")
                unchanged = (body == e["pre_jp"] and name == e["name"])
                if unchanged:
                    continue
                new_raw, name, manual = build_text(item, e)
            all_warns.extend(check_lines(new_raw, "%s#%d" % (stem, msg)))
            if new_raw != e["orig_text"]:
                changed += 1
            lines[e["line_no"]] = e["prefix"] + '"' + disassembler.escape_text(new_raw) + '"'
        out_path = path
        if out_dir:
            is_dir = (os.path.isdir(out_dir) or out_dir.endswith(os.sep)
                      or not os.path.splitext(out_dir)[1])
            if is_dir:
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, os.path.basename(path))
            elif len(files) == 1:
                out_path = out_dir
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines))
        total += len(data)
        print("%s -> %s（%d 条，改动 %d 条）" % (path, out_path, len(data), changed))
    for w in all_warns[:50]:
        print("警告: " + w, file=sys.stderr)
    if len(all_warns) > 50:
        print("警告: 还有 %d 条超长行未列出" % (len(all_warns) - 50), file=sys.stderr)
    print("共 %d 条" % total)
    return 0


# ---------------------------------------------------------------- JSON <-> TSV

def esc_tsv(text):
    return text.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def unesc_tsv(text):
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append({"t": "\t", "n": "\n", "\\": "\\"}.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def write_txt(path, data):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for item in data:
            f.write("\t".join(esc_tsv(str(x)) for x in (
                item.get("id", ""), item.get("msg", ""),
                item.get("name", ""), item.get("message", ""))) + "\n")


def cmd_to_txt(args):
    files = [os.path.join(args.src, n) for n in sorted(os.listdir(args.src))
             if n.lower().endswith(".json")] if os.path.isdir(args.src) else [args.src]
    os.makedirs(args.out, exist_ok=True)
    for path in files:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        out_path = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0] + ".txt")
        write_txt(out_path, data)
        print("%s -> %s" % (path, out_path))
    return 0


def cmd_to_json(args):
    files = [os.path.join(args.src, n) for n in sorted(os.listdir(args.src))
             if n.lower().endswith(".txt")] if os.path.isdir(args.src) else [args.src]
    os.makedirs(args.out, exist_ok=True)
    for path in files:
        rows = []
        raw = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                cols = line.split("\t")
                while len(cols) < 4:
                    cols.append("")
                raw.append({
                    "id": cols[0],
                    "msg": int(cols[1]) if cols[1].isdigit() else 0,
                    "name": cols[2],
                    "text": unesc_tsv(cols[3]),
                })
        i = 0
        while i < len(raw):
            j = i
            while j < len(raw) and raw[j]["msg"] == raw[i]["msg"] and raw[i]["msg"] != 0:
                j += 1
            group = raw[i:j]
            if len(group) > 1:
                # 同一消息多条 = 选项，恢复成 choice-1 / choice-2 ……
                for k, g in enumerate(group, 1):
                    rows.append({"id": g["id"], "msg": g["msg"], "ref": "",
                                 "kind": "choice-%d" % k,
                                 "pre_jp": g["text"], "message": g["text"]})
            else:
                g = group[0]
                item = {"id": g["id"], "msg": g["msg"], "ref": "", "kind": "text"}
                if g["name"]:
                    item["name"] = unesc_tsv(g["name"])
                item["pre_jp"] = g["text"]
                item["message"] = g["text"]
                rows.append(item)
            i = j
        out_path = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0] + ".json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("%s -> %s（%d 条）" % (path, out_path, len(rows)))
    return 0


# ---------------------------------------------------------------- report

def cmd_report(args):
    files = asm_files(args.src)
    if not files:
        raise TextError("没有找到 asm 文件：%s" % args.src)
    out = []
    grand = 0
    named_total = 0
    choice_total = 0
    for path in files:
        _lines, entries = scan_asm(path)
        named = [e for e in entries if e["name"]]
        choices = [e for e in entries if e["kind"] == "choice"]
        longest = max((text_width(e["pre_jp"]) for e in entries if e["kind"] != "choice"),
                      default=0)
        out.append("== %s ==" % os.path.basename(path))
        out.append("条目: %d，带人名: %d，选项组: %d，最长正文: %g 全角"
                   % (len(entries), len(named), len(choices), longest))
        names = {}
        for e in named:
            names[e["name"]] = names.get(e["name"], 0) + 1
        if names:
            out.append("说话人 %d 个: %s" % (len(names), ", ".join(
                "%s(%d)" % (n, c) for n, c in sorted(names.items(), key=lambda x: -x[1])[:10])))
        grand += len(entries)
        named_total += len(named)
        choice_total += len(choices)
    out.append("总计: %d 条，带人名 %d 条，选项组 %d 条" % (grand, named_total, choice_total))
    text = "\n".join(out) + "\n"
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("-> %s" % args.o)
    else:
        print(text)
    return 0


def build_parser():
    ap = argparse.ArgumentParser(description="こんなアタシでも… asm <-> JSON 文本工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="asm.txt -> JSON")
    p.add_argument("--src", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--txt", default=None, help="同时输出 TSV 的目录")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="JSON -> asm.txt")
    p.add_argument("--src", required=True)
    p.add_argument("--json", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("to-txt", help="JSON -> TSV")
    p.add_argument("--src", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_to_txt)

    p = sub.add_parser("to-json", help="TSV -> JSON")
    p.add_argument("--src", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_to_json)

    p = sub.add_parser("report", help="统计")
    p.add_argument("--src", required=True)
    p.add_argument("-o", default=None)
    p.set_defaults(func=cmd_report)
    return ap


def main(argv=None):
    disassembler._utf8_stdout()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (TextError, ValueError) as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
