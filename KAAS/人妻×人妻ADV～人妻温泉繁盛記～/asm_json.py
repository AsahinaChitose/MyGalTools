#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wwadv.asm.txt <-> JSON 文本提取 / 注入 / TXT 转换。

适配本工程 disassembler.py 生成的 asm.txt。可翻译文本就是文本记录里的
``MESSAGE`` / ``MESSAGE_WAIT`` / ``OPTION`` 行：

    MESSAGE       "一平「うん、ただいま了子さん。\\nって、それ新車？」", 0x7930, 0xB2DF
    MESSAGE_WAIT  "開口一番、それだ。", 0x5E00, 0xB2D0
    OPTION        "うまいな、俺"

两种正文形态（由引用指令决定）：

    TEXT_SCROLL   0x41 -> ADV（屏幕下方文本框，每行上限 26 个全角字符）
    TEXT_SCROLL2  0x45 -> VN （全屏文本，每行上限 23 个全角字符）
    TEXT          0x17 -> 选择肢（不换行）

用法::

    # asm -> 每个 asm 文件一个 JSON（可同时输出 TSV）
    python asm_json.py extract --src wwadv.asm.txt --out json_jp [--txt txt_jp]

    # JSON -> asm（只改文本行，其余原样）
    python asm_json.py inject --src wwadv.asm.txt --json json_cn --out asm_cn

    # JSON <-> TSV
    python asm_json.py to-txt  --src json_cn --out txt_cn
    python asm_json.py to-json --src txt_cn  --out json_cn

    # 统计报告
    python asm_json.py report --src wwadv.asm.txt -o text_report.txt

JSON 结构（按 asm 中出现顺序）::

    [
      {
        "id": "wwadv#00001",
        "kind": "adv",            // adv | vn | option
        "limit": 26,              // 换行上限（全角字符数），option 为 0
        "ref": "t_030DCF#03",     // 记录标签#页序号，便于核对
        "name": "一平",            // 仅人名开头（「」『』（））时存在
        "pre_jp": "「うん、ただいま了子さん。って、それ新車？」",
        "message": "「うん、ただいま了子さん。って、それ新車？」"
      }
    ]

``pre_jp`` / ``message`` 里的换行已全部去掉；``name`` 不包含在 ``message`` 内，
注入时按 ``name + message`` 拼回，并把姓名计入首行字数。

例外：原文里出现“换行 + 全角空格”（``\\n　``，共 32 条）的段落是手工排版的，
不做折行处理——提取时原样保留 ``\\n``，注入时只要 ``message`` 里还有 ``\\n``
就照原样写回，不再套用字数上限。
若 ``message`` 中出现全角斜杠 ``／``，则按它手动断行，不再自动换行。

人名除了普通名字，也支持 ``？？``、``！！`` 这类纯符号说话人。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata

ENCODING = "cp932"

# 指令 -> (kind, 每行全角字符上限)
TEXT_FORM = {
    "TEXT_SCROLL": ("adv", 26),
    "TEXT_SCROLL2": ("vn", 23),
    "TEXT": ("option", 0),
}

TEXT_MNEMONICS = ("MESSAGE", "MESSAGE_WAIT", "OPTION")

# 人名分隔符
OPENERS = {"「": "」", "『": "』", "（": "）"}
# 不允许出现在人名里的字符（全角/半角标点与空白）；「・」是组合人名的分隔符，允许
NAME_BAD = set("、。！？…「」『』（）,.　 ")
NAME_MAX = 8

# 换行禁则
NO_LINE_START = set("」』）！？、。…ー")
NO_LINE_END = set("「『（")

LINE_RE = re.compile(
    r'^(?P<indent>\s*)(?P<mnem>MESSAGE_WAIT|MESSAGE|OPTION)\s+"(?P<text>(?:[^"\\]|\\.)*)"'
    r'(?P<tail>\s*,\s*0x[0-9A-Fa-f]+\s*,\s*0x[0-9A-Fa-f]+)?\s*$'
)


class TextError(Exception):
    def __init__(self, msg, path=None, line=None):
        self.path = path
        self.line = line
        super().__init__(msg)


# ---------------------------------------------------------------------------
# 宽度 / 人名 / 换行
# ---------------------------------------------------------------------------
def char_width(ch: str) -> float:
    # 这个游戏的字体把 “…” “—” “×” “★” 等 Ambiguous 字符也按全角绘制，
    # 因此 W/F/A 一律按 1 个全角计，只有真正的半角（ASCII 等）按 0.5 计。
    return 1.0 if unicodedata.east_asian_width(ch) in ("W", "F", "A") else 0.5


def text_width(text: str) -> float:
    return sum(char_width(ch) for ch in text)


def is_punct_name(pre: str) -> bool:
    """「？？」「！！」这类纯符号说话人也算人名。"""
    return bool(re.fullmatch(r"[？?！!]{1,4}", pre))


def find_name(text: str, vocab):
    """返回 (name, 去掉 name 后的正文)；不是人名开头则 (None, text)。"""
    limit = min(NAME_MAX, len(text) - 1)
    for k in range(1, limit + 1):
        ch = text[k]
        if ch not in OPENERS:
            continue
        pre = text[:k]
        if not pre:
            return None, text
        if any(c in NAME_BAD for c in pre) and not is_punct_name(pre):
            return None, text
        if pre in vocab:
            return pre, text[k:]
        return None, text
    return None, text


def build_name_vocab(texts):
    """第一遍：收集“以闭合引号收尾”的人名候选。"""
    vocab = set()
    for text in texts:
        for k in range(1, min(NAME_MAX, len(text) - 1) + 1):
            ch = text[k]
            if ch not in OPENERS:
                continue
            pre = text[:k]
            if not pre or (any(c in NAME_BAD for c in pre) and not is_punct_name(pre)):
                break
            if text.rstrip().endswith(OPENERS[ch]):
                vocab.add(pre)
            break
    return vocab


def wrap_text(body: str, limit: int, name: str | None = None):
    """按全角字数上限断行；name 视为不可拆分的整体，计入首行。"""
    if limit <= 0:
        return [body]
    units = []
    if name:
        units.append(name)
    units.extend(body)
    lines = []
    cur = ""
    width = 0.0
    for unit in units:
        uw = text_width(unit)
        if width + uw > limit and cur:
            if cur[-1] in NO_LINE_END:
                moved = cur[-1]
                cur = cur[:-1]
                lines.append(cur)
                cur = moved + unit
                width = text_width(cur)
                continue
            lines.append(cur)
            cur = unit
            width = uw
        else:
            cur += unit
            width += uw
    if cur:
        lines.append(cur)
    return lines


# ---------------------------------------------------------------------------
# asm 读写
# ---------------------------------------------------------------------------
def unescape_literal(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "\\":
                out.append("\\")
            elif nxt == '"':
                out.append('"')
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def escape_literal(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def read_asm(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        return f.read().split("\n")


def scan_asm(lines, path=None):
    """解析 asm，返回 (entries, line_index_of_entry)。

    entry: dict(id, kind, limit, ref, name, text, p1, p2, mnemonic, line_no)
    """
    entries = []
    last_mnemonic = None
    label = None
    page_no = 0
    stem = os.path.splitext(os.path.basename(path))[0] if path else "script"

    for idx, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        if s.startswith("."):
            continue
        if s.endswith(":") and " " not in s:
            label = s[:-1]
            page_no = 0
            continue
        m = LINE_RE.match(line)
        if m:
            mnem = m.group("mnem")
            if mnem == "OPTION":
                kind, limit = "option", 0
            else:
                kind, limit = TEXT_FORM.get(last_mnemonic or "", ("adv", 26))
            tail = m.group("tail") or ""
            nums = re.findall(r"0x[0-9A-Fa-f]+", tail)
            p1 = int(nums[0], 16) if len(nums) > 0 else None
            p2 = int(nums[1], 16) if len(nums) > 1 else None
            entries.append({
                "kind": kind,
                "limit": limit,
                "ref": "%s#%02d" % (label or "?", page_no),
                "text": unescape_literal(m.group("text")),
                "p1": p1,
                "p2": p2,
                "mnemonic": mnem,
                "line_no": idx,
            })
            page_no += 1
            continue
        last_mnemonic = s.split(None, 1)[0]
    return entries


def split_name_all(entries):
    vocab = build_name_vocab([e["text"] for e in entries if e["kind"] != "option"])
    for e in entries:
        if e["kind"] == "option":
            e["name"], e["body"] = None, e["text"]
        else:
            e["name"], e["body"] = find_name(e["text"], vocab)
        e["orig_text"] = e["text"]


def make_entries(path):
    lines = read_asm(path)
    entries = scan_asm(lines, path)
    split_name_all(entries)
    stem = os.path.splitext(os.path.basename(path))[0]
    if stem.endswith(".asm"):
        stem = stem[:-4]
    out = []
    for i, e in enumerate(entries, 1):
        item = {
            "id": "%s#%05d" % (stem, i),
            "kind": e["kind"],
            "limit": e["limit"],
            "ref": e["ref"],
        }
        if e["name"]:
            item["name"] = e["name"]
        keep_nl = "\n　" in e["text"]
        body = e["body"] if keep_nl else e["body"].replace("\n", "")
        item["pre_jp"] = body
        item["message"] = body
        item["jp_width"] = text_width(body.replace("\n", ""))
        if keep_nl:
            item["keep_nl"] = True
        out.append((item, e))
    return lines, out


# ---------------------------------------------------------------------------
# extract / inject
# ---------------------------------------------------------------------------
def cmd_extract(args):
    srcs = collect_inputs(args.src, ".asm.txt")
    if not srcs:
        raise TextError("没有找到 asm 文件: %s" % args.src)
    os.makedirs(args.out, exist_ok=True)
    txt_dir = args.txt
    if txt_dir:
        os.makedirs(txt_dir, exist_ok=True)
    total = 0
    for path in srcs:
        _lines, pairs = make_entries(path)
        data = [item for item, _e in pairs]
        stem = os.path.splitext(os.path.basename(path))[0]
        # 去掉 asm 后缀中的 .asm
        stem = stem[:-4] if stem.endswith(".asm") else stem
        out_path = os.path.join(args.out, stem + ".json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        if txt_dir:
            write_txt(os.path.join(txt_dir, stem + ".txt"), data)
        total += len(data)
        print("%s -> %s（%d 条）" % (path, out_path, len(data)))
    print("共 %d 条" % total)
    return 0


def cmd_inject(args):
    asm_paths = collect_inputs(args.src, ".asm.txt")
    if not asm_paths:
        raise TextError("没有找到 asm 文件: %s" % args.src)
    out_dir = args.out
    if out_dir and not os.path.isdir(out_dir) and len(asm_paths) > 1:
        os.makedirs(out_dir, exist_ok=True)
    total = 0
    for path in asm_paths:
        stem = os.path.splitext(os.path.basename(path))[0]
        stem = stem[:-4] if stem.endswith(".asm") else stem
        json_path = os.path.join(args.json, stem + ".json")
        if not os.path.isfile(json_path):
            raise TextError("找不到对应的 JSON: %s" % json_path)
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        lines, pairs = make_entries(path)
        if len(data) != len(pairs):
            raise TextError("%s: JSON %d 条 / asm %d 条，数量不一致"
                            % (json_path, len(data), len(pairs)))
        changed = 0
        for item, (item0, entry) in zip(data, pairs):
            if item.get("id") != item0["id"]:
                raise TextError("%s: id 不匹配（%s != %s）"
                                % (json_path, item.get("id"), item0["id"]))
            body = item.get("message", "")
            name = item.get("name")
            orig_name = entry["name"]
            keep = (body == item.get("pre_jp") and name == orig_name)
            if keep:
                new_text = entry["orig_text"]
            else:
                if name:
                    body = name + body
                if "\n" in body:
                    new_text = body          # 手动断行，原样保留
                    if entry["limit"]:
                        for seg in new_text.split("\n"):
                            if seg.strip() and text_width(seg) > entry["limit"]:
                                print("警告: %s 手写断行超过 %d 全角：%r"
                                      % (item.get("id"), entry["limit"], seg),
                                      file=sys.stderr)
                elif "／" in body:
                    new_text = "\n".join(body.split("／"))
                else:
                    new_text = "\n".join(wrap_text(body, entry["limit"]))
            if new_text != entry["orig_text"]:
                changed += 1
            lines[entry["line_no"]] = rebuild_line(entry, new_text)
        out_path = path
        if out_dir:
            is_dir = (os.path.isdir(out_dir) or out_dir.endswith(os.sep)
                      or not os.path.splitext(out_dir)[1])
            if is_dir:
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, os.path.basename(path))
            elif len(asm_paths) == 1:
                out_path = out_dir
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8-sig", newline="\n") as f:
            f.write("\n".join(lines))
        total += len(data)
        print("%s -> %s（%d 条，改动 %d 条）" % (path, out_path, len(data), changed))
    print("共 %d 条" % total)
    return 0


def rebuild_line(entry, text):
    shown = escape_literal(text)
    mnem = entry["mnemonic"]
    if mnem == "OPTION":
        return '        %s "%s"' % (mnem.ljust(13), shown)
    tail = ""
    if entry["p1"] is not None and entry["p2"] is not None:
        tail = ", 0x%04X, 0x%04X" % (entry["p1"], entry["p2"])
    return '        %s "%s"%s' % (mnem.ljust(13), shown, tail)


# ---------------------------------------------------------------------------
# JSON <-> TXT
# ---------------------------------------------------------------------------
def write_txt(path, data):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for item in data:
            fields = [
                item.get("id", ""),
                item.get("kind", ""),
                item.get("name", ""),
                item.get("message", ""),
            ]
            f.write("\t".join(esc_tsv(x) for x in fields) + "\n")


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


def cmd_to_txt(args):
    files = collect_inputs(args.src, ".json")
    os.makedirs(args.out, exist_ok=True)
    for path in files:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        out_path = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0] + ".txt")
        write_txt(out_path, data)
        print("%s -> %s" % (path, out_path))
    return 0


def cmd_to_json(args):
    files = collect_inputs(args.src, ".txt")
    os.makedirs(args.out, exist_ok=True)
    for path in files:
        rows = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                cols = line.split("\t")
                while len(cols) < 4:
                    cols.append("")
                kind = cols[1] or "adv"
                limit = {"adv": 26, "vn": 23, "option": 0}.get(kind, 26)
                item = {"id": cols[0] or ("tsv#%05d" % (len(rows) + 1)),
                        "kind": kind, "limit": limit, "ref": ""}
                if cols[2]:
                    item["name"] = unesc_tsv(cols[2])
                msg = unesc_tsv(cols[3])
                item["pre_jp"] = msg
                item["message"] = msg
                rows.append(item)
        out_path = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0] + ".json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("%s -> %s（%d 条）" % (path, out_path, len(rows)))
    return 0


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
def cmd_report(args):
    asm_paths = collect_inputs(args.src, ".asm.txt")
    lines = []
    grand = 0
    for path in asm_paths:
        _l, pairs = make_entries(path)
        by_kind = {}
        by_name = {}
        wide = []
        for item, entry in pairs:
            by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
            if item.get("name"):
                by_name[item["name"]] = by_name.get(item["name"], 0) + 1
            if entry["limit"] and text_width(item["pre_jp"]) > entry["limit"] * 3:
                wide.append((item["id"], text_width(item["pre_jp"])))
        grand += len(pairs)
        lines.append("== %s ==" % path)
        lines.append("条目: %d" % len(pairs))
        for k in sorted(by_kind):
            lines.append("  %-7s %d" % (k, by_kind[k]))
        lines.append("说话人 %d 个: %s" % (len(by_name),
                     ", ".join("%s(%d)" % (n, c) for n, c in
                               sorted(by_name.items(), key=lambda x: -x[1])[:12])))
        if wide:
            lines.append("超长条目: %d" % len(wide))
    lines.append("总计: %d 条" % grand)
    text = "\n".join(lines) + "\n"
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("-> %s" % args.o)
    else:
        print(text)
    return 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def collect_inputs(path, suffix):
    if os.path.isdir(path):
        return [os.path.join(path, n) for n in sorted(os.listdir(path))
                if n.lower().endswith(suffix)]
    return [path] if os.path.isfile(path) and path.lower().endswith(suffix) else []


def main(argv=None):
    ap = argparse.ArgumentParser(description="wwadv asm <-> JSON 文本工具")
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

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except TextError as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
