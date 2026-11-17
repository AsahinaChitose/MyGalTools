#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDT asm.txt 文本提取 / 注入 / JSON-TXT 转换

适配本作 disassembler.py 生成的 asm.txt。

可翻译文本（按 opcode）：
    MESSAGE            0x00B8  对话正文        -> kind=message
    MESSAGE_ALT        0x00BC  对话变体        -> kind=message_alt
    CMD_C0             0x00C0  选项            -> kind=choice
    SET_SCRIPT_NAME    0x011D  章节名          -> kind=title

用法:
    # asm.txt -> 每文件一个 JSON（可选同时输出 TXT）
    python sdt_text.py extract --src dis --out json_jp [--txt txt_jp]

    # JSON -> asm.txt（保持其余字节不变）
    python sdt_text.py inject --src dis --json json_cn --out dis_cn

    # JSON <-> TXT
    python sdt_text.py to-txt  --src json_cn --out txt_cn
    python sdt_text.py to-json --src txt_cn  --out json_cn

    # 扫描所有含字符串的指令，检查还有哪些文本
    python sdt_text.py report --src dis -o text_report.txt

JSON 结构（按 asm 中出现顺序）：
    [
      {"kind":"message","name":"友則","message":"「・・・な、すごいって言っただろ」"},
      {"kind":"message","message":"俺の気のない返事にも、…"},
      {"kind":"choice","message":"洗い物を手伝う"},
      {"kind":"title","message":"バシリスク号"}
    ]
    name 只有 MESSAGE/MESSAGE_ALT 开头是 <N...> 时才存在；正文保留 <R...>、<W...> 等标签。

TXT 结构（TSV，字段内 \\t \\n \\\\ 转义）：
    # 01010.SDT
    0	message	友則	「・・・な、すごいって言っただろ」
    1	message		「・・・ああ」
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import opcodelist as oc

ENCODING = "cp932"

MNEMONIC_KIND = {
    "MESSAGE": "message",
    "MESSAGE_ALT": "message_alt",
    "CMD_C0": "choice",
    "SET_SCRIPT_NAME": "title",
}

# report 用：其它含字符串的指令分类
MNEMONIC_CLASS = {
    "MESSAGE": ("对话", True),
    "MESSAGE_ALT": ("对话变体", True),
    "CMD_C0": ("选项", True),
    "SET_SCRIPT_NAME": ("章节名", True),
    "CHANGE_SCRIPT": ("脚本编号", False),
    "MOVIE": ("动画文件名", False),
    "CMD_DA": ("动画资源名", False),
    "CMD_D5": ("图片资源名", False),
    "CMD_40": ("数值/表达式", False),
    "CMD_42": ("数值/表达式", False),
    "CMD_47": ("数值/表达式", False),
    "CMD_48": ("数值/表达式", False),
    "CMD_100": ("数值/表达式", False),
    "CMD_56": ("数值/表达式", False),
    "CMD_5D": ("数值/表达式", False),
    "CMD_74": ("数值/表达式", False),
    "CMD_76": ("数值/表达式", False),
    "CMD_E9": ("数值/表达式", False),
    "CMD_EC": ("数值/表达式", False),
    "CMD_E6": ("数值/表达式", False),
    "CMD_57": ("数值/表达式", False),
}

SPEAKER_RE = re.compile(r"^<N([^>]*)>(.*)$", re.S)


class TextError(Exception):
    def __init__(self, msg, path=None, line=None):
        self.path = path
        self.line = line
        super().__init__(msg)


# ---------------------------------------------------------------------------
# asm 字符串字面量
# ---------------------------------------------------------------------------
def find_literals(line: str):
    """返回第一个引号串内部内容的 (start, end) 列表。"""
    spans = []
    i = 0
    n = len(line)
    while i < n:
        if line[i] != '"':
            i += 1
            continue
        j = i + 1
        while j < n:
            c = line[j]
            if c == "\\":
                j += 2
                continue
            if c == '"':
                break
            j += 1
        if j >= n:
            break
        spans.append((i + 1, j))
        i = j + 1
    return spans


def literal_to_text(inner: str) -> str:
    raw = oc.encode_string(inner, ENCODING)
    return raw.decode(ENCODING)


def text_to_literal(text: str) -> str:
    return oc.decode_string(text.encode(ENCODING), ENCODING)


def classify(line: str):
    st = line.strip()
    if not st or st.startswith(";") or st.startswith("."):
        return None
    parts = st.split(None, 1)
    if not parts:
        return None
    mn = parts[0]
    if mn not in MNEMONIC_KIND:
        return None
    return mn, MNEMONIC_KIND[mn]


def strip_tags(text: str) -> str:
    t = re.sub(r"<[^>]*>", "", text)
    t = t.replace("\\k", "").replace("\\n", "").replace("\\r", "")
    t = t.replace("\u3000", "").replace(" ", "").replace("\t", "")
    return t


def split_speaker(text: str):
    m = SPEAKER_RE.match(text)
    if m:
        return m.group(1), m.group(2)
    return None, text


def parse_asm(path: Path):
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except UnicodeDecodeError:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    entries = []
    for li, line in enumerate(lines):
        cls = classify(line)
        if cls is None:
            continue
        mn, kind = cls
        spans = find_literals(line)
        if not spans:
            continue
        inner = line[spans[0][0]:spans[0][1]]
        text = literal_to_text(inner)
        if mn == "MESSAGE_ALT" and not strip_tags(text):
            # 只有 \k\n、全角空格之类的控制串，不算可译文本
            continue
        name, msg = split_speaker(text)
        ent = {"kind": kind, "line": li, "message": msg}
        if name:
            ent["name"] = name
        entries.append(ent)
    return lines, entries


# ---------------------------------------------------------------------------
# JSON / TXT
# ---------------------------------------------------------------------------
def to_json_entry(e):
    d = {"kind": e["kind"]}
    if e.get("name"):
        d["name"] = e["name"]
    d["message"] = e["message"]
    return d


def json_to_entries(path: Path):
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        raise TextError("JSON 必须是数组: %s" % path, path)
    out = []
    for i, item in enumerate(data):
        if not isinstance(item, dict) or "message" not in item:
            raise TextError("第 %d 条缺少 message" % (i + 1), path)
        kind = item.get("kind")
        msg = item["message"]
        if not isinstance(msg, str):
            raise TextError("第 %d 条 message 不是字符串" % (i + 1), path)
        out.append({"kind": kind, "name": item.get("name"), "message": msg})
    return out


def esc_txt(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def unesc_txt(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "\\":
                out.append("\\")
            elif n == "t":
                out.append("\t")
            elif n == "r":
                out.append("\r")
            elif n == "n":
                out.append("\n")
            else:
                out.append(n)
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def entries_to_txt(stem: str, entries) -> str:
    lines = ["# " + stem]
    for i, e in enumerate(entries):
        lines.append("\t".join([
            str(i), e["kind"], esc_txt(e.get("name") or ""), esc_txt(e["message"])
        ]))
    return "\n".join(lines) + "\n"


def txt_to_entries(text: str, path: Path):
    out = []
    for no, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        parts = raw.split("\t")
        if len(parts) != 4:
            raise TextError("TXT 行应有 4 个 TAB 字段（行 %d）" % no, path, no)
        idx, kind, name, msg = parts
        e = {"kind": kind, "message": unesc_txt(msg)}
        if name:
            e["name"] = unesc_txt(name)
        out.append(e)
    return out


# ---------------------------------------------------------------------------
# 命令：extract
# ---------------------------------------------------------------------------
def cmd_extract(args) -> int:
    src = Path(args.src)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    txtdir = Path(args.txt) if args.txt else None
    if txtdir:
        txtdir.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in src.iterdir() if p.name.lower().endswith(".asm.txt"))
    total = 0
    counts = {}
    for p in files:
        try:
            lines, entries = parse_asm(p)
        except TextError as e:
            print("失败 %s: %s" % (p.name, e), file=sys.stderr)
            continue
        stem = p.name[:-len(".asm.txt")]
        data = [to_json_entry(e) for e in entries]
        (out / (stem + ".json")).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        if txtdir:
            (txtdir / (stem + ".txt")).write_text(
                entries_to_txt(stem, data), encoding="utf-8")
        total += len(entries)
        for e in entries:
            counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    print("提取完成: %d 个文件, %d 条 -> %s" % (len(files), total, out))
    for k in ("message", "message_alt", "choice", "title"):
        if counts.get(k):
            print("  %-12s %d" % (k, counts[k]))
    return 0


# ---------------------------------------------------------------------------
# 命令：inject
# ---------------------------------------------------------------------------
def cmd_inject(args) -> int:
    src = Path(args.src)
    jdir = Path(args.json)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    cn_map = {}
    map_arg = args.cn_map
    if map_arg is None and not args.no_cn_map:
        for cand in (Path.cwd() / "subs_cn_jp.json",
                     Path(__file__).resolve().parent / "subs_cn_jp.json"):
            if cand.exists():
                map_arg = str(cand)
                break
    if map_arg:
        mp = Path(map_arg)
        if not mp.exists():
            raise TextError("映射文件不存在: %s" % mp, mp)
        cn_map = json.loads(mp.read_text(encoding="utf-8-sig"))
        if not isinstance(cn_map, dict):
            raise TextError("映射 JSON 必须是 {简体: 槽位字符}: %s" % mp, mp)
        print("已加载映射 %s（%d 条）" % (mp, len(cn_map)))

    def conv(s):
        if not cn_map:
            return s
        return "".join(cn_map.get(ch, ch) for ch in s)

    files = sorted(p for p in src.iterdir() if p.name.lower().endswith(".asm.txt"))
    total = 0
    changed_files = 0
    for p in files:
        stem = p.name[:-len(".asm.txt")]
        jp = None
        for cand in (stem + ".json", stem + ".json.json", stem + ".TXT.json"):
            cp = jdir / cand
            if cp.exists():
                jp = cp
                break
        if jp is None:
            jp = jdir / (stem + ".json")
        raw = p.read_text(encoding="utf-8-sig")
        lines = raw.splitlines(keepends=True)
        entries = parse_asm(p)[1]
        if not jp.exists():
            (out / p.name).write_text(raw, encoding="utf-8")
            print("[跳过] %s（没有 %s）" % (p.name, jp.name))
            continue
        tr = json_to_entries(jp)
        if len(tr) != len(entries):
            raise TextError("%s: JSON 条目 %d != asm 条目 %d" % (jp.name, len(tr), len(entries)),
                            jp)
        changed = False
        for idx, (e, t) in enumerate(zip(entries, tr), 1):
            if t.get("kind") and t["kind"] != e["kind"]:
                raise TextError("%s 第 %d 条 kind 不一致: %s != %s" %
                                (jp.name, idx, t["kind"], e["kind"]), jp)
            msg = conv(t["message"].replace("\r\n", " ").replace("\r", " ").replace("\n", " "))
            if e["kind"] in ("message", "message_alt"):
                name = conv(t.get("name") or "") or None
                if name:
                    if ">" in name or "<" in name:
                        raise TextError("%s: 名字含 '<' 或 '>': %r" % (jp.name, name), jp)
                    text = "<N%s>%s" % (name, msg)
                else:
                    text = msg
            else:
                text = msg
            try:
                lit = text_to_literal(text)
            except UnicodeEncodeError as ex:
                raise TextError("%s 第 %d 条无法用 %s 编码: %r" %
                                (jp.name, idx, ENCODING, text), jp)
            line = lines[e["line"]]
            spans = find_literals(line)
            s, en = spans[0]
            lines[e["line"]] = line[:s] + lit + line[en:]
            if lit != line[s:en]:
                changed = True
            total += 1
        (out / p.name).write_text("".join(lines), encoding="utf-8")
        if changed:
            changed_files += 1
    print("注入完成: %d 条, %d 个文件有改动 -> %s" % (total, changed_files, out))
    return 0


# ---------------------------------------------------------------------------
# 命令：JSON <-> TXT
# ---------------------------------------------------------------------------
def cmd_to_txt(args) -> int:
    src = Path(args.src)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in src.iterdir() if p.suffix.lower() == ".json")
    n = 0
    for p in files:
        entries = json_to_entries(p)
        stem = p.stem
        (out / (stem + ".txt")).write_text(entries_to_txt(stem, entries), encoding="utf-8")
        n += len(entries)
    print("JSON -> TXT: %d 个文件, %d 条 -> %s" % (len(files), n, out))
    return 0


def cmd_to_json(args) -> int:
    src = Path(args.src)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in src.iterdir() if p.suffix.lower() == ".txt")
    n = 0
    for p in files:
        entries = txt_to_entries(p.read_text(encoding="utf-8-sig"), p)
        (out / (p.stem + ".json")).write_text(
            json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
        n += len(entries)
    print("TXT -> JSON: %d 个文件, %d 条 -> %s" % (len(files), n, out))
    return 0


# ---------------------------------------------------------------------------
# 命令：report
# ---------------------------------------------------------------------------
def cmd_report(args) -> int:
    src = Path(args.src)
    stats = {}
    for p in sorted(src.iterdir()):
        if not p.name.lower().endswith(".asm.txt"):
            continue
        for line in p.read_text(encoding="utf-8-sig").splitlines():
            st = line.strip()
            if not st or st.startswith(";") or st.startswith("."):
                continue
            mn = st.split(None, 1)[0]
            spans = find_literals(line)
            if not spans:
                continue
            s = stats.setdefault(mn, {"lines": 0, "strings": 0, "samples": []})
            s["lines"] += 1
            s["strings"] += len(spans)
            if len(s["samples"]) < 3:
                try:
                    s["samples"].append(literal_to_text(line[spans[0][0]:spans[0][1]]))
                except Exception:
                    pass
    out = ["含字符串字面量的指令统计（按出现次数排序）", ""]
    out.append("%-16s %8s %8s  %-8s %s" % ("mnemonic", "指令数", "字符串", "可译", "样例"))
    for mn, s in sorted(stats.items(), key=lambda kv: -kv[1]["lines"]):
        cls = MNEMONIC_CLASS.get(mn)
        if cls:
            label, trans = cls
        else:
            label, trans = "未分类", False
        sample = " | ".join(x[:30] for x in s["samples"])
        out.append("%-16s %8d %8d  %-8s %s" % (mn, s["lines"], s["strings"],
                                               "是" if trans else "否", sample))
        out.append("    -> %s" % label)
    text = "\n".join(out) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print("报告 -> %s" % args.output)
    print(text)
    return 0


# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="SDT asm.txt 文本提取/注入/JSON-TXT")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="asm.txt -> JSON（可选 TXT）")
    p.add_argument("--src", default="dis")
    p.add_argument("--out", default="json_jp")
    p.add_argument("--txt")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="JSON -> asm.txt")
    p.add_argument("--src", default="dis")
    p.add_argument("--json", default="json_cn")
    p.add_argument("--out", default="dis_cn")
    p.add_argument("--cn-map", help="简体→CP932槽位映射；默认自动使用 subs_cn_jp.json")
    p.add_argument("--no-cn-map", action="store_true", help="不自动套 subs_cn_jp.json")
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("to-txt", help="JSON -> TXT")
    p.add_argument("--src", default="json_cn")
    p.add_argument("--out", default="txt_cn")
    p.set_defaults(func=cmd_to_txt)

    p = sub.add_parser("to-json", help="TXT -> JSON")
    p.add_argument("--src", default="txt_cn")
    p.add_argument("--out", default="json_cn")
    p.set_defaults(func=cmd_to_json)

    p = sub.add_parser("report", help="扫描所有含字符串的指令")
    p.add_argument("--src", default="dis")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except TextError as e:
        loc = ""
        if e.path:
            loc = str(e.path) + ((":%d" % e.line) if e.line else "") + ": "
        print("错误: %s%s" % (loc, e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
