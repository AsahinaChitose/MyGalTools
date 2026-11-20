#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asm_json.py -- 真冬外伝 的 asm <-> JSON 文本提取 / 注入

本作的正文都内联在 asm 的 MSG / MSG_H 行里，一条指令一行，没有换行符：

    MSG     0x0000, "V02597", "真冬「ひぁううううんっ・・・・！！！！！」"
    MSG_H   0x01C7, -,        "１・真冬を助けたいと、アツノリに代わって念じる/２・このまま傍観を決め込む"

提取规则（本作实测：5476 条正文里 2521 条人名行、7 条选项行，其余是旁白）：

* 人名行：整条正文形如 ``人名「文本」`` 时，把 ``人名`` 放进 ``name``，
  ``「文本」``（含括号）作为 ``message``。注入时拼回 ``name + message``。
* 选项行：正文用 ``/`` 分隔，且每一段都以 ``全角数字 + ・`` 开头时，拆成多条，
  ``kind`` 为 ``choice-1`` / ``choice-2`` ……，**每段保留自己的「１・」「２・」前缀**
  （按需求不过滤）。注入时按 kind 顺序用 ``/`` 拼回去。
* 旁白：``name`` 不出现，``message`` 就是整条正文。

没有折行 / 补换行符的逻辑：本作一条 MSG 就是屏幕上一段，长度由引擎自己排。

用法::

    python asm_json.py extract --src asm --out json_jp
    python asm_json.py inject  --src asm --json json_cn --out asm_cn
    python asm_json.py report  --src asm

JSON 结构（每个 asm 文件一个 .json，条目按出现顺序）::

    [
      {
        "id": "SCR#00101#00001",
        "msg": 0,                      // 对应 MSG 里的文本号（0x0000 -> 0）
        "ref": "loc_0003",             // 所在的最近一个标签，没有则为 ""
        "kind": "text",
        "name": "真冬",                // 仅人名行才有
        "pre_jp": "「ひぁううううんっ・・・・！！！！！」",
        "message": "「ひぁううううんっ・・・・！！！！！」"
      },
      {
        "id": "SCR#00001#00455",
        "msg": 455,
        "ref": "loc_0012",
        "kind": "choice-1",            // 同一条 MSG_H 拆出的第 1 段
        "pre_jp": "１・真冬を助けたいと、アツノリに代わって念じる",
        "message": "１・真冬を助けたいと、アツノリに代わって念じる"
      }
    ]

未修改时 extract -> inject 必须做到 asm 逐字节不变（`--verify` 可自检）。
"""

import argparse
import json
import os
import re
import sys

import opcodelist as OL

DEFAULT_ENCODING = "cp932"

# asm 行：<缩进>MSG / MSG_H  <文本号>, <语音|->,  "<正文>"
LINE_RE = re.compile(
    r'^(?P<prefix>[ \t]*(?P<mn>MSG|MSG_H)[ \t]+(?P<tid>0x[0-9A-Fa-f]+)[ \t]*,[ \t]*'
    r'(?P<voice>-|"(?:[^"\\]|\\.)*")[ \t]*,[ \t]*)'
    r'"(?P<text>(?:[^"\\]|\\.)*)"(?P<tail>.*)$'
)
LABEL_RE = re.compile(r"^(loc_[0-9A-Fa-f]{4,}):")

# 人名行：整条正文 = 人名「……」
NAME_RE = re.compile(r"^([^「」]{1,10})「(.*)」$")
# 选项段：全角数字 + ・
CHOICE_PART_RE = re.compile(r"^[０-９]+・")


class AsmJsonError(Exception):
    pass


def unescape(text, encoding):
    return OL.unescape_text(text, encoding).decode(encoding, "surrogateescape")


def escape(text):
    return OL.escape_text(text)


def asm_files(src):
    if os.path.isdir(src):
        return [os.path.join(src, n) for n in sorted(os.listdir(src))
                if n.lower().endswith(".asm.txt")]
    if os.path.isfile(src):
        return [src]
    return []


def stem_of(path):
    name = os.path.basename(path)
    if name.lower().endswith(".asm.txt"):
        return name[:-len(".asm.txt")]
    return os.path.splitext(name)[0]


def split_choice(raw):
    """若整条正文是“１・…/２・…”形式，返回各段（保留前缀），否则返回 None。"""
    if "/" not in raw:
        return None
    parts = raw.split("/")
    if len(parts) >= 2 and all(CHOICE_PART_RE.match(p) for p in parts):
        return parts
    return None


def scan_asm(path, encoding):
    """返回 (lines, entries)。entries 保留行号、前缀、原文，供注入还原。"""
    lines = open(path, encoding="utf-8", newline="").read().split("\n")
    entries = []
    ref = ""
    for idx, line in enumerate(lines):
        m_lab = LABEL_RE.match(line.strip())
        if m_lab:
            ref = m_lab.group(1)
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        raw = unescape(m.group("text"), encoding)
        tid = int(m.group("tid"), 16)
        parts = split_choice(raw)
        if parts is not None:
            entries.append({
                "line_no": idx,
                "prefix": m.group("prefix"),
                "tail": m.group("tail"),
                "msg": tid,
                "ref": ref,
                "kind": "choice",
                "name": None,
                "parts": parts,
                "raw": raw,
            })
            continue
        m_name = NAME_RE.match(raw)
        if m_name:
            name = m_name.group(1)
            body = "「%s」" % m_name.group(2)
        else:
            name = None
            body = raw
        entries.append({
            "line_no": idx,
            "prefix": m.group("prefix"),
            "tail": m.group("tail"),
            "msg": tid,
            "ref": ref,
            "kind": "text",
            "name": name,
            "body": body,
            "raw": raw,
        })
    return lines, entries


# ---------------------------------------------------------------- extract

def cmd_extract(args):
    files = asm_files(args.src)
    if not files:
        raise AsmJsonError("没有找到 asm 文件：%s" % args.src)
    os.makedirs(args.out, exist_ok=True)
    total = 0
    for path in files:
        stem = stem_of(path)
        _lines, entries = scan_asm(path, args.encoding)
        seen = set()
        data = []
        for e in entries:
            if e["msg"] in seen:
                raise AsmJsonError("%s: 文本号 %d 重复出现" % (path, e["msg"]))
            seen.add(e["msg"])
            if e["kind"] == "choice":
                for i, part in enumerate(e["parts"], 1):
                    data.append({
                        "id": "%s#%05d" % (stem, len(data) + 1),
                        "msg": e["msg"],
                        "ref": e["ref"],
                        "kind": "choice-%d" % i,
                        "pre_jp": part,
                        "message": part,
                    })
                continue
            item = {
                "id": "%s#%05d" % (stem, len(data) + 1),
                "msg": e["msg"],
                "ref": e["ref"],
                "kind": "text",
            }
            if e["name"]:
                item["name"] = e["name"]
            item["pre_jp"] = e["body"]
            item["message"] = e["body"]
            data.append(item)
        out_path = os.path.join(args.out, stem + ".json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        total += len(data)
        print("%s -> %s（%d 条）" % (path, out_path, len(data)))
    print("共 %d 条" % total)
    return 0


# ---------------------------------------------------------------- inject

def _choice_index(item):
    m = re.search(r"choice-(\d+)", str(item.get("kind", "")))
    return int(m.group(1)) if m else 0


def build_raw(e, items):
    """按 JSON 条目重建这条 MSG 的正文。"""
    if e["kind"] == "choice":
        items = sorted(items, key=_choice_index)
        if len(items) != len(e["parts"]):
            raise AsmJsonError("文本号 %d 的选项数 %d，原为 %d（不能增删选项）"
                               % (e["msg"], len(items), len(e["parts"])))
        parts = []
        for it in items:
            body = it.get("message")
            if body is None:
                body = it.get("pre_jp", "")
            if not isinstance(body, str):
                raise AsmJsonError("文本号 %d 的 message 不是字符串" % e["msg"])
            if "/" in body:
                raise AsmJsonError("文本号 %d 的选项里不能再出现 '/'：%r" % (e["msg"], body))
            parts.append(body)
        return "/".join(parts)
    if len(items) != 1:
        raise AsmJsonError("文本号 %d 的 JSON 条目数为 %d（应为 1）" % (e["msg"], len(items)))
    it = items[0]
    body = it.get("message")
    if body is None:
        body = it.get("pre_jp", "")
    if not isinstance(body, str):
        raise AsmJsonError("文本号 %d 的 message 不是字符串" % e["msg"])
    name = it.get("name")
    if name:
        m = NAME_RE.match(body)
        if m:
            # 译者把「人名」也写进了 message，避免重复拼接
            return body
        return "%s%s" % (name, body)
    return body


def cmd_inject(args):
    files = asm_files(args.src)
    if not files:
        raise AsmJsonError("没有找到 asm 文件：%s" % args.src)
    os.makedirs(args.out, exist_ok=True)
    total = 0
    all_warn = []
    for path in files:
        stem = stem_of(path)
        json_path = os.path.join(args.json, stem + ".json") if os.path.isdir(args.json) else args.json
        if not os.path.isfile(json_path):
            raise AsmJsonError("找不到对应的 JSON：%s" % json_path)
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        lines, entries = scan_asm(path, args.encoding)
        by_msg = {e["msg"]: e for e in entries}
        groups = {}
        for item in data:
            msg = item.get("msg")
            if msg not in by_msg:
                raise AsmJsonError("%s：JSON 里的文本号 %r 在 asm 中不存在" % (json_path, msg))
            groups.setdefault(msg, []).append(item)
        if set(groups) != set(by_msg):
            missing = sorted(set(by_msg) - set(groups))[:6]
            extra = sorted(set(groups) - set(by_msg))[:6]
            raise AsmJsonError("%s：文本号集合不一致（asm 缺 %s / JSON 多 %s）"
                               % (json_path, missing, extra))
        changed = 0
        for msg, e in by_msg.items():
            new_raw = build_raw(e, groups[msg])
            if new_raw == e["raw"]:
                continue
            changed += 1
            lines[e["line_no"]] = e["prefix"] + '"' + escape(new_raw) + '"' + e["tail"]
            if len(new_raw) > 300:
                all_warn.append("%s#%d 正文长度 %d 字节，可能超屏"
                                % (stem, msg, len(new_raw.encode(args.encoding, "surrogateescape"))))
        out_path = os.path.join(args.out, os.path.basename(path))
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            f.write("\n".join(lines))
        total += len(data)
        print("%s -> %s（%d 条，改动 %d 条）" % (path, out_path, len(data), changed))
    for w in all_warn[:20]:
        sys.stderr.write("警告: %s\n" % w)
    print("共 %d 条" % total)
    return 0


# ---------------------------------------------------------------- report

def cmd_report(args):
    files = asm_files(args.src)
    if not files:
        raise AsmJsonError("没有找到 asm 文件：%s" % args.src)
    grand = named = choice = 0
    lines = []
    names = {}
    longest = (0, "", "")
    for path in files:
        _lines, entries = scan_asm(path, args.encoding)
        n_named = sum(1 for e in entries if e["kind"] == "text" and e["name"])
        n_choice = sum(len(e["parts"]) for e in entries if e["kind"] == "choice")
        lines.append("%s: 正文 %d 条，人名 %d，选项 %d" % (
            os.path.basename(path), len(entries), n_named, n_choice))
        for e in entries:
            if e["kind"] == "text" and e["name"]:
                names[e["name"]] = names.get(e["name"], 0) + 1
            if e["kind"] == "text" and len(e["body"]) > longest[0]:
                longest = (len(e["body"]), e["body"], os.path.basename(path))
        grand += len(entries)
        named += n_named
        choice += n_choice
    lines.append("")
    lines.append("总计：正文 %d 条，人名 %d 条，选项 %d 段" % (grand, named, choice))
    if names:
        lines.append("说话人 %d 个：%s" % (len(names), "，".join(
            "%s(%d)" % (k, v) for k, v in sorted(names.items(), key=lambda x: -x[1])[:15])))
    if longest[0]:
        lines.append("最长正文 %d 字（%s）：%s" % (longest[0], longest[2], longest[1][:60]))
    text = "\n".join(lines) + "\n"
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("-> %s" % args.o)
    else:
        print(text)
    return 0


# ---------------------------------------------------------------- verify

def cmd_verify(args):
    """extract -> inject 自检：验证未修改时 asm 逐字节不变。"""
    import tempfile

    files = asm_files(args.src)
    if not files:
        raise AsmJsonError("没有找到 asm 文件：%s" % args.src)
    tmp = tempfile.mkdtemp(prefix="asmjson_")
    jsdir = os.path.join(tmp, "json")
    outdir = os.path.join(tmp, "asm")
    os.makedirs(jsdir, exist_ok=True)
    os.makedirs(outdir, exist_ok=True)
    rc = cmd_extract(argparse.Namespace(src=args.src, out=jsdir, encoding=args.encoding))
    if rc:
        return rc
    rc = cmd_inject(argparse.Namespace(src=args.src, json=jsdir, out=outdir, encoding=args.encoding))
    if rc:
        return rc
    bad = 0
    for path in files:
        a = open(path, "rb").read()
        b = open(os.path.join(outdir, os.path.basename(path)), "rb").read()
        if a != b:
            bad += 1
            print("不一致：%s" % path)
    print("verify：%d 个文件，%d 个不一致" % (len(files), bad))
    return 0 if bad == 0 else 1


def build_parser():
    ap = argparse.ArgumentParser(description="真冬外伝 asm <-> JSON 文本工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="asm.txt -> JSON")
    p.add_argument("--src", required=True, help="asm 目录或单个 asm.txt")
    p.add_argument("--out", required=True, help="输出 JSON 目录")
    p.add_argument("--encoding", default=DEFAULT_ENCODING)
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="JSON -> asm.txt")
    p.add_argument("--src", required=True, help="原 asm 目录或单个 asm.txt")
    p.add_argument("--json", required=True, help="JSON 目录或单个 json")
    p.add_argument("--out", required=True, help="输出 asm 目录")
    p.add_argument("--encoding", default=DEFAULT_ENCODING)
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("report", help="统计正文/人名/选项")
    p.add_argument("--src", required=True)
    p.add_argument("-o", default=None)
    p.add_argument("--encoding", default=DEFAULT_ENCODING)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("verify", help="extract->inject 自检，确认 asm 逐字节不变")
    p.add_argument("--src", required=True)
    p.add_argument("--encoding", default=DEFAULT_ENCODING)
    p.set_defaults(func=cmd_verify)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (AsmJsonError, ValueError) as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
