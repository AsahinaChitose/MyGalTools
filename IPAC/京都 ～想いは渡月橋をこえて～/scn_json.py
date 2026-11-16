#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scn_json.py -- 京都引擎 .scn 脚本 <-> 翻译 JSON 双向转换

.scn 是逐行文本脚本（CRLF），行种类：

    //...            注释（整行跳过，可含日文）
    #CMD [args]      指令（#SCENE / #BGM / #FLAG / #CENTER / #DARK ...）
    [tag]            场景标签（[bg06a] 等）
    -e014_000        语音/台词标签
    ?                选择肢开始，其后连续的文本行是选项（本作每个 ? 恰好 2 项）
    N {  ...  }      选择肢分支块
    \\  *  <ev_001>  :B_END     流程控制行（纯 ASCII）
    其余非 ASCII 行   正文 / 旁白 / 选项

提取：每个"显示行"一条记录，id = <文件名>#<4位序号>，字段 id / pre_jp / message。
      纯 ASCII 的控制行（* \\ <ev_xxx> :A_END 等）不提取；注释行不提取。
注入：按 id 定位原行，只替换该行整行内容；
      message 为空或与 pre_jp 相同 → 保留原始字节（不重编码）；
      其余按 --encoding（默认 gbk）编码后写回，其余字节（换行、指令、注释）逐字节保留。

用法：
    python scn_json.py extract -s scr_unpacked -o json_jp
    python scn_json.py inject  -s scr_unpacked -j json_cn -o scn_cn --encoding gbk
    python scn_json.py inject  -s scr_unpacked -j json_cn --in-place --encoding gbk
    python scn_json.py stats   -s scr_unpacked

只输出 JSON（每个 .scn 一个同名 .json），不写任何额外元数据文件。
输出目录可直接交给 pak_tool.py pack（inject 会顺带拷贝 _pak_manifest.json 以保持封包顺序）。
"""

import argparse
import json
import os
import re
import sys

SRC_ENC = "cp932"
TGT_ENC = "gbk"

RE_BRANCH = re.compile(r"^\d+\s*\{\s*$")
RE_CONTROL = re.compile(r"^[\\*]?$|^<[^>]*>$|^:[A-Za-z0-9_]+$")


# ---------------------------------------------------------------------------
# 行分类
# ---------------------------------------------------------------------------
def classify(s):
    """返回行类型：BLANK/COMMENT/CMD/TAG/LABEL/CHOICE_MARK/BRANCH/BRANCH_END/CONTROL/TEXT"""
    st = s.strip()
    if not st:
        return "BLANK"
    if s.startswith("//"):
        return "COMMENT"
    if s.startswith("#"):
        return "CMD"
    if s.startswith("["):
        return "TAG"
    if s.startswith("-"):
        return "LABEL"
    if st == "?":
        return "CHOICE_MARK"
    if st == "}":
        return "BRANCH_END"
    if RE_BRANCH.match(st):
        return "BRANCH"
    if all(ord(c) < 128 for c in st):
        return "CONTROL"
    return "TEXT"


def split_lines(raw):
    """按 CRLF 切分并给出每行在 raw 中的 [start, end) 字节区间。"""
    out = []
    pos = 0
    for part in raw.split(b"\r\n"):
        out.append((pos, pos + len(part), part))
        pos += len(part) + 2
    return out


def scan(raw, enc=SRC_ENC, stem=None):
    """扫描脚本，返回显示行记录列表。

    每条：{id, type, line(1-based), text, start, end}；给定 stem 时 id = <stem>#<序号>。
    """
    entries = []
    seq = 0
    in_choice = False
    for idx, (start, end, part) in enumerate(split_lines(raw)):
        try:
            s = part.decode(enc)
        except UnicodeDecodeError:
            s = part.decode(enc, "replace")
        kind = classify(s)
        if kind == "CHOICE_MARK":
            in_choice = True
            continue
        if kind == "TEXT":
            seq += 1
            entries.append({
                "id": ("%s#%04d" % (stem, seq)) if stem else None,
                "type": "CHOICE" if in_choice else "TEXT",
                "line": idx + 1,
                "text": s,
                "start": start,
                "end": end,
            })
            continue
        if kind != "BLANK":
            in_choice = False
    return entries


def stem_of(path):
    base = os.path.basename(path)
    if base.lower().endswith(".scn"):
        return base[:-4]
    return os.path.splitext(base)[0]


def collect(src):
    if os.path.isdir(src):
        return [os.path.join(src, f) for f in sorted(os.listdir(src))
                if f.lower().endswith(".scn")]
    return [src]


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------
def cmd_extract(args):
    files = collect(args.src)
    if not files:
        print("[-] 没有找到 .scn 文件: %s" % args.src)
        return 1
    os.makedirs(args.out, exist_ok=True)
    total_text = total_choice = 0
    for path in files:
        stem = stem_of(path)
        raw = open(path, "rb").read()
        entries = scan(raw, args.encoding, stem)
        data = []
        for e in entries:
            item = {"id": e["id"], "pre_jp": e["text"], "message": e["text"]}
            data.append(item)
        with open(os.path.join(args.out, stem + ".json"), "w",
                  encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        n_text = sum(1 for e in entries if e["type"] == "TEXT")
        n_choice = len(entries) - n_text
        total_text += n_text
        total_choice += n_choice
        print("%-16s -> %-22s  %4d 行 (正文 %d / 选项 %d)" %
              (os.path.basename(path), stem + ".json", len(entries), n_text, n_choice))
    print("done: %d 个文件, 正文 %d, 选项 %d" % (len(files), total_text, total_choice))
    return 0


# ---------------------------------------------------------------------------
# inject
# ---------------------------------------------------------------------------
def _encode_report(codec, text):
    try:
        return text.encode(codec), None
    except UnicodeEncodeError as ex:
        return None, text[ex.start:ex.end]


# ---------------------------------------------------------------------------
# 21 字修正：绘制换行点在 21 个全角字（504px）处，正好占满整行时
# 会多换一行而排版没算，导致下一句被画高 24px。补一个全角空格即可。
# ---------------------------------------------------------------------------
PAD_PX = 504
FULL_SPACE = b"\xa1\xa1"


def text_px(blob):
    """按引擎绘制宽度算一串 GBK 字节占多少像素（全角 24 / 半角 12）。"""
    px = 0
    i = 0
    n = len(blob)
    while i < n:
        if blob[i] >= 0x80:
            px += 24
            i += 2
        else:
            px += 12
            i += 1
    return px


def need_pad(blob):
    px = text_px(blob)
    return px > 0 and px % PAD_PX == 0


def cmd_inject(args):
    files = collect(args.src)
    if not files:
        print("[-] 没有找到 .scn 文件: %s" % args.src)
        return 1
    if not args.in_place:
        os.makedirs(args.out, exist_ok=True)
    total = replaced = same_text = fallback = missing = enc_fail = padded = 0
    warn = []
    changed_files = 0
    for path in files:
        stem = stem_of(path)
        raw = open(path, "rb").read()
        entries = scan(raw, args.source_encoding, stem)
        jp = os.path.join(args.json, stem + ".json")
        if not os.path.exists(jp):
            print("[跳过] %s（没有 %s.json）" % (os.path.basename(path), stem))
            if not args.in_place:
                open(os.path.join(args.out, os.path.basename(path)), "wb").write(raw)
            continue
        data = json.load(open(jp, encoding="utf-8-sig"))
        if not isinstance(data, list):
            raise SystemExit("%s 不是 JSON 数组" % jp)
        by_id = {d["id"]: d for d in data if isinstance(d, dict) and "id" in d}
        if not by_id and len(data) == len(entries):
            # 兼容纯数组：按顺序对应
            by_id = {e["id"]: d for e, d in zip(entries, data)}
        known = set(by_id)
        followed = {e["id"]: (i + 1 < len(entries) and entries[i + 1]["line"] == e["line"] + 1)
                    for i, e in enumerate(entries)}
        repls = []
        for e in entries:
            total += 1
            item = by_id.get(e["id"])
            if item is None:
                # JSON 里没有这条：仍然把原文转成目标编码写回去，
                # 否则会留下 CP932 字节，在 GBK 字体下变成乱码。
                missing += 1
                msg = e["text"]
            else:
                known.discard(e["id"])
                msg = item.get("message")
                if not isinstance(msg, str) or not msg.strip():
                    msg = e["text"]
                    fallback += 1
                elif msg == e["text"]:
                    same_text += 1
            if "\r" in msg or "\n" in msg:
                warn.append((stem, e["id"], "文本含换行"))
                continue
            blob, bad = _encode_report(args.encoding, msg)
            if blob is None:
                enc_fail += 1
                warn.append((stem, e["id"], "无法用 %s 编码: %r" % (args.encoding, bad)))
                continue
            if followed.get(e["id"]) and need_pad(blob):
                blob += FULL_SPACE
                padded += 1
            repls.append((e["start"], e["end"], blob))
            replaced += 1
        if known:
            warn.append((stem, "-", "JSON 里有 %d 条 id 在脚本中不存在" % len(known)))
        out = raw
        for start, end, blob in sorted(repls, key=lambda x: x[0], reverse=True):
            out = out[:start] + blob + out[end:]
        if out != raw:
            changed_files += 1
        if args.in_place:
            if out != raw:
                bak = path + ".bak"
                if not os.path.exists(bak):
                    open(bak, "wb").write(raw)
            target = path
        else:
            target = os.path.join(args.out, os.path.basename(path))
        with open(target, "wb") as f:
            f.write(out)

    # 保持封包顺序用
    man = os.path.join(args.src if os.path.isdir(args.src) else os.path.dirname(args.src),
                       "_pak_manifest.json")
    if not args.in_place and os.path.exists(man):
        with open(man, "rb") as f:
            blob = f.read()
        with open(os.path.join(args.out, "_pak_manifest.json"), "wb") as f:
            f.write(blob)

    if missing:
        print("[!] %d 条脚本行在 JSON 中找不到对应 id（已按原文转码写回）" % missing)
    if enc_fail:
        print("[!] %d 条无法用 %s 编码（保留原始字节）" % (enc_fail, args.encoding))
    for stem, tid, why in warn[:30]:
        print("    %s %s: %s" % (stem, tid, why))
    if len(warn) > 30:
        print("    ...（其余 %d 条省略）" % (len(warn) - 30))
    if padded:
        print("[i] %d 行正好 21/42 字，已补全角空格防重合" % padded)
    if same_text:
        print("[i] %d 行译文与原文相同（已重新按 %s 编码写回）" % (same_text, args.encoding))
    print("done: %d 个文件, %d 行, 替换 %d, 回退原文 %d, 文件改动 %d -> %s" %
          (len(files), total, replaced, fallback, changed_files,
           args.src if args.in_place else os.path.abspath(args.out)))
    return 0


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------
def cmd_stats(args):
    files = collect(args.src)
    counts = {"TEXT": 0, "CHOICE": 0}
    chars = 0
    bad = []
    longest = (0, "", 0)
    kinds = {}
    for path in files:
        raw = open(path, "rb").read()
        entries = scan(raw, args.encoding)
        for e in entries:
            counts[e["type"]] += 1
            chars += len(e["text"])
            if len(e["text"]) > longest[0]:
                longest = (len(e["text"]), os.path.basename(path), e["line"])
            blob, fail = _encode_report(args.encoding, e["text"])
            if blob is None:
                bad.append((os.path.basename(path), e["line"], fail, e["text"][:30]))
        # 行类型统计
        for _, _, part in split_lines(raw):
            k = classify(part.decode(args.encoding, "replace"))
            kinds[k] = kinds.get(k, 0) + 1
        if args.verbose:
            print("%-16s %4d 行" % (os.path.basename(path), len(entries)))
    print("files: %d  正文: %d  选项: %d  字数: %d" %
          (len(files), counts["TEXT"], counts["CHOICE"], chars))
    print("行类型:", ", ".join("%s=%d" % (k, v) for k, v in sorted(kinds.items())))
    print("最长行: %d 字 (%s:%d)" % longest)
    if bad:
        print("[!] %d 行含 %s 无法编码的字符（注入时会保留原文）:" % (len(bad), args.encoding))
        for x in bad[:20]:
            print("    %s:%d %r  %r" % (x[0], x[1], x[2], x[3]))
        if len(bad) > 20:
            print("    ...（其余 %d 条省略）" % (len(bad) - 20))
    return 0


# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="京都 .scn 脚本 <-> 翻译 JSON")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help=".scn -> JSON")
    p.add_argument("-s", "--src", required=True)
    p.add_argument("-o", "--out", default="json_jp")
    p.add_argument("--encoding", default=SRC_ENC, help="源脚本编码（默认 cp932）")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="JSON -> 新 .scn")
    p.add_argument("-s", "--src", required=True)
    p.add_argument("-j", "--json", required=True)
    p.add_argument("-o", "--out", default="scn_cn")
    p.add_argument("--in-place", action="store_true", help="覆盖源 .scn（先备份 .bak）")
    p.add_argument("--encoding", default=TGT_ENC, help="注入文本编码（默认 gbk）")
    p.add_argument("--source-encoding", default=SRC_ENC, help="源脚本编码（默认 cp932）")
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("stats", help="统计可提取文本")
    p.add_argument("-s", "--src", required=True)
    p.add_argument("--encoding", default=SRC_ENC)
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_stats)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
