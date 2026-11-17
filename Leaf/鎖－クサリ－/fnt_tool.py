#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kusari / xlvns 位图字体 (.FNT) 处理工具

字体格式（由 kusari.exe sub_416650 反推）：
    整个文件就是字形数组，无文件头。
    字形边长 = 24（mainFont.fnt）或 12（systemFont.fnt），
    每像素 1 字节：
        0       透明
        1..64   文字颜色填充（64 = 满色）
        65..128 黑色描边（128 = 满黑）
    行优先，无压缩、无调色板。
    字形数 = 8316（0..8315），文件大小 = glyph_count * size * size。

字符 -> 字形下标（sub_416650）：
    ASCII 0x00..0x7F      : idx = b + 8095          （半角）
    半角片假名 0xA1..0xDF : idx = b + 8063          （半角）
    双字节:
        lead = b1
        if lead < 0xF0:
            if lead >= 0xE0: lead -= 64
        else:
            lead -= 69
        idx = 189*lead + b2 - 24445                 （全角）

命令:
    python fnt_tool.py info   <fnt> [<fnt> ...]
    python fnt_tool.py map    <fnt> [-o map.json] [--csv map.csv]
    python fnt_tool.py atlas  <fnt> -o atlas.png [--cols 64] [--scale 1]
    python fnt_tool.py glyph  <fnt> <字符|下标> -o glyph.png [--scale 8]
    python fnt_tool.py text   <fnt> "字符串" -o text.png [--scale 2]
    python fnt_tool.py patch  <fnt> --map pairs.json --ttf font.ttf -o out.fnt
    python fnt_tool.py verify <fnt>
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import struct
import sys
import unicodedata
import zlib
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageOps
except Exception:
    Image = ImageDraw = ImageFont = ImageFilter = None

GLYPH_COUNT = 8316
BASE_ASCII = 8095
BASE_HALFKANA = 8063
BASE_FULL = 24445
STEP_FULL = 189

# 标点：不能按自身 bbox 居中，否则“。”会飘到字框中间。
PUNCT_EXTRA = set("，。？！、；：…—―・·～〜「」『』（）()《》〈〉【】[]〔〕——")

# 这些符号本身是“居中”的：不能按普通标点的右下偏移，否则会偏下/被切边。
CENTER_PUNCT = set("・･·•∙⋅―—─")


def is_punct(ch: str) -> bool:
    if not ch:
        return False
    if ch in PUNCT_EXTRA:
        return True
    return unicodedata.category(ch[0]).startswith("P")


class FntError(Exception):
    pass


# ---------------------------------------------------------------------------
# 字体对象
# ---------------------------------------------------------------------------
def detect_size(data: bytes, explicit: int | None = None) -> int:
    if explicit:
        return explicit
    n = len(data)
    cands = []
    for s in range(8, 65):
        if n % (s * s) == 0:
            count = n // (s * s)
            if 1 <= count <= 200000:
                cands.append((s, count))
    if not cands:
        raise FntError("文件大小 %d 无法分解为 size*size*glyph_count" % n)
    # 优先 8316 个字形；其次取最接近 8316 的
    exact = [c for c in cands if c[1] == GLYPH_COUNT]
    if exact:
        # 优先 24 / 12
        for s in (24, 12):
            if (s, GLYPH_COUNT) in exact:
                return s
        return exact[0][0]
    cands.sort(key=lambda c: abs(c[1] - GLYPH_COUNT))
    return cands[0][0]


class BitmapFont:
    def __init__(self, path: Path, size: int | None = None):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.size = detect_size(self.data, size)
        self.glyph_bytes = self.size * self.size
        if len(self.data) % self.glyph_bytes:
            raise FntError("文件大小不是 %d 的整数倍" % self.glyph_bytes)
        self.count = len(self.data) // self.glyph_bytes

    def glyph(self, index: int) -> bytes:
        if not (0 <= index < self.count):
            raise FntError("字形下标越界: %d (count=%d)" % (index, self.count))
        o = index * self.glyph_bytes
        return self.data[o:o + self.glyph_bytes]

    def ink_bbox(self, index: int):
        g = self.glyph(index)
        xs = [i % self.size for i, v in enumerate(g) if v]
        ys = [i // self.size for i, v in enumerate(g) if v]
        if not xs:
            return None
        return min(xs), min(ys), max(xs), max(ys)


def sjis_index(raw: bytes) -> tuple[int, str]:
    """返回 (glyph_index, 'half'|'full')。"""
    if len(raw) == 1:
        b = raw[0]
        if b < 0x80:
            return b + BASE_ASCII, "half"
        if 0xA0 <= b <= 0xDF:
            return b + BASE_HALFKANA, "half"
        raise FntError("单字节无法映射: 0x%02X" % b)
    if len(raw) != 2:
        raise FntError("只支持 1/2 字节 CP932")
    b1, b2 = raw[0], raw[1]
    lead = b1
    if lead < 0xF0:
        if lead >= 0xE0:
            lead -= 64
    else:
        lead -= 69
    return STEP_FULL * lead + b2 - BASE_FULL, "full"


def char_index(ch: str) -> tuple[int, str]:
    try:
        raw = ch.encode("cp932")
    except UnicodeEncodeError:
        raise FntError("字符不在 CP932 中: %r" % ch)
    return sjis_index(raw)


# ---------------------------------------------------------------------------
# 映射表
# ---------------------------------------------------------------------------
def _valid_two_byte(b1: int, b2: int) -> bool:
    if not (0x40 <= b2 <= 0x7E or 0x80 <= b2 <= 0xFC):
        return False
    try:
        bytes([b1, b2]).decode("cp932")
        return True
    except UnicodeDecodeError:
        return False


def iter_mapping(count: int):
    """枚举引擎可映射且下标在字体范围内的 CP932 字符。"""
    rows = []
    for b in range(0x20, 0x7F):
        idx, kind = sjis_index(bytes([b]))
        if idx < count:
            rows.append((idx, kind, bytes([b]), chr(b), "single"))
    for b in range(0xA1, 0xE0):
        idx, kind = sjis_index(bytes([b]))
        if idx < count:
            try:
                ch = bytes([b]).decode("cp932")
            except UnicodeDecodeError:
                ch = ""
            rows.append((idx, kind, bytes([b]), ch, "single"))
    for b1 in range(0x81, 0xA0):
        for b2 in range(0x40, 0xFD):
            if not _valid_two_byte(b1, b2):
                continue
            idx, kind = sjis_index(bytes([b1, b2]))
            if idx < count:
                rows.append((idx, kind, bytes([b1, b2]),
                             bytes([b1, b2]).decode("cp932"), "double"))
    for b1 in range(0xE0, 0xF0):
        for b2 in range(0x40, 0xFD):
            if not _valid_two_byte(b1, b2):
                continue
            idx, kind = sjis_index(bytes([b1, b2]))
            if idx < count:
                rows.append((idx, kind, bytes([b1, b2]),
                             bytes([b1, b2]).decode("cp932"), "double"))
    rows.sort(key=lambda r: (r[0], r[3]))
    return rows


# ---------------------------------------------------------------------------
# 图像
# ---------------------------------------------------------------------------
def glyph_image(font: BitmapFont, index: int, invert: bool = True, scale: int = 1):
    if Image is None:
        raise FntError("需要 Pillow 才能输出图像")
    g = font.glyph(index)
    s = font.size
    if invert:
        img = Image.frombytes("L", (s, s), bytes(255 - v for v in g))
    else:
        img = Image.frombytes("L", (s, s), g)
    if scale != 1:
        img = img.resize((s * scale, s * scale), Image.Resampling.NEAREST)
    return img


def _write_png_raw(path: Path, w: int, h: int, data: bytes):
    """不依赖 Pillow 的灰度 PNG 写入（备用）。"""
    raw = b"".join(b"\x00" + data[y * w:(y + 1) * w] for y in range(h))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    out = (b"\x89PNG\r\n\x1a\n" +
           chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)) +
           chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
    path.write_bytes(out)


def save_image(img, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        img.save(path)
    except Exception:
        w, h = img.size
        _write_png_raw(path, w, h, img.tobytes())


# ---------------------------------------------------------------------------
# 命令
# ---------------------------------------------------------------------------
def cmd_info(args) -> int:
    for p in args.fnt:
        font = BitmapFont(Path(p), args.size)
        rows = iter_mapping(font.count)
        idxs = sorted({r[0] for r in rows})
        covered = len(idxs)
        gaps = font.count - covered
        dup = len(rows) - covered
        print("== %s" % p)
        print("  size      : %dx%d, %d 字节/字形" % (font.size, font.size, font.glyph_bytes))
        print("  glyphs    : %d" % font.count)
        print("  file size : %d" % len(font.data))
        print("  mapped    : %d 个字形 / %d 条 CP932 映射（重叠 %d）" % (covered, len(rows), dup))
        print("  blank slots: %d" % gaps)
        print("  glyph0 bbox: %r" % (font.ink_bbox(0),))
    return 0


def cmd_map(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    rows = iter_mapping(font.count)
    out = []
    for idx, kind, raw, ch, src in rows:
        out.append({
            "index": idx,
            "kind": kind,
            "cp932": " ".join("%02X" % x for x in raw),
            "char": ch,
            "source": src,
        })
    if args.output:
        p = Path(args.output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print("已写出 JSON: %s（%d 条）" % (p, len(out)))
    if args.csv:
        p = Path(args.csv)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8-sig", newline="") as f:
            f.write("index,kind,cp932,char,source\n")
            for r in out:
                f.write('%d,%s,"%s","%s",%s\n' % (r["index"], r["kind"], r["cp932"],
                                                  r["char"].replace('"', '""'), r["source"]))
        print("已写出 CSV: %s" % p)
    if not args.output and not args.csv:
        for r in out[:40]:
            print(r)
    return 0


def cmd_atlas(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    start = args.start
    count = min(args.count or font.count, font.count - start)
    cols = args.cols
    s = font.size
    rows = (count + cols - 1) // cols
    atlas = Image.new("L", (cols * s, rows * s), 255)
    for k in range(count):
        idx = start + k
        g = font.glyph(idx)
        cell = Image.frombytes("L", (s, s), bytes(255 - v for v in g))
        atlas.paste(cell, ((k % cols) * s, (k // cols) * s))
    if args.grid:
        d = ImageDraw.Draw(atlas)
        for x in range(0, cols * s, s):
            d.line([(x, 0), (x, rows * s)], fill=220)
        for y in range(0, rows * s, s):
            d.line([(0, y), (cols * s, y)], fill=220)
    if args.scale != 1:
        atlas = atlas.resize((atlas.width * args.scale, atlas.height * args.scale), Image.Resampling.NEAREST)
    save_image(atlas, Path(args.output))
    print("atlas: %d..%d -> %s (%dx%d)" % (start, start + count - 1, args.output, atlas.width, atlas.height))
    return 0


def _parse_index(font: BitmapFont, token: str) -> int:
    t = token.strip()
    if t.lstrip("-").isdigit():
        return int(t)
    if t.startswith("0x") or t.startswith("0X"):
        return int(t, 16)
    idx, _ = char_index(t[0])
    return idx


def cmd_glyph(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    idx = _parse_index(font, args.glyph)
    img = glyph_image(font, idx, invert=True, scale=args.scale)
    save_image(img, Path(args.output))
    print("glyph %d -> %s" % (idx, args.output))
    return 0


def cmd_text(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    text = args.text
    raw = text.encode("cp932")
    glyphs = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b < 0x80:
            chunk = raw[i:i + 1]
            i += 1
        elif 0xA1 <= b <= 0xDF:
            chunk = raw[i:i + 1]
            i += 1
        else:
            if i + 1 >= len(raw):
                raise FntError("文本尾部有不完整双字节")
            chunk = raw[i:i + 2]
            i += 2
        idx, kind = sjis_index(chunk)
        glyphs.append((idx, kind))
    s = font.size
    advances = [s // 2 if kind == "half" else s for _, kind in glyphs]
    width = sum(advances) + args.spacing * (len(glyphs) - 1) + 4
    height = s + 4
    img = Image.new("L", (width, height), 255)
    x = 2
    for (idx, kind), adv in zip(glyphs, advances):
        g = font.glyph(idx)
        cell = Image.frombytes("L", (s, s), bytes(255 - v for v in g))
        img.paste(cell, (x, 2))
        x += adv + args.spacing
    if args.scale != 1:
        img = img.resize((img.width * args.scale, img.height * args.scale), Image.Resampling.NEAREST)
    save_image(img, Path(args.output))
    print("text: %d 字 -> %s (%dx%d)" % (len(glyphs), args.output, img.width, img.height))
    return 0


def _load_pairs(path: Path):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    pairs = []
    if isinstance(data, dict):
        for k, v in data.items():
            pairs.append((str(k), v))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                src = item.get("char") or item.get("src") or item.get("cn")
                dst = item.get("slot") or item.get("dst") or item.get("jp") or item.get("index")
                if src is not None and dst is not None:
                    pairs.append((str(src), dst))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.append((str(item[0]), item[1]))
    else:
        raise FntError("映射 JSON 必须是对象或数组")
    return pairs


def render_ttf_glyph(ch: str, ttf: str, px: int, size: int, kind: str,
                     xoff: int = 0, yoff: int = 0, ttc_index: int = 0,
                     bold: int = 0, outline: bool = True, stroke: int = 0,
                     outline_width: int | None = None) -> bytes:
    """把 TTF 字符画成游戏字体的 8bpp 数据。

    关键 1：游戏位图不是普通灰度图。
        1..64   = 文字颜色填充（0x40 为满色）
        65..128 = 黑色描边（128 为满黑）
        0       = 透明
    关键 2：所有全角字都按“国”的 bbox 对齐（固定 baseline），
    不按每个字自己的 bbox 居中；否则“。”“一”等会上下乱飘、大小感不一致。
    """
    if ImageFont is None:
        raise FntError("需要 Pillow 才能从 TTF 渲染")

    ow = 2 if size >= 20 else 0
    if outline_width is not None:
        ow = max(0, outline_width)
    if not outline:
        ow = 0
    # 原字库的黑色部分 = 1px 四周描边 + 右下 1px 投影，右/下比左/上多 1px。
    sx = 1 if (size >= 20 and outline) else 0
    sy = sx

    if kind == "half":
        cw = size // 2
        # 半角槽窄：逐渐缩小 px 直到 bbox 放得下，再水平/垂直居中
        p = px
        font = ImageFont.truetype(ttf, p, index=ttc_index)
        d0 = ImageDraw.Draw(Image.new("L", (1, 1)))
        while p > max(7, px // 2):
            bb = d0.textbbox((0, 0), ch, font=font)
            bw, bh = bb[2] - bb[0], bb[3] - bb[1]
            if bw <= cw and bh <= size:
                break
            p -= 1
            font = ImageFont.truetype(ttf, p, index=ttc_index)
        bb = d0.textbbox((0, 0), ch, font=font)
        bw, bh = bb[2] - bb[0], bb[3] - bb[1]
        img = Image.new("L", (cw, size), 255)
        x = (cw - bw) // 2 - bb[0] + xoff
        y = (size - bh) // 2 - bb[1] + yoff
        kw = {"stroke_width": stroke, "stroke_fill": 0} if stroke else {}
        ImageDraw.Draw(img).text((x, y), ch, font=font, fill=0, **kw)
    else:
        font = ImageFont.truetype(ttf, px, index=ttc_index)
        img = Image.new("L", (size, size), 255)
        d = ImageDraw.Draw(img)
        # 以“国”为统一基准：所有全角字共用同一 baseline
        rb = d.textbbox((0, 0), "国", font=font)
        rw, rh = rb[2] - rb[0], rb[3] - rb[1]
        x = (size - rw) // 2 - rb[0] + xoff
        y = (size - rh) // 2 - rb[1] + yoff
        kw = {"stroke_width": stroke, "stroke_fill": 0} if stroke else {}
        if ch in CENTER_PUNCT:
            # 以“实际墨迹”居中，不按 textbbox：TTF 的 bbox 可能带大量空白，
            # 按 bbox 居中会让“・”偏高、“―”偏下并切右边。
            pad = size
            p2 = px
            f2 = font
            bb2 = None
            w = h = 0
            while p2 >= 8:
                f2 = ImageFont.truetype(ttf, p2, index=ttc_index)
                tmp = Image.new("L", (size * 3, size * 3), 255)
                ImageDraw.Draw(tmp).text((pad, pad), ch, font=f2, fill=0, **kw)
                inv = ImageOps.invert(tmp)
                bb2 = inv.getbbox()
                if bb2:
                    w, h = bb2[2] - bb2[0], bb2[3] - bb2[1]
                    # 墨迹 + 两侧描边都要放得下
                    if w + 2 * ow <= size and h + 2 * ow <= size:
                        break
                p2 -= 1
            if bb2:
                x = (size - w) // 2 - (bb2[0] - pad) + xoff
                y = (size - h) // 2 - (bb2[1] - pad) + yoff
                ImageDraw.Draw(img).text((x, y), ch, font=f2, fill=0, **kw)
        else:
            if is_punct(ch):
                x += 2 if size >= 20 else 1
                y += 1
            d.text((x, y), ch, font=font, fill=0, **kw)

    if bold > 0:
        inv = Image.eval(img, lambda p: 255 - p)
        inv = inv.filter(ImageFilter.MaxFilter(bold * 2 + 1))
        img = Image.eval(inv, lambda p: 255 - p)

    if img.width != size:
        canvas = Image.new("L", (size, size), 255)
        canvas.paste(img, (0, 0))
        img = canvas
    alpha = bytes(255 - p for p in img.getdata())

    # 内部填充：1..64
    fill = bytearray(size * size)
    for i, a in enumerate(alpha):
        if a:
            v = int(round(a * 64 / 255))
            fill[i] = 64 if v > 64 else (1 if v < 1 else v)

    if not outline:
        return bytes(fill)

    # 描边：阈值化后做 4 邻域膨胀（上下左右各 1 像素），外圈写 65..128。
    # 不用 3x3 MaxFilter：那会把对角也扩一圈，24px 下显得又粗又糊。
    core = bytearray(255 if a >= 64 else 0 for a in alpha)

    def dilate4(m):
        d = bytearray(size * size)
        for yy in range(size):
            for xx in range(size):
                if not m[yy * size + xx]:
                    continue
                if yy > 0:
                    d[(yy - 1) * size + xx] = 255
                if yy + 1 < size:
                    d[(yy + 1) * size + xx] = 255
                if xx > 0:
                    d[yy * size + xx - 1] = 255
                if xx + 1 < size:
                    d[yy * size + xx + 1] = 255
        return d

    ring = core
    for _ in range(ow):
        ring = dilate4(ring)
    # 第二层：向右下偏移 1px 的软阴影（96 = 半透明黑），
    # 与四周围 128 的硬描边区分开，做出原字库那种“两层”立体感。
    shadow = bytearray(size * size)
    if sx or sy:
        for yy in range(size):
            for xx in range(size):
                if not ring[yy * size + xx]:
                    continue
                tx, ty = xx + sx, yy + sy
                if 0 <= tx < size and 0 <= ty < size:
                    shadow[ty * size + tx] = 96
    cell = bytearray(size * size)
    for i in range(size * size):
        if core[i]:
            cell[i] = fill[i]
        elif ring[i]:
            cell[i] = 128
        elif shadow[i]:
            cell[i] = 96
    return bytes(cell)


DEFAULT_MAP_NAME = "subs_cn_jp.json"


def _font_cmap(ttf: str, ttc_index: int):
    """返回字体 cmap 的 Unicode 集合；没有 fontTools 时返回 None（视为全支持）。"""
    try:
        from fontTools.ttLib import TTFont, TTCollection
    except Exception:
        return None
    try:
        if ttf.lower().endswith((".ttc", ".otc")):
            coll = TTCollection(ttf)
            font = coll.fonts[ttc_index]
        else:
            font = TTFont(ttf)
        return set(font.getBestCmap().keys())
    except Exception:
        return None


def patch_full_font(font: BitmapFont, pairs, ttf: str, px: int, xoff: int, yoff: int,
                    ttc_index: int, bold: int, outline: bool = True, verbose: bool = True,
                    stroke: int = 0, outline_width: int | None = None):
    """把字体覆盖到的所有可寻址字形槽全部重画一遍，统一风格。"""
    sources = {}
    kinds = {}
    for idx, kind, raw, ch, src in iter_mapping(font.count):
        if ch:
            sources[idx] = ch
            kinds[idx] = kind
    # 先用 subs_cn_jp.json 覆盖：这→這 表示 這 的槽画“这”
    for key, dst in pairs:
        try:
            if isinstance(dst, int):
                idx = dst
            else:
                idx, _k = char_index(str(dst)[0])
        except (FntError, ValueError):
            continue
        if 0 <= idx < font.count and idx in sources:
            sources[idx] = key[0]
    cmap = _font_cmap(ttf, ttc_index)
    buf = bytearray(font.data)
    patched = fallback = 0
    for idx, ch in sorted(sources.items()):
        if cmap is not None and ord(ch) not in cmap:
            fallback += 1
            continue
        try:
            cell = render_ttf_glyph(ch, ttf, px, font.size, kinds.get(idx, "full"),
                                    xoff, yoff, ttc_index, bold, outline, stroke,
                                    outline_width)
        except (FntError, OSError, ValueError):
            fallback += 1
            continue
        o = idx * font.glyph_bytes
        buf[o:o + font.glyph_bytes] = cell
        patched += 1
    if verbose and fallback:
        print("  TTF 缺字/无法渲染，保留原字形: %d 个" % fallback)
    return buf, patched, fallback


def _resolve_map(path_arg) -> Path:
    if path_arg:
        p = Path(path_arg)
        if not p.exists():
            raise FntError("映射文件不存在: %s" % p)
        return p
    for p in (Path.cwd() / DEFAULT_MAP_NAME, Path(__file__).resolve().parent / DEFAULT_MAP_NAME):
        if p.exists():
            return p
    raise FntError("未指定 --map，且找不到默认映射 %s" % DEFAULT_MAP_NAME)


def patch_font(font: BitmapFont, pairs, ttf: str, px: int, xoff: int, yoff: int,
               ttc_index: int, bold: int, verbose: bool = True, outline: bool = True,
               stroke: int = 0, outline_width: int | None = None):
    buf = bytearray(font.data)
    patched = skipped = 0
    for src_ch, dst in pairs:
        if not src_ch:
            skipped += 1
            continue
        try:
            if isinstance(dst, int):
                idx = dst
                kind = "full"
            else:
                idx, kind = char_index(str(dst)[0])
            if not (0 <= idx < font.count):
                raise FntError("下标越界 %d" % idx)
            cell = render_ttf_glyph(src_ch[0], ttf, px, font.size,
                                    kind, xoff, yoff, ttc_index, bold, outline, stroke,
                                    outline_width)
            o = idx * font.glyph_bytes
            buf[o:o + font.glyph_bytes] = cell
            patched += 1
        except (FntError, UnicodeEncodeError, OSError) as e:
            if verbose:
                print("跳过 %r -> %r: %s" % (src_ch, dst, e))
            skipped += 1
    return buf, patched, skipped


def cmd_patch(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    pairs = _load_pairs(_resolve_map(args.map))
    px = args.px or font.size
    outline = not args.no_outline
    if args.all:
        buf, patched, fallback = patch_full_font(font, pairs, args.ttf, px,
                                                 args.xoff, args.yoff, args.ttc_index,
                                                 args.bold, outline, stroke=args.stroke,
                                                 outline_width=args.outline_width)
        print("patch-all-glyphs: %d 个字形（TTF 缺字保留 %d）-> %s" %
              (patched, fallback, args.output))
    else:
        buf, patched, skipped = patch_font(font, pairs, args.ttf, px,
                                           args.xoff, args.yoff, args.ttc_index,
                                           args.bold, outline=outline, stroke=args.stroke,
                                           outline_width=args.outline_width)
        print("patch: %d 个字形, 跳过 %d, 映射 %d 条 -> %s" %
              (patched, skipped, len(pairs), args.output))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(buf)
    return 0


def cmd_patch_all(args) -> int:
    d = Path(args.dir)
    if not d.is_dir():
        raise FntError("不是目录: %s" % d)
    pairs = _load_pairs(_resolve_map(args.map))
    out = Path(args.output)
    if out.resolve() == d.resolve():
        raise FntError("输出目录不能与输入目录相同（会覆盖原字体）")
    out.mkdir(parents=True, exist_ok=True)
    # 先把整个解包目录复制过去，这样 patched 目录可以直接交给 pak_tool.py pack
    copied = 0
    for p in d.iterdir():
        if p.is_file():
            shutil.copy2(p, out / p.name)
            copied += 1
    print("已复制 %d 个文件到 %s" % (copied, out))
    found = {p.name.upper(): p for p in d.iterdir() if p.is_file()}
    targets = [("MAINFONT.FNT", args.px_main), ("SYSTEMFONT.FNT", args.px_sys)]
    done = 0
    for name, px_opt in targets:
        p = found.get(name)
        if p is None:
            print("警告: 目录中没有 %s" % name)
            continue
        font = BitmapFont(p, args.size)
        px = px_opt or args.px or font.size
        outline = not args.no_outline
        if args.all:
            buf, patched, fallback = patch_full_font(font, pairs, args.ttf, px,
                                                     args.xoff, args.yoff, args.ttc_index,
                                                     args.bold, outline, stroke=args.stroke,
                                                     outline_width=args.outline_width)
            print("%s: %dx%d, 全字体重画 %d（TTF 缺字保留 %d）-> %s" %
                  (p.name, font.size, font.size, patched, fallback, out / p.name))
        else:
            buf, patched, skipped = patch_font(font, pairs, args.ttf, px,
                                               args.xoff, args.yoff, args.ttc_index,
                                               args.bold, outline=outline, stroke=args.stroke,
                                               outline_width=args.outline_width)
            print("%s: %dx%d, patch %d, 跳过 %d -> %s" %
                  (p.name, font.size, font.size, patched, skipped, out / p.name))
        dst = out / p.name
        dst.write_bytes(buf)
        done += 1
    if not done:
        raise FntError("没有找到 MAINFONT.FNT / SYSTEMFONT.FNT")
    return 0


def cmd_check_map(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    pairs = _load_pairs(_resolve_map(args.map))
    mapped = {r[0] for r in iter_mapping(font.count)}
    dup = collections.Counter(str(v)[0] for _, v in pairs if isinstance(v, str))
    good = bad = blank = 0
    samples = []
    invalid = []
    for src, dst in pairs:
        slot = str(dst)[0] if not isinstance(dst, int) else None
        try:
            if slot is None:
                idx, kind = int(dst), "full"
            else:
                idx, kind = char_index(slot)
        except (FntError, ValueError):
            bad += 1
            invalid.append((src, dst, "无 CP932 编码"))
            continue
        if idx >= font.count or idx not in mapped:
            bad += 1
            invalid.append((src, dst, "下标 %d 不对应任何字符" % idx))
            continue
        if not any(font.glyph(idx)):
            blank += 1
        else:
            good += 1
        if len(samples) < 10:
            samples.append((src, slot or dst, idx, kind))
    print("字体: %s  %dx%d" % (font.path.name, font.size, font.size))
    print("映射: %d 条；目标槽有效且有字 %d，空白槽 %d，无效 %d" %
          (len(pairs), good, blank, bad))
    if dup and max(dup.values()) > 1:
        print("重复目标槽: %d 个" % sum(1 for v in dup.values() if v > 1))
        for k, c in dup.most_common(5):
            if c > 1:
                print("  %r 被使用 %d 次" % (k, c))
    print("示例: " + "  ".join("%s→%s(idx=%d,%s)" % s for s in samples))
    if invalid:
        print("无效项（前 10）:")
        for it in invalid[:10]:
            print("  %r -> %r: %s" % it)
    return 0


def cmd_copy(args) -> int:
    src = BitmapFont(Path(args.src), args.src_size)
    dst = BitmapFont(Path(args.dst), args.dst_size)
    sidx, _ = char_index(args.src_char)
    didx, dkind = char_index(args.dst_char)
    if src.glyph_bytes != dst.glyph_bytes:
        raise FntError("两个字体尺寸不同，无法直接复制")
    buf = bytearray(dst.data)
    buf[didx * dst.glyph_bytes:(didx + 1) * dst.glyph_bytes] = src.glyph(sidx)
    Path(args.output).write_bytes(buf)
    print("%s[%d] -> %s[%d]" % (args.src_char, sidx, args.dst_char, didx))
    return 0


def cmd_lookup(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    for ch in args.text:
        try:
            idx, kind = char_index(ch)
        except FntError as e:
            print("%r  无 CP932 编码（%s）" % (ch, e))
            continue
        if not (0 <= idx < font.count):
            print("%r  cp932=%s  index=%d  (超出范围)" %
                  (ch, ch.encode("cp932").hex(" ").upper(), idx))
            continue
        g = font.glyph(idx)
        nz = sum(1 for v in g if v)
        bbox = font.ink_bbox(idx)
        print("%r  cp932=%s  index=%d  %s  非空像素=%d  bbox=%r" %
              (ch, ch.encode("cp932").hex(" ").upper(), idx, kind, nz, bbox))
    return 0


def cmd_freeslots(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    mapped = {r[0] for r in iter_mapping(font.count)}
    free = [i for i in range(font.count) if i not in mapped]
    ranges = []
    for i in free:
        if ranges and i == ranges[-1][1] + 1:
            ranges[-1][1] = i
        else:
            ranges.append([i, i])
    blank = [i for i in free if not any(font.glyph(i))]
    print("未映射槽位: %d 个（其中全空白 %d 个）" % (len(free), len(blank)))
    print("区间: " + ", ".join("%d-%d" % (a, b) if a != b else str(a) for a, b in ranges))
    if args.output:
        p = Path(args.output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"free": free, "blank": blank,
                                 "ranges": ranges}, ensure_ascii=False, indent=2), encoding="utf-8")
        print("已写出: %s" % p)
    return 0


def cmd_verify(args) -> int:
    font = BitmapFont(Path(args.fnt), args.size)
    rows = iter_mapping(font.count)
    idxs = {r[0] for r in rows}
    print("size=%d count=%d mapped=%d/%d" % (font.size, font.count, len(idxs), font.count))
    missing = [i for i in range(font.count) if i not in idxs]
    print("无字符映射的下标: %d 个%s" % (len(missing), ("，例如 %s" % missing[:10]) if missing else ""))
    print("字形 0 空白: %s" % all(v == 0 for v in font.glyph(0)))
    return 0


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="kusari/xlvns .FNT 位图字体工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="字体信息")
    p.add_argument("fnt", nargs="+")
    p.add_argument("--size", type=int)
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("map", help="导出 CP932 -> 字形下标映射")
    p.add_argument("fnt")
    p.add_argument("--size", type=int)
    p.add_argument("-o", "--output")
    p.add_argument("--csv")
    p.set_defaults(func=cmd_map)

    p = sub.add_parser("atlas", help="导出整张字形图集 PNG")
    p.add_argument("fnt")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--size", type=int)
    p.add_argument("--cols", type=int, default=64)
    p.add_argument("--scale", type=int, default=1)
    p.add_argument("--start", type=int, default=0)
    p.add_argument("--count", type=int)
    p.add_argument("--grid", action="store_true")
    p.set_defaults(func=cmd_atlas)

    p = sub.add_parser("glyph", help="导出单个字形")
    p.add_argument("fnt")
    p.add_argument("glyph", help="字符或下标")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--size", type=int)
    p.add_argument("--scale", type=int, default=8)
    p.set_defaults(func=cmd_glyph)

    p = sub.add_parser("text", help="用字体渲染一行文本")
    p.add_argument("fnt")
    p.add_argument("text")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--size", type=int)
    p.add_argument("--scale", type=int, default=2)
    p.add_argument("--spacing", type=int, default=0)
    p.set_defaults(func=cmd_text)

    p = sub.add_parser("patch", help="用 TTF 重绘指定字形槽")
    p.add_argument("fnt")
    p.add_argument("--map", help="默认使用 subs_cn_jp.json（{简体: 目标CP932字符}）")
    p.add_argument("--ttf", required=True)
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--size", type=int)
    p.add_argument("--px", type=int, help="TTF 像素大小，默认等于字形边长")
    p.add_argument("--xoff", type=int, default=0)
    p.add_argument("--yoff", type=int, default=0)
    p.add_argument("--ttc-index", type=int, default=0)
    p.add_argument("--bold", type=int, default=0)
    p.add_argument("--stroke", type=int, default=0, help="TTF 描边加粗像素（0=原样，1=笔画更粗）")
    p.add_argument("--outline-width", type=int, default=None,
                   help="黑色描边宽度；默认 24px=2、12px=0（与原字库一致）")
    p.add_argument("--all", action="store_true", help="重画所有可寻址字形，统一成该 TTF 风格")
    p.add_argument("--no-outline", action="store_true", help="不生成 65..128 的黑色描边")
    p.set_defaults(func=cmd_patch)

    p = sub.add_parser("patch-all", help="同时 patch MAINFONT.FNT 与 SYSTEMFONT.FNT")
    p.add_argument("dir", help="包含两个 FNT 的目录")
    p.add_argument("--map", help="默认使用 subs_cn_jp.json")
    p.add_argument("--ttf", required=True)
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--size", type=int)
    p.add_argument("--px", type=int, help="统一的 TTF 像素大小")
    p.add_argument("--px-main", type=int, help="24px 字体用的像素大小")
    p.add_argument("--px-sys", type=int, help="12px 字体用的像素大小")
    p.add_argument("--xoff", type=int, default=0)
    p.add_argument("--yoff", type=int, default=0)
    p.add_argument("--ttc-index", type=int, default=0)
    p.add_argument("--bold", type=int, default=0)
    p.add_argument("--stroke", type=int, default=0, help="TTF 描边加粗像素（0=原样）")
    p.add_argument("--outline-width", type=int, default=None,
                   help="黑色描边宽度；默认 24px=2、12px=0")
    p.add_argument("--all", action="store_true", help="两个字体所有可寻址字形全部重画")
    p.add_argument("--no-outline", action="store_true", help="不生成黑色描边")
    p.set_defaults(func=cmd_patch_all)

    p = sub.add_parser("check-map", help="检查 subs_cn_jp.json 的目标槽是否可用")
    p.add_argument("fnt")
    p.add_argument("--map", help="默认使用 subs_cn_jp.json")
    p.add_argument("--size", type=int)
    p.set_defaults(func=cmd_check_map)

    p = sub.add_parser("copy", help="把源字体的某个字形复制到目标字体槽")
    p.add_argument("src")
    p.add_argument("src_char")
    p.add_argument("dst")
    p.add_argument("dst_char")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--src-size", type=int)
    p.add_argument("--dst-size", type=int)
    p.set_defaults(func=cmd_copy)

    p = sub.add_parser("verify", help="检查字体与映射")
    p.add_argument("fnt")
    p.add_argument("--size", type=int)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("lookup", help="查询字符的字形下标/是否空白")
    p.add_argument("fnt")
    p.add_argument("text")
    p.add_argument("--size", type=int)
    p.set_defaults(func=cmd_lookup)

    p = sub.add_parser("freeslots", help="列出没有 CP932 字符占用的槽位")
    p.add_argument("fnt")
    p.add_argument("-o", "--output")
    p.add_argument("--size", type=int)
    p.set_defaults(func=cmd_freeslots)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (FntError, FileNotFoundError) as e:
        print("错误: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
