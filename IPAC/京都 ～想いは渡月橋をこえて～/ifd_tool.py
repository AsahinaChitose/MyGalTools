#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ifd_tool.py -- IEF24M.IFD 字体文件的解析与 GBK 排版生成

文件结构（由 kyoto.exe 的 sub_406640 / sub_406740 逆向确认）
------------------------------------------------------------
    0x0000            u16 字号（24）
    0x0002            16384 x u16  SJIS -> 字形序号表（0xFFFF=缺字，原版用）
                      （打 GBK 补丁后这张表不再被读取，仅原样保留）
    0x8002            u32 位图宽 width  = 768  （32 列 x 24px）
    0x8006            u32 位图高 height = 行数 x 24
    0x800A            u32 bpp = 8
    ...               调色板等，像素数据在 0x8002+1044 处
    像素              8bpp，逐行存储；第 0~3 行留给 ASCII（12x24，每行 64 字），
                      双字节字模从第 4 行开始，按 32 列排布
                      字模 (row, col) 偏移 = 1044 + 24*col + width*24*(row+4)

GBK 排版
--------
打上 GBK 补丁的 exe 直接用 GBK 序号当字形序号：

    idx = 190*(lead-0x81) + (trail-0x40) - (trail>0x7F)    0 <= idx < 23940

所以本工具把 23940 个 GBK 槽位从第 4 行开始依次排好；ASCII 用的前 4 行
从原字体原样拷贝。任意 TTF/TTC 都可以用来生成（默认 simhei.ttf）。

字号与阈值
----------
原版日文字模的墨迹约 19x19（24x24 格），所以默认 --size 20。
引擎只把“非 0 字节”当笔画、再自己生成抗锯齿，所以默认 --threshold 96
把 TTF 渲染出的浅抗锯齿外圈去掉；保留外圈（--threshold 0）会明显变粗。

用法
----
    python ifd_tool.py info  ../data/IEF24M.ifd
    python ifd_tool.py build ../data/IEF24M.ifd -o IEF24M_gbk.ifd --ttf simhei.ttf
    python ifd_tool.py build ../data/IEF24M.ifd -o out.ifd --ttf msyh.ttc --index 0 --size 22 --threshold 96
    python ifd_tool.py dump  IEF24M_gbk.ifd 中
    python ifd_tool.py fonts            # 列出本机可用的中文字体
"""

import argparse
import os
import shutil
import struct
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))

MAP_BYTES = 0x8002          # 字号 + SJIS 映射表
BMP_HDR = 1044              # 宽/高/bpp/调色板 到像素数据的距离
GLYPH = 24                  # 字模边长
COLS = 32                   # 每行字数
RESERVED_ROWS = 4           # 0~3 行留给 ASCII
WIDTH = COLS * GLYPH        # 768
GLYPH_COUNT = 23940         # 126 前导 x 190 尾字节
DEFAULT_SIZE = 22           # 默认字号：22px 时墨迹约 20x20，逗号等标点也不会退化成点
DEFAULT_THRESHOLD = 96      # 灰度阈值：去掉抗锯齿外圈，否则引擎会把外圈也当成实心笔画

FONT_CANDIDATES = ["simhei.ttf", "simsun.ttc", "msyh.ttc",
                   "simkai.ttf", "simfang.ttf", "Deng.ttf"]


# ---------------------------------------------------------------------------
# GBK 序号
# ---------------------------------------------------------------------------
def inv_index(idx):
    """GBK 序号 -> 双字节码。"""
    if not 0 <= idx < GLYPH_COUNT:
        return None
    lead = 0x81 + idx // 190
    rem = idx % 190
    trail = 0x40 + rem if rem < 63 else 0x41 + rem
    return (lead << 8) | trail


def index_of(code):
    """双字节码 -> GBK 序号；非法返回 None。"""
    lead, trail = code >> 8, code & 0xFF
    if lead < 0x81 or lead > 0xFE or trail < 0x40 or trail == 0x7F or trail > 0xFE:
        return None
    return 190 * (lead - 0x81) + (trail - 0x40) - (1 if trail > 0x7F else 0)


def need_height():
    return (RESERVED_ROWS + (GLYPH_COUNT + COLS - 1) // COLS) * GLYPH


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def _load(path):
    if not os.path.exists(path):
        raise SystemExit("找不到字体：%s" % path)
    d = open(path, "rb").read()
    if len(d) < MAP_BYTES + BMP_HDR:
        raise SystemExit("不是 IEF 字体（文件太小）：%s" % path)
    return d


def read_info(path):
    d = _load(path)
    w, h, bpp = struct.unpack_from("<III", d, MAP_BYTES)
    return {
        "path": path,
        "size": len(d),
        "glyph": struct.unpack_from("<H", d, 0)[0],
        "width": w,
        "height": h,
        "bpp": bpp,
        "rows": h // GLYPH,
        "pixels": MAP_BYTES + BMP_HDR,
        "gbk_ready": h >= need_height(),
    }


def glyph_pixels(d, idx):
    """取第 idx 个双字节字模（24 行 x 24 字节）。"""
    base = MAP_BYTES + BMP_HDR
    row, col = divmod(idx, COLS)
    off = base + GLYPH * col + WIDTH * GLYPH * (row + RESERVED_ROWS)
    return [d[off + r * WIDTH: off + r * WIDTH + GLYPH] for r in range(GLYPH)]


# ---------------------------------------------------------------------------
# 字体定位
# ---------------------------------------------------------------------------
def font_search_dirs():
    dirs = [HERE, os.getcwd()]
    win = os.environ.get("WINDIR", r"C:\Windows")
    dirs.append(os.path.join(win, "Fonts"))
    return dirs


def find_ttf(name=None):
    """按名字（或默认 simhei.ttf）在脚本目录/当前目录/系统字体目录里找。"""
    if name:
        if os.path.exists(name):
            return name
        for d in font_search_dirs():
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
        return None
    for name in FONT_CANDIDATES:
        for d in font_search_dirs():
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    return None


def list_fonts():
    seen = []
    for d in font_search_dirs():
        for name in FONT_CANDIDATES:
            p = os.path.join(d, name)
            if os.path.exists(p) and p not in seen:
                seen.append(p)
    return seen


# ---------------------------------------------------------------------------
# 生成
# ---------------------------------------------------------------------------
def build(src_path, out_path, ttf_path, size=DEFAULT_SIZE, index=0, dx=1, dy=1,
          threshold=DEFAULT_THRESHOLD, quiet=False):
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        raise SystemExit("需要 Pillow 才能生成字体（pip install pillow）")

    src = _load(src_path)
    w, h, bpp = struct.unpack_from("<III", src, MAP_BYTES)
    if w != WIDTH or bpp != 8:
        raise SystemExit("源字体几何不符：width=%d bpp=%d（需要 %d / 8）" % (w, bpp, WIDTH))

    bmp_hdr = bytearray(src[MAP_BYTES:MAP_BYTES + BMP_HDR])
    old_pix = src[MAP_BYTES + BMP_HDR:]
    reserved = old_pix[:RESERVED_ROWS * GLYPH * WIDTH]

    rows = RESERVED_ROWS + (GLYPH_COUNT + COLS - 1) // COLS
    new_h = rows * GLYPH
    pixels = bytearray(new_h * WIDTH)
    pixels[:len(reserved)] = reserved
    struct.pack_into("<II", bmp_hdr, 0, WIDTH, new_h)

    py_size = int(size) if size else GLYPH
    try:
        font = ImageFont.truetype(ttf_path, py_size, index=index)
    except OSError as exc:
        raise SystemExit("加载字体失败：%s (%s)" % (ttf_path, exc))

    cell = Image.new("L", (GLYPH, GLYPH), 0)
    draw = ImageDraw.Draw(cell)
    made = 0
    for idx in range(GLYPH_COUNT):
        code = inv_index(idx)
        ch = None
        try:
            ch = bytes([code >> 8, code & 0xFF]).decode("gbk")
        except (UnicodeDecodeError, ValueError):
            pass
        draw.rectangle([0, 0, GLYPH - 1, GLYPH - 1], fill=0)
        if ch is not None:
            try:
                draw.text((dx, dy), ch, font=font, fill=255)
                made += 1
            except Exception:
                pass
        row, col = divmod(idx, COLS)
        y = (row + RESERVED_ROWS) * GLYPH
        x = col * GLYPH
        rows_bytes = cell.tobytes()
        if threshold:
            rows_bytes = bytes(255 if v >= threshold else 0 for v in rows_bytes)
        for r in range(GLYPH):
            o = (y + r) * WIDTH + x
            pixels[o:o + GLYPH] = rows_bytes[r * GLYPH:(r + 1) * GLYPH]

    out = bytearray()
    out += src[:MAP_BYTES]
    out += bmp_hdr
    out += pixels

    if os.path.exists(out_path) and not os.path.exists(out_path + ".bak"):
        shutil.copyfile(out_path, out_path + ".bak")
        if not quiet:
            print("  已备份 -> %s.bak" % out_path)
    tmp = out_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.replace(tmp, out_path)

    if not quiet:
        print("  输出   : %s (%s 字节)" % (out_path, format(len(out), ",")))
        print("  源字体 : %s (%dpx, ttc index %d, offset %d,%d)"
              % (ttf_path, py_size, index, dx, dy))
        print("  尺寸   : %dx%d 8bpp  %d 行（0~3 行保留 ASCII）" % (WIDTH, new_h, rows))
        print("  可解码 : %d / %d" % (made, GLYPH_COUNT))
    return True


# ---------------------------------------------------------------------------
# 命令
# ---------------------------------------------------------------------------
def cmd_info(args):
    info = read_info(args.ifd)
    print(info["path"])
    print("  字号      %d" % info["glyph"])
    print("  位图      %dx%d  %dbpp" % (info["width"], info["height"], info["bpp"]))
    print("  行数      %d（每行 %d 字）" % (info["rows"], COLS))
    print("  文件大小  %s" % format(info["size"], ","))
    print("  GBK 就绪  %s（需要高度 %d，当前 %d）"
          % ("是" if info["gbk_ready"] else "否", need_height(), info["height"]))
    return 0


def cmd_build(args):
    ttf = find_ttf(args.ttf)
    if not ttf:
        print("找不到字体 %r，可用 --ttf 指定，或先运行 `python ifd_tool.py fonts` 查看本机字体"
              % (args.ttf or "simhei.ttf"))
        return 1
    print("[i] 生成 GBK 字体")
    print("  源     : %s" % args.src)
    build(args.src, args.out, ttf, size=args.size, index=args.index,
          dx=args.dx, dy=args.dy, threshold=args.threshold)
    return 0


def cmd_dump(args):
    info = read_info(args.ifd)
    ch = args.char
    if len(ch) != 1:
        print("请给一个字符")
        return 1
    try:
        b = ch.encode("gbk")
    except UnicodeEncodeError:
        print("%r 无法用 GBK 编码" % ch)
        return 1
    if len(b) != 2:
        print("%r 不是双字节 GBK 字" % ch)
        return 1
    code = (b[0] << 8) | b[1]
    idx = index_of(code)
    print("%r  GBK=%02X%02X  序号=%d  (row %d, col %d)"
          % (ch, b[0], b[1], idx, idx // COLS + RESERVED_ROWS, idx % COLS))
    for line in glyph_pixels(open(args.ifd, "rb").read(), idx):
        print("  " + "".join("#" if v > 127 else ("+" if v else ".") for v in line))
    return 0


def cmd_fonts(args):
    found = list_fonts()
    if not found:
        print("没有找到常见中文字体")
        return 1
    for p in found:
        print("%-58s %s" % (p, format(os.path.getsize(p), ",")))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="IEF24M.IFD 字体解析 / GBK 排版生成")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="查看字体结构")
    p.add_argument("ifd")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("build", help="按 GBK 序号重新排版（可换任意字体）")
    p.add_argument("src", help="原始 .ifd（提供 ASCII 行与头部）")
    p.add_argument("-o", "--out", required=True, help="输出 .ifd")
    p.add_argument("--ttf", default=None, help="TTF/TTC 路径或文件名（默认 simhei.ttf）")
    p.add_argument("--index", type=int, default=0, help="TTC 内的字体序号")
    p.add_argument("--size", type=int, default=DEFAULT_SIZE, help="字号（默认 20，与原版 19px 墨迹接近）")
    p.add_argument("--dx", type=int, default=1, help="绘制横向偏移（默认 1）")
    p.add_argument("--dy", type=int, default=1, help="绘制纵向偏移（默认 1）")
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                   help="灰度阈值（默认 96；0 = 保留抗锯齿，笔画会明显变粗）")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("dump", help="打印某个字的 24x24 字模")
    p.add_argument("ifd")
    p.add_argument("char")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("fonts", help="列出本机可用中文字体")
    p.set_defaults(func=cmd_fonts)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
