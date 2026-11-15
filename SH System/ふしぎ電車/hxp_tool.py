#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hxp_tool.py -- HIMAURI(SH System) HXP 封包/解包工具

格式（逆向自 FUSHIGI.EXE / HimEngine.exe，IDA Pro 9.1）

  通用块结构:  u32 comp_size, u32 orig_size, 数据
               comp_size == 0 -> 数据原样存放(未压缩)
               comp_size != 0 -> LZSS 变体压缩流

  Him5  (命名封包, 本作 FD_001.HXP 文本):
    "Him5", u32 bucket_count,
    bucket_count * (u32 block_size, u32 block_offset)
    每个 block: 若干记录 [u8 记录长度][u32 BE 数据偏移][ASCII 名字\0] 末尾 0x00
    桶号 = him_hash(name) % bucket_count; 桶内按名字字节序升序

  Him4  (编号封包, 本作 FD_002.HXP 图片):
    "Him4", u32 count, u32 offset[count]
    数据区从 8+4*count 开始顺序排列

LZSS 解码规则（对应 sub_406870）:
  0x00-0x1C  文字列, 长度 = code+1
  0x1D       文字列, 长度 = next8+30
  0x1E       文字列, 长度 = BE16+286
  0x1F       文字列, 长度 = BE32
  0x20-0x3F  匹配 dist=(c>>2)&7, len=(c&3)+3
  0x40-0x5F  匹配 dist=next8,     len=(c&0x1F)+7
  0x60-0x7F  匹配 dist=((c&0x1F)<<8)|next8, len 按后续字节:
              v<254 -> v+7 ; v==254 -> BE16+261 ; v==255 -> BE32+3
  0x80-0xFF  匹配 dist=((c&0x1F)<<8)|next8, len=((c>>5)&3)+3
  实际回退距离 = dist+1 (窗口 8192), 允许重叠复制
"""

import argparse
import array
import hashlib
import json
import os
import struct
import sys
import zlib

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8')
    except Exception:
        pass

MAGIC_V4 = b'Him4'
MAGIC_V5 = b'Him5'
WINDOW = 8192
MAX_MATCH = 258           # 0x60 形式 v<254 时可编码到 260
CHAIN_LIMIT = 64


# --------------------------------------------------------------------------
# LZSS
# --------------------------------------------------------------------------
def lzss_decompress(src, out_len):
    """按 sub_406870 的语义解压。"""
    out = bytearray()
    n = len(src)
    i = 0

    def need(k):
        if i + k > n:
            raise ValueError('压缩流在 0x%X 处截断(需要 %d 字节)' % (i, k))

    while len(out) < out_len:
        need(1)
        c = src[i]
        i += 1

        if c < 0x1D:
            ln = c + 1
            need(ln)
            out += src[i:i + ln]
            i += ln
            continue
        if c < 0x20:
            if c == 0x1D:
                need(1)
                ln = src[i] + 30
                i += 1
            elif c == 0x1E:
                need(2)
                ln = ((src[i] << 8) | src[i + 1]) + 286
                i += 2
            else:
                need(4)
                ln = int.from_bytes(src[i:i + 4], 'big')
                i += 4
            need(ln)
            out += src[i:i + ln]
            i += ln
            continue

        if c < 0x40:
            dist = (c >> 2) & 7
            ln = (c & 3) + 3
        elif c < 0x60:
            need(1)
            dist = src[i]
            i += 1
            ln = (c & 0x1F) + 7
        elif c < 0x80:
            need(2)
            dist = ((c & 0x1F) << 8) | src[i]
            v = src[i + 1]
            i += 2
            if v < 254:
                ln = v + 7
            elif v == 254:
                need(2)
                ln = ((src[i] << 8) | src[i + 1]) + 261
                i += 2
            else:
                need(4)
                ln = int.from_bytes(src[i:i + 4], 'big') + 3
                i += 4
        else:
            need(1)
            dist = ((c & 0x1F) << 8) | src[i]
            i += 1
            ln = ((c >> 5) & 3) + 3

        pos = len(out) - dist - 1
        if pos < 0:
            raise ValueError('非法回退距离 %d (输出位置 %d)' % (dist, len(out)))
        if pos + ln <= len(out):
            out += out[pos:pos + ln]
        else:
            for _ in range(ln):
                out.append(out[pos])
                pos += 1

    if len(out) != out_len:
        raise ValueError('解压长度不符: %d != %d' % (len(out), out_len))
    return bytes(out)


def _emit_literals(out, data, start, end):
    while start < end:
        ln = end - start
        if ln <= 29:
            out.append(ln - 1)
        elif ln <= 285:
            out.append(0x1D)
            out.append(ln - 30)
        elif ln <= 65821:
            out.append(0x1E)
            out += struct.pack('>H', ln - 286)
        else:
            ln = 65822
            out.append(0x1F)
            out += struct.pack('>I', ln)
        out += data[start:start + ln]
        start += ln


def _emit_match(out, ln, dist):
    if ln <= 6 and dist <= 7:
        out.append(0x20 | (dist << 2) | (ln - 3))
    elif ln <= 6:
        out.append(0x80 | ((ln - 3) << 5) | (dist >> 8))
        out.append(dist & 0xFF)
    elif dist <= 255 and ln <= 38:
        out.append(0x40 | (ln - 7))
        out.append(dist)
    else:
        out.append(0x60 | (dist >> 8))
        out.append(dist & 0xFF)
        v = ln - 7
        if v < 254:
            out.append(v)
        elif v <= 65535 + 254:
            out.append(254)
            out += struct.pack('>H', v - 254)
        else:
            out.append(255)
            out += struct.pack('>I', ln - 3)


def lzss_compress(data):
    """贪心最长匹配 LZSS 压缩, 输出可被引擎 sub_406870 解压。"""
    n = len(data)
    out = bytearray()
    if n == 0:
        return bytes(out)

    prev = array.array('i', [-1]) * n
    head = {}
    i = 0
    lit_start = 0

    def insert(p):
        if p + 2 < n:
            key = (data[p] << 16) | (data[p + 1] << 8) | data[p + 2]
            prev[p] = head.get(key, -1)
            head[key] = p

    while i < n:
        maxl = min(MAX_MATCH, n - i)
        best_len = 0
        best_dist = 0
        if maxl >= 3:
            key = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
            cand = head.get(key, -1)
            limit = i - WINDOW
            chain = 0
            while cand >= 0 and cand >= limit and chain < CHAIN_LIMIT:
                if data[cand + best_len] == data[i + best_len]:
                    l = 3
                    while l < maxl and data[cand + l] == data[i + l]:
                        l += 1
                    if l > best_len:
                        best_len = l
                        best_dist = i - cand - 1
                        if l == maxl:
                            break
                cand = prev[cand]
                chain += 1

        if best_len >= 3:
            if i > lit_start:
                _emit_literals(out, data, lit_start, i)
            _emit_match(out, best_len, best_dist)
            end = i + best_len
            for j in range(i, min(end, n)):
                insert(j)
            i = end
            lit_start = i
        else:
            insert(i)
            i += 1

    if lit_start < n:
        _emit_literals(out, data, lit_start, n)
    return bytes(out)


# --------------------------------------------------------------------------
# 名字哈希 (sub_407050)
# --------------------------------------------------------------------------
def him_hash(name):
    """sub_407050: 名字哈希, 用于 Him5 桶号 = him_hash(name) % bucket_count。"""
    if isinstance(name, str):
        name = name.encode('latin-1')
    v = 0
    i = 1
    for b in name:
        c = b if b < 128 else b - 256
        v = (v ^ (i * c)) & 0xFFFFFFFF
        i += 499
    return (v ^ (v >> 11)) & 0xFFFFFFFF


# --------------------------------------------------------------------------
# 封包读写
# --------------------------------------------------------------------------
def parse_him5(data):
    if data[:4] != MAGIC_V5:
        raise ValueError('不是 Him5 封包')
    bucket_count = struct.unpack_from('<I', data, 4)[0]
    table = []
    for i in range(bucket_count):
        size, off = struct.unpack_from('<II', data, 8 + i * 8)
        table.append((size, off))
    entries = []       # 按数据偏移顺序
    buckets = []       # 每个桶的名字, 顺序同表
    for size, off in table:
        block = data[off:off + size]
        names = []
        p = 0
        while p < len(block) and block[p] != 0:
            rl = block[p]
            eoff = int.from_bytes(block[p + 1:p + 5], 'big')
            name = block[p + 5:p + rl].split(b'\0')[0].decode('latin-1')
            names.append((name, eoff))
            p += rl
        buckets.append(names)
        entries.extend(names)
    entries.sort(key=lambda x: x[1])
    info = []
    for name, off in entries:
        comp, orig = struct.unpack_from('<II', data, off)
        info.append((name, off, comp, orig))
    payloads = {}
    for name, off, comp, orig, in info:
        blob = data[off + 8:off + 8 + comp]
        payloads[name] = (lzss_decompress(blob, orig) if comp else data[off + 8:off + 8 + orig])
    return bucket_count, buckets, info, payloads


def parse_him4(data):
    if data[:4] != MAGIC_V4:
        raise ValueError('不是 Him4 封包')
    count = struct.unpack_from('<I', data, 4)[0]
    offs = [struct.unpack_from('<I', data, 8 + i * 4)[0] for i in range(count)]
    info = []
    payloads = []
    for i, off in enumerate(offs):
        comp, orig = struct.unpack_from('<II', data, off)
        blob = data[off + 8:off + 8 + comp]
        payloads.append(lzss_decompress(blob, orig) if comp else data[off + 8:off + 8 + orig])
        info.append((i, off, comp, orig))
    return count, info, payloads


# --------------------------------------------------------------------------
# 解包
# --------------------------------------------------------------------------
def sniff_ext(payload):
    if payload[:8] == b'Himauri\0':
        return '.hst'
    if payload[:2] == b'BM':
        return '.bmp'
    if payload[:2] == b'\xff\xd8':
        return '.jpg'
    if (len(payload) >= 18 and payload[1] == 0 and payload[2] in (1, 2, 3, 9, 10, 11)
            and payload[16] in (8, 15, 16, 24, 32)):
        return '.tga'
    if b'TRUEVISION-XFILE.' in payload[-32:]:
        return '.tga'
    if b'\x00' not in payload and b'\n' in payload and len(payload) < 1 << 16:
        return '.txt'
    if payload and all(9 <= b < 127 or b in (10, 13) for b in payload[:128]):
        return '.txt'
    return '.bin'


def _img_size(payload, ext):
    try:
        if ext == '.tga':
            return struct.unpack_from('<HH', payload, 12)
        if ext == '.bmp':
            w, h = struct.unpack_from('<ii', payload, 18)
            return w, abs(h)
    except Exception:
        pass
    return None


def cmd_unpack(args):
    data = open(args.archive, 'rb').read()
    outdir = args.out or os.path.splitext(os.path.basename(args.archive))[0] + '_unpacked'
    os.makedirs(outdir, exist_ok=True)
    magic = data[:4]
    manifest = {'source': os.path.abspath(args.archive),
                'size': len(data),
                'sha256': hashlib.sha256(data).hexdigest(),
                'entries': []}

    if magic == MAGIC_V5:
        bucket_count, buckets, info, payloads = parse_him5(data)
        manifest['format'] = 'him5'
        manifest['bucket_count'] = bucket_count
        for idx, (name, off, comp, orig) in enumerate(info):
            payload = payloads[name]
            fn = name + '.hst'
            with open(os.path.join(outdir, fn), 'wb') as f:
                f.write(payload)
            manifest['entries'].append({
                'order': idx, 'name': name, 'file': fn, 'offset': off,
                'comp_size': comp, 'orig_size': orig,
                'crc32': zlib.crc32(payload) & 0xFFFFFFFF,
                'sha256': hashlib.sha256(payload).hexdigest()[:16],
            })
    elif magic == MAGIC_V4:
        count, info, payloads = parse_him4(data)
        manifest['format'] = 'him4'
        manifest['count'] = count
        for idx, (i, off, comp, orig) in enumerate(info):
            payload = payloads[i]
            ext = sniff_ext(payload)
            wh = _img_size(payload, ext) if ext in ('.tga', '.bmp', '.jpg') else None
            if wh:
                fn = '%04d_%dx%d%s' % (i, wh[0], wh[1], ext)
            else:
                fn = '%04d%s' % (i, ext)
            with open(os.path.join(outdir, fn), 'wb') as f:
                f.write(payload)
            manifest['entries'].append({
                'order': idx, 'index': i, 'file': fn, 'offset': off,
                'comp_size': comp, 'orig_size': orig,
                'crc32': zlib.crc32(payload) & 0xFFFFFFFF,
                'sha256': hashlib.sha256(payload).hexdigest()[:16],
            })
    else:
        raise SystemExit('未知封包头: %r' % magic)

    with open(os.path.join(outdir, 'manifest.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=1, ensure_ascii=False)

    total = sum(e['orig_size'] for e in manifest['entries'])
    print('[+] %s -> %s' % (args.archive, outdir))
    print('    格式 %s, 条目 %d, 解压后 %s / 封包 %s (%.1f%%)' % (
        manifest['format'], len(manifest['entries']), _sz(total), _sz(len(data)),
        100.0 * len(data) / max(1, total)))
    return 0


def _sz(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return '%.1f%s' % (n, unit) if unit != 'B' else '%dB' % n
        n /= 1024.0


# --------------------------------------------------------------------------
# 封包
# --------------------------------------------------------------------------
def _load_manifest(d):
    with open(os.path.join(d, 'manifest.json'), encoding='utf-8') as f:
        return json.load(f)


def cmd_pack(args):
    d = args.directory
    man = _load_manifest(d)
    fmt = man['format']
    entries = man['entries']
    payloads = []
    for e in entries:
        with open(os.path.join(d, e['file']), 'rb') as f:
            payloads.append(f.read())
    if len(payloads) != len(entries):
        raise SystemExit('条目数不符')

    original = None
    if args.reuse:
        if not os.path.exists(args.reuse):
            raise SystemExit('reuse 源不存在: %s' % args.reuse)
        original = open(args.reuse, 'rb').read()

    reuse_map = {}
    if original is not None:
        if fmt == 'him5' and original[:4] == MAGIC_V5:
            _, _, oinfo, opay = parse_him5(original)
            for (name, off, comp, orig) in oinfo:
                reuse_map[('him5', name)] = (original[off:off + 8 + comp], hashlib.sha256(opay[name]).hexdigest())
        elif fmt == 'him4' and original[:4] == MAGIC_V4:
            _, oinfo, opay = parse_him4(original)
            for (i, off, comp, orig) in oinfo:
                reuse_map[('him4', i)] = (original[off:off + 8 + comp], hashlib.sha256(opay[i]).hexdigest())

    blobs = []
    recomp = 0
    for idx, e in enumerate(entries):
        payload = payloads[idx]
        key = ('him5', e['name']) if fmt == 'him5' else ('him4', e['index'])
        hit = reuse_map.get(key)
        if hit and hit[1] == hashlib.sha256(payload).hexdigest():
            blobs.append(hit[0])
            continue
        comp = lzss_compress(payload)
        if len(comp) >= len(payload):
            blobs.append(struct.pack('<II', 0, len(payload)) + payload)
        else:
            blobs.append(struct.pack('<II', len(comp), len(payload)) + comp)
        recomp += 1

    if fmt == 'him5':
        out = _build_him5(man, entries, blobs)
    else:
        out = _build_him4(entries, blobs)

    target = args.out or (os.path.splitext(os.path.basename(man['source']))[0] + '_repack.hxp')
    with open(target, 'wb') as f:
        f.write(out)
    print('[+] %s -> %s (%s, %d 条目, 重新压缩 %d 条)' % (d, target, _sz(len(out)), len(blobs), recomp))
    return 0


def _build_him4(entries, blobs):
    count = len(blobs)
    header_len = 8 + 4 * count
    offs = []
    body = bytearray()
    cur = header_len
    for b in blobs:
        offs.append(cur)
        body += b
        cur += len(b)
    out = bytearray(MAGIC_V4)
    out += struct.pack('<I', count)
    for o in offs:
        out += struct.pack('<I', o)
    out += body
    return bytes(out)


def _build_him5(man, entries, blobs):
    bucket_count = man.get('bucket_count') or max(1, min(64, (len(entries) + 4) // 5))
    names = [e['name'] for e in entries]
    buckets = [[] for _ in range(bucket_count)]
    for i, nm in enumerate(names):
        buckets[him_hash(nm) % bucket_count].append(i)
    for b in buckets:
        b.sort(key=lambda i: names[i].encode('latin-1'))

    # 目录块长度与偏移无关, 先算块大小, 再算数据区起点
    bucket_bytes = []
    for b in buckets:
        size = 0
        for i in b:
            size += 5 + len(names[i].encode('latin-1')) + 1
        bucket_bytes.append(size + 1)  # 末尾 0x00

    order = sorted(range(len(entries)), key=lambda i: entries[i].get('order', i))
    cur = 8 + 8 * bucket_count + sum(bucket_bytes)
    data_offsets = {}
    body = bytearray()
    for i in order:
        data_offsets[i] = cur
        body += blobs[i]
        cur += len(blobs[i])

    blocks = []
    for b in buckets:
        blk = bytearray()
        for i in b:
            nm = names[i].encode('latin-1')
            rl = 5 + len(nm) + 1
            if rl > 255:
                raise SystemExit('名字过长: %s' % names[i])
            blk.append(rl)
            blk += struct.pack('>I', data_offsets[i])
            blk += nm + b'\0'
        blk.append(0)
        blocks.append(bytes(blk))
        assert len(blk) == bucket_bytes[len(blocks) - 1]

    out = bytearray(MAGIC_V5)
    out += struct.pack('<I', bucket_count)
    off = 8 + 8 * bucket_count
    for blk in blocks:
        out += struct.pack('<II', len(blk), off)
        off += len(blk)
    if off != 8 + 8 * bucket_count + sum(len(b) for b in blocks):
        raise SystemExit('布局错误')
    out += b''.join(blocks)
    out += body
    return bytes(out)


# --------------------------------------------------------------------------
# info / verify
# --------------------------------------------------------------------------
def cmd_info(args):
    data = open(args.archive, 'rb').read()
    magic = data[:4]
    if magic == MAGIC_V5:
        bucket_count, buckets, info, payloads = parse_him5(data)
        print('%s: Him5 (命名封包)' % args.archive)
        print('  桶数 %d, 条目 %d, 文件 %d 字节' % (bucket_count, len(info), len(data)))
        comp = sum(i[2] for i in info)
        orig = sum(i[3] for i in info)
        print('  压缩 %d -> %d (%.1f%%)' % (comp, orig, 100.0 * comp / max(1, orig)))
        for name, off, c, o in info[:5]:
            print('    %-10s off=0x%06X comp=%6d orig=%6d' % (name, off, c, o))
    elif magic == MAGIC_V4:
        count, info, payloads = parse_him4(data)
        print('%s: Him4 (编号封包)' % args.archive)
        print('  条目 %d, 文件 %d 字节' % (count, len(data)))
        comp = sum(i[2] for i in info)
        orig = sum(i[3] for i in info)
        print('  压缩 %d -> %d (%.1f%%)' % (comp, orig, 100.0 * comp / max(1, orig)))
    else:
        raise SystemExit('未知封包头 %r' % magic)
    return 0


def cmd_verify(args):
    """解包->重打包->再解包, 校验内容一致; 可选 --original 比对字节。"""
    import tempfile
    data = open(args.archive, 'rb').read()
    tmp = tempfile.mkdtemp(prefix='hxp_verify_')
    a = argparse.Namespace(archive=args.archive, out=os.path.join(tmp, 'unpack'))
    cmd_unpack(a)
    man = _load_manifest(a.out)

    repack = os.path.join(tmp, 'repack.hxp')
    rc = cmd_pack(argparse.Namespace(directory=a.out, out=repack, reuse=None))
    b = argparse.Namespace(archive=repack, out=os.path.join(tmp, 'unpack2'))
    cmd_unpack(b)

    man2 = _load_manifest(b.out)
    ok = True
    m1 = {e['file']: e for e in man['entries']}
    m2 = {e['file']: e for e in man2['entries']}
    if set(m1) != set(m2):
        print('[-] 文件集合不一致')
        ok = False
    for fn in sorted(m1):
        if fn not in m2:
            continue
        if m1[fn]['sha256'] != m2[fn]['sha256'] or m1[fn]['crc32'] != m2[fn]['crc32']:
            print('[-] 内容不一致: %s' % fn)
            ok = False
    print('[%s] 解包->压缩->解包 内容一致 (%d 条)' % ('OK' if ok else 'FAIL', len(m1)))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description='HIMAURI / SH System HXP 封包工具')
    sub = ap.add_subparsers(dest='cmd')

    p = sub.add_parser('info', help='查看封包信息')
    p.add_argument('archive')
    p.set_defaults(func=cmd_info)

    p = sub.add_parser('unpack', help='解包(自动解压)')
    p.add_argument('archive')
    p.add_argument('-o', '--out')
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser('pack', help='封包(自动压缩)')
    p.add_argument('directory')
    p.add_argument('-o', '--out')
    p.add_argument('--reuse', help='原始封包路径; 内容未变的条目直接复用原压缩流(可做到字节级一致)')
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser('verify', help='解包->封包->解包自检')
    p.add_argument('archive')
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    if not getattr(args, 'func', None):
        ap.print_help()
        return 1
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
