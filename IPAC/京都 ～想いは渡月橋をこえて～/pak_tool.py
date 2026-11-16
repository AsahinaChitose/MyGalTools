#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pak_tool.py -- IPAC (.pak) archive tool for the "Kyoto" engine (kyoto.exe).

Format (static-verified against kyoto.exe; loader @ 0x4074D0, LZSS decode @ 0x407350)
----------------------------------------------------------------------------------
Header (8 bytes):
    u32  magic       'IPAC'  (little-endian 0x43415049)  -> compared in exe
    u16  count       number of entries
    u16  version     archive version (all shipped paks use 2)

Table of contents (count * 24 bytes), immediately after the header:
    char name[16]     ASCII, NUL padded (game lookup is case-insensitive)
    u32  offset       absolute file offset of the payload
    u32  size         stored payload size in bytes

Payload:
    If payload[0:4] == b'IEL1' (0x314C4549):
        u32  raw_size     size after decompression
        ...  LZSS stream  (raw_size bytes once decoded)
    otherwise the payload is stored verbatim.

Compression: classic Okumura LZSS
    ring buffer 4096, initialised with 4078 spaces, max match 18, min match 3
    flag byte holds 8 token flags (LSB first):
        bit == 1 -> literal byte follows
        bit == 0 -> 2 bytes follow: offset low 8 bits,
                    then ((offset >> 4) & 0xF0) | (length - 3)
    Verified to reproduce the original compressed bytes bit-for-bit on every
    shipped archive (scr/chr/bg), so unpack -> pack is byte-identical.

Encryption: none.  There is no XOR/Camellia/etc. layer in this archive format.
Only the per-entry LZSS layer exists, and it is handled automatically.

Usage
-----
    python pak_tool.py list    <pak>
    python pak_tool.py unpack  <pak> [-o OUTDIR] [--no-manifest]
    python pak_tool.py pack    <DIR> -o <pak> [--store] [--jobs N]
    python pak_tool.py verify  <pak>

Examples
--------
    python pak_tool.py unpack scr.pak -o scr_unpacked
    python pak_tool.py pack   scr_unpacked -o scr_repack.pak
    python pak_tool.py verify bg.pak

Notes
-----
* The game looks for a loose file first (DATA\\SCR\\NAME.SCN, DATA\\CHR\\NAME.IES,
  DATA\\BG\\NAME.IES) and only falls back to the .pak, so a translation can also
  ship loose files without touching the archives.
* `pack` keeps the original entry order by reading `_pak_manifest.json`, written
  by `unpack`.  Without it, files are packed in sorted order.
"""
from __future__ import annotations

import argparse
import concurrent.futures as _fut
import hashlib
import json
import os
import struct
import sys

MAGIC = b"IPAC"
MAGIC_LE = 0x43415049
IEL1 = b"IEL1"
HEADER_SIZE = 8
ENTRY_SIZE = 24
NAME_SIZE = 16
MANIFEST = "_pak_manifest.json"

# --- LZSS parameters (must match kyoto.exe) --------------------------------
N = 4096
F = 18
THRESHOLD = 2
NIL = N

__all__ = [
    "PakError", "read_pak", "write_pak", "lzss_decompress", "lzss_compress",
    "load_dir", "main",
]


class PakError(Exception):
    pass


# --------------------------------------------------------------------------
# LZSS
# --------------------------------------------------------------------------
def lzss_decompress(src: bytes, raw_size: int) -> bytes:
    """Decode an LZSS stream exactly like kyoto.exe @ 0x407350."""
    buf = bytearray(4096)
    buf[:4078] = b" " * 4078          # memset(byte_41BE30, ' ', 4078)
    r = 4078                           # dword_413A18 write cursor
    i = 0
    flags = 0
    out = bytearray()
    n = len(src)
    append = out.append
    while len(out) < raw_size:
        flags >>= 1
        if flags & 0x100 == 0:
            if i >= n:
                raise PakError("LZSS stream truncated (flag byte)")
            flags = src[i] | 0xFF00
            i += 1
        if flags & 1:                  # literal
            if i >= n:
                raise PakError("LZSS stream truncated (literal)")
            c = src[i]
            i += 1
            append(c)
            buf[r] = c
            r = (r + 1) & 0xFFF
        else:                          # back-reference
            if i + 1 >= n:
                raise PakError("LZSS stream truncated (match)")
            b1 = src[i]
            b2 = src[i + 1]
            i += 2
            pos = ((b2 & 0xF0) << 4) | b1
            ln = (b2 & 0x0F) + 3
            for _ in range(ln):
                c = buf[pos & 0xFFF]
                pos += 1
                append(c)
                buf[r] = c
                r = (r + 1) & 0xFFF
    return bytes(out)


class _LZSSEncoder:
    """Okumura binary-tree LZSS encoder, byte-identical to the original tool."""

    __slots__ = ("tb", "lson", "rson", "dad", "mp", "ml")

    def __init__(self):
        self.tb = bytearray(N + F - 1)
        self.lson = [NIL] * (N + 1)
        self.rson = [NIL] * (N + 257)
        self.dad = [NIL] * (N + 1)
        self.mp = 0
        self.ml = 0

    def init_tree(self):
        rson = self.rson
        dad = self.dad
        for i in range(N + 1, N + 257):
            rson[i] = NIL
        for i in range(N):
            dad[i] = NIL

    def insert(self, r):
        tb = self.tb
        lson = self.lson
        rson = self.rson
        dad = self.dad
        cmp_ = 1
        p = N + 1 + tb[r]
        rson[r] = NIL
        lson[r] = NIL
        ml = 0
        while True:
            if cmp_ >= 0:
                q = rson[p]
                if q != NIL:
                    p = q
                else:
                    rson[p] = r
                    dad[r] = p
                    self.ml = ml
                    return
            else:
                q = lson[p]
                if q != NIL:
                    p = q
                else:
                    lson[p] = r
                    dad[r] = p
                    self.ml = ml
                    return
            i = 1
            while i < F:
                cmp_ = tb[r + i] - tb[p + i]
                if cmp_:
                    break
                i += 1
            if i > ml:
                self.mp = p
                ml = i
                if i >= F:
                    break
        self.ml = ml
        dad[r] = dad[p]
        lson[r] = lson[p]
        rson[r] = rson[p]
        dad[lson[p]] = r
        dad[rson[p]] = r
        if rson[dad[p]] == p:
            rson[dad[p]] = r
        else:
            lson[dad[p]] = r
        dad[p] = NIL

    def delete(self, p):
        dad = self.dad
        lson = self.lson
        rson = self.rson
        if dad[p] == NIL:
            return
        if rson[p] == NIL:
            q = lson[p]
        elif lson[p] == NIL:
            q = rson[p]
        else:
            q = lson[p]
            if rson[q] != NIL:
                while rson[q] != NIL:
                    q = rson[q]
                rson[dad[q]] = lson[q]
                dad[lson[q]] = dad[q]
                lson[q] = lson[p]
                dad[lson[p]] = q
            rson[q] = rson[p]
            dad[rson[p]] = q
        dad[q] = dad[p]
        if rson[dad[p]] == p:
            rson[dad[p]] = q
        else:
            lson[dad[p]] = q
        dad[p] = NIL


def lzss_compress(data: bytes) -> bytes:
    """Encode `data` into the exact stream kyoto.exe expects."""
    data = bytes(data)
    n = len(data)
    if n == 0:
        return b""
    e = _LZSSEncoder()
    tb = e.tb
    e.init_tree()
    out = bytearray()
    code = bytearray(17)
    code_ptr = 1
    mask = 1
    s = 0
    r = N - F
    for i in range(s, r):
        tb[i] = 0x20
    pos = 0
    look = 0
    while look < F and pos < n:
        tb[r + look] = data[pos]
        pos += 1
        look += 1
    for i in range(1, F + 1):
        e.insert(r - i)
    e.insert(r)
    while True:
        ml = e.ml
        if ml > look:
            ml = look
        if ml <= THRESHOLD:
            ml = 1
            code[code_ptr] = tb[r]
            code_ptr += 1
            code[0] |= mask
        else:
            mp = e.mp
            code[code_ptr] = mp & 0xFF
            code[code_ptr + 1] = ((mp >> 4) & 0xF0) | (ml - (THRESHOLD + 1))
            code_ptr += 2
        mask = (mask << 1) & 0xFF
        if mask == 0:
            out += code[:code_ptr]
            code[0] = 0
            code_ptr = 1
            mask = 1
        last = ml
        i = 0
        while i < last:
            if pos >= n:
                break
            c = data[pos]
            pos += 1
            e.delete(s)
            tb[s] = c
            if s < F - 1:
                tb[s + N] = c
            s = (s + 1) & (N - 1)
            r = (r + 1) & (N - 1)
            e.insert(r)
            i += 1
        while i < last:
            e.delete(s)
            s = (s + 1) & (N - 1)
            r = (r + 1) & (N - 1)
            i += 1
            look -= 1
            if look:
                e.insert(r)
        if look <= 0:
            break
    if code_ptr > 1:
        out += code[:code_ptr]
    return bytes(out)


# --------------------------------------------------------------------------
# archive layer
# --------------------------------------------------------------------------
def _decode_payload(blob: bytes) -> tuple[bytes, bool]:
    if len(blob) >= 8 and blob[:4] == IEL1:
        raw_size = struct.unpack_from("<I", blob, 4)[0]
        return lzss_decompress(blob[8:], raw_size), True
    return blob, False


def _encode_payload(raw: bytes, store: bool = False) -> bytes:
    if store:
        return raw
    return IEL1 + struct.pack("<I", len(raw)) + lzss_compress(raw)


def parse_pak(data: bytes, path: str = "<memory>") -> dict:
    """Parse an IPAC archive buffer and decompress every member."""
    if len(data) < HEADER_SIZE:
        raise PakError("%s: file too small" % path)
    if data[:4] != MAGIC:
        raise PakError("%s: bad magic %r (expected %r)" % (path, data[:4], MAGIC))
    count, version = struct.unpack_from("<HH", data, 4)
    if HEADER_SIZE + count * ENTRY_SIZE > len(data):
        raise PakError("%s: TOC (%d entries) exceeds file size" % (path, count))
    entries = []
    for idx in range(count):
        base = HEADER_SIZE + idx * ENTRY_SIZE
        name = data[base:base + NAME_SIZE].split(b"\0", 1)[0].decode("cp932", "replace")
        off, size = struct.unpack_from("<II", data, base + 16)
        if off + size > len(data):
            raise PakError("%s: entry %d (%s) out of bounds" % (path, idx, name))
        payload, compressed = _decode_payload(data[off:off + size])
        entries.append({
            "index": idx,
            "name": name,
            "offset": off,
            "size": size,
            "raw_size": len(payload),
            "compressed": compressed,
            "data": payload,
        })
    return {"path": path, "version": version, "count": count, "entries": entries, "size": len(data)}


def read_pak(path: str) -> dict:
    """Parse an IPAC archive on disk and decompress every member."""
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_pak(data, path)


def read_pak_bytes(data: bytes) -> dict:
    """Same as read_pak but from an in-memory buffer (used by verify)."""
    return parse_pak(data, "<memory>")


def _toc_name(name: str) -> bytes:
    blob = name.encode("ascii")
    if len(blob) > NAME_SIZE - 1:
        raise PakError("entry name too long (%d > %d): %s" % (len(blob), NAME_SIZE - 1, name))
    return blob + b"\0" * (NAME_SIZE - len(blob))


def build_pak(entries: list[tuple[str, bytes]], version: int = 2, store: bool = False) -> bytes:
    """entries: [(name, raw_bytes)] in TOC order."""
    if len(entries) > 0xFFFF:
        raise PakError("too many entries (%d)" % len(entries))
    out = bytearray()
    out += MAGIC + struct.pack("<HH", len(entries), version)
    offset = HEADER_SIZE + len(entries) * ENTRY_SIZE
    toc = bytearray()
    payloads = bytearray()
    for name, raw in entries:
        blob = _encode_payload(raw, store=store)
        toc += _toc_name(name) + struct.pack("<II", offset, len(blob))
        payloads += blob
        offset += len(blob)
    out += toc
    out += payloads
    return bytes(out)


def write_pak(path: str, entries: list[tuple[str, bytes]], version: int = 2, store: bool = False) -> int:
    blob = build_pak(entries, version=version, store=store)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(blob)
    os.replace(tmp, path)
    return len(blob)


# --------------------------------------------------------------------------
# directory helpers
# --------------------------------------------------------------------------
def _manifest_path(outdir: str) -> str:
    return os.path.join(outdir, MANIFEST)


def safe_name(name: str) -> str:
    """Reject or sanitise names that could escape the output directory."""
    name = name.replace("\\", "/").split("/")[-1] or "unnamed"
    for ch in '<>:"/\\|?*':
        name = name.replace(ch, "_")
    return name


def load_dir(dirname: str) -> tuple[list[tuple[str, bytes]], int, bool]:
    """Collect (name, bytes) from a directory, honouring _pak_manifest.json order."""
    manifest = None
    mpath = _manifest_path(dirname)
    if os.path.isfile(mpath):
        try:
            with open(mpath, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
        except (OSError, ValueError) as exc:
            print("warning: ignoring unreadable manifest: %s" % exc, file=sys.stderr)
    order = []
    version = 2
    if manifest:
        version = int(manifest.get("version", 2))
        order = [e.get("name") for e in manifest.get("entries", []) if e.get("name")]
    present = {}
    for fn in os.listdir(dirname):
        full = os.path.join(dirname, fn)
        if not os.path.isfile(full) or fn == MANIFEST:
            continue
        with open(full, "rb") as fh:
            present[fn] = fh.read()
    ordered = []
    used = set()
    for name in order:
        if name in present:
            ordered.append((name, present[name]))
            used.add(name)
    for name in sorted(set(present) - used):
        ordered.append((name, present[name]))
    order_ok = [n for n, _ in ordered] == order if order else False
    return ordered, version, order_ok


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_list(args) -> int:
    pak = read_pak(args.pak)
    print("%s: %d entries, version %d, %d bytes" %
          (pak["path"], pak["count"], pak["version"], pak["size"]))
    print("  %-3s %-16s %10s %10s %10s  %s" % ("#", "name", "offset", "stored", "raw", "ratio"))
    for e in pak["entries"]:
        ratio = ("%.2f" % (e["size"] / e["raw_size"])) if e["raw_size"] else "-"
        print("  %-3d %-16s %10d %10d %10d  %s%s" % (
            e["index"], e["name"], e["offset"], e["size"], e["raw_size"], ratio,
            "" if e["compressed"] else "  (raw)"))
    return 0


def cmd_unpack(args) -> int:
    pak = read_pak(args.pak)
    outdir = args.output or (os.path.splitext(os.path.basename(args.pak))[0] + "_unpacked")
    os.makedirs(outdir, exist_ok=True)
    meta = {"format": "IPAC", "version": pak["version"], "source": os.path.abspath(args.pak),
            "source_size": pak["size"], "entries": []}
    for e in pak["entries"]:
        fn = safe_name(e["name"])
        with open(os.path.join(outdir, fn), "wb") as fh:
            fh.write(e["data"])
        meta["entries"].append({
            "name": fn, "offset": e["offset"], "size": e["size"],
            "raw_size": e["raw_size"], "compressed": e["compressed"],
            "sha256": hashlib.sha256(e["data"]).hexdigest(),
        })
    if not args.no_manifest:
        with open(_manifest_path(outdir), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(meta, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    total_raw = sum(e["raw_size"] for e in pak["entries"])
    total_stored = sum(e["size"] for e in pak["entries"])
    print("unpacked %d entries -> %s" % (len(pak["entries"]), os.path.abspath(outdir)))
    print("  stored %d bytes, raw %d bytes" % (total_stored, total_raw))
    if args.verbose:
        for e in pak["entries"]:
            print("  %-16s %8d -> %8d" % (e["name"], e["size"], e["raw_size"]))
    return 0


def _compress_job(item):
    return item[0], lzss_compress(item[1])


def pack_entries(entries: list[tuple[str, bytes]], version: int = 2,
                 store: bool = False, jobs: int = 1) -> bytes:
    """Build an archive from [(name, raw_bytes)] in TOC order."""
    if len(entries) > 0xFFFF:
        raise PakError("too many entries (%d)" % len(entries))
    out = bytearray(MAGIC + struct.pack("<HH", len(entries), version))
    offset = HEADER_SIZE + len(entries) * ENTRY_SIZE
    toc = bytearray()
    payloads = bytearray()
    if store:
        for name, raw in entries:
            toc += _toc_name(name) + struct.pack("<II", offset, len(raw))
            payloads += raw
            offset += len(raw)
        return bytes(out + toc + payloads)
    jobs = max(1, jobs)
    if jobs > 1 and len(entries) > 1:
        with _fut.ProcessPoolExecutor(max_workers=jobs) as pool:
            comps = list(pool.map(_compress_job, entries, chunksize=1))
    else:
        comps = [_compress_job(it) for it in entries]
    raw_by_name = {n: d for n, d in entries}
    for name, comp in comps:
        raw = raw_by_name[name]
        payload = IEL1 + struct.pack("<I", len(raw)) + comp
        toc += _toc_name(name) + struct.pack("<II", offset, len(payload))
        payloads += payload
        offset += len(payload)
    return bytes(out + toc + payloads)


def cmd_pack(args) -> int:
    entries, version, order_ok = load_dir(args.dir)
    if not entries:
        print("error: no files found in %s" % args.dir, file=sys.stderr)
        return 2
    names = [n.lower() for n, _ in entries]
    if len(set(names)) != len(names):
        print("warning: duplicate entry names (case-insensitive lookup in game)", file=sys.stderr)
    if not order_ok and os.path.isfile(_manifest_path(args.dir)):
        print("warning: directory contents differ from manifest order", file=sys.stderr)
    print("packing %d entries (version %d%s)" %
          (len(entries), version, ", stored raw" if args.store else ""))
    blob = pack_entries(entries, version=version, store=args.store, jobs=args.jobs)
    size = len(blob)
    tmp = args.output + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(blob)
    os.replace(tmp, args.output)
    print("wrote %s (%d bytes)" % (os.path.abspath(args.output), size))
    return 0


def cmd_verify(args) -> int:
    pak = read_pak(args.pak)
    entries = [(e["name"], e["data"]) for e in pak["entries"]]
    rebuilt = pack_entries(entries, version=pak["version"], store=args.store, jobs=args.jobs)
    with open(args.pak, "rb") as fh:
        original = fh.read()
    same = rebuilt == original
    print("%s: %d entries" % (pak["path"], pak["count"]))
    print("  original %d bytes, rebuilt %d bytes" % (len(original), len(rebuilt)))
    print("  byte-identical: %s" % ("YES" if same else "NO"))
    if not same:
        limit = min(len(original), len(rebuilt))
        for i in range(limit):
            if original[i] != rebuilt[i]:
                print("  first difference at 0x%X: %02X != %02X" %
                      (i, original[i], rebuilt[i]))
                break
        else:
            print("  files differ only in length")
        return 1
    # independent content check: decode rebuilt and compare every member
    check = read_pak_bytes(rebuilt)
    for a, b in zip(pak["entries"], check["entries"]):
        if a["name"] != b["name"] or a["data"] != b["data"]:
            print("  MISMATCH on %s" % a["name"])
            return 1
    print("  content round-trip: OK")
    return 0


# --------------------------------------------------------------------------
def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pak_tool.py",
        description="IPAC .pak unpack/pack tool (kyoto.exe). LZSS is handled automatically; no encryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage\n-----", 1)[-1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="list archive entries")
    p.add_argument("pak")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("unpack", help="extract every member (auto-decompresses LZSS)")
    p.add_argument("pak")
    p.add_argument("-o", "--output", help="output directory (default: <pak>_unpacked)")
    p.add_argument("--no-manifest", action="store_true", help="do not write _pak_manifest.json")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("pack", help="build an archive from a directory (auto-compresses LZSS)")
    p.add_argument("dir")
    p.add_argument("-o", "--output", required=True, help="output .pak path")
    p.add_argument("--store", action="store_true", help="store members uncompressed")
    p.add_argument("--jobs", type=int, default=1, help="parallel compress workers (default 1)")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("verify", help="unpack+repack in memory and compare with the original")
    p.add_argument("pak")
    p.add_argument("--store", action="store_true", help="rebuild with raw storage instead of LZSS")
    p.add_argument("--jobs", type=int, default=1, help="parallel compress workers (default 1)")
    p.set_defaults(func=cmd_verify)
    return ap


def main(argv=None) -> int:
    args = build_argparser().parse_args(argv)
    try:
        return args.func(args)
    except PakError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
