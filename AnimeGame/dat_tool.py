#!/usr/bin/env python3
"""List, unpack, and repack AnimeGameSystem DAT/AGS archives (pack&)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any

MAGIC = b"pack"
HEADER_SIZE = 6
ENTRY = struct.Struct("<16sII")
MANIFEST = "dat_manifest.json"


class DatError(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_name(raw: bytes) -> str:
    name_raw = raw.split(b"\0", 1)[0]
    if not name_raw:
        raise DatError("empty archive member name")
    try:
        name = name_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DatError(f"non-ASCII member name field: {raw.hex()}") from exc
    if name in {".", ".."} or any(c in name for c in ("/", "\\", ":")):
        raise DatError(f"unsafe member name: {name!r}")
    return name


def parse_archive(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    data = path.read_bytes()
    if len(data) < HEADER_SIZE or data[:4] != MAGIC:
        raise DatError("not an AnimeGameSystem DAT archive: expected 'pack' signature")
    count = struct.unpack_from("<H", data, 4)[0]
    directory_end = HEADER_SIZE + count * ENTRY.size
    if directory_end > len(data):
        raise DatError(f"directory extends past EOF (count={count}, end=0x{directory_end:X})")

    entries: list[dict[str, Any]] = []
    names: set[str] = set()
    ranges: list[tuple[int, int, str]] = []
    for index in range(count):
        pos = HEADER_SIZE + index * ENTRY.size
        name_field, offset, size = ENTRY.unpack_from(data, pos)
        name = decode_name(name_field)
        if name in names:
            raise DatError(f"duplicate member name: {name}")
        names.add(name)
        end = offset + size
        if offset < directory_end:
            raise DatError(f"{name}: payload starts inside header/index (0x{offset:X} < 0x{directory_end:X})")
        if end > len(data):
            raise DatError(f"{name}: payload end 0x{end:X} exceeds archive size 0x{len(data):X}")
        entries.append({
            "index": index,
            "name": name,
            "name_field_hex": name_field.hex(),
            "offset": offset,
            "size": size,
            "data": data[offset:end],
        })
        if size:
            ranges.append((offset, end, name))

    ranges.sort()
    for previous, current in zip(ranges, ranges[1:]):
        if current[0] < previous[1]:
            raise DatError(f"payloads overlap: {previous[2]} and {current[2]}")
    return data, entries


def xor_stream(data: bytes, initial: int, increment: int) -> bytes:
    key = initial & 0xFF
    result = bytearray(data)
    for i in range(len(result)):
        result[i] ^= key
        key = (key + increment) & 0xFF
    return bytes(result)


def unpack(args: argparse.Namespace) -> int:
    archive = Path(args.archive).resolve()
    raw, entries = parse_archive(archive)
    out_dir = Path(args.output).resolve() if args.output else archive.with_name(archive.stem + "_unpacked")
    xor_cfg = None
    if args.xor_initial is not None or args.xor_increment is not None:
        if args.xor_initial is None or args.xor_increment is None:
            raise DatError("--xor-initial and --xor-increment must be specified together")
        xor_cfg = {"initial": args.xor_initial, "increment": args.xor_increment}

    if out_dir.exists() and any(out_dir.iterdir()) and not args.force:
        raise DatError(f"output directory is not empty (use --force to replace extracted members): {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_entries = []
    for item in entries:
        member_data = item["data"]
        if xor_cfg is not None:
            member_data = xor_stream(member_data, xor_cfg["initial"], xor_cfg["increment"])
        (out_dir / item["name"]).write_bytes(member_data)
        manifest_entries.append({
            "index": item["index"],
            "name": item["name"],
            "name_field_hex": item["name_field_hex"],
            "original_offset": item["offset"],
            "original_size": item["size"],
            "sha256": sha256(member_data),
        })
    manifest = {
        "format": "AnimeGameSystem DAT/AGS (pack&)",
        "source_archive": archive.name,
        "source_path": str(archive),
        "source_size": len(raw),
        "source_sha256": sha256(raw),
        "entry_count": len(entries),
        "compression": "none (not present in this container format)",
        "xor": xor_cfg,
        "entries": manifest_entries,
    }
    (out_dir / MANIFEST).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    state = "XOR-transformed using supplied key" if xor_cfg else "raw payloads; no XOR key supplied"
    print(f"Extracted {len(entries)} entries to {out_dir} ({state}; container has no compression flag/stream).")
    print(f"Manifest: {out_dir / MANIFEST}")
    return 0


def load_manifest(folder: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = folder / MANIFEST
    if not manifest_path.is_file():
        raise DatError(f"missing {MANIFEST} in {folder}; unpack the archive first")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatError(f"cannot read manifest: {exc}") from exc
    if manifest.get("format") != "AnimeGameSystem DAT/AGS (pack&)":
        raise DatError("manifest format/version not recognized")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) > 0xFFFF:
        raise DatError("manifest entries must be a list of at most 65535 members")
    return manifest, entries


def pack(args: argparse.Namespace) -> int:
    folder = Path(args.directory).resolve()
    manifest, entries = load_manifest(folder)
    source_name = Path(manifest.get("source_archive", "repacked.dat"))
    output = Path(args.output).resolve() if args.output else folder.with_name(source_name.stem + "_repacked" + (source_name.suffix or ".dat"))
    original_path = manifest.get("source_path")
    if original_path and output == Path(original_path).resolve():
        raise DatError("refusing to overwrite the source archive; choose a different --output path")
    if output.exists() and not args.force:
        raise DatError(f"output exists (use --force to overwrite): {output}")

    xor_cfg = manifest.get("xor")
    if args.xor_initial is not None or args.xor_increment is not None:
        if args.xor_initial is None or args.xor_increment is None:
            raise DatError("--xor-initial and --xor-increment must be specified together")
        xor_cfg = {"initial": args.xor_initial, "increment": args.xor_increment}
    if xor_cfg is not None:
        if not isinstance(xor_cfg, dict) or not all(isinstance(xor_cfg.get(k), int) and 0 <= xor_cfg[k] <= 255 for k in ("initial", "increment")):
            raise DatError("manifest XOR config must have byte values 'initial' and 'increment'")

    if len({e.get("name") for e in entries}) != len(entries):
        raise DatError("manifest contains duplicate member names")
    header_size = HEADER_SIZE + len(entries) * ENTRY.size
    payloads: list[tuple[bytes, bytes, str]] = []
    for item in entries:
        name = item.get("name")
        if not isinstance(name, str) or not name or name in {".", ".."} or any(c in name for c in ("/", "\\", ":")):
            raise DatError(f"unsafe or invalid member name in manifest: {name!r}")
        path = folder / name
        if not path.is_file():
            raise DatError(f"missing member file: {path}")
        member_data = path.read_bytes()
        name_hex = item.get("name_field_hex")
        try:
            original_field = bytes.fromhex(name_hex) if isinstance(name_hex, str) else b""
        except ValueError:
            original_field = b""
        if len(original_field) == 16 and decode_name(original_field) == name:
            name_field = original_field
        else:
            try:
                encoded = name.encode("ascii")
            except UnicodeEncodeError as exc:
                raise DatError(f"renamed member must use ASCII: {name!r}") from exc
            if len(encoded) > 16 or b"\0" in encoded:
                raise DatError(f"member name must fit in 16 ASCII bytes: {name!r}")
            name_field = encoded.ljust(16, b"\0")
        if xor_cfg is not None:
            member_data = xor_stream(member_data, xor_cfg["initial"], xor_cfg["increment"])
        payloads.append((name_field, member_data, name))

    chunks = [bytearray(MAGIC + struct.pack("<H", len(payloads)))]
    directory = bytearray()
    cursor = header_size
    for name_field, member_data, _name in payloads:
        if len(member_data) > 0xFFFFFFFF or cursor > 0xFFFFFFFF:
            raise DatError("archive exceeds 32-bit DAT offset/size limits")
        directory += ENTRY.pack(name_field, cursor, len(member_data))
        chunks.append(member_data)
        cursor += len(member_data)
    chunks.insert(1, directory)
    archive_data = b"".join(chunks)

    output.parent.mkdir(parents=True, exist_ok=True)
    if args.force:
        output.write_bytes(archive_data)
    else:
        with output.open("xb") as f:
            f.write(archive_data)
    # Re-parse what was written to enforce table/range invariants.
    reparsed, reparsed_entries = parse_archive(output)
    if len(reparsed_entries) != len(payloads):
        raise DatError("post-write validation failed: entry count mismatch")
    print(f"Packed {len(payloads)} entries -> {output} ({len(reparsed)} bytes, sha256={sha256(reparsed)}).")
    if xor_cfg:
        print(f"Applied XOR stream: initial=0x{xor_cfg['initial']:02X}, increment=0x{xor_cfg['increment']:02X}.")
    else:
        print("No encryption applied (this archive has no self-describing encryption flag).")
    print("No compression applied: this container has no compression metadata or stream.")
    return 0


def list_archive(args: argparse.Namespace) -> int:
    archive = Path(args.archive).resolve()
    raw, entries = parse_archive(archive)
    print(f"{archive}: AnimeGameSystem DAT/AGS; magic=pack; count={len(entries)}; size={len(raw)}")
    print("index  offset      size        name")
    for item in entries:
        print(f"{item['index']:5d}  0x{item['offset']:08X}  0x{item['size']:08X}  {item['name']}")
    print("Compression: none in container metadata. XOR encryption is external/keyed and cannot be inferred from the header.")
    return 0


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_list = sub.add_parser("list", help="validate and list archive members")
    p_list.add_argument("archive")
    p_list.set_defaults(func=list_archive)
    p_unpack = sub.add_parser("unpack", help="extract members and write dat_manifest.json")
    p_unpack.add_argument("archive")
    p_unpack.add_argument("-o", "--output", help="output folder (default: <archive>_unpacked)")
    p_unpack.add_argument("--xor-initial", type=lambda x: int(x, 0), help="optional external AGS XOR initial byte (0..255)")
    p_unpack.add_argument("--xor-increment", type=lambda x: int(x, 0), help="optional external AGS XOR increment byte (0..255)")
    p_unpack.add_argument("--force", action="store_true", help="allow writing into a non-empty output folder")
    p_unpack.set_defaults(func=unpack)
    p_pack = sub.add_parser("pack", help="rebuild archive from extracted folder and manifest")
    p_pack.add_argument("directory", help="folder created by unpack")
    p_pack.add_argument("-o", "--output", help="output archive path")
    p_pack.add_argument("--xor-initial", type=lambda x: int(x, 0), help="override external AGS XOR initial byte")
    p_pack.add_argument("--xor-increment", type=lambda x: int(x, 0), help="override external AGS XOR increment byte")
    p_pack.add_argument("--force", action="store_true", help="overwrite output archive")
    p_pack.set_defaults(func=pack)
    return parser


def main() -> int:
    parser = make_parser()
    args = parser.parse_args()
    try:
        for key in ("xor_initial", "xor_increment"):
            value = getattr(args, key, None)
            if value is not None and not 0 <= value <= 255:
                raise DatError(f"--{key.replace('_', '-')} must be in 0..255")
        return args.func(args)
    except (DatError, OSError) as exc:
        print(f"dat_tool: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


