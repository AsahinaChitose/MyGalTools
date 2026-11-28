"""Disassemble decrypted HITOMI ISF members into editable UTF-8 assembly."""

import argparse
from pathlib import Path
import struct
import sys

import opcodelist as vm


def label(offset):
    return f"loc_{offset:08X}"


def read_program(data):
    if len(data) < 14 or data[:6] != b"HITOMI":
        raise vm.FormatError("expected a decrypted HITOMI ISF member")
    start = 6 + struct.unpack_from("<I", data, 6)[0]
    if not 14 <= start <= len(data) or (start - 14) % 4:
        raise vm.FormatError(f"invalid entry table end at file 0x{start:X}")
    entries = [value for value, in struct.iter_unpack("<I", data[14:start])]
    records = []
    pos = start
    while pos < len(data):
        if len(data) - pos == 6 and data[pos:] == bytes(6):
            break
        if pos + 2 > len(data):
            raise vm.FormatError(f"file 0x{pos:X}: missing opcode or length")
        code, total = data[pos:pos + 2]
        width = 2
        if total & 0x80:
            if pos + 3 > len(data):
                raise vm.FormatError(f"file 0x{pos:X}: missing second length byte")
            total = ((total & 0x7F) << 8) | data[pos + 2]
            width = 3
        if total < width or pos + total > len(data):
            raise vm.FormatError(f"file 0x{pos:X}: opcode 0x{code:02X} has invalid length {total}")
        records.append((pos - start, code, width, data[pos + width:pos + total]))
        pos += total
    boundaries = {offset for offset, _, _, _ in records}
    for slot, offset in enumerate(entries):
        if offset not in boundaries:
            raise vm.FormatError(f"entry slot {slot} (file 0x{14 + slot * 4:X}) targets "
                                 f"code +0x{offset:X}, outside instruction boundaries")
    return data[10:14], entries, records, len(data) - pos, start


class Decode:
    def __init__(self, payload, entries, encoding):
        self.reader = vm.Reader(payload)
        self.entries = entries
        self.encoding = encoding

    def string(self, kind):
        reader = self.reader
        if kind.startswith("s"):
            limit = int(kind[1:])
            data, ending = reader.string(limit, (0,), fixed_limit=True)
            if ending not in (None, 0):
                raise vm.FormatError("invalid resource terminator")
        elif kind == "q":
            data, ending = reader.string(13, (0, 13))
        else:
            limit = (reader.remaining if kind == "z" else
                     int(kind[1:]) if len(kind) > 1 else 255)
            data, ending = reader.string(limit, (0, 13), fixed_limit=kind != "z")
        token = vm.quote(vm.plain_units(data, self.encoding))
        if kind == "q" and ending not in (0, 13):
            token += f" end={ending}"
        elif ending == 13:
            token += " end=cr"
        return token

    def fields(self, schema):
        tokens = []
        for field in schema:
            if field not in vm.WIDTHS:
                tokens.append(self.string(field))
                continue
            value = self.reader.uint(vm.WIDTHS[field])
            if field == "x":
                tokens.append(vm.expression(value))
            elif field == "v":
                tokens.append(f"v{value}")
            elif field == "j":
                if value >= len(self.entries):
                    raise vm.FormatError(f"entry slot {value} is outside the entry table")
                tokens.append(f"{label(self.entries[value])}@{value}")
            else:
                tokens.append(str(value))
        return tokens

    def message(self):
        reader = self.reader
        rows = []
        while reader.remaining > 1:
            control = reader.uint(1)
            if control == 0xFF:
                units, forms = [], []
                while reader.remaining > 1:
                    unit, form = vm.read_glyph(reader, self.encoding)
                    if unit is None:
                        break
                    if form:
                        forms.append(f"{len(units)}:{form}")
                    units.append(unit)
                else:
                    raise vm.FormatError("unterminated MESSAGE text")
                row = ["TEXT", vm.quote(units)]
                if forms:
                    row.append("form=" + ",".join(forms))
            else:
                if control not in vm.MESSAGE_CONTROLS:
                    raise vm.FormatError(f"unknown MESSAGE control 0x{control:02X}")
                name, schema = vm.MESSAGE_CONTROLS[control]
                row = [name, *self.fields(schema)]
            rows.append(row)
        trailer = reader.uint(1)
        if trailer:
            rows.append(["RECORD_TRAILER", str(trailer)])
        return rows

    def conditions(self):
        reader = self.reader
        rows = []
        while True:
            left, comparison, right = self.fields(("x", "b", "x"))
            op = int(comparison)
            if op not in vm.RELATIONS:
                raise vm.FormatError(f"unknown IF comparison 0x{op:02X}")
            row = [vm.RELATIONS[op], left, right]
            action = reader.uint(1)
            if action == 0:
                row += ["JUMP", *self.fields(("j",))]
            elif action == 1:
                row += ["SET", *self.fields(("v", "x"))]
            elif action == 255:
                rows.append(row + ["STOP"])
                return rows
            else:
                rows.append(row + (["AND"] if action == 2 else ["AND", str(action)]))
                continue
            rows.append(row)
            if reader.remaining:
                if reader.uint(1) != 255:
                    raise vm.FormatError("expected IF tail marker FF")
                rows.append(["END"])
            return rows

    def body(self, op, width):
        reader = self.reader
        name = op.mnemonic
        schema = op.operands
        args = self.fields(schema)
        rows = []
        layout = op.layout
        if layout == "dispatch":
            count = reader.uint(1)
            targets = self.fields(("j",) * count)
            rows = [["TARGETS", *targets[i:i + 6]] for i in range(0, count, 6)]
        elif layout == "skins":
            while reader.remaining:
                rows.append(["SKIN", *self.fields(("s28",))])
            if len(rows) not in (1, 3, 4, 5, 6):
                raise vm.FormatError("expected 1, 3, 4, 5 or 6 message skin names")
        elif layout == "speaker":
            if width != 2:
                raise vm.FormatError("DEFINE_SPEAKER requires a short record header")
            args.append(vm.quote(vm.plain_units(reader.take(reader.remaining), self.encoding)))
        elif layout == "message":
            if (width == 3) != (len(reader.data) + width > 127):
                raise vm.FormatError("MESSAGE length and header width disagree")
            rows = self.message()
        elif layout == "data":
            while reader.remaining:
                data = reader.take(min(reader.remaining, 16))
                rows.append(["DATA", *(str(value) for value in data)])
        elif layout == "arithmetic":
            while True:
                mode = reader.uint(1)
                if mode not in vm.ARITHMETIC:
                    rows.append(["END"] if mode == 5 else ["END", str(mode)])
                    break
                rows.append([vm.ARITHMETIC[mode], *self.fields(("x",))])
        elif layout == "conditions":
            rows = self.conditions()
        elif layout in ("blit", "layer"):
            mode = reader.uint(1)
            title, extra = vm.variant(vm.BLIT if layout == "blit" else vm.LAYER, mode)
            name += "." + title
            args = self.fields(("x",) * 8 + extra + (("x", "x") if op.bytecode == 0x5E else ()))
        elif layout in vm.MODE_LAYOUTS:
            table, extra = vm.MODE_LAYOUTS[layout]
            mode = reader.uint(1)
            if mode not in table:
                raise vm.FormatError(f"unknown {name} subcode 0x{mode:02X}")
            name += "." + table[mode]
            args += self.fields(extra)
        elif layout == "menu_mode":
            if reader.remaining:
                if reader.take(3) != bytes(3):
                    raise vm.FormatError("unknown SELECT_CURSOR reserved bytes")
                name += ".PADDED"
        elif layout == "menu_run":
            flags = reader.uint(1)
            name += ".WAIT" if flags & 2 else ".POLL"
            args.append(f"0x{flags & ~2:02X}")
        elif layout == "short_strings":
            for _ in range(reader.uint(2)):
                rows.append(["STRING", *self.fields(("q",))])
        elif layout == "system":
            mode = reader.uint(1)
            if mode not in vm.SYSTEM:
                raise vm.FormatError(f"unknown SYSTEM subcode 0x{mode:02X}")
            subname, schema = vm.SYSTEM[mode]
            name += "." + subname
            if mode == 3:
                panel = reader.uint(1)
                if panel not in vm.PANELS:
                    raise vm.FormatError(f"unknown SYSTEM.PANEL subcode 0x{panel:02X}")
                subname, schema = vm.PANELS[panel]
                name += "." + subname
            args = self.fields(schema)
            if mode == 8:
                for _ in range(reader.uint(2)):
                    rows.append(["STRING", *self.fields(("z",))])
        reader.end()
        return name, args, rows


def disassemble(data, filename, encoding="cp932"):
    encoding = vm.encoding_name(encoding)
    mode, entries, records, tail, start = read_program(data)
    if not filename.lower().endswith(".isf"):
        filename = Path(filename).stem + ".ISF"
    lines = ["; HITOMI ISF assembly (UTF-8)", f".encoding {encoding}",
             f".script {vm.quote(filename)}", ".mode " + " ".join(f"0x{value:02X}" for value in mode)]
    for slot, offset in enumerate(entries):
        lines.append(f".entry {slot} {label(offset)}")
    lines += ["", ".code"]
    targets = set(entries)
    for offset, code, width, payload in records:
        if offset in targets:
            lines += ["", f"{label(offset)}:"]
        op = vm.OPCODES.get(code)
        try:
            if op is None:
                raise vm.FormatError(f"undefined opcode 0x{code:02X} (dispatcher default)")
            name, args, rows = Decode(payload, entries, encoding).body(op, width)
        except (ValueError, UnicodeError) as error:
            total = len(payload) + width
            length = bytes([total]) if width == 2 else bytes([0x80 | (total >> 8), total & 0xFF])
            original = bytes([code]) + length + payload
            preview = original.hex(" ") if op is None else original[:48].hex(" ")
            if op is not None and len(original) > 48:
                preview += " ..."
            context = op.mnemonic if op else "UNKNOWN"
            raise vm.FormatError(f"file 0x{start + offset:X}, code +0x{offset:X}, {context}: "
                                 f"{error}; record ({len(original)} bytes): {preview}") from None
        fields = [name, *(["@long"] if width == 3 else []), *args]
        lines.append("    " + " ".join(fields))
        speaker_picture = 0
        for row in rows:
            if op.layout == "message":
                if row[0] == "SET_POSITION":
                    speaker_picture = int(row[1])
                elif row[0] == "TEXT" and 0 < speaker_picture < 0x1000:
                    if speaker_picture < len(vm.SPEAKER_PICTURES):
                        speaker = vm.SPEAKER_PICTURES[speaker_picture]
                    else:
                        speaker = f"FW{speaker_picture:03d}.GG2"
                    lines.append("        ; NAME " + vm.quote(speaker))
            lines.append("        | " + " ".join(row))
    if tail:
        lines.append(f".tail_zero {tail}")
    lines.append(".end_code")
    return "\n".join(lines) + "\n"


def output_jobs(inputs, out):
    jobs = []
    directory = len(inputs) > 1 or any(path.is_dir() for path in inputs) or (out and out.is_dir())
    for path in inputs:
        if path.is_dir():
            path = path.resolve()
            members = sorted(member for member in path.rglob("*") if member.is_file() and member.suffix.lower() == ".isf")
            if not members:
                raise vm.FormatError(f"no ISF files in {path}")
            dest = out or path.with_name(path.name + "_asm")
            for member in members:
                relative = member.relative_to(path)
                jobs.append((member, dest / relative.with_suffix(".asm.txt")))
        elif path.is_file():
            name = path.with_suffix(".asm.txt").name
            dest = (out / name if directory else out) if out else path.with_name(name)
            jobs.append((path, dest))
        else:
            raise vm.FormatError(f"input does not exist: {path}")
    vm.safe_outputs(jobs)
    return jobs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, metavar="SCRIPT_OR_DIRECTORY")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--encoding", default="cp932")
    args = parser.parse_args(argv)
    source = None
    try:
        encoding = vm.encoding_name(args.encoding)
        jobs = output_jobs(args.inputs, args.output)
        for source, destination in jobs:
            text = disassemble(source.read_bytes(), source.name, encoding)
            vm.write_atomic(destination, text.encode("utf-8"))
        print(f"Disassembled {len(jobs)} file(s).")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{source or 'disassembler'}: {error}\n")


if __name__ == "__main__":
    main()
