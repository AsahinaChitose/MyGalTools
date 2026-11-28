"""Assemble editable UTF-8 HITOMI assembly into decrypted ISF members."""

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import struct

import opcodelist as vm


class Fields:
    def __init__(self, tokens, line):
        self.tokens = list(tokens)
        self.pos = 0
        self.line = line

    @property
    def remaining(self):
        return self.tokens[self.pos:]

    def pop(self):
        if self.pos == len(self.tokens):
            raise vm.FormatError("missing operand")
        result = self.tokens[self.pos]
        self.pos += 1
        return result

    def option(self, prefix):
        if self.pos < len(self.tokens) and self.tokens[self.pos].startswith(prefix):
            return self.pop()[len(prefix):]
        return None

    def end(self):
        if self.remaining:
            raise vm.FormatError(f"unexpected operand {self.remaining[0]!r}")


def require_label(name):
    if not vm.LABEL.fullmatch(name):
        raise vm.FormatError(f"invalid label {name!r}")
    return name


def reverse(table, name):
    for key, value in table.items():
        if value == name:
            return key
    raise vm.FormatError(f"unknown subcode name {name!r}")


class Encode:
    def __init__(self, entries, source, target, preserve_forms):
        self.entries = entries
        self.source = source
        self.target = target
        self.preserve_forms = preserve_forms
        self.line = 0
        self.data = bytearray()

    def uint(self, value, width):
        self.data.extend(value.to_bytes(width, "little"))

    def entry(self, token):
        name, separator, slot = token.partition("@")
        require_label(name)
        if not separator:
            slots = [index for index, target in self.entries.items() if target == name]
            if len(slots) != 1:
                raise vm.FormatError(f"{name} needs an explicit entry slot (label@slot)")
            return slots[0]
        index = vm.number(slot, 2)
        if self.entries.get(index) != name:
            raise vm.FormatError(f"entry slot {index} does not target {name}")
        return index

    def string(self, fields, kind):
        resource = kind.startswith("s")
        limit = {"q": 13, "z": 32764}.get(kind, 255) if len(kind) == 1 else int(kind[1:])
        data = vm.plain_bytes(fields.pop(), self.source if resource else self.target)
        if b"\0" in data or (not resource and b"\r" in data):
            raise vm.FormatError("embedded string terminator")
        if len(data) > limit:
            raise vm.FormatError(f"string encoded to {len(data)} bytes, limit is {limit}")
        end = fields.option("end=")
        if resource and end is not None:
            raise vm.FormatError("resource strings use an implicit NUL or their fixed byte limit")
        ending = 13 if end == "cr" else vm.number(end, 1) if end is not None else 0
        if ending not in (0, 13) and (kind != "q" or len(data) != limit):
            raise vm.FormatError("nonstandard terminator only valid after 13 bytes of short string")
        if len(data) == limit and kind != "q" and end is not None:
            raise vm.FormatError("maximum-width string has no stored terminator")
        self.data.extend(data)
        if len(data) < limit or kind in ("q", "z"):
            self.uint(ending, 1)

    def fields(self, fields, schema):
        for kind in schema:
            if kind not in vm.WIDTHS:
                self.string(fields, kind)
                continue
            token = fields.pop()
            if kind == "v":
                if not token.startswith("v"):
                    raise vm.FormatError(f"expected a variable such as v0, got {token!r}")
                value = vm.number(token[1:], 2)
            elif kind == "x":
                value = vm.expression_value(token)
            elif kind == "j":
                value = self.entry(token)
            else:
                value = vm.number(token, vm.WIDTHS[kind])
            self.uint(value, vm.WIDTHS[kind])

    def message(self, rows):
        controls = {name: (mode, schema) for mode, (name, schema) in vm.MESSAGE_CONTROLS.items()}
        trailer = 0
        for index, row in enumerate(rows):
            self.line = row.line
            name = row.pop()
            if name == "TEXT":
                self.uint(255, 1)
                units = vm.unquote(row.pop())
                forms = {}
                spec = row.option("form=")
                if spec is not None:
                    for pair in spec.split(","):
                        key, colon, kind = pair.partition(":")
                        index_in_text = vm.number(key)
                        if not colon or index_in_text < 0 or index_in_text in forms:
                            raise vm.FormatError(f"invalid glyph form assignment {pair!r}")
                        # Validate the annotation even when a new encoding will bypass it.
                        if not vm.GLYPH_FORM.fullmatch(kind):
                            raise vm.FormatError(f"unknown message glyph form {kind!r}")
                        forms[index_in_text] = kind
                for position, unit in enumerate(units):
                    try:
                        encoded = None
                        if self.preserve_forms and position in forms:
                            # The spelling may become inapplicable after editing the text.
                            encoded = vm.glyph_form(unit, forms[position], self.target)
                        self.data.extend(encoded or vm.message_unit(unit, self.target))
                    except vm.FormatError as error:
                        raise vm.FormatError(f"MESSAGE character {position + 1}: {error}") from None
                self.uint(0, 1)
            elif name == "RECORD_TRAILER":
                if index != len(rows) - 1:
                    raise vm.FormatError("RECORD_TRAILER must be the last MESSAGE row")
                trailer = vm.number(row.pop(), 1)
            else:
                if name not in controls:
                    raise vm.FormatError(f"unknown MESSAGE control {name!r}")
                mode, schema = controls[name]
                self.uint(mode, 1)
                self.fields(row, schema)
            row.end()
        self.uint(trailer, 1)

    def conditions(self, rows):
        state = "condition"
        for row in rows:
            self.line = row.line
            name = row.pop()
            if state == "tail" and name == "END":
                self.uint(255, 1)
                state = "done"
                row.end()
                continue
            if state != "condition":
                raise vm.FormatError("unexpected row after terminal IF action")
            relation = reverse(vm.RELATIONS, name)
            self.fields(row, ("x",))
            self.uint(relation, 1)
            self.fields(row, ("x",))
            action = row.pop()
            if action == "JUMP":
                self.uint(0, 1)
                self.fields(row, ("j",))
                state = "tail"
            elif action == "SET":
                self.uint(1, 1)
                self.fields(row, ("v", "x"))
                state = "tail"
            elif action == "AND":
                flag = vm.number(row.pop(), 1) if row.remaining else 2
                if flag in (0, 1, 255):
                    raise vm.FormatError("AND continuation must be in 2..254")
                self.uint(flag, 1)
            elif action == "STOP":
                self.uint(255, 1)
                state = "done"
            else:
                raise vm.FormatError(f"unknown IF action {action!r}")
            row.end()
        if state == "condition":
            raise vm.FormatError("IF must end in JUMP, SET or STOP")

    def body(self, name, fields, rows):
        self.line = fields.line
        mnemonic, _, variant = name.partition(".")
        if mnemonic not in vm.BY_NAME:
            raise vm.FormatError(f"unknown mnemonic {mnemonic!r}")
        op = vm.BY_NAME[mnemonic]
        wide = fields.option("@long")
        if wide not in (None, ""):
            raise vm.FormatError("expected @long")
        schema = op.operands
        self.fields(fields, schema)
        layout = op.layout
        if layout in ("fixed", "dispatch", "skins", "speaker", "message", "data",
                      "arithmetic", "conditions", "short_strings") and variant:
            raise vm.FormatError(f"unexpected variant {variant!r} for {mnemonic}")
        if layout in ("fixed", "speaker", "blit", "layer", "system_test", "system_get",
                      "system_set", "file_action", "menu_mode", "menu_run") and rows:
            self.line = rows[0].line
            raise vm.FormatError(f"{name} has no continuation rows")
        if layout == "dispatch":
            targets = []
            for row in rows:
                self.line = row.line
                if row.pop() != "TARGETS" or not row.remaining:
                    raise vm.FormatError("expected TARGETS and one or more entry labels")
                targets += row.remaining
            if len(targets) > 255:
                raise vm.FormatError("switch has more than 255 targets")
            self.uint(len(targets), 1)
            self.fields(Fields(targets, self.line), ("j",) * len(targets))
        elif layout == "skins":
            if len(rows) not in (1, 3, 4, 5, 6):
                raise vm.FormatError("expected 1, 3, 4, 5 or 6 SKIN rows")
            self.string_rows(rows, "SKIN", "s28")
        elif layout == "speaker":
            name_bytes = vm.plain_bytes(fields.pop(), self.target)
            if b"\0" in name_bytes:
                raise vm.FormatError("embedded NUL in speaker name")
            self.data.extend(name_bytes)
        elif layout == "message":
            self.message(rows)
        elif layout == "data":
            for row in rows:
                self.line = row.line
                if row.pop() != "DATA" or not row.remaining:
                    raise vm.FormatError("expected DATA and one or more bytes")
                self.data.extend(vm.number(value, 1) for value in row.remaining)
        elif layout == "arithmetic":
            if not rows:
                raise vm.FormatError("CALCULATE needs an END row")
            for index, row in enumerate(rows):
                self.line = row.line
                name = row.pop()
                if name == "END":
                    if index != len(rows) - 1:
                        raise vm.FormatError("CALCULATE END must be the last row")
                    stop = vm.number(row.pop(), 1) if row.remaining else 5
                    if stop <= 4:
                        raise vm.FormatError("CALCULATE stop code must exceed 4")
                    self.uint(stop, 1)
                else:
                    if index == len(rows) - 1:
                        raise vm.FormatError("CALCULATE needs a final END row")
                    self.uint(reverse(vm.ARITHMETIC, name), 1)
                    self.fields(row, ("x",))
                row.end()
        elif layout == "conditions":
            self.conditions(rows)
        elif layout in ("blit", "layer"):
            table = vm.BLIT if layout == "blit" else vm.LAYER
            mode = vm.variant_value(table, variant)
            self.uint(mode, 1)
            extra = vm.variant(table, mode)[1]
            self.fields(fields, ("x",) * 8 + extra + (("x", "x") if op.bytecode == 0x5E else ()))
        elif layout in vm.MODE_LAYOUTS:
            table, extra = vm.MODE_LAYOUTS[layout]
            self.uint(reverse(table, variant), 1)
            self.fields(fields, extra)
        elif layout == "menu_mode":
            if variant == "PADDED":
                self.data.extend(bytes(3))
            elif variant:
                raise vm.FormatError(f"unknown SELECT_CURSOR variant {variant!r}")
        elif layout == "menu_run":
            flags = vm.number(fields.pop(), 1)
            if flags & 2 or variant not in ("WAIT", "POLL"):
                raise vm.FormatError("RUN_MENU needs WAIT or POLL and flags without bit 1 set")
            self.uint(flags | (2 if variant == "WAIT" else 0), 1)
        elif layout == "short_strings":
            self.counted_strings(rows, "q")
        elif layout == "system":
            name, separator, nested = variant.partition(".")
            mode = next((key for key, (title, _) in vm.SYSTEM.items() if title == name), None)
            if mode is None:
                raise vm.FormatError(f"unknown SYSTEM variant {variant!r}")
            self.uint(mode, 1)
            schema = vm.SYSTEM[mode][1]
            if mode == 3:
                panel = vm.variant_value(vm.PANELS, nested)
                if panel not in vm.PANELS:
                    raise vm.FormatError(f"unknown panel subcode {panel}")
                self.uint(panel, 1)
                schema = vm.PANELS[panel][1]
            elif separator:
                raise vm.FormatError(f"unexpected nested SYSTEM variant {nested!r}")
            self.fields(fields, schema)
            if mode == 8:
                self.counted_strings(rows, "z")
            elif rows:
                self.line = rows[0].line
                raise vm.FormatError(f"SYSTEM.{variant} has no continuation rows")
        self.line = fields.line
        fields.end()
        width = 3 if wide is not None or len(self.data) + 2 > 127 else 2
        total = width + len(self.data)
        if layout == "speaker" and width == 3:
            raise vm.FormatError("DEFINE_SPEAKER exceeds the 123-byte name limit or has an invalid @long")
        if layout == "message" and width == 3 and total <= 127:
            # A shortened message must go back to the short width for the VM
            # to calculate the same start/end of the renderer substream.
            width = 2
            total -= 1
        if total > 32767:
            raise vm.FormatError(f"{mnemonic} record has {total} bytes, limit is 32767")
        length = bytes([total]) if width == 2 else bytes([0x80 | (total >> 8), total & 255])
        return bytes([op.bytecode]) + length + self.data

    def string_rows(self, rows, name, kind):
        for row in rows:
            self.line = row.line
            if row.pop() != name:
                raise vm.FormatError(f"expected {name} row")
            self.string(row, kind)
            row.end()

    def counted_strings(self, rows, kind):
        if len(rows) > 65535:
            raise vm.FormatError("too many strings")
        self.uint(len(rows), 2)
        self.string_rows(rows, "STRING", kind)


@dataclass
class Statement:
    tokens: list[str]
    line: int
    labels: list[tuple[str, int]]
    rows: list[Fields] = field(default_factory=list)


@dataclass
class Document:
    encoding: str
    script: str | None
    mode: bytes
    entries: dict[int, str]
    statements: list[Statement]
    tail: int


def read_assembly(text):
    meta = {}
    entries = {}
    statements = []
    labels = []
    tail = 0
    phase = "header"
    for line_no, line in enumerate(text.splitlines(), 1):
        try:
            tokens = vm.tokenize(line)
            if not tokens:
                continue
            directive, *args = tokens
            fields = Fields(args, line_no)
            if phase == "header":
                if directive == ".entry":
                    index = vm.number(fields.pop(), 2)
                    if index != len(entries):
                        raise vm.FormatError(".entry slots must be consecutive from zero")
                    entries[index] = require_label(fields.pop())
                elif directive == ".code":
                    phase = "code"
                elif directive in (".encoding", ".script", ".mode"):
                    if directive in meta:
                        raise vm.FormatError(f"duplicate {directive}")
                    if directive == ".mode":
                        meta[directive] = bytes(vm.number(fields.pop(), 1) for _ in range(4))
                    elif directive == ".script":
                        units = vm.unquote(fields.pop())
                        if any(not isinstance(unit, str) or unit == "\n" for unit in units):
                            raise vm.FormatError(".script requires a plain filename")
                        filename = "".join(units)
                        if any(char in filename for char in '/\\:<>|?*"') or not filename.lower().endswith(".isf"):
                            raise vm.FormatError(".script must contain a local .ISF filename")
                        meta[directive] = filename
                    else:
                        meta[directive] = vm.encoding_name(fields.pop())
                else:
                    raise vm.FormatError(f"unexpected header directive {directive!r}")
                fields.end()
            elif phase == "code" and directive == "|":
                if not statements or labels:
                    raise vm.FormatError("continuation without a preceding instruction")
                statements[-1].rows.append(fields)
            elif phase == "code" and directive.endswith(":"):
                labels.append((require_label(directive[:-1]), line_no))
                fields.end()
            elif phase == "code" and directive == ".tail_zero":
                tail = vm.number(fields.pop())
                if tail != 6 or labels:
                    raise vm.FormatError("expected an unlabeled six-byte ISF tail")
                fields.end()
                phase = "tail"
            elif phase in ("code", "tail") and directive == ".end_code":
                if labels:
                    raise vm.FormatError("label does not name an instruction")
                fields.end()
                phase = "end"
            elif phase == "code" and not directive.startswith("."):
                statements.append(Statement(tokens, line_no, labels))
                labels = []
            else:
                raise vm.FormatError(f"unexpected token {directive!r}")
        except vm.FormatError as error:
            raise vm.FormatError(f"line {line_no}: {error}") from None
    if phase != "end":
        raise vm.FormatError("missing .end_code")
    if ".mode" not in meta or ".encoding" not in meta:
        raise vm.FormatError(".mode and .encoding are required")
    return Document(meta[".encoding"], meta.get(".script"), meta[".mode"], entries, statements, tail)


def assemble(text, encoding=None):
    return assemble_document(read_assembly(text), encoding)


def assemble_document(document, encoding=None):
    target = vm.encoding_name(encoding) if encoding is not None else document.encoding
    preserve_forms = target == document.encoding and not (encoding is not None and target == "gbk")
    labels = {}
    code = bytearray()
    for statement in document.statements:
        for name, line in statement.labels:
            if name in labels:
                raise vm.FormatError(f"line {line}: duplicate label {name!r}")
            labels[name] = len(code)
        mnemonic, *arguments = statement.tokens
        build = Encode(document.entries, document.encoding, target, preserve_forms)
        try:
            code.extend(build.body(mnemonic, Fields(arguments, statement.line), statement.rows))
        except vm.FormatError as error:
            raise vm.FormatError(f"line {build.line}: {mnemonic}: {error}") from None
    entry_table = bytearray()
    for index, label in document.entries.items():
        if label not in labels:
            raise vm.FormatError(f".entry {index} refers to undefined label {label!r}")
        entry_table.extend(struct.pack("<I", labels[label]))
    return b"HITOMI" + struct.pack("<I", 8 + len(entry_table)) + document.mode + entry_table + code + bytes(document.tail)


def default_name(path):
    if path.name.lower().endswith(".asm.txt"):
        return path.name[:-8]
    return path.stem


def output_jobs(inputs, out):
    jobs = []
    directory = len(inputs) > 1 or any(path.is_dir() for path in inputs) or (out and out.is_dir())
    for path in inputs:
        if path.is_dir():
            path = path.resolve()
            members = sorted(member for member in path.rglob("*") if member.is_file()
                             and (member.name.lower().endswith(".asm.txt") or member.name.lower() == "asm.txt"))
            if not members:
                raise vm.FormatError(f"no asm.txt or *.asm.txt files in {path}")
            dest = out or path.with_name(path.name + "_rebuild")
            for member in members:
                try:
                    document = read_assembly(member.read_text(encoding="utf-8-sig"))
                except ValueError as error:
                    raise vm.FormatError(f"{member}: {error}") from None
                filename = document.script or default_name(member) + ".ISF"
                directory_path = dest / member.relative_to(path).parent
                jobs.append((member, directory_path / filename))
        elif path.is_file():
            name = default_name(path) + ".rebuild"
            dest = (out / name if directory else out) if out else path.with_name(name)
            jobs.append((path, dest))
        else:
            raise vm.FormatError(f"input does not exist: {path}")
    vm.safe_outputs(jobs)
    return jobs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, metavar="ASM_OR_DIRECTORY")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--encoding", help="output character encoding (defaults to .encoding)")
    args = parser.parse_args(argv)
    source = None
    try:
        encoding = vm.encoding_name(args.encoding) if args.encoding else None
        jobs = output_jobs(args.inputs, args.output)
        for source, destination in jobs:
            data = assemble(source.read_text(encoding="utf-8-sig"), encoding)
            vm.write_atomic(destination, data)
        print(f"Assembled {len(jobs)} file(s).")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{source or 'assembler'}: {error}\n")


if __name__ == "__main__":
    main()
