"""Disassemble RSA SD scripts and MS.MHU settings into UTF-8 assembly."""

import re
import struct
import sys
from dataclasses import dataclass
from itertools import groupby

from opcodelist import (
    CODE_FORMAT, CONDITIONAL_JUMPS, DEFAULT_ENCODING, METADATA_OPCODE, NO_CALL_TARGET, OPCODES,
    FormatError, condition_tokens, find_companion, format_mhu, mhu_name_fields,
    quote_bytes, read_mhu, run_cli, segment_kind,
)


NAME_INDEX = re.compile(rb"[Nn]\s*([+-]?[0-9]{1,3})(?![0-9])")


def mhu_companion(source):
    if source.suffix.lower() != ".mhu":
        return find_companion(source, "MS.MHU", parent=True)
    return None


def load_speaker_names(source, encoding=DEFAULT_ENCODING):
    resource = mhu_companion(source)
    if resource is None:
        return ()
    try:
        content = read_mhu(resource.read_bytes()).body.partition(b"\0")[0]
        names = mhu_name_fields(content.split(b","))
        return tuple(quote_bytes(field, encoding)[1:-1].strip() for field in names)
    except (OSError, ValueError) as exc:
        print(f"{resource}: could not read speaker names ({exc})", file=sys.stderr)
        return ()


def speaker_name(text, names):
    match = NAME_INDEX.match(text)
    if match is None:
        return ""
    index = int(match[1]) & 0xFF
    return names[index] if 0 < index < len(names) else ""


@dataclass(frozen=True)
class Record:
    offset: int
    opcode: int
    values: tuple


class Reader:
    def __init__(self, data):
        self.data = data
        self.position = 0

    def peek_word(self):
        return self._number("<H", 2)

    def _number(self, layout, size):
        if self.position + size > len(self.data):
            raise FormatError(f"truncated u{size * 8} at 0x{self.position:08X}")
        return struct.unpack_from(layout, self.data, self.position)[0]

    def word(self):
        value = self.peek_word()
        self.position += 2
        return value

    def dword(self):
        value = self._number("<I", 4)
        self.position += 4
        return value

    def string(self):
        end = self.data.find(b"\0", self.position)
        if end < 0:
            raise FormatError(f"unterminated string at 0x{self.position:08X}")
        value = self.data[self.position:end]
        self.position = end + 1
        return value

    def message_segment(self):
        text = self.string()
        if segment_kind(text) == "VOICE":
            return text, self.word(), self.dword()
        return (text,)

    def operands(self, schema):
        if schema == "I":
            words = []
            while self.peek_word() & 0x8000:
                words.append(self.word() & 0x7FFF)
            if self.peek_word() not in CONDITIONAL_JUMPS:
                raise FormatError("IF must be followed by JMP or JMP_ALT")
            return tuple(words)
        if schema == "T":
            return tuple(self.message_segment() for _ in range(self.word()))
        if schema == "C":
            return tuple(self.string() for _ in range(self.word()))
        if schema == "J":
            variable = self.word()
            return variable, tuple(self.dword() for _ in range(self.word()))
        readers = {"W": self.word, "D": self.dword, "A": self.dword, "S": self.string}
        return tuple(readers[field]() for field in schema)


def parse(data):
    if not data:
        raise FormatError("empty SD script")
    reader = Reader(data)
    records = []
    while reader.position < len(data):
        offset = reader.position
        try:
            value = reader.word()
            if value not in OPCODES:
                raise FormatError(f"unknown opcode 0x{value:04X}")
            schema = OPCODES[value].operands
            operands = reader.operands(schema)
            if schema == "I":
                condition_tokens(operands)
        except FormatError as exc:
            raise FormatError(f"record at 0x{offset:08X}: {exc}") from exc
        records.append(Record(offset, value, operands))
    return records


def get_labels(records):
    boundaries = {record.offset for record in records if record.opcode != METADATA_OPCODE}
    if 0 not in boundaries:
        raise FormatError("entry point is not a code instruction")
    labels = {0: "loc_00000000"}
    for record in records:
        schema = OPCODES[record.opcode].operands
        if schema == "J":
            destinations = record.values[1]
        elif schema == "A" and not (record.opcode == 31 and record.values[0] == NO_CALL_TARGET):
            destinations = record.values
        else:
            continue
        for target in destinations:
            if target not in boundaries:
                raise FormatError(f"0x{record.offset:08X}: target 0x{target:08X} is not a code boundary")
            labels[target] = f"loc_{target:08X}"
    return labels


def format_instruction(record, labels, encoding, names=()):
    opcode = OPCODES[record.opcode]
    schema = opcode.operands
    values = record.values
    instruction = "    " + opcode.mnemonic
    if schema == "T":
        yield instruction
        for kind, segments in groupby(values, key=lambda segment: segment_kind(segment[0])):
            if kind == "LINE":
                quoted = r"\n".join(quote_bytes(segment[0], encoding)[1:-1] for segment in segments)
                yield f'        LINE "{quoted}"'
                continue
            for text, *audio in segments:
                segment = f"        {kind} {quote_bytes(text, encoding)}"
                if audio:
                    segment += f" {audio[0]} 0x{audio[1]:08X}"
                if kind == "NAME" and (name := speaker_name(text, names)):
                    segment += f"  ; {name}"
                yield segment
        yield "    .end"
    elif schema == "C":
        yield instruction
        for option in values:
            yield "        OPTION " + quote_bytes(option, encoding)
        yield "    .end"
    elif schema == "J":
        yield f"{instruction} {values[0]}"
        targets = values[1]
        for start in range(0, len(targets), 6):
            yield "        TARGET " + " ".join(labels[target] for target in targets[start:start + 6])
        yield "    .end"
    elif schema == "I":
        yield " ".join([instruction, *condition_tokens(values)])
    else:
        operands = []
        for kind, value in zip(schema, values, strict=True):
            if kind == "S":
                operands.append(quote_bytes(value, encoding))
            elif kind == "A":
                operands.append("NEXT" if value == NO_CALL_TARGET else labels[value])
            elif kind == "D":
                operands.append(f"0x{value:08X}")
            else:
                operands.append(str(value))
        yield " ".join([instruction, *operands])


def disassemble(path, encoding):
    records = parse(path.read_bytes())
    labels = get_labels(records)
    names = load_speaker_names(path, encoding)
    lines = ["; RSA SD script", " ".join(CODE_FORMAT), f".encoding {encoding}", ".code"]
    for record in records:
        if record.offset in labels:
            lines.extend(("", labels[record.offset] + ":"))
        if record.opcode == METADATA_OPCODE:
            lines.extend(("", "    ; Inline resource metadata"))
        lines.extend(format_instruction(record, labels, encoding, names))
    lines.extend(("", ".end_code", ""))
    return "\n".join(lines).encode("utf-8")


def disassemble_file(path, encoding):
    if path.suffix.lower() == ".mhu":
        return format_mhu(path.read_bytes(), encoding)
    return disassemble(path, encoding)


def output_name(path, _folder):
    if path.name.lower() == "ms.mhu":
        return "MS.MHU.asm.txt"
    if path.suffix.lower() == ".mhu":
        return path.name + ".asm.txt"
    return path.stem + ".asm.txt"


if __name__ == "__main__":
    run_cli(
        __doc__, lambda name: name.endswith(".sd") or name == "ms.mhu",
        output_name, disassemble_file, default_encoding=DEFAULT_ENCODING, companion=mhu_companion,
    )
