"""Assemble UTF-8 listings into RSA SD scripts and MS.MHU settings."""

import re
import struct
from hashlib import sha256

from opcodelist import (
    CODE_FORMAT, CONDITIONAL_JUMPS, DEFAULT_ENCODING, LABEL, METADATA_OPCODE,
    MHU_FORMAT, MNEMONICS, NO_CALL_TARGET,
    FormatError, choose_lzss_tokens, codec_name, condition_words, find_companion,
    mhu_name_fields, number, pack_lzss, read_mhu, run_cli, segment_kind,
    unquote_bytes, unquote_lines,
)


TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[^\s";]+')


def tokenize(line):
    tokens = []
    cursor = 0
    while cursor < len(line):
        if line[cursor].isspace():
            cursor += 1
            continue
        if line[cursor] == ";":
            break
        match = TOKEN.match(line, cursor)
        if not match:
            raise FormatError("invalid token or unterminated string")
        tokens.append(match[0])
        cursor = match.end()
        if cursor < len(line) and not (line[cursor].isspace() or line[cursor] == ";"):
            raise FormatError("expected whitespace between fields")
    return tokens


def word(value):
    if not 0 <= value <= 0xFFFF:
        raise FormatError(f"word or record count out of u16 range: {value}")
    return struct.pack("<H", value)


def dword(value):
    if not 0 <= value <= 0xFFFFFFFF:
        raise FormatError(f"offset outside u32 range: {value}")
    return struct.pack("<I", value)


def arity(args, expected):
    if len(args) != expected:
        raise FormatError(f"expected {expected} operand(s), found {len(args)}")


class Assembler:
    def __init__(self, chosen_encoding):
        self.override = chosen_encoding
        self.encoding = DEFAULT_ENCODING
        self.declared_encoding = False
        self.output = bytearray()
        self.labels = {}
        self.relocations = []
        self.block = None
        self.count_offset = 0
        self.count = 0
        self.phase = "format"
        self.last_opcode = None
        self.line = 0

    def add_target(self, target, *, allow_next=False):
        if allow_next and target == "NEXT":
            self.output.extend(dword(NO_CALL_TARGET))
            return
        if not LABEL.fullmatch(target):
            raise FormatError(f"expected code label, got {target!r}")
        self.relocations.append((len(self.output), target, self.line))
        self.output.extend(dword(0))

    def string(self, token):
        return unquote_bytes(token, self.override or self.encoding)

    def start_block(self, schema):
        self.block = schema
        self.count_offset = len(self.output)
        self.count = 0
        self.output.extend(word(0))

    def instruction(self, opcode, args):
        schema = opcode.operands
        if self.last_opcode == 58 and opcode.value not in CONDITIONAL_JUMPS:
            raise FormatError("IF must be followed by JMP or JMP_ALT")
        if opcode.value == METADATA_OPCODE and len(self.output) in self.labels.values():
            raise FormatError("code labels cannot point to resource metadata")
        if opcode.value == METADATA_OPCODE and not self.output:
            raise FormatError("entry point must be a code instruction")
        self.output.extend(word(opcode.value))
        self.last_opcode = opcode.value
        if schema == "I":
            for value in condition_words(args):
                self.output.extend(word(0x8000 | value))
        elif schema in {"T", "C", "J"}:
            arity(args, int(schema == "J"))
            if schema == "J":
                self.output.extend(word(number(args[0], 16)))
            self.start_block(schema)
        else:
            arity(args, len(schema))
            for kind, arg in zip(schema, args, strict=True):
                if kind == "W":
                    self.output.extend(word(number(arg, 16)))
                elif kind == "D":
                    self.output.extend(dword(number(arg, 32)))
                elif kind == "S":
                    self.output.extend(self.string(arg) + b"\0")
                else:
                    self.add_target(arg, allow_next=(opcode.value == 31))

    def block_line(self, command, args):
        if command == ".end":
            arity(args, 0)
            self.output[self.count_offset:self.count_offset + 2] = word(self.count)
            self.block = None
        elif self.block == "T":
            is_voice = command == "VOICE"
            arity(args, 3 if is_voice else 1)
            segments = (unquote_lines(args[0], self.override or self.encoding)
                        if command == "LINE" else [self.string(args[0])])
            for data in segments:
                if (kind := segment_kind(data)) != command:
                    raise FormatError(f"encoded message segment requires {kind}, got {command}")
                self.output.extend(data + b"\0")
            if is_voice:
                self.output.extend(word(number(args[1], 16)))
                self.output.extend(dword(number(args[2], 32)))
            self.count += len(segments)
        elif self.block == "C" and command == "OPTION":
            arity(args, 1)
            self.output.extend(self.string(args[0]) + b"\0")
            self.count += 1
        elif self.block == "J" and command == "TARGET" and args:
            for label in args:
                self.add_target(label)
            self.count += len(args)
        else:
            expected = "OPTION" if self.block == "C" else "TARGET"
            raise FormatError(f"expected {expected} or .end")

    def consume(self, tokens):
        command, *args = tokens
        if self.phase == "format":
            if tuple(tokens) != CODE_FORMAT:
                raise FormatError("expected .format RSA_SD 1")
            self.phase = "header"
        elif self.phase == "header":
            if command == ".encoding" and not self.declared_encoding:
                arity(args, 1)
                self.encoding = codec_name(args[0])
                self.declared_encoding = True
            elif command == ".code":
                arity(args, 0)
                self.phase = "code"
            else:
                raise FormatError("expected .encoding or .code")
        elif self.phase == "done":
            raise FormatError("unexpected content after .end_code")
        elif self.block is not None:
            self.block_line(command, args)
        elif command == ".end_code":
            arity(args, 0)
            if self.last_opcode == 58:
                raise FormatError("IF must be followed by a jump")
            self.phase = "done"
        elif command.endswith(":"):
            arity(args, 0)
            label = command[:-1]
            if label == "NEXT" or not LABEL.fullmatch(label):
                raise FormatError(f"invalid label {label!r}")
            if label in self.labels:
                raise FormatError(f"duplicate label {label}")
            self.labels[label] = len(self.output)
        elif command in MNEMONICS:
            self.instruction(MNEMONICS[command], args)
        else:
            raise FormatError(f"unknown instruction or directive {command!r}")

    def assemble(self, text):
        # Split on physical lines only. Unicode line separators are byte escapes in generated text.
        for self.line, source in enumerate(text.split("\n"), 1):
            try:
                tokens = tokenize(source)
                if tokens:
                    self.consume(tokens)
            except FormatError as exc:
                raise FormatError(f"line {self.line}: {exc}") from exc
        if self.phase != "done":
            raise FormatError("unfinished assembly or missing .end_code")
        if not self.output:
            raise FormatError("empty SD script")
        for label, offset in self.labels.items():
            if offset == len(self.output):
                raise FormatError(f"label {label} at EOF does not precede an instruction")
        for slot, target, line in self.relocations:
            if target not in self.labels:
                raise FormatError(f"line {line}: undefined label {target}")
            self.output[slot:slot + 4] = dword(self.labels[target])
        return bytes(self.output)


class MhuAssembler:
    def __init__(self, encoding):
        self.override = encoding
        self.encoding = DEFAULT_ENCODING
        self.mode = "lzss"
        self.fields = []
        self.section = None
        self.name_index = 0
        self.body_digest = None
        self.decoded_suffix = b""
        self.pad_to = None
        self.file_tail = bytearray()
        self.original_tokens = None
        self.unused_flags = 0
        self.in_layout = False

    def consume(self, command, args):
        if self.in_layout:
            if command == ".end_lzss":
                arity(args, 0)
                self.in_layout = False
            elif command == "LITERAL":
                arity(args, 1)
                self.original_tokens.extend([None] * number(args[0], 24))
            elif command == "COPY":
                arity(args, 2)
                offset, length = number(args[0], 12), number(args[1], 5)
                if not 3 <= length <= 18:
                    raise FormatError("LZSS copy length must be between 3 and 18")
                self.original_tokens.append((offset, length))
            else:
                raise FormatError(f"invalid LZSS layout command {command!r}")
            return

        if command == ".encoding":
            arity(args, 1)
            self.encoding = codec_name(args[0])
        elif command == ".packing":
            arity(args, 1)
            if args[0] not in {"lzss", "stored"}:
                raise FormatError("expected lzss or stored MHU packing")
            self.mode = args[0]
        elif command == ".body_sha256":
            arity(args, 1)
            if not re.fullmatch(r"[0-9a-fA-F]{64}", args[0]):
                raise FormatError("invalid original MHU body SHA-256")
            self.body_digest = args[0].lower()
        elif command == ".lzss":
            arity(args, 1)
            if self.section is not None or self.original_tokens is not None:
                raise FormatError("LZSS layout must appear once outside text sections")
            self.unused_flags = number(args[0], 8)
            self.original_tokens = []
            self.in_layout = True
        elif command == ".pad_to":
            arity(args, 1)
            self.pad_to = number(args[0], 32)
        elif command in {".file_tail", ".decoded_suffix"}:
            arity(args, 1)
            data = unquote_bytes(args[0], self.override or self.encoding, allow_nul=True)
            if command == ".file_tail":
                self.file_tail.extend(data)
            elif not data.startswith(b"\0"):
                raise FormatError("decoded suffix must begin with a NUL byte")
            else:
                self.decoded_suffix = data
        elif command in {".section", ".end_section", "FIELD", "NAME"}:
            self.text_field(command, args)
        else:
            raise FormatError(f"unknown MHU directive {command!r}")

    def text_field(self, command, args):
        arity(args, 2 if command == "NAME" else 1)
        field = unquote_bytes(args[-1], self.override or self.encoding)
        trimmed = field.lstrip(b" \t")
        if b"," in field:
            raise FormatError("an MHU field cannot contain ASCII commas; use a full-width comma")
        if command == ".section":
            if self.section is not None or not trimmed.startswith(b"//") or trimmed == b"//END":
                raise FormatError("invalid MHU section header")
            self.section = trimmed
            self.name_index = 0
        elif command == ".end_section":
            if self.section is None or trimmed != b"//END":
                raise FormatError("invalid MHU section terminator")
            self.section = None
        elif trimmed.startswith(b"//"):
            raise FormatError("MHU fields cannot be section markers")
        elif self.section == b"//NameStr":
            if command != "NAME" or number(args[0], 16) != self.name_index:
                raise FormatError(f"expected NAME {self.name_index} in the name table")
            self.name_index += 1
        elif command == "NAME":
            raise FormatError("NAME must be inside the //NameStr section")
        self.fields.append(field)

    def assemble(self, rows):
        for line, tokens in rows:
            try:
                command, *args = tokens
                self.consume(command, args)
            except FormatError as exc:
                raise FormatError(f"line {line}: {exc}") from exc
        if self.section is not None or self.in_layout:
            raise FormatError("unfinished text section or LZSS layout")
        if self.pad_to is not None and self.file_tail:
            raise FormatError("use .pad_to or .file_tail, not both")
        mhu_name_fields(self.fields)
        body = b",".join(self.fields) + self.decoded_suffix
        if len(body) >= 0x40000000:
            raise FormatError("MHU decoded size exceeds header range")
        if self.mode == "stored":
            output = dword(len(body) | 0x40000000) + body
        else:
            keep_layout = self.original_tokens is not None and sha256(body).hexdigest() == self.body_digest
            tokens = self.original_tokens if keep_layout else choose_lzss_tokens(body)
            flags = self.unused_flags if keep_layout else 0
            output = dword(len(body)) + pack_lzss(body, tokens, flags)
            if read_mhu(output).body != body:
                raise FormatError("reconstructed MHU compression layout does not match its text")
        if self.pad_to is not None:
            return output.ljust(max(len(output), self.pad_to), b"\0")
        return output + bytes(self.file_tail)


def assembly_rows(text):
    for line, source in enumerate(text.split("\n"), 1):
        try:
            tokens = tokenize(source)
        except FormatError as exc:
            raise FormatError(f"line {line}: {exc}") from exc
        if tokens:
            yield line, tokens


def assemble_file(path, encoding):
    text = path.read_text(encoding="utf-8-sig")
    rows = assembly_rows(text)
    _, header = next(rows, (0, ()))
    if tuple(header) == MHU_FORMAT:
        return MhuAssembler(encoding).assemble(rows)
    return Assembler(encoding).assemble(text)


def assembly_header(source):
    with source.open(encoding="utf-8-sig") as handle:
        for line in handle:
            tokens = tokenize(line)
            if tokens:
                return tuple(tokens)
    return ()


def mhu_companion(source):
    if source.name.lower() == "ms.mhu.asm.txt" or assembly_header(source)[:2] == MHU_FORMAT[:2]:
        return None
    return find_companion(source, "MS.MHU.asm.txt")


def find_sd_source(input_directory):
    """Find a unique SD in the nearest directory with any SD files."""
    for directory in (input_directory, input_directory.parent):
        candidates = [file for file in directory.iterdir()
                      if file.suffix.casefold() == ".sd" and file.is_file()]
        if candidates:
            return candidates[0] if len(candidates) == 1 else None
    return None


def output_name(path, folder):
    suffix = ".asm.txt"
    name = path.name.lower()
    stem = path.name[:-len(suffix)] if name.endswith(suffix) else path.stem
    input_directory = path.parent.resolve()
    output_directory = folder.resolve()
    separate_folder = output_directory != input_directory
    if stem.lower().endswith(".mhu"):
        return stem if separate_folder else stem + ".rebuild"
    if separate_folder and name == "asm.txt" and assembly_header(path) == CODE_FORMAT:
        source = find_sd_source(input_directory)
        if source is not None:
            target = output_directory / source.name
            # The parent may contain another original with the same name.
            overwrites_parent = output_directory == input_directory.parent and target.exists()
            if not overwrites_parent and target.resolve() != source.resolve():
                return source.name
    if separate_folder and name.endswith(suffix) and mhu_companion(path) is not None:
        return stem + ".SD"
    return stem + ".rebuild"


if __name__ == "__main__":
    run_cli(
        __doc__, lambda name: name == "asm.txt" or name.endswith(".asm.txt"),
        output_name, assemble_file, companion=mhu_companion,
    )
