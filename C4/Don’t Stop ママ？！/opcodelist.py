"""Mp17 encoding and complete C4 scenario VM dispatch tables."""

import argparse
import codecs
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from tempfile import NamedTemporaryFile
import unicodedata


MAGIC = b"Mp17"
HEADER_SIZE = 16
FILE_LIMIT = 0x10000
POOL_XOR = 0x24
GLOBAL_BASE = 256
CHOICE_LIMIT = 67


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class Opcode:
    mnemonic: str
    operands: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    variant: str = ""

    @property
    def length(self):
        """Fixed prefix length. Each group extends it to its terminator."""
        return 1 + sum(WIDTHS[kind] for kind in self.operands)


WIDTHS = {"target": 2, "text": 2, "counter": 2, "i16": 2, "u8": 1}
OPCODES = {
    0x00: Opcode("NOP"),
    0x01: Opcode("OFFER_CHOICE", ("target", "text"), ("when",), "resume at following instruction on selection"),
    0x03: Opcode("OFFER_CHOICE_ALT", ("target", "text"), ("when",), "same VM behavior with distinct wire opcode"),
    0x04: Opcode("SHOW_IF_COUNT", ("i16", "u8", "text"), variant="negative counter selects system slot 1023"),
    0x05: Opcode("SHOW_UPDATE_IF_COUNT", ("i16", "u8", "text"), ("update",), "negative counter selects system slot 1023"),
    0x06: Opcode("DEFER_IF", ("text",), ("when", "update"), "false skips one byte following update group"),
    0x07: Opcode("UPDATE_SHOW_IF", ("text",), ("when", "update")),
    0x08: Opcode("OPEN_CHOICE_GROUP"),
    0x09: Opcode("RESET_COUNT_AT", ("counter", "u8")),
    0x0A: Opcode("SHOW_IF_COUNT_NO_INCREMENT", ("counter", "u8", "text")),
    0x0B: Opcode("EVAL_STORE", groups=("expr",)),
    0xFE: Opcode("COMMIT_BLOCK", variant="restart or open scenario requested by %j"),
    0xFF: Opcode("CHOOSE", variant="resume chosen continuation, cancel or fall through"),
}
OPCODES_BY_NAME = {op.mnemonic: (byte, op) for byte, op in OPCODES.items()}

# Value operands: s16 >= 0 is an immediate, s16 < 0 is variable ~value.
# Update targets use the same negative variable encoding, with no immediate.
SUBOPS = {
    "when": {
        0x00: ("END_WHEN", ()),
        0x01: ("GE", ("value", "value")),
        0x02: ("GT", ("value", "value")),
        0x03: ("LE", ("value", "value")),
        0x04: ("LT", ("value", "value")),
        0x05: ("EQ", ("value", "value")),
        0x06: ("NE", ("value", "value")),
        0x08: ("AND", ()),
        0x09: ("OR", ()),
    },
    "update": {
        0x00: ("END_UPDATE", ()),
        0x01: ("SET", ("var", "value")),
        0x02: ("ADD", ("var", "value")),
        0x03: ("SUB", ("var", "value")),
    },
    "expr": {
        0xFDFA: ("MOD", ()),
        0xFDFB: ("DIV", ()),
        0xFDFC: ("MUL", ()),
        0xFDFD: ("SUB", ()),
        0xFDFE: ("ADD", ()),
        0xFDFF: ("STORE", ("index",)),
        # All other words push an immediate/variable. PUSH emits only its operand.
        None: ("PUSH", ("value",)),
    },
}
SUBOPS_BY_NAME = {
    group: {name: (value, operands) for value, (name, operands) in subops.items()}
    for group, subops in SUBOPS.items()
}
TERMINATORS = {"when": 0, "update": 0, "expr": 0xFDFF}

# Render-stream commands handled separately from the VM instruction stream.
# The engine folds the command letter's case. Preserve wire case in the editor.
TEXT_CONTROLS = {
    "e": ("engine_event", "args"),
    "f": ("stop_music", "args"),
    "g": ("set_graphic", "variant"),
    "i": ("initialize_ui", "none"),
    "j": ("request_scenario", "args"),
    "k": ("wait_for_advance", "none"),
    "l": ("open_load_dialog", "none"),
    "m": ("play_music", "args"),
    "n": ("newline", "none"),
    "o": ("set_overlay", "args"),
    "q": ("quit", "none"),
    "r": ("break_page_or_line", "none"),
    "s": ("set_flag", "args"),
    "v": ("set_voice", "args"),
    "w": ("wait_timer", "args"),
    "y": ("clear_message", "none"),
}
GRAPHIC_VARIANTS = {
    ",": "set_full_graphic", "b": "set_background", "c": "set_picture_and_mark_gallery",
    "f": "set_foreground", "n": "set_named_graphic",
}
NEWLINE = "%N"
LINE_BREAK_CONTROLS = {letter for letter, (verb, _) in TEXT_CONTROLS.items()
                       if verb in ("newline", "wait_for_advance")}
GBK_SUBSTITUTIONS = {"\u266a": "\u203b", "\u30fb": "\u00b7", "\u226b": "\uff1e\uff1e"}
IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
PLACEHOLDER = re.compile(r"\{\{([\da-fA-F]{2}(?::[\da-fA-F]{2})*)\}\}", re.ASCII)
TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[^\s";]+')


def codec_name(name):
    try:
        codec = codecs.lookup(name).name
        ascii_sample = bytes(range(128))
        if ascii_sample.decode(codec) == "".join(map(chr, ascii_sample)):
            return codec
    except (LookupError, ValueError):
        pass
    raise FormatError(f"not an ASCII-compatible text encoding: {name}")


def variable(index, symbols):
    if index < GLOBAL_BASE:
        return f"$l{index}"
    offset = index - GLOBAL_BASE
    if offset < len(symbols):
        name = symbols[offset]
        if IDENT.fullmatch(name) and symbols.count(name) == 1 and not re.fullmatch(r"[lg]\d+", name):
            return f"${name}"
    return f"$g{index}"


def value_token(value, symbols):
    return variable(~value, symbols) if value < 0 else str(value)


def wire_text_fragments(raw, encoding):
    """Render whole encoded characters, never interpret a trail byte as control."""
    fragments = []
    fragment = []
    pos = 0
    while pos < len(raw):
        if (raw[pos] == 0x25 and pos + 1 < len(raw)
                and chr(raw[pos + 1]).lower() in LINE_BREAK_CONTROLS):
            control = raw[pos:pos + 2].decode("ascii")
            fragment.append(r"\n" if control == NEWLINE else control)
            fragments.append('"' + "".join(fragment) + '"')
            fragment = []
            pos += 2
            continue
        for width in range(1, min(4, len(raw) - pos) + 1):
            unit = raw[pos:pos + width]
            try:
                char = unit.decode(encoding)
            except UnicodeDecodeError:
                continue
            if len(char) == 1:
                break
        else:
            unit = raw[pos:pos + 1]
            char = ""
        if not char or unicodedata.category(char).startswith("C") or char.encode(encoding) != unit:
            fragment.append("{{" + ":".join(f"{byte:02X}" for byte in unit) + "}}")
        elif char in '\\"{':
            fragment.append("\\" + char)
        else:
            fragment.append(char)
        pos += len(unit)
    if fragment or not fragments:
        fragments.append('"' + "".join(fragment) + '"')
    return fragments


def asm_tokens(line):
    """Lex only the UTF-8 assembly grammar. A quoted semicolon is data."""
    tokens = []
    pos = 0
    while pos < len(line):
        if line[pos].isspace():
            pos += 1
            continue
        if line[pos] == ";":
            break
        match = TOKEN.match(line, pos)
        if not match:
            raise FormatError("unterminated or invalid token")
        tokens.append(match[0])
        pos = match.end()
        if pos < len(line) and not line[pos].isspace() and line[pos] != ";":
            raise FormatError("expected whitespace between tokens")
    return tokens


def text_tokens(token):
    if len(token) < 2 or not (token.startswith('"') and token.endswith('"')):
        raise FormatError("expected a double-quoted text fragment")
    content = token[1:-1]
    chunks = []
    pos = 0
    while pos < len(content):
        if content[pos] == "\\":
            escape = content[pos + 1:pos + 2]
            if escape == "n":
                chunks.append(NEWLINE)
            elif escape in ('\\', '"', '{'):
                chunks.append(escape)
            else:
                raise FormatError(f"invalid text escape \\{escape}")
            pos += 2
        elif content.startswith("{{", pos):
            match = PLACEHOLDER.match(content, pos)
            if not match:
                raise FormatError("invalid byte placeholder")
            chunks.append(bytes.fromhex(match[1].replace(":", " ")))
            pos = match.end()
        else:
            char = content[pos]
            if unicodedata.category(char).startswith("C"):
                raise FormatError("control/private character must use a byte placeholder")
            chunks.append(char)
            pos += 1
    return chunks


def encode_text(chunks, encoding, substitutions=None):
    result = bytearray()
    for chunk in chunks:
        if isinstance(chunk, bytes):
            result.extend(chunk)
            continue
        for char in chunk:
            if substitutions is not None and char in GBK_SUBSTITUTIONS:
                substitutions[char] += 1
                char = GBK_SUBSTITUTIONS[char]
            result.extend(char.encode(encoding))
    if 0 in result:
        raise FormatError("NUL is the implicit terminator and cannot occur inside an Mp17 string")
    return bytes(result)


def cli(description, argv=None):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("inputs", nargs="+", type=Path, metavar="FILE_OR_DIR")
    parser.add_argument("-o", "--output", metavar="FILE_OR_DIR")
    parser.add_argument("--encoding", metavar="CODEC")
    return parser.parse_args(argv)


def jobs(args, input_suffix, default_suffix, directory_suffix):
    files = []
    batch = len(args.inputs) > 1
    for path in args.inputs:
        if path.is_dir():
            batch = True
            members = sorted(p for p in path.iterdir()
                             if p.is_file() and (p.name.lower().endswith(input_suffix)
                                                 or p.name.lower() == input_suffix.removeprefix(".")))
            if not members:
                raise FormatError(f"{path}: no {input_suffix} inputs")
            files.extend(members)
        elif path.is_file():
            files.append(path)
        else:
            raise FormatError(f"{path}: input does not exist")
    files = list(dict.fromkeys(path.resolve() for path in files))
    output = Path(args.output) if args.output else None
    out_dir = output is not None and (batch or output.is_dir() or args.output.endswith(("/", "\\")))
    if out_dir and output.exists() and not output.is_dir():
        raise FormatError(f"{output}: batch output must be a directory")
    targets = set()
    for path in files:
        filename = path.name
        base = filename[:-len(input_suffix)] if filename.lower().endswith(input_suffix) else path.stem
        if out_dir:
            target = output / (base + directory_suffix)
        elif output is not None:
            target = output
        else:
            target = path.with_name(base + default_suffix)
        resolved = target.resolve()
        if resolved in files or resolved in targets:
            raise FormatError(f"{target}: output collides with an input or another output")
        targets.add(resolved)
        yield path, target


def write_output(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def error_exit(error):
    print(f"error: {error}", file=sys.stderr)
    return 1
