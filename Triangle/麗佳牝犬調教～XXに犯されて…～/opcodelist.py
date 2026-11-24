"""RSA.EXE SD script layouts and shared lossless text/CLI utilities."""

import argparse
import codecs
import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from hashlib import sha256
from itertools import groupby
from pathlib import Path


class FormatError(ValueError):
    """The input does not match the supported script or assembly format."""


@dataclass(frozen=True)
class Opcode:
    value: int
    mnemonic: str
    operands: str


# W: u16, D: u32 resource offset, S: NUL string, A: u32 code address.
# I: IF words, T: message segments, C: options, J: indexed code addresses.
# See vm_analysis.md for the dispatch evidence and complete operand layouts.
_OPCODE_ROWS = """
  1 RESET_SCENE                 W
  5 OPEN_MOVIE                  SWWW
  6 READ_SCENE_WORDS            WWW
  7 WAIT_INPUT_RESULT           WW
  8 SKIP_WORD                   W
  9 SCROLL_BACKGROUND           W
 10 TEST_SCROLL_BACKGROUND      W
 11 RESET_HISTORY_AND_YIELD     -
 12 SET_TEXT_COLORS             WWWWWW
 13 GET_DISPLAY_STATE           W
 14 SET_DISPLAY_MODE            W
 15 SET_EFFECT_FLAG             W
 16 FADE_SCREEN                 WWW
 17 WAIT_FADE                   W
 18 SET_INPUT_EFFECT_MODE       W
 21 OPEN_SYSTEM_DIALOG          -
 22 CAPTURE_RECTANGLE           WWWWWWW
 23 TRANSITION_RECTANGLE        WWWWWWW
 24 SET_WINDOW_INPUT            W
 25 SKIP_SIX_WORDS              WWWWWW
 26 SET_FONT                    WWW
 27 DRAW_RESOURCE_PAIR          SSWWWW
 28 TRACK_TRANSITION            W
 30 RUN_SYSTEM_ACTION           W
 31 CALL                        A
 32 JMP                         A
 33 DRAW_BACKGROUND_RECT        SWWWWWWW
 34 DRAW_OVERLAY_RECT           SWWWWWWW
 35 DRAW_RESOURCE_AT            SWWWW
 36 DRAW_BACKGROUND             SWWW
 37 DRAW_LAYER_PAIR             SSWWW
 38 DRAW_BACKGROUND_EFFECT      SWWW
 39 DRAW_LAYER_PAIR_EFFECT      SSWWW
 40 DRAW_THREE_RESOURCES        SSSWWWWW
 41 DRAW_RESOURCE_EFFECT        SWWWWWWWWW
 42 DRAW_FOUR_RESOURCES         SSSSWWWWWW
 43 DRAW_FOREGROUND             SWWW
 44 DRAW_LAYER_PAIR_SIMPLE      SSWWW
 45 DRAW_SCROLLING_BACKGROUND   SWWWWWWWWW
 46 REFRESH_DISPLAY             -
 47 DRAW_RESOURCE_OFFSET        SWWWW
 48 DRAW_PAIR_OFFSET            SSWWWW
 49 DRAW_PAIR_SWITCH            SSWWWW
 50 DRAW_AND_STORE_RESULT       SWWWWWWWWWWW
 51 DRAW_PAIR_AND_STORE_RESULT  SSWWWWWWWWWWW
 52 DRAW_BLACK_REGION_AND_STORE WWWWWWWWWWW
 53 SET_BACKDROP_MODE           W
 54 REFRESH_TEXT_WINDOW         -
 55 CLEAR_TEXT_WINDOW           -
 56 TEST_INPUT_SETTING          WW
 57 RESET_INPUT_SETTING         W
 58 IF                          I
 59 JMP_ALT                     A
 60 MARK_SCENE                  W
 61 READ_SCENE_COUNTER          WW
 62 RESUME_SCENE                -
 63 SET_SYSTEM_BUTTON_STATE     W
 64 CLEAR_RESUME_OPCODE         -
 65 SET_TEXT_METRICS            WW
 66 TEST_BIT                    WW
 67 ENABLE_SYSTEM_CONTROL       W
 68 ENABLE_SKIP_CONTROL         W
 69 CLEAR_MENU_STATE            -
 70 NOP                         -
 72 MESSAGE                     T
 73 CHOICES                     C
 77 FADE_SCREEN_ALT             WWW
 79 SET_PAGE_MODE               W
 80 GET_INPUT_STATUS            W
 81 MESSAGE_WAIT                -
 82 TITLE_PANEL                 -
 83 MENU_YIELD                  -
 84 WINDOW_INPUT_YIELD          -
 85 SET_MODE_TABLE_ENTRY        WW
 86 SAVE_CONTEXT                -
 87 REFRESH_SYSTEM_MENU         -
 89 SET_SELECTION_STYLE         W
 90 DRAW_TEXT_RESOURCE          WWWS
 91 MENU_INPUT_RESULT           WW
 92 NOP_ALT1                    -
 93 ENABLE_MESSAGE_CONTROL      W
 94 SET_SAVE_TITLE              S
 95 MENU_RESULT                 W
 96 MENU_WITH_FLAG              WW
 97 TEST_MENU_RESULT            W
 98 MENU_WITH_SCENE             WW
 99 GALLERY_SELECT              WW
100 OPEN_MAIN_MENU              W
101 OPEN_TITLE_MENU             W
102 SHOW_SYSTEM_MENU            WWWWWWW
103 SHOW_SYSTEM_MENU_ALT        WWWWWWW
104 OPEN_GALLERY                WW
106 OPEN_CHARACTER_MENU         WWW
107 OPEN_LOAD_MENU              W
108 OPEN_VOICE_MENU             WWW
109 SET_INPUT_MAP               WWWWW
110 CONFIG_TEXT_INPUT           WWWWWW
111 CONFIG_MESSAGE_WINDOW       WWWWWW
112 CONFIG_TEXT_STYLE           WWWWWW
113 CONFIG_SCENE_FLAGS          WWWWWW
114 CONFIG_TEXT_EFFECTS         WWWWWW
115 CONFIG_MENU_BEHAVIOR        WWWWWW
116 CONFIG_INPUT_BEHAVIOR       WWWWWW
117 CONFIG_MESSAGE_FLAGS        WWWWWW
118 CONFIG_WINDOW_LAYOUT        WWWWWW
119 CONFIG_SCREEN_LAYOUT        WWWWWWWW
121 CONFIG_UI_RESOURCES         SSWWWWWWW
122 CONFIG_GEOMETRY             WWWWWWWWWWW
123 CONFIG_MENU_LAYOUT          WWWWWWWW
124 CONFIG_BUTTON_LAYOUT_A      WWWWWW
125 CONFIG_BUTTON_LAYOUT_B      WWWWWW
126 CONFIG_BUTTON_LAYOUT_C      WWWWWW
128 DEFINE_AUDIO_RESOURCE       WWWD
129 SET_STARTUP_OPTION          W
130 SET_PLAYBACK_MODE           W
131 ENABLE_AUTO_CONTROL         W
132 SET_AUDIO_MODE              W
133 OPEN_SETTINGS_PANEL         -
134 NOP_ALT2                    -
135 RET                         -
136 ADD_VARIABLE                WW
137 SUB_VARIABLE_FLOOR_ZERO     WW
138 NOP_ALT3                    -
139 DIV_VARIABLE                WW
140 MUL_VARIABLE                WW
141 MOD_VARIABLE                WW
142 SET_VARIABLE                WW
143 TEST_RANDOM_THRESHOLD       WW
144 SELECT_WEIGHTED_INDEX       WWWW
145 SELECT_RANGE_INDEX          WWWW
146 SWITCH                      J
147 SWITCH_ALT                  J
148 PLAY_SYSTEM_VOICE           WWW
149 TIMER                       WWW
150 PLAY_RANDOM_VOICE           W
152 WAIT_VOICE_RESULT           WW
153 SET_VOICE_WAIT_MODE         W
154 CONTROL_CURSOR              W
155 TIMED_INPUT_RESULT          WWW
156 RESTORE_DRAW_STATE          -
157 UPDATE_SCENE_STATE          W
158 SCREEN_EFFECT               WWW
159 COPY_RECTANGLE              WWWWWWW
160 TRANSITION_TO_WHITE         WWWWWWW
161 CLEAR_TO_BLACK              -
162 DRAW_BASE_REGION            WWWW
163 READ_RESOURCE_PARAMETERS    SWWWW
164 DRAW_EFFECT_RESULT          WWWWWW
167 LOAD_SCRIPT                 S
168 REPLACE_BACKGROUND          SW
169 REPLACE_LAYER_PAIR          SSW
170 APPLY_SCENE_EFFECT          W
171 LOAD_BACKGROUND             S
172 SHOW_BACKGROUND_EFFECT      SW
173 SHOW_LAYER_PAIR_EFFECT      SSW
174 LOAD_FOREGROUND             S
175 LOAD_LAYER_PAIR             SS
176 REPLACE_FOREGROUND          SW
177 REPLACE_FOREGROUND_PAIR     SSW
178 WAIT_CHOICE_RESULT          W
179 UPDATE_BACKGROUND_REGION    SW
180 UPDATE_LAYER_PAIR_REGION    SSW
181 APPLY_WHITE_EFFECT          W
182 RESOURCE_METADATA           SSS
183 HALT                        -
"""
OPCODES = {}
for row in _OPCODE_ROWS.strip().splitlines():
    number, name, operands = row.split()
    opcode = Opcode(int(number), name, operands.removesuffix("-"))
    OPCODES[opcode.value] = opcode
MNEMONICS = {opcode.mnemonic: opcode for opcode in OPCODES.values()}

MESSAGE_KINDS = dict(zip(b"NVWM@nvwm", ("NAME", "VOICE", "WAIT", "PAGE", "CONTROL",
                                          "NAME", "VOICE", "WAIT", "PAGE")))
CONDITIONAL_JUMPS = frozenset((32, 59))
CODE_FORMAT = (".format", "RSA_SD", "1")
MHU_FORMAT = (".format", "RSA_MHU", "1")
DEFAULT_ENCODING = "cp932"
NO_CALL_TARGET = 0xFFFFFFFF
METADATA_OPCODE = 182
LABEL = re.compile(r"[A-Za-z_][A-Za-z_0-9]*", re.ASCII)
PLACEHOLDER = re.compile(r"\{\{([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})*)\}\}")
NUMBER = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)")
COMPARE = {2: "EQ", 3: "GT", 4: "LT", 5: "GE", 6: "LE", 7: "NE"}
COMBINE = {0: "AND", 1: "OR", 2: "END", 8: "NOT_AND", 9: "NOT_OR"}
ESCAPES = {'"': '\\"', "\\": "\\\\", "{": "\\{", "}": "\\}"}


def segment_kind(data):
    return MESSAGE_KINDS.get(data[0], "LINE") if data else "LINE"


def codec_name(name):
    try:
        codec = codecs.lookup(name).name
        ascii_sample = "\x00\n\r" + "".join(map(chr, range(32, 127)))
        if ascii_sample.encode(codec) != ascii_sample.encode("ascii"):
            raise FormatError(f"encoding {name!r} is not ASCII-compatible")
    except LookupError as exc:
        raise FormatError(f"unknown or unsupported encoding {name!r}") from exc
    return codec


def number(text, bits):
    if not NUMBER.fullmatch(text):
        raise FormatError(f"expected u{bits} integer, got {text!r}")
    value = int(text, 16 if text.lower().startswith("0x") else 10)
    if value >= 1 << bits:
        raise FormatError(f"{text} is outside u{bits} range")
    return value


def quote_bytes(data, encoding):
    """Emit printable round-trippable characters and group opaque byte tokens."""
    parts = ['"']
    opaque = []
    position = 0
    while position < len(data):
        for width in range(1, min(4, len(data) - position) + 1):
            chunk = data[position:position + width]
            try:
                char = chunk.decode(encoding)
            except UnicodeDecodeError:
                continue
            if len(char) == 1:
                break
        else:
            char, chunk = "", data[position:position + 1]
        visible = char and (char == "\u3000" or char.isprintable())
        if visible and not unicodedata.category(char).startswith("C") and char.encode(encoding) == chunk:
            if opaque:
                parts.append("{{" + ":".join(opaque) + "}}")
                opaque.clear()
            parts.append(ESCAPES.get(char, char))
        else:
            for value in chunk:
                if len(opaque) == 8:
                    parts.append("{{" + ":".join(opaque) + "}}")
                    opaque.clear()
                opaque.append(f"{value:02X}")
        position += len(chunk)
    if opaque:
        parts.append("{{" + ":".join(opaque) + "}}")
    parts.append('"')
    return "".join(parts)


def unquote_bytes(token, encoding, *, allow_nul=False):
    return _unquote(token, encoding, grouped=False, allow_nul=allow_nul)[0]


def unquote_lines(token, encoding):
    """Treat an unescaped \n marker as a boundary between physical message segments."""
    return _unquote(token, encoding, grouped=True)


def _unquote(token, encoding, *, grouped, allow_nul=False):
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        raise FormatError("expected a double-quoted string")
    content = token[1:-1]
    output = bytearray()
    lines = []
    index = 0
    while index < len(content):
        char = content[index]
        if char == "\\":
            index += 1
            if grouped and content[index:index + 1] == "n":
                lines.append(bytes(output))
                output.clear()
                index += 1
                continue
            if index >= len(content) or content[index] not in ESCAPES:
                raise FormatError("invalid string escape; use {{XX}} for a byte")
            char = content[index]
        elif content.startswith("{{", index):
            match = PLACEHOLDER.match(content, index)
            if not match:
                raise FormatError("invalid byte placeholder; use {{XX}} or {{XX:YY}}")
            values = bytes(int(byte, 16) for byte in match[1].split(":"))
            if not allow_nul and 0 in values:
                raise FormatError("a NUL-terminated field cannot contain embedded NUL bytes")
            output.extend(values)
            index = match.end()
            continue
        try:
            encoded = char.encode(encoding)
            if not allow_nul and 0 in encoded:
                raise FormatError("a NUL-terminated field cannot contain embedded NUL bytes")
            output.extend(encoded)
        except UnicodeEncodeError as exc:
            raise FormatError(f"{encoding} cannot encode {char!r} (U+{ord(char):04X})") from exc
        index += 1
    lines.append(bytes(output))
    return lines


def condition_roles(words):
    """Yield logical field types without losing flags ignored by the evaluator."""
    role = "flag"
    for word in words:
        if role == "flag":
            yield "flag"
            role = "operator"
        elif role == "rhs":
            yield "var" if word & 0x4000 else "imm"
            role = "join"
        elif role == "operator" and word & 0x10:
            yield "cmp"
            role = "rhs"
        else:
            yield "join"
            role = "flag"
    if role == "rhs":
        raise FormatError("condition comparison is missing its right operand")


def condition_tokens(words):
    tokens = []
    for role, word in zip(condition_roles(words), words, strict=True):
        if role == "cmp":
            value = COMPARE.get(word ^ 0x10, hex(word))
        elif role == "join":
            value = COMBINE.get(word, hex(word))
        else:
            value = str(word & 0x3FFF if role == "var" else word)
        tokens.append(f"{role}={value}")
    return tokens


def condition_words(tokens):
    aliases = {"cmp": {name: value | 0x10 for value, name in COMPARE.items()},
               "join": {name: value for value, name in COMBINE.items()}}
    words = []
    roles = []
    for token in tokens:
        role, equals, value = token.partition("=")
        if not equals or role not in {"flag", "cmp", "join", "var", "imm"}:
            raise FormatError(f"invalid condition field {token!r}")
        value_alias = aliases.get(role, {}).get(value)
        word = value_alias if value_alias is not None else number(value, 14 if role == "var" else 15)
        words.append(word | 0x4000 if role == "var" else word)
        roles.append(role)
    if list(condition_roles(words)) != roles:
        raise FormatError("condition field types do not match the VM expression layout")
    return words


LZSS_WINDOW = 4096
LZSS_START = LZSS_WINDOW - 18
LZSS_MASK = LZSS_WINDOW - 1


@dataclass(frozen=True)
class MhuResource:
    body: bytes
    tail: bytes
    mode: str
    unused_flags: int = 0
    # None represents a literal. A pair is (window offset, encoded copy length).
    tokens: tuple = ()


def read_mhu(data):
    """Read the two MHU layouts supported by this resource editor."""
    if len(data) < 4:
        raise FormatError("truncated MHU header")
    size = int.from_bytes(data[:4], "little")
    payload = data[4:]
    if size & 0x80000000:
        raise FormatError("unsupported RLE MHU resource")
    if size & 0x40000000:
        size &= 0x3FFFFFFF
        if size > len(payload):
            raise FormatError("truncated stored MHU data")
        return MhuResource(payload[:size], payload[size:], "stored")

    window = bytearray(LZSS_WINDOW)
    write_pos = LZSS_START
    output = bytearray()
    tokens = []
    cursor = 0
    unused_flags = 0

    def read_byte():
        nonlocal cursor
        if cursor >= len(payload):
            raise FormatError("truncated LZSS MHU data")
        value = payload[cursor]
        cursor += 1
        return value

    def append(value):
        nonlocal write_pos
        output.append(value)
        window[write_pos] = value
        write_pos = (write_pos + 1) & LZSS_MASK

    while len(output) < size:
        flags = read_byte()
        for bit in range(8):
            if flags & (1 << bit):
                tokens.append(None)
                append(read_byte())
            else:
                low, high = read_byte(), read_byte()
                start = low | ((high & 0xF0) << 4)
                length = (high & 0xF) + 3
                tokens.append((start, length))
                for index in range(min(length, size - len(output))):
                    append(window[(start + index) & LZSS_MASK])
            if len(output) == size:
                unused_flags = flags & (0xFF << (bit + 1))
                break
    return MhuResource(bytes(output), payload[cursor:], "lzss", unused_flags, tuple(tokens))


def find_companion(source, filename, *, parent=False):
    folders = (source.parent, source.parent.parent) if parent else (source.parent,)
    for folder in folders:
        direct = folder / filename
        if direct.is_file():
            return direct
        match = next((path for path in sorted(folder.iterdir())
                      if path.name.casefold() == filename.casefold() and path.is_file()), None)
        if match is not None:
            return match
    return None


def mhu_name_fields(fields):
    normalized = [field.lstrip(b" \t") for field in fields]
    try:
        start = normalized.index(b"//NameStr") + 1
        end = normalized.index(b"//END", start)
    except ValueError as exc:
        raise FormatError("missing //NameStr or closing //END in MHU") from exc
    return fields[start:end]


def format_mhu(data, encoding):
    resource = read_mhu(data)
    lines = ["; RSA MS.MHU settings", " ".join(MHU_FORMAT), f".encoding {encoding}",
             f".packing {resource.mode}", f".body_sha256 {sha256(resource.body).hexdigest()}"]
    body, separator, trailing = resource.body.partition(b"\0")
    if separator:
        lines.append(".decoded_suffix " + quote_bytes(separator + trailing, encoding))
    if any(resource.tail):
        for i in range(0, len(resource.tail), 16):
            lines.append(".file_tail " + quote_bytes(resource.tail[i:i + 16], encoding))
    else:
        lines.append(f".pad_to {len(data)}")

    names = False
    index = 0
    for field in body.split(b","):
        normalized = field.lstrip(b" \t")
        token = quote_bytes(field, encoding)
        if normalized == b"//END":
            lines.append(f".end_section {token}")
            names = False
        elif normalized.startswith(b"//"):
            lines.extend(("", f".section {token}"))
            names = normalized == b"//NameStr"
            index = 0
        elif names:
            lines.append(f"    NAME {index} {token}")
            index += 1
        else:
            lines.append(f"    FIELD {token}")

    if resource.mode == "lzss":
        lines.extend(("", "; Original LZSS token layout for exact round-trip", f".lzss {resource.unused_flags}"))
        # Keep compressed layout metadata separate from editable text.
        for is_literal, entries in groupby(resource.tokens, key=lambda token: token is None):
            if is_literal:
                lines.append(f"    LITERAL {sum(1 for _ in entries)}")
            else:
                lines.extend(f"    COPY {offset} {length}" for offset, length in entries)
        lines.append(".end_lzss")
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def choose_lzss_tokens(body):
    """Select matches within the bytes already written to the game's ring buffer."""
    cursor = 0
    while cursor < len(body):
        low = max(0, cursor - LZSS_WINDOW)
        longest = min(18, len(body) - cursor, cursor - low)
        for length in range(longest, 2, -1):
            previous = body.rfind(body[cursor:cursor + length], low, cursor)
            if previous >= 0:
                yield ((LZSS_START + previous) & LZSS_MASK, length)
                cursor += length
                break
        else:
            yield None
            cursor += 1


def pack_lzss(body, tokens, unused_flags=0):
    output = bytearray()
    cursor = 0
    for index, token in enumerate(tokens):
        if cursor == len(body):
            raise FormatError("extra tokens in the MHU compression layout")
        bit = index % 8
        if bit == 0:
            flag_slot = len(output)
            output.append(0)
        if token is None:
            output[flag_slot] |= 1 << bit
            output.append(body[cursor])
            cursor += 1
        else:
            offset, length = token
            output.extend((offset & 0xFF, ((offset >> 4) & 0xF0) | (length - 3)))
            cursor = min(cursor + length, len(body))
        if cursor == len(body):
            if unused_flags & ((1 << (bit + 1)) - 1):
                raise FormatError("original MHU flag value overlaps used bits")
            output[flag_slot] |= unused_flags
    if cursor != len(body):
        raise FormatError("incomplete MHU compression layout")
    return bytes(output)


def write_output(path, data):
    """Publish complete files, including when replacing a previous export."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as output:
        scratch = Path(output.name)
    try:
        scratch.write_bytes(data)
        os.replace(scratch, path)
    finally:
        scratch.unlink(missing_ok=True)


def run_cli(description, matches, output_name, process, *, default_encoding=None, companion=None):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("inputs", nargs="+", metavar="INPUT", help="file(s) or directories")
    parser.add_argument("-o", "--output", metavar="OUTPUT", help="output path or directory")
    parser.add_argument("--encoding", default=default_encoding, help="binary string encoding")
    args = parser.parse_args()
    inputs = [Path(argument) for argument in args.inputs]
    files = []
    try:
        encoding = codec_name(args.encoding) if args.encoding is not None else None
        for path in inputs:
            if path.is_dir():
                children = sorted(p for p in path.iterdir() if p.is_file() and matches(p.name.lower()))
                if not children:
                    raise FormatError(f"no matching inputs in {path}")
                files.extend(children)
            elif path.is_file():
                files.append(path)
            else:
                raise FormatError(f"input does not exist: {path}")
        output = Path(args.output) if args.output is not None else None
        directory_mode = (output is not None and
                          (len(inputs) > 1 or inputs[0].is_dir() or output.is_dir() or
                           args.output.endswith(("/", "\\"))))
        if directory_mode and output.exists() and not output.is_dir():
            raise FormatError(f"batch output must be a directory: {output}")
        companions = [(path, companion(path)) for path in files] if companion else []
        input_paths = {path.resolve() for path in files}
        input_paths.update(side.resolve() for _, side in companions if side is not None)
        planned = {}
        targets = {}

        def add(source, target):
            key = target.resolve()
            if key in input_paths:
                raise FormatError(f"output would overwrite an input: {target}")
            if key in planned and planned[key][0].resolve() != source.resolve():
                raise FormatError(f"two inputs map to {target}; choose distinct output paths")
            planned[key] = (source, target)
            targets[source.resolve()] = target

        for path in files:
            if output is not None and not directory_mode:
                target = output
            else:
                folder = output if output is not None else path.parent
                target = folder / output_name(path, folder)
            add(path, target)
        for primary, side in companions:
            if side is None:
                continue
            folder = targets[primary.resolve()].parent
            if any(side.resolve() == path.resolve() for path in files):
                continue  # A directly requested companion already has its own destination.
            add(side, folder / output_name(side, folder))

        # Validate the whole batch before publishing either member of a pair.
        payloads = []
        for source, target in planned.values():
            try:
                payloads.append((source, target, process(source, encoding)))
            except (OSError, ValueError) as exc:
                raise FormatError(f"{source}: {exc}") from exc
        for source, target, payload in payloads:
            try:
                write_output(target, payload)
            except OSError as exc:
                raise FormatError(f"{target}: {exc}") from exc
            print(f"{source} -> {target}")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
