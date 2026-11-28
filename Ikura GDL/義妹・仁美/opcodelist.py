"""Instruction definitions for the HITOMI build of Ikura GDL.

Each schema describes bytes after the opcode and length field. Addresses refer
 to the local x86 IDA export. See vm_analysis.md for the operand notation.
"""

from codecs import lookup
from dataclasses import dataclass
from pathlib import Path
import re
import tempfile


@dataclass(frozen=True)
class Opcode:
    bytecode: int
    mnemonic: str
    handler: str
    operands: tuple[str, ...]
    layout: str = "fixed"

    @property
    def length(self):
        if self.layout == "fixed" and all(field in WIDTHS for field in self.operands):
            return f"header + {sum(WIDTHS[field] for field in self.operands)}"
        return "header + encoded operands"

    @property
    def sub_opcodes(self):
        return SUB_OPCODES.get(self.layout, {})

    @property
    def variants(self):
        return LAYOUT_VARIANTS.get(self.layout, "")


WIDTHS = {"b": 1, "w": 2, "d": 4, "v": 2, "x": 4, "j": 2}

# This list is exhaustive for the switch in 447BF0, with FE added for the
# observed empty default-dispatch record. Entries on a shared handler retain
# distinct opcodes and, where applicable, distinct argument contracts.
_DEFINITIONS = """
00 HALT                    447BF0
01 JUMP_SCRIPT             449710 s13
02 CALL_SCRIPT             449750 s13
03 RETURN_SCRIPT           4497D0
04 JUMP                    449870 j
05 CALL                    449890 j
06 RETURN                  449910
07 SWITCH_JUMP             449970 x /dispatch
08 SWITCH_CALL             4499D0 x /dispatch
09 SET_SCRIPT_BASE         449A80 s13
0A SCRIPT_STRING_ACTION    449B20 t
10 CREATE_IMAGE_WINDOW     449BB0 b x x x x b
11 LOAD_WINDOW_IMAGE       449D80 b b s13
12 LOAD_WINDOW_REGION      449E20 b b s13
13 CONFIGURE_MESSAGE_STYLE 449EB0 b*20
14 PLACE_WINDOW_REGION     44A070 b b x x x
15 DEFINE_MESSAGE_REGION   44A0F0 b b x x x x t
16 SET_MESSAGE_WAIT        44A1D0 b x b
17 RESET_MESSAGE_WINDOW    44A230 b
18 CONFIGURE_MESSAGE_KEY   44A270 b w b
1A ENABLE_MESSAGE_SYSTEM   44A2E0
1B DISABLE_MESSAGE_SYSTEM  44A310
1C CONFIGURE_TEXT_REGION   44A340 b x*4 t x*6
20 CREATE_MESSAGE_WINDOW   44A480 b x*4 b
21 LOAD_MESSAGE_SKIN       44A4F0 b b /skins
22 SET_WINDOW_RESOURCE     44A6A0 b s13
23 POSITION_MESSAGE_WINDOW 44A700 b x x b
24 SET_MESSAGE_WINDOW_MODE 44A7A0 b b
25 DEFINE_SPEAKER           44A800 b b /speaker
26 SET_MESSAGE_DELAY       44A860 b x
27 SELECT_SPEAKER          44A8D0 b x
28 SET_MESSAGE_ATTRIBUTE   44A910 b b
29 SHOW_MESSAGE_WINDOW     44A970 b
2A HIDE_MESSAGE_WINDOW     44AA20 b
2B MESSAGE                 44AAD0 b /message
2C CONDITIONAL_MESSAGE     44AB20 b /message
2D MESSAGE_LAYER_ENABLE    44AB90 x
2E MESSAGE_LAYER_DISABLE   44ABC0 x
30 ALLOCATE_FLAGS          44AC00 w
31 SET_FLAG                44AC50 w b
32 SET_FLAG_RANGE          44AC90 w w b
33 JUMP_IF_FLAG_NONZERO      44ACF0 w j
34 COPY_FLAG_RANGE         44AD50 w w w
35 SET_FLAG_TABLE          44ADA0 b /data
36 JUMP_ON_INPUT           44ADF0 b j
37 RUN_SYSTEM_EVENT        44AE90 x x
38 SAVE_FLAG_RANGE         44B460 w w
39 LOAD_FLAG_RANGE         44B5E0 w w
3A JUMP_IF_SYSTEM_STATE    44B6B0 /system_test
3B JUMP_IF_FLAG_NOT_ONE        44ACF0 w j
3C JUMP_ON_INPUT_MODE      44ADF0 b b j
40 ALLOCATE_VARIABLES      44B990 w
41 SET_VARIABLE            44B9E0 v x
42 INCREMENT_VARIABLE      44BA20 v
43 DECREMENT_VARIABLE      44BA50 v
44 CALCULATE               44BA80 v /arithmetic
45 ASSIGN_INDIRECT         44BB90 v v x
46 COPY_VARIABLE_RANGE     44BC30 v v w
47 IF                      44BC80 /conditions
48 LOAD_SYSTEM_BLOCK       44BD80 w w
49 SAVE_STATE_RANGE        44C120 x x x b
4A LOAD_STATE_RANGE        44C180 x x x b
4B READ_SYSTEM_VALUE       44C2F0 v /system_get
4C WRITE_SYSTEM_VALUE      44C440 v /system_set
50 CREATE_SURFACE          44C490 x x x
51 SET_SURFACE_ORIGIN      44C4F0 x x x
52 RESET_SURFACES          44C530
53 SET_SURFACE_COLOR       44C560 x b b b
54 FADE_SURFACE_TO_COLOR   44C5E0 x x b b b
55 TRANSITION_TO_COLOR     44C690 x b b b b
56 LOAD_SURFACE_IMAGE      44C810 x s28
57 BLIT                    44C8E0 /blit
58 DEFINE_SPRITE_REGION    44CBB0 x b*4 x*4
59 RESET_SPRITE_REGION     44CC70 x
5A SET_SPRITE_REGION_MODE  44CCA0 b
5B WRITE_SPRITE_DATA       44CCF0 x x x /data
5C SET_LAYER_PARAMETER     44CD50 b x x
5D UPDATE_LAYER_PARAMETER  44CDC0 b x x
5E DRAW_LAYER              44CE10 /layer
5F DRAW_LAYER_WAIT         44D0A0 /layer
60 LOAD_EFFECT             44D2F0 x*5 s13
61 STRETCH_SURFACE         44D3A0 b x*10
62 FILTER_SURFACE          44D4D0 b x*14
63 SET_EFFECT_PARAMETER    44D600 w b b x
64 SET_LAYER_MODE          44D660 x b
65 LOAD_ALPHA_RESOURCE     44D6B0 x s13
66 SET_LAYER_RECT          44D700 x*4
67 CONFIGURE_ANIMATION     44D760 x w w
68 RESET_ANIMATION         44D7B0
69 CLEAR_EFFECT            44D7E0 x
6F SET_IMAGE_GEOMETRY      44D810 x*4
70 PLAY_MUSIC              44D880 s13 b
71 FADE_MUSIC              44DC60 b x
72 STOP_AUDIO_CHANNEL      44DE70 x
73 STOP_AUDIO              44DF00
74 LOAD_SOUND              44DF60 s13 x
75 PLAY_SOUND              44E0A0 x x
76 RELEASE_SOUND           44E220 x
77 SET_AUDIO_OUTPUT_MODE   44E290 b
78 PLAY_VOICE_FILE         44E3A0 s13
79 RESET_AUDIO_CHANNEL     44E4F0 x
7A AUDIO_COMMAND_NOP       44E550
7B FADE_AUDIO_CHANNEL      44E580 x x
7C READ_AUDIO_STATE        44E5F0 b w
7D READ_CHANNEL_STATE      44E710 x b w
7E READ_AUDIO_DEVICE       44E7E0 b w
7F AUDIO_OUTPUT_NOP        44E8A0
80 SET_MENU_LAYOUT         44E8D0 b s13
81 SELECT_CURSOR           44E920 b /menu_mode
82 UPDATE_MENU_RECT        44E950 x*4
83 SET_MENU_OFFSET         44EA40 x x
84 DEFINE_MENU_REGION      44EAA0 b x*4 b w b b b
85 RUN_MENU                44EBB0 v v b /menu_run
86 SHOW_MENU               44EC50
87 HIDE_MENU               44EC70
88 SET_MENU_STATES         44EC90 b x*8
89 SELECT_MENU             44EDE0 x
8A MOUNT_IMAGE_ARCHIVE     44EE10 s28 x x
8B UNMOUNT_IMAGE_ARCHIVE   44EE80
8C DRAW_ARCHIVE_REGION     44EEA0 x*8
8D UPDATE_UI_STATE         44EF40 b x
8E READ_UI_STATE           44EF50 x
90 SET_AUDIO_LEVELS        44EF90 x x
91 SWITCH_AUDIO_CHANNEL    44EFD0 x b x
92 RESET_SOUND_CHANNEL     44F130 x
9F SYNC_AUDIO_CHANNEL      44F150 b x
A0 RESET_OVERLAY           44F2C0
A1 SET_OVERLAY_COLOR       44F2F0 b*6
A2 CONFIGURE_OVERLAY       44F3A0 b*6 w b w w
A3 BASIC_FLAG_STORAGE      44F490 d
A4 RESET_BASIC_FLAG_STATE  44F500
A5 INIT_PERSISTENT_FLAGS   44F540 d
A6 UPDATE_OVERLAY          44F5B0 b w w
A7 SET_SYSTEM_VAR_FROM_FLAG 44F620 w x
AD CONFIGURE_COLOR_EFFECT  44F690 x x x
AE SET_DRAWING_RECT        44F6D0 b x*4
AF SET_MESSAGE_CLIP        44F780 b x*4
B3 SET_MENU_CAPTION        44F830 x t b
B4 UPDATE_AUDIO_DEVICE     44F8F0 x
BD SET_UI_RESOURCES        430F40 x*4
BE RESERVED_DISPATCH_A     447BF0
BF RESERVED_DISPATCH_B     447BF0
D6 ADD_TEXT_TABLE          44FB30 b b /data
D7 ADD_SHORT_STRINGS       44FBD0 x /short_strings
DA CLEAR_SHORT_STRINGS     44FC30 x
E0 OPEN_DATA_FILE          44FC60 b s28
E1 WRITE_DATA_STRING       44FD50 b b t64
E2 READ_DATA_VARIABLE      44FE10 b b b v s28
E3 WRITE_DATA_VARIABLE     44FFF0 b b b v s28
E4 COMPUTE_DATA_VALUE      450190 b*4 s28 s28 s28 b x*3 b v v
E5 CONFIGURE_UI_RESOURCE   450440 b
E6 RESET_UI_RESOURCES       450490
E7 SET_UI_COLOR            4504B0 b b b
E8 SET_UI_COLOR_ALT        450540 b b b
E9 UPDATE_UI_RESOURCES      4505D0 x
EF SYSTEM                  450600 /system
F0 SYSTEM_FILE_ACTION      450F00 /file_action
F1 START_TIMER             4513C0 x
F2 WAIT_TIMER              4513F0
F3 PLAY_MOVIE              451400 x*4 s13
F4 SET_SKIP_MODE           4515E0 b
F5 SET_MESSAGE_ADVANCE     451610 b
F7 DISPLAY_SYSTEM_STRING   451650 t
F8 SET_TEXT_STYLE          451690 b b
F9 SET_TEXT_COLOR          451720 b b b b b
FA START_MEASUREMENT       4517B0 x
FB STOP_MEASUREMENT        4517D0
FC READ_MEASUREMENT        4517F0 v
FD SET_MOVIE_RESOURCES     451830 x s13 b b s13 s13
FE SKIP_DEFAULT            447BF0
FF WAIT_TIMER_ALT          4513F0
"""


def expand(schema):
    fields = []
    for item in schema:
        field, _, repeat = item.partition("*")
        fields.extend([field] * (int(repeat) if repeat else 1))
    return tuple(fields)


OPCODES = {}
for row in _DEFINITIONS.strip().splitlines():
    code, name, handler, *schema = row.split()
    layout = schema.pop()[1:] if schema and schema[-1].startswith("/") else "fixed"
    value = int(code, 16)
    OPCODES[value] = Opcode(value, name, handler, expand(schema), layout)
BY_NAME = {op.mnemonic: op for op in OPCODES.values()}

# Tables are indexed by the actual byte read by the code. A name ending in an
# effect index identifies the downstream mode, even where its visual action
# has not been inspected at runtime.
ARITHMETIC = dict(enumerate(("ADD", "SUB", "MUL", "DIV", "MOD")))
RELATIONS = dict(enumerate(("EQ", "LT", "LE", "GT", "GE", "NE")))
BLIT = {0: ("COPY", ()), 1: ("KEY_COPY", ())}
for effect in (*range(2, 20), *range(24, 30)):
    extra = 2 if 15 <= effect <= 18 else 4 if effect >= 28 else 0
    BLIT[effect] = (f"TRANSITION_{effect - 2}", ("x",) * extra)
BLIT.update({20: ("BLEND", ("x",)), 21: ("KEY_BLEND", ("x",))})
SYSTEM_TEST = {
    0: "CONFIG_BYTE", 1: "DISPLAY_FLAGS", 2: "CONFIG_SWITCH_2",
    3: "CONFIG_SWITCH_3", 4: "CONFIG_SWITCH_4", 5: "CONFIG_SWITCH_5",
    6: "CONFIG_SWITCH_6", 7: "CONFIG_SWITCH_7", 8: "INPUT_STATE",
    9: "CONFIG_SWITCH_9", 10: "CONFIG_SWITCH_10", 11: "CONFIG_SWITCH_11",
    12: "CONFIG_SWITCH_12", 13: "SYSTEM_STATUS", 14: "VM_FLAGS",
    15: "ENVIRONMENT_STATUS", 17: "DATA_PRESENT",
}
SYSTEM_VALUES = {0: "RECORDS_PENDING", 4: "RESOURCE_KIND", 5: "VM_READY",
                 8: "STATUS_8", 10: "CONTROL_KEY_DOWN", 16: "STATUS_16",
                 20: "MESSAGE_SETTING"}
SYSTEM = {
    1: ("LOAD_SLOT", ("x", "x")), 2: ("SELECT_SLOT", ("x",)),
    3: ("PANEL", ()), 4: ("DRAW_SLOT", ("x",) * 7),
    5: ("DRAW_SLOT_TEXT", ("x",) * 4), 6: ("CONFIGURE_SLOT", ("x",) * 5),
    7: ("SET_PANEL_INDEX", ("x", "x")), 8: ("SET_PANEL_STRINGS", ("x",)),
}
PANELS = {0: ("CREATE", ("x",) * 5), 1: ("POSITION", ("x",) * 4),
          2: ("SIZE", ("x",) * 4), 3: ("CLOSE", ("x",))}
FILE_ACTIONS = dict(enumerate(("LOAD_VM_DATA", "LOAD_LAYOUT_DATA", "LOAD_RENDER_DATA", "LOAD_FONT_DATA", "LOAD_AUX_DATA", "LOAD_AUDIO_DATA")))
MODE_LAYOUTS = {
    "system_test": (SYSTEM_TEST, ("b", "j")),
    "system_get": (SYSTEM_VALUES, ()),
    "system_set": ({20: SYSTEM_VALUES[20]}, ()),
    "file_action": (FILE_ACTIONS, ("s13",)),
}
MESSAGE_CONTROLS = {
    0x00: ("RESET_LINE", ()), 0x01: ("SET_TEXT_PARAMETERS", ("b", "b", "b", "b")),
    0x02: ("WAIT_INPUT", ()), 0x03: ("CLEAR", ()),
    0x04: ("SET_SPACING", ("b",)), 0x05: ("CLEAR_AND_END", ()),
    0x06: ("NEWLINE", ()), 0x07: ("IGNORED_PARAMETER", ("b",)),
    0x08: ("SET_STYLE", ("d",)), 0x09: ("INSERT_STRING", ("b",)),
    0x0A: ("CONFIGURE_INSERT", ("w", "b", "b")),
    0x0B: ("SET_LAYER", ("b", "b")), 0x0C: ("UPDATE_LAYER", ("b", "b")),
    0x10: ("SET_LAYER_STATE", ("b", "b")), 0x11: ("SET_POSITION", ("d",)),
    0x13: ("VOICE", ("s28",)),
}

# 40F3B0 selects FWnnn.GG2 using the 11 message control argument.
# Checked against the shipped nameplate images and START.ISF speaker slots.
# FW000.GG2 is the blank nameplate.
SPEAKER_PICTURES = (
    "", "前島　孝弘", "前島　仁美", "前島　容子", "柳本　有希", "前島　信弘",
    "孝弘・有希", "孝弘・有希・仁美", "有希・仁美", "孝弘・仁美", "男　子", "女　子",
    "おばちゃん", "小学生", "女子アナ", "店　員", "男", "ウェイトレス", "？？？",
)

# Data at VA 49C154. Index zero ends text. Index 7F enters direct-byte mode.
# Entry 80 is a NUL pair, not a displayable glyph.
GLYPHS = (
    "　　、。・？！（）「」０１２３４５６７８９あいうえおかがきぎくぐ"
    "　げこごさざしじすずせぜそぞただちぢっつづてでとどなにぬねのはば"
    "ひびふぶへべほぼまみむめもゃやゅゆょよらりるれろわをんアイウエオ"
    "カキクケコサシスセソタチッツテトナニけネノハヒフヘホマミムメモヤ"
)
GBK_EQUIVALENTS = {"・": "·", "♪": "☆"}

# Four operand variants store dependent amounts of data after a mode byte.
LAYER = {
    mode: (f"EFFECT_{mode}", ("x",) * (2 if 15 <= mode <= 18 else 4 if mode in (28, 29) else 0))
    for mode in range(30)
}


SUB_OPCODES = {
    **{name: table for name, (table, _) in MODE_LAYOUTS.items()},
    "arithmetic": ARITHMETIC,
    "conditions": {"compare": RELATIONS, "actions": {0: "JUMP", 1: "SET", 255: "STOP"}},
    "blit": BLIT,
    "layer": LAYER,
    "message": {**MESSAGE_CONTROLS, 255: ("TEXT", ())},
    "system": {**SYSTEM, 3: ("PANEL", PANELS)},
}
LAYOUT_VARIANTS = {
    "dispatch": "u8 count followed by count entry slots",
    "skins": "one or three through six s28 resource names, bounded by the record",
    "speaker": "remainder of short record is an inline name",
    "message": "control stream, glyph runs and a separate trailer byte",
    "data": "bytes bounded by the record",
    "arithmetic": "operator and expression pairs ending at a subcode greater than four",
    "conditions": "comparison and action, action controls operand width and continuation",
    "blit": "u8 subcode, eight expressions and subcode-specific operands",
    "layer": "u8 subcode, eight expressions, mode operands and two extra expressions for 5E",
    "system_test": "u8 subcode, u8 expected value and an entry slot",
    "system_get": "u8 subcode after a variable slot",
    "system_set": "u8 subcode after a variable slot",
    "file_action": "u8 subcode and s13 resource name",
    "menu_mode": "u8 cursor number with an optional three-byte zero trailer",
    "menu_run": "flags bit 1 selects WAIT or POLL, the argument retains the other bits",
    "short_strings": "u16 count followed by count q strings",
    "system": "u8 subcode, nested mode for 3, counted strings for 8",
}

def variant(mapping, mode):
    return mapping.get(mode, (f"DEFAULT_{mode}", ()))


def variant_value(mapping, name):
    for mode, (title, _) in mapping.items():
        if title == name:
            return mode
    if name.startswith("DEFAULT_"):
        mode = number(name[8:], 1)
        if mode not in mapping:
            return mode
    raise FormatError(f"unknown variant {name!r}")




class FormatError(ValueError):
    pass


def encoding_name(value):
    try:
        return lookup(value).name
    except LookupError:
        raise FormatError(f"unknown encoding {value!r}") from None


def number(token, width=None):
    try:
        result = int(token, 16 if token.lower().lstrip("+-").startswith("0x") else 10)
    except ValueError:
        raise FormatError(f"invalid integer {token!r}") from None
    if width is not None and not 0 <= result < 1 << (8 * width):
        raise FormatError(f"{token} is outside the unsigned {width * 8}-bit range")
    return result


def expression(value):
    index = value & 0x3FFFFFFF
    if index & 0x20000000:
        index -= 1 << 30
    token = f"v{index}" if value & 0x80000000 else str(index)
    return f"rand({token})" if value & 0x40000000 else token


def expression_value(token):
    flags = 0
    if token.startswith("rand(") and token.endswith(")"):
        flags = 0x40000000
        token = token[5:-1]
    if token.startswith("v"):
        token = token[1:]
        flags |= 0x80000000
    value = number(token)
    if not -(1 << 29) <= value < 1 << 29:
        raise FormatError("expression operand is outside the signed 30-bit range")
    return flags | (value & 0x3FFFFFFF)


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    @property
    def remaining(self):
        return len(self.data) - self.pos

    def take(self, size):
        start = self.pos
        if size > self.remaining:
            raise FormatError(f"truncated operand at payload +0x{start:X}, needs {size} bytes")
        self.pos += size
        return self.data[start:self.pos]

    def uint(self, size):
        return int.from_bytes(self.take(size), "little")

    def string(self, limit, terminators, fixed_limit=False):
        start = self.pos
        for _ in range(limit):
            if self.uint(1) in terminators:
                return self.data[start:self.pos - 1], self.data[self.pos - 1]
        if fixed_limit:
            return self.data[start:self.pos], None
        terminator = self.uint(1)
        return self.data[start:self.pos - 1], terminator

    def end(self):
        if self.remaining:
            raise FormatError(f"{self.remaining} unconsumed operand bytes at payload +0x{self.pos:X}")


_TOKEN = re.compile(r'"(?:[^"\\\r\n]|\\.)*"|[^\s;"\x00-\x1f]+')
_PLACEHOLDER = re.compile(r"\{\{([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})?)\}\}")
LABEL = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


def tokenize(line):
    tokens = []
    cursor = 0
    while cursor < len(line):
        if line[cursor].isspace():
            cursor += 1
            continue
        if line[cursor] == ";":
            break
        match = _TOKEN.match(line, cursor)
        if match is None:
            raise FormatError(f"invalid token at column {cursor + 1}")
        tokens.append(match[0])
        cursor = match.end()
        if cursor < len(line) and not (line[cursor].isspace() or line[cursor] == ";"):
            raise FormatError(f"missing field separator at column {cursor + 1}")
    return tokens


def quote(units):
    pieces = []
    for unit in units:
        if isinstance(unit, bytes):
            pieces.append("{{" + ":".join(f"{val:02X}" for val in unit) + "}}")
        else:
            pieces.append({"\\": r"\\", '"': r'\"', "{": r"\{", "\n": r"\n"}.get(unit, unit))
    return '"' + "".join(pieces) + '"'


def unquote(token):
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        raise FormatError(f"expected a quoted string, got {token!r}")
    value = token[1:-1]
    result = []
    pos = 0
    escapes = {"\\": "\\", '"': '"', "{": "{", "n": "\n"}
    while pos < len(value):
        char = value[pos]
        if char == "\\":
            key = value[pos + 1:pos + 2]
            if key not in escapes:
                raise FormatError(f"unsupported string escape \\{key}")
            result.append(escapes[key])
            pos += 2
        elif value.startswith("{{", pos):
            match = _PLACEHOLDER.match(value, pos)
            if match is None:
                raise FormatError(f"invalid byte placeholder at string character {pos + 1}")
            result.append(bytes.fromhex(match[1].replace(":", "")))
            pos = match.end()
        else:
            if not char.isprintable() and char != "　":
                raise FormatError(f"use a byte placeholder for U+{ord(char):04X}")
            result.append(char)
            pos += 1
    return result


def plain_units(data, encoding):
    # surrogateescape preserves undecodable bytes. A reversible check retains
    # any ambiguous code page spelling without showing replacement glyphs.
    text = data.decode(encoding, errors="surrogateescape")
    result = []
    pos = 0
    for char in text:
        if 0xDC80 <= ord(char) <= 0xDCFF:
            result.append(bytes([ord(char) - 0xDC00]))
            pos += 1
            continue
        encoded = char.encode(encoding)
        actual = data[pos:pos + len(encoded)]
        if encoded != actual or (not char.isprintable() and char != "　"):
            result.extend(actual[i:i + 1] for i in range(len(actual)))
        else:
            result.append(char)
        pos += len(encoded)
    if pos != len(data):
        return [bytes([value]) for value in data]
    return result


def encoded_char(char, encoding):
    if encoding == "gbk":
        char = GBK_EQUIVALENTS.get(char, char)
    try:
        return char.encode(encoding)
    except UnicodeEncodeError:
        raise FormatError(f"{char!r} (U+{ord(char):04X}) cannot be encoded as {encoding}") from None


def plain_bytes(token, encoding):
    result = bytearray()
    for unit in unquote(token):
        if isinstance(unit, bytes):
            result.extend(unit)
        elif unit == "\n":
            raise FormatError(r"\n is only available in MESSAGE text; use {{0A}} for a raw LF")
        else:
            result.extend(encoded_char(unit, encoding))
    return bytes(result)


GLYPH_CODES = {}
for _index in range(1, 0x7F):
    if _index != 0x5C:
        GLYPH_CODES.setdefault(GLYPHS[_index], _index)


def direct_glyph(raw):
    # The renderer tests for its quote marker before checking direct mode.
    # Quoting the prefix lets a literal ASCII backslash reach direct mode.
    return b"\x5c\x7f\x5c" if raw == b"\x5c" else b"\x7f" + raw

def message_unit(unit, encoding):
    if isinstance(unit, bytes):
        if (len(unit) == 2 and unit[0] > 0x80) or unit == b"\x80":
            return unit
        if len(unit) == 1 and unit[0] not in (0, 0x7F):
            return direct_glyph(unit)
        raise FormatError("placeholder cannot form one message glyph")
    if unit == "\n":
        return b"\x00\x06\xff"
    if encoding == "cp932" and unit in GLYPH_CODES:
        return bytes([GLYPH_CODES[unit]])
    encoded = encoded_char(unit, encoding)
    if len(encoded) == 2 and encoded[0] > 0x80 and 0 not in encoded:
        return encoded
    if len(encoded) == 1 and encoded[0] not in (0, 0x7F):
        return direct_glyph(encoded)
    raise FormatError(f"{unit!r} cannot be represented in the message stream using {encoding}")


def read_glyph(reader, encoding):
    start = reader.pos
    first = reader.uint(1)
    if first == 0:
        return None, None
    form = None
    if first == 0x5C:
        if not reader.remaining:
            raise FormatError("truncated message quote")
        if reader.data[reader.pos] == 0:
            reader.take(1)
            return GLYPHS[first], "short_i"
        first = reader.uint(1)
        form = "quoted_"
    if first == 0x7F:
        raw = reader.take(1)
        if raw in (b"\0", b"\x7f") or (raw == b"\x5c" and not form):
            raise FormatError("invalid direct-byte message glyph")
        units = plain_units(raw, encoding)
        unit, = units
        kind = "direct"
    elif first == 0x80:
        unit = b"\x80"
        kind = "empty_glyph"
    elif first > 0x80:
        raw = bytes([first]) + reader.take(1)
        try:
            char = raw.decode(encoding)
        except UnicodeDecodeError:
            char = ""
        if len(char) == 1 and (char.isprintable() or char == "　"):
            unit = char
            kind = "wide" if char.encode(encoding) == raw else f"code_{int.from_bytes(raw, 'big'):04X}"
        else:
            unit = raw
            kind = "wide"
    else:
        unit = GLYPHS[first]
        kind = f"dictionary_{first}"
    if message_unit(unit, encoding) == reader.data[start:reader.pos]:
        return unit, None
    return unit, (form or "") + kind


def glyph_form(unit, kind, encoding):
    quoted = kind.startswith("quoted_")
    kind = kind.removeprefix("quoted_")
    if kind.startswith("dictionary_"):
        slot = number(kind[11:], 1)
        if slot < 1 or slot >= 0x7F or (slot == 0x5C and not quoted):
            raise FormatError(f"invalid message dictionary slot {slot}")
        encoded = bytes([slot]) if GLYPHS[slot] == unit else None
    elif kind == "short_i":
        if quoted:
            raise FormatError("short_i cannot be quoted")
        encoded = b"\x5c\x00" if unit == "イ" else None
    elif kind == "empty_glyph":
        encoded = b"\x80" if unit == b"\x80" else None
    elif kind == "direct":
        raw = unit if isinstance(unit, bytes) else encoded_char(unit, encoding)
        encoded = b"\x7f" + raw if len(raw) == 1 and raw[0] not in (0, 0x7F) else None
        if raw == b"\x5c" and not quoted:
            encoded = None
    elif kind == "wide":
        raw = unit if isinstance(unit, bytes) else encoded_char(unit, encoding)
        encoded = raw if len(raw) == 2 and raw[0] > 0x80 else None
    elif re.fullmatch(r"code_[0-9A-Fa-f]{4}", kind):
        raw = bytes.fromhex(kind[5:])
        encoded = raw if raw[0] > 0x80 and raw.decode(encoding, errors="replace") == unit else None
    else:
        raise FormatError(f"unknown message glyph form {kind!r}")
    if encoded is None:
        return None
    return b"\x5c" + encoded if quoted else encoded


def write_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def safe_outputs(jobs):
    sources = {source.resolve() for source, _ in jobs}
    destinations = set()
    for _, destination in jobs:
        resolved = destination.resolve()
        if resolved in sources:
            raise FormatError(f"output would overwrite an input: {destination}")
        if resolved in destinations:
            raise FormatError(f"several inputs would write the same output: {destination}")
        destinations.add(resolved)

GLYPH_FORM = re.compile(r'(?:(?:quoted_)?(?:dictionary_[0-9]{1,3}|empty_glyph|direct|wide|code_[0-9A-Fa-f]{4})|short_i)')
