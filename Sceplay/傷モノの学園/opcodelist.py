"""Instruction definitions for the Sceplay VM in kizumono.exe.

The game-command schema and handler addresses are documented in vm_analysis.md.
V is a tagged value, K a tagged string-slot index, S a C string, X a scene
name, J a script-relative address and E a packed expression record.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Opcode:
    tag: int
    number: int
    mnemonic: str
    operands: str
    handler: str

    @property
    def minimum_size(self):
        return 3 + sum(OPERAND_MINIMUM[operand] for operand in self.operands)


OPERAND_MINIMUM = {"V": 3, "K": 3, "S": 1, "X": 1, "J": 4, "E": 8}
BANKS = ("", "a", "b", "t")
EVAL_NAMES = (
    "MUL", "DIV", "MOD", "ADD", "SUB", "SHL", "SAR", "LT", "LE", "GT", "GE",
    "EQ", "NE", "AND", "XOR", "OR", "BOOL_AND", "BOOL_OR", "ASSIGN",
)
EVAL_NUMBERS = {name: number for number, name in enumerate(EVAL_NAMES)}
CORE = (
    Opcode(4, 0, "JUMP_IF_ZERO", "J", "419130"),
    Opcode(4, 1, "JUMP_IF_NONZERO", "J", "419160"),
    Opcode(4, 2, "JUMP", "J", "419190"),
    Opcode(4, 3, "CALL", "J", "4191B0"),
    Opcode(4, 4, "RETURN", "", "419200"),
    Opcode(4, 5, "JUMP_SCENE", "X", "4193A0"),
    Opcode(4, 6, "CALL_SCENE", "X", "419430"),
    Opcode(4, 7, "RETURN_SCENE", "", "4196C0"),
    Opcode(4, 8, "EVAL", "E", "419720"),
)

# IDA x86 handler addresses identify the executable's implementation.
COMMANDS = (
    Opcode(0, 100, "ARRAY_READ_INDIRECT", "VVV", "41BD60"),
    Opcode(0, 101, "ARRAY_WRITE_INDIRECT", "VVV", "41BE30"),
    Opcode(0, 102, "ARRAY_ADDRESS", "VV", "41BEF0"),
    Opcode(0, 103, "ARRAY_READ_INDEXED", "VVV", "41BF90"),
    Opcode(0, 104, "ARRAY_WRITE_INDEXED", "VVV", "41C060"),
    Opcode(0, 105, "PUSH_VALUE", "V", "41C110"),
    Opcode(0, 106, "POP_VALUE", "V", "41C170"),
    Opcode(0, 107, "RESET_SCRIPT_VARIABLES", "", "41C1F0"),
    Opcode(0, 108, "STOP_WITH_ERROR", "", "41C250"),
    Opcode(0, 109, "DISCARD_LOCAL_RETURNS", "", "41C270"),
    Opcode(0, 110, "STOP_WITH_DEBUG_ERROR", "", "41C2A0"),
    Opcode(0, 111, "KEEP_CURRENT_SCENE", "", "41C2C0"),
    Opcode(0, 200, "SET_STRING", "KS", "426D10"),
    Opcode(0, 201, "SET_STRING_BYTE", "KVV", "426D60"),
    Opcode(0, 202, "CLEAR_STRING", "K", "426DE0"),
    Opcode(0, 203, "COPY_STRING", "KK", "426E30"),
    Opcode(0, 204, "APPEND_STRING", "KK", "426ED0"),
    Opcode(0, 205, "FORMAT_NUMBER_STRING", "KVVVV", "426F70"),
    Opcode(0, 206, "COMPARE_STRINGS", "KKV", "427220"),
    Opcode(0, 207, "STRING_BYTE_LENGTH", "KV", "4272F0"),
    Opcode(0, 300, "CONFIGURE_IMAGE_MODES", "VV", "401000"),
    Opcode(0, 301, "CREATE_SURFACE", "VVV", "401030"),
    Opcode(0, 302, "FREE_SURFACE", "V", "401150"),
    Opcode(0, 303, "LOAD_IMAGE", "VVVS", "4011F0"),
    Opcode(0, 304, "LOAD_IMAGE_FROM_STRING", "VVVK", "401390"),
    Opcode(0, 305, "GET_SURFACE_DIMENSIONS", "VVV", "401580"),
    Opcode(0, 306, "SET_COLOR_KEY", "VVVV", "401620"),
    Opcode(0, 307, "COPY_SURFACE_DESCRIPTOR", "VVVV", "4016B0"),
    Opcode(0, 308, "BLIT_RECT", "VVVVVVVVV", "4017B0"),
    Opcode(0, 309, "BLIT_STRETCHED", "VVVVVVVVVVV", "4018B0"),
    Opcode(0, 310, "BLIT_EFFECT", "VVVVVVVVVVVV", "4019F0"),
    Opcode(0, 311, "BLIT_KEYED_STRETCHED", "VVVVVVVVVVV", "401B40"),
    Opcode(0, 312, "BLIT_MASKED", "VVVVVVVVVVVVV", "401C60"),
    Opcode(0, 313, "BLIT_MASKED_SCALED", "VVVVVVVVVVVVVVV", "401DB0"),
    Opcode(0, 314, "BLIT_ALPHA", "VVVVVVVVVVVVV", "401F40"),
    Opcode(0, 315, "BLIT_ALPHA_SCALED", "VVVVVVVVVVVVVVV", "4020A0"),
    Opcode(0, 316, "BLIT_TRANSFORMED", "VVVVVVVVVVVVVVVVV", "402250"),
    Opcode(0, 317, "CAPTURE_OR_PRESENT", "VVVVVVVVV", "402430"),
    Opcode(0, 318, "TRANSITION_SINGLE", "VVVVVVVVVV", "402580"),
    Opcode(0, 319, "TRANSITION_PAIR", "VVVVVVVVVVV", "402BA0"),
    Opcode(0, 320, "PRESENT_RECT", "VVVVVVVVV", "403840"),
    Opcode(0, 400, "SET_TEXT_ORIGIN", "VV", "41A920"),
    Opcode(0, 401, "GET_TEXT_ORIGIN", "VV", "41A9B0"),
    Opcode(0, 402, "SET_TEXT_SPACING", "VV", "41AA10"),
    Opcode(0, 403, "GET_TEXT_SPACING", "VV", "41AAA0"),
    Opcode(0, 404, "SET_TEXT_GRID", "VV", "41AB00"),
    Opcode(0, 405, "GET_TEXT_GRID", "VV", "41AB90"),
    Opcode(0, 406, "SET_TEXT_PIXEL_OFFSET", "VV", "41ABF0"),
    Opcode(0, 407, "GET_TEXT_PIXEL_OFFSET", "VV", "41AC80"),
    Opcode(0, 408, "SET_TEXT_BASE_EXTENT", "VV", "41ACE0"),
    Opcode(0, 409, "GET_TEXT_BASE_EXTENT", "VV", "41AD70"),
    Opcode(0, 410, "SET_TEXT_RELATIVE_OFFSET", "VV", "41ADD0"),
    Opcode(0, 411, "GET_TEXT_RELATIVE_OFFSET", "VV", "41AE60"),
    Opcode(0, 412, "SET_TCY_MODE", "V", "41AEC0"),
    Opcode(0, 413, "GET_TCY_MODE", "V", "41AF40"),
    Opcode(0, 414, "SET_TEXT_COLUMN", "V", "41AF70"),
    Opcode(0, 415, "GET_TEXT_COLUMN", "V", "41AFF0"),
    Opcode(0, 416, "SET_TEXT_COLUMN_LIMIT", "V", "41B020"),
    Opcode(0, 417, "GET_TEXT_COLUMN_LIMIT", "V", "41B0A0"),
    Opcode(0, 418, "SET_GLYPH_SIZE_OFFSET", "VV", "41B0D0"),
    Opcode(0, 419, "GET_GLYPH_SIZE_OFFSET", "VV", "41B160"),
    Opcode(0, 420, "SET_TEXT_COLOR", "VVV", "41B1C0"),
    Opcode(0, 421, "GET_TEXT_COLOR", "VVV", "41B280"),
    Opcode(0, 422, "SET_SHADOW_COLOR", "VVV", "41B300"),
    Opcode(0, 423, "GET_SHADOW_COLOR", "VVV", "41B3C0"),
    Opcode(0, 424, "SET_TEXT_FLAG_M", "V", "41B440"),
    Opcode(0, 425, "GET_TEXT_FLAG_M", "V", "41B4C0"),
    Opcode(0, 426, "SET_TEXT_FLAG_N", "V", "41B4F0"),
    Opcode(0, 427, "GET_TEXT_FLAG_N", "V", "41B570"),
    Opcode(0, 428, "SET_TEXT_FLAG_O", "V", "41B5A0"),
    Opcode(0, 429, "GET_TEXT_FLAG_O", "V", "41B620"),
    Opcode(0, 430, "SET_TEXT_FLAG_P", "V", "41B650"),
    Opcode(0, 431, "GET_TEXT_FLAG_P", "V", "41B6D0"),
    Opcode(0, 432, "SET_TEXT_WRAP_MODE", "V", "41B700"),
    Opcode(0, 433, "GET_TEXT_WRAP_MODE", "V", "41B780"),
    Opcode(0, 434, "SET_TEXT_FLAG_R", "V", "41B7B0"),
    Opcode(0, 435, "GET_TEXT_FLAG_R", "V", "41B830"),
    Opcode(0, 436, "SET_TEXT_FLAG_S", "V", "41B860"),
    Opcode(0, 437, "GET_TEXT_FLAG_S", "V", "41B8E0"),
    Opcode(0, 438, "SET_TEXT_FLAG_T", "V", "41B910"),
    Opcode(0, 439, "GET_TEXT_FLAG_T", "V", "41B990"),
    Opcode(0, 440, "SET_TEXT_FLAG_U", "V", "41B9C0"),
    Opcode(0, 441, "GET_TEXT_FLAG_U", "V", "41BA40"),
    Opcode(0, 442, "SET_TEXT_FLAG_V", "V", "41BA70"),
    Opcode(0, 443, "GET_TEXT_FLAG_V", "V", "41BAF0"),
    Opcode(0, 444, "TEXT_WAIT", "V", "41BB20"),
    Opcode(0, 445, "TEXT_NEWLINE", "", "41BBA0"),
    Opcode(0, 446, "TEXT_NEW_PAGE", "", "41BC00"),
    Opcode(0, 500, "REFRESH_DRAWING_CONTEXT", "VVV", "429FC0"),
    Opcode(0, 600, "CONFIGURE_MESSAGE_SURFACE", "VVVVVVVV", "408B20"),
    Opcode(0, 601, "CONFIGURE_MESSAGE_SHADOW", "VVVV", "408BA0"),
    Opcode(0, 602, "SET_GLYPH_DRAW_MODE", "V", "408BF0"),
    Opcode(0, 603, "SET_MESSAGE_WAIT_SCENE", "X", "408C10"),
    Opcode(0, 604, "SET_MESSAGE_AFTER_SCENE", "X", "408C30"),
    Opcode(0, 605, "DEFINE_CUSTOM_GLYPH", "VVVVVVVV", "408C50"),
    Opcode(0, 606, "DRAW_MESSAGE_BACKGROUND", "", "408D20"),
    Opcode(0, 607, "TEXT", "S", "408D80"),
    Opcode(0, 608, "TEXT_FROM_STRING", "K", "408E40"),
    Opcode(0, 609, "TEXT_CUSTOM_GLYPH", "V", "408F30"),
    Opcode(0, 610, "TEXT_APPEND_TO_STRING", "KS", "409000"),
    Opcode(0, 611, "GET_MESSAGE_STATE", "VVVVVV", "40C3F0"),
    Opcode(0, 612, "REDRAW_LOG_TEXT", "", "40C4F0"),
    Opcode(0, 613, "RETURN_FROM_TEXT_CALLBACK", "", "40C660"),
    Opcode(0, 700, "CLEAR_MESSAGE_LOG", "", "411A60"),
    Opcode(0, 701, "START_MESSAGE_LOG_ENTRY", "", "411AA0"),
    Opcode(0, 702, "FINISH_MESSAGE_LOG_ENTRY", "", "411B00"),
    Opcode(0, 703, "TOGGLE_MESSAGE_LOG", "", "411B40"),
    Opcode(0, 704, "GET_MESSAGE_LOG_COUNT", "V", "411B60"),
    Opcode(0, 705, "DRAW_MESSAGE_LOG_ENTRY", "VVVV", "411B90"),
    Opcode(0, 800, "PLAY_STREAM", "VVVVVVV", "41C3A0"),
    Opcode(0, 801, "PLAY_STREAM_ALTERNATE", "VVVVVVV", "41C880"),
    Opcode(0, 802, "STOP_STREAM", "VV", "41C890"),
    Opcode(0, 803, "PAUSE_RESUME_STREAM", "VV", "41CAB0"),
    Opcode(0, 804, "GET_STREAM_STATE", "VV", "41CCE0"),
    Opcode(0, 900, "PLAY_MEDIA_BY_NAME", "VSVVVVVV", "4180D0"),
    Opcode(0, 901, "PLAY_MEDIA_QUEUED_BY_NAME", "VVVVVVVS", "4187F0"),
    Opcode(0, 902, "PLAY_MEDIA_FROM_STRING", "VKVVVVVV", "418800"),
    Opcode(0, 903, "STOP_MEDIA", "VV", "418810"),
    Opcode(0, 904, "PAUSE_RESUME_MEDIA", "VV", "418A30"),
    Opcode(0, 905, "GET_MEDIA_STATE", "VV", "418C60"),
    Opcode(0, 1000, "PLAY_WAVE_BY_NAME", "VSVVVVVV", "417410"),
    Opcode(0, 1001, "PLAY_WAVE_QUEUED_BY_NAME", "VVVVVVVS", "417B60"),
    Opcode(0, 1002, "PLAY_WAVE_FROM_STRING", "VKVVVVVV", "417B70"),
    Opcode(0, 1003, "STOP_WAVE", "VV", "417B80"),
    Opcode(0, 1004, "PAUSE_RESUME_WAVE", "VV", "417DD0"),
    Opcode(0, 1005, "GET_WAVE_STATE", "VV", "418000"),
    Opcode(0, 1100, "LOAD_AUX_SOUND", "VVS", "417290"),
    Opcode(0, 1101, "PLAY_AUX_SOUND", "VV", "417320"),
    Opcode(0, 1200, "PLAY_BLOCKING_MEDIA", "VSVVV", "408920"),
    Opcode(0, 1300, "MARK_BANK_A_PERSISTENT", "V", "40C690"),
    Opcode(0, 1301, "MARK_BANK_B_PERSISTENT", "V", "40C700"),
    Opcode(0, 1302, "SET_BANK_A_PERSISTENCE_RANGE", "VV", "40C770"),
    Opcode(0, 1303, "SET_BANK_B_PERSISTENCE_RANGE", "VV", "40C7B0"),
    Opcode(0, 1304, "SET_BANK_A_DEBUG_NAME", "VV", "40C7E0"),
    Opcode(0, 1305, "SET_BANK_B_DEBUG_NAME", "VV", "40C830"),
    Opcode(0, 1306, "READ_SAVE_HEADER", "VV", "40C880"),
    Opcode(0, 1307, "LOAD_SAVE_SLOT", "V", "40C940"),
    Opcode(0, 1308, "VALIDATE_SAVE_SLOT", "V", "40CAC0"),
    Opcode(0, 1309, "READ_SAVE_METADATA", "V", "40CC40"),
    Opcode(0, 1310, "WRITE_SAVE_SLOT", "", "40CD30"),
    Opcode(0, 1311, "SNAPSHOT_RENDER_STATE", "", "40CE90"),
    Opcode(0, 1312, "SNAPSHOT_MESSAGE_STATE", "", "40CEB0"),
    Opcode(0, 1313, "SNAPSHOT_TEXT_STATE", "", "40CED0"),
    Opcode(0, 1314, "SNAPSHOT_STREAM_STATE", "", "40CEF0"),
    Opcode(0, 1315, "SNAPSHOT_MEDIA_STATE", "", "40CF10"),
    Opcode(0, 1316, "SNAPSHOT_WAVE_STATE", "", "40CF30"),
    Opcode(0, 1317, "SNAPSHOT_VALUE_STACK", "", "40CF50"),
    Opcode(0, 1318, "SNAPSHOT_SCENE_STACK", "", "40CF70"),
    Opcode(0, 1319, "RESTORE_IMAGE_RESOURCES", "", "40CFF0"),
    Opcode(0, 1320, "RESTORE_MESSAGE_STATE", "", "40D1D0"),
    Opcode(0, 1321, "RESTORE_STREAM_STATE", "", "40D1F0"),
    Opcode(0, 1322, "RESTORE_MEDIA_STATE", "", "40D2A0"),
    Opcode(0, 1323, "RESTORE_WAVE_STATE", "", "40D350"),
    Opcode(0, 1324, "RESTORE_BANK_A", "", "40D420"),
    Opcode(0, 1325, "RESTORE_BANK_B", "", "40D450"),
    Opcode(0, 1326, "RESTORE_SCENE_STACK", "", "40D480"),
    Opcode(0, 1400, "CONFIGURE_INPUT_MAPPING", "VVVVVVVVVVVVVVVVVVVVVVVVVV", "421610"),
    Opcode(0, 1401, "POLL_MAPPED_INPUT", "", "421970"),
    Opcode(0, 1402, "SET_INPUT_BINDING", "VV", "421D40"),
    Opcode(0, 1403, "GET_INPUT_BINDING", "VV", "421D90"),
    Opcode(0, 1404, "ENABLE_INPUT_FEATURE", "V", "421E00"),
    Opcode(0, 1405, "DISABLE_INPUT_FEATURE", "V", "421ED0"),
    Opcode(0, 1406, "TEST_CURSOR_IN_REGION", "VVVVVVVV", "421FA0"),
    Opcode(0, 1500, "UPDATE_MOUSE_TRACKER", "VVV", "4294D0"),
    Opcode(0, 1600, "WAIT_TIMER", "VV", "41CDB0"),
    Opcode(0, 1601, "SET_TIMER_BASE", "VV", "41CE90"),
    Opcode(0, 1602, "READ_ELAPSED_TIME", "VV", "41CF00"),
    Opcode(0, 1700, "LOCALE_CLASSIC_STUB", "", "jump-table case 168"),
    Opcode(0, 1701, "SET_DELAY_INTERVAL", "V", "425200"),
    Opcode(0, 1702, "WAIT_DELAY", "", "425220"),
    Opcode(0, 1800, "SEED_RANDOM", "V", "427370"),
    Opcode(0, 1801, "RANDOM_RANGE", "VVV", "427390"),
    Opcode(0, 1900, "READ_LOCAL_TIME", "VVVVVVVVV", "4273F0"),
    Opcode(0, 2000, "QUERY_CPU_FEATURES", "VV", "4250F0"),
    Opcode(0, 2100, "CONFIRM_RESOURCE_PATH", "VVSS", "40ED50"),
    Opcode(0, 2200, "MESSAGE_BOX", "SSVVV", "41C320"),
    Opcode(0, 2300, "READ_REGISTRY_DWORD", "SV", "414510"),
    Opcode(0, 2301, "WRITE_REGISTRY_DWORD", "SV", "4145C0"),
    Opcode(0, 2400, "DESTROY_GAME_WINDOW", "", "41C300"),
    Opcode(0, 2500, "CONFIGURE_RESOURCE_ROOT", "VVSSV", "403A90"),
    Opcode(0, 2501, "OPEN_PAK", "VVSVSV", "403BA0"),
    Opcode(0, 2502, "CONFIGURE_RESOURCE_LOOKUP", "VVSV", "403CC0"),
    Opcode(0, 2503, "SET_STARTUP_SCENE", "X", "403DE0"),
    Opcode(0, 2504, "STARTUP_NOOP", "", "403E00"),
    Opcode(0, 2505, "SET_SAVE_DIRECTORY", "S", "403E10"),
    Opcode(0, 2506, "SYNC_STARTUP_IO", "", "403E30"),
    Opcode(0, 2507, "QUERY_STARTUP_FLAG", "V", "403E60"),
    Opcode(0, 2600, "SET_BUTTON_CONFIG", "VVVVVVV", "4292A0"),
    Opcode(0, 2601, "GET_BUTTON_CONFIG", "VVVVVVV", "429340"),
    Opcode(0, 2602, "POLL_BUTTON_CONFIG", "VV", "429480"),
    Opcode(0, 3000, "SHOW_CHOICES", "VVKKKSSSV", "422140"),
    Opcode(0, 3100, "LOAD_COLOR_AND_MASK_IMAGES", "VVVVVS", "405BD0"),
)
OPCODES = {(entry.tag, entry.number): entry for entry in (*CORE, *COMMANDS)}
MNEMONICS = {entry.mnemonic: entry for entry in OPCODES.values()}
DEFAULT_ENCODING = "cp932"


def script_encoding(name):
    import codecs

    codec = codecs.lookup(name).name
    if "ASCII ;\\\"".encode(codec) != b'ASCII ;\\"' or "\0".encode(codec) != b"\0":
        raise ValueError(f"encoding {name!r} is not compatible with NUL-terminated Sceplay strings")
    return codec


def plan_jobs(inputs, output, input_suffix, output_suffix, directory_suffix,
              *, single_suffix=None, allow_named_text=False):
    from pathlib import Path

    def input_stem(path, *, explicit=False):
        name = path.name.lower()
        if name.endswith(input_suffix):
            return path.name[:-len(input_suffix)]
        if allow_named_text and (name == "asm.txt" or (explicit and name.endswith(".txt"))):
            return path.stem
        return None

    jobs = []
    if output is not None and len(inputs) != 1:
        raise ValueError("-o requires exactly one input file or directory")
    for source in map(Path, inputs):
        if source.is_dir():
            destination = output if output is not None else source.resolve().with_name(
                source.resolve().name + directory_suffix
            )
            found = sorted(path for path in source.rglob("*")
                           if path.is_file() and input_stem(path) is not None)
            if not found:
                raise ValueError(f"{source}: no {input_suffix} files found")
            for path in found:
                relative = path.relative_to(source)
                name = input_stem(path) + output_suffix
                jobs.append((path, destination / relative.with_name(name)))
        elif source.is_file() and (stem := input_stem(source, explicit=True)) is not None:
            if output is None:
                destination = source.with_name(stem + (single_suffix or output_suffix))
            elif output.is_dir():
                destination = output / (stem + output_suffix)
            else:
                destination = output
            jobs.append((source, destination))
        else:
            raise ValueError(f"{source}: expected a {input_suffix} file or a directory")

    sources = {source.resolve() for source, _ in jobs}
    destinations = set()
    for _, target in jobs:
        resolved = target.resolve()
        if resolved in sources or resolved in destinations:
            raise ValueError(f"output path collides with an input or another output: {target}")
        destinations.add(resolved)
    return jobs


def write_output(path, payload):
    from pathlib import Path
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        staged = Path(stream.name)
        try:
            stream.write(payload)
            stream.close()
            staged.replace(path)
        finally:
            staged.unlink(missing_ok=True)
