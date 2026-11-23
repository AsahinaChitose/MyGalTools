"""Verified command layouts for the Ankh SNR script VM."""

from __future__ import annotations


def u32(name: str, meaning: str = "") -> dict[str, str]:
    return {"kind": "u32", "name": name, "meaning": meaning}


def target(name: str, meaning: str = "") -> dict[str, str]:
    return {"kind": "target", "name": name, "meaning": meaning}


def text(name: str, meaning: str = "") -> dict[str, str]:
    return {"kind": "text", "name": name, "meaning": meaning}


def repeat(count: str, fields: list[dict[str, object]], maximum: int) -> dict[str, object]:
    return {"kind": "repeat", "count": count, "fields": fields, "maximum": maximum}


def when(field: str, equals: int, fields: list[dict[str, str]]) -> dict[str, object]:
    return {"kind": "when", "field": field, "equals": equals, "fields": fields}


def text_slots(name: str, count: int) -> dict[str, object]:
    return {"kind": "text_slots", "name": name, "count": count}


def command(mnemonic: str, handler: str, fields: list[dict[str, object]], summary: str) -> dict[str, object]:
    return {
        "mnemonic": mnemonic,
        "bytecode": "u32le opcode",
        "length": "4-byte opcode followed by fields",
        "handler": handler,
        "fields": fields,
        "summary": summary,
    }


OPCODES: dict[int, dict[str, object]] = {
    0: command("MESSAGE_NO_ID", "0x419130(a2=0, a3=0)", [
        text("text", "message bytes"), u32("wait_mode", "display/wait mode"),
    ], "Display a length-prefixed message."),
    1: command("MESSAGE", "0x419130(a2=0, a3=1)", [
        u32("message_id", "message/voice lookup id"),
        text("text", "message bytes"),
        u32("wait_mode", "display/wait mode"),
    ], "Display a message with an id."),
    2: command("JUMP", "0x418B90", [
        target("destination", "absolute byte offset from script start"),
    ], "Unconditional byte-offset jump."),
    3: command("CALL", "0x418BF0", [
        target("destination", "absolute byte offset from script start"),
    ], "Push the return offset and jump."),
    4: command("RETURN", "0x418CB0", [], "Return to a saved script offset."),
    5: command("VAR_SET", "0x4199B0", [
        u32("destination_var"), u32("source_is_var"), u32("source"),
    ], "Assign an immediate or variable value."),
    6: command("VAR_ADD", "0x419A40(case 0)", [
        u32("destination_var"), u32("source_is_var"), u32("source"),
    ], "Add an immediate or variable value."),
    7: command("VAR_SUB", "0x419A40(case 1)", [
        u32("destination_var"), u32("source_is_var"), u32("source"),
    ], "Subtract an immediate or variable value."),
    8: command("VAR_MUL", "0x419A40(case 2)", [
        u32("destination_var"), u32("source_is_var"), u32("source"),
    ], "Multiply by an immediate or variable value."),
    9: command("VAR_DIV", "0x419A40(case 3)", [
        u32("destination_var"), u32("source_is_var"), u32("source"),
    ], "Divide by an immediate or variable value."),
    10: command("IF_VAR", "0x418D50", [
        u32("left_var"), u32("comparison"), u32("right_is_var"),
        u32("right"), target("destination", "absolute byte offset from script start"),
    ], "Conditional branch; comparison codes are documented in vm_analysis.md."),
    11: command("DRAW_BACKGROUND", "0x418010", [
        text("resource", "resource name"), u32("mode"), u32("arg0"), u32("arg1"),
        when("mode", 8, [text("alternate_resource", "alternate resource name")]),
    ], "Load/draw a named background resource."),
    12: command("SET_EVENT", "0x4197F0", [u32("event_id")], "Set an engine event."),
    14: command("PLAY_VOICE", "0x419830", [
        text("resource", "voice/resource name"), u32("wait_after_playback"),
    ], "Play a named voice resource."),
    15: command("SET_NAME", "0x4198E0", [
        u32("name_id"), text("name", "speaker name bytes"),
    ], "Set the displayed speaker name."),
    16: command("CHOICE", "0x4194B0", [
        u32("choice_count"), u32("selection_var"),
        repeat("choice_count", [
            text("choice_text", "choice label bytes"), u32("flag_id"),
        ], 4),
    ], "Display a list of choices with flag ids."),
    17: command("DRAW_TEXT", "0x418280(a2=0)", [
        text("text"), u32("arg0"), u32("arg1"), u32("arg2"), u32("arg3"),
    ], "Draw text with four engine parameters."),
    18: command("LOAD_SNR", "0x418F20", [
        text("script_name", "script member name"),
    ], "Load another SNR script by name."),
    19: command("SLEEP", "0x417B40", [u32("milliseconds")], "Sleep for a duration."),
    20: command("SET_MOVIE_NAME", "0x417B90", [
        text("movie_name", "movie/resource name"),
    ], "Set the movie resource name."),
    21: command("SWITCH_VAR", "0x418F80", [
        u32("variable"), u32("target_count"),
        repeat("target_count", [target("destination", "absolute byte offset from script start")], 256),
    ], "Branch through a variable-indexed target table."),
    22: command("SET_FLAG", "0x417BE0", [u32("flag_id")], "Set an engine flag."),
    23: command("IF_FLAG", "0x419070", [
        u32("flag_id"), target("destination", "absolute byte offset from script start"),
    ], "Branch when a flag is set."),
    24: command("SET_TEXT_MODE", "0x417C20", [u32("mode")], "Select a text display mode."),
    25: command("DRAW_TEXT_PANEL", "0x418490", [u32("arg0"), u32("arg1"), u32("arg2")],
                "Draw/update the text panel."),
    26: command("RESET_TEXT_SLOT", "0x418550", [u32("slot")], "Reset a text slot."),
    27: command("DRAW_DIALOG", "0x4185A0", [
        text_slots("labels", 4), u32("mode"),
        u32("arg0"), u32("arg1"), u32("arg2"), u32("arg3"), u32("arg4"),
        when("mode", 8, [text("alternate_text")]),
    ], "Draw a dialog with up to four inline labels."),
    28: command("SET_PANEL_POSITION", "0x4183C0", [
        u32("panel"), u32("x"), u32("y"), u32("width"),
    ], "Set panel layout parameters."),
    29: command("DRAW_TEXT_ALT", "0x418280(a2=1)", [
        text("text"), u32("arg0"), u32("arg1"),
    ], "Draw text using the alternate handler variant."),
    30: command("DRAW_EFFECT", "0x418780", [u32("effect"), u32("duration")],
                "Apply a display effect."),
    31: command("SET_VIEW_RANGE", "0x418810", [
        u32("start"), u32("end"), u32("arg0"), u32("arg1"), u32("arg2"), u32("arg3"),
    ], "Set a view/text range."),
    32: command("MESSAGE_NAMED", "0x419130(a2=1, a3=1)", [
        u32("message_id"), text("text"), u32("wait_mode"), u32("name_id"),
        text("name", "speaker name bytes"),
    ], "Display a message with an explicit speaker name."),
    33: command("START_MOVIE", "0x417DB0", [
        text("movie_name", "movie/resource name"),
    ], "Start playback of the selected movie."),
    34: command("INVALIDATE_DISPLAY", "0x4188B0", [u32("region")], "Invalidate a display region."),
    35: command("SET_SCREEN_COLOR", "0x4188F0", [u32("red"), u32("green"), u32("blue")],
                "Set screen color components."),
    36: command("CLEAR_TEXT", "0x417CB0", [], "Clear text display state."),
    37: command("WAIT_INPUT", "0x417CD0", [], "Wait for input and reset display state."),
    38: command("CLEAR_DISPLAY", "0x419660", [], "Clear the display surface."),
    39: command("DRAW_TEXT_CONFIG", "0x418950", [
        u32("font_mode"), u32("arg0"), u32("arg1"), u32("arg2"),
        u32("arg3"), u32("arg4"), u32("arg5"),
    ], "Draw/update text with seven parameters."),
    40: command("DRAW_TEXT_STYLE", "0x418A50", [
        u32("style"), u32("arg0"), u32("arg1"),
    ], "Apply a text drawing style."),
    41: command("DRAW_INLINE_RESOURCE", "0x419670", [
        text("resource_data"), u32("duration"), u32("x"), u32("y"),
    ], "Draw a length-prefixed resource payload."),
    42: command("SET_DRAW_COLOR", "0x418B00", [
        u32("mode"), u32("red"), u32("green"), u32("blue"), u32("alpha"),
    ], "Set draw/color parameters."),
    43: command("RESET_DISPLAY", "0x417D50", [], "Reset display and wait state."),
}

OPCODE_BY_MNEMONIC = {entry["mnemonic"]: opcode for opcode, entry in OPCODES.items()}
# Accept the earlier draft name in asm files created before the handler was
# confirmed to index a variable table rather than a bit flag.
OPCODE_BY_MNEMONIC["SWITCH_FLAG"] = 21
RESERVED_OPCODES = {13}
COMMAND_WIDTH = 4
INTEGER_FORMAT = "<I"
SCRIPT_ENCODING = "cp932"
ASSEMBLER_DEFAULT_ENCODING = "<read .encoding from asm header>"
SOURCE_HASH_SUFFIX = "@src=sha256:"
MAX_TEXT_BYTES = 0xFFFFFFFF
MAX_INSTRUCTIONS = 2_000_000
