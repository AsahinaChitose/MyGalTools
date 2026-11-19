# -*- coding: utf-8 -*-
"""
opcodelist.py -- GsWIN SC (SCW) 字节码操作码表

真值源: vm_analysis.md（CLAUDE.md §0 要求的 VM 分析定义文档）
证据:   exe/Saeko_disasm.asm + exe/Saeko_pseudo.c 中 sub_40B960 的分派树
        与各 handler 的 ip 推进、字段访问、调用链。

字段说明:
  mnemonic    助记符。只有能由程序内字符串/调用链确证的才用官方名，
              其余为 _OPxx 占位（CLAUDE.md：不得臆造名称）。
  length      定长字节数；None 表示未确认。
  kind        "fixed" | "expr"（20+12n）| "cond"（16+12n）| "block" | "unknown"
  fields      该记录内 4 字节操作数字段的偏移（不含 opcode 本身）
  text_fields 其中「文本池字节偏移」的字段偏移（重定位白名单）
  status      已确认的维度：L=长度 F=字段 S=语义
"""

# ---------------------------------------------------------------------------
# 记录形态
# ---------------------------------------------------------------------------
EXPR = "expr"        # 20 + 12*count，count 在 +16
COND = "cond"        # 16 + 12*count，count 在 +12
BLOCK = "block"      # _LOOP
FIXED = "fixed"
UNKNOWN = "unknown"

# 文本池引用的原生字段（伪代码中 *(v3+K) + this[124]，以及字段普查结果）
# 普查方法: 对每个 opcode 记录逐字段统计「值落在字符串起点」的比例,
# 仅收录比例 >= 93% 且样本 >= 4 的字段（见 scw_asm.md）。
TEXT_RAW_FIELDS = {
    0x070000: [8, 12, 16, 20],
    0x0A0000: [8, 12, 16],
    0x0D0000: [4],
    0x1D0000: [4],
    0x230000: [4, 8],
    0x260000: [4],
    0x320000: [8],
    0x330000: [4],
    0x400000: [4],
    0x4C0000: [4],
    0x4D0000: [4],
    0x4E0000: [4],
    0x150000: [4],
    0x160000: [4],
    0x170000: [4],
    0x180000: [4],
    0x5E0000: [40],
    0x620000: [40, 44],
    0x120000: [8],
}

# opcode -> (mnemonic, kind, length, fields, status)
_T = [
    (0x000003, "_OP03", UNKNOWN, None, [], "L?"),
    (0x0000D0, "_OPD0", FIXED, 8, [4], "LF"),
    (0x010000, "_OP01", FIXED, 12, [4, 8], "LFS"),
    (0x030000, "_OP03b", FIXED, 8, [4], "LF"),
    (0x060000, "_OP06", FIXED, 8, [4], "LF"),
    (0x070000, "_OP07", FIXED, 24, [4, 8, 12, 16, 20], "LF"),
    (0x080000, "_OP08", FIXED, 20, [4, 8, 12, 16, 20], "LF"),
    (0x090000, "_OP09", FIXED, 16, [4, 8, 12, 16], "LF"),
    (0x0A0000, "_OP0A", FIXED, 20, [4, 8, 12, 16, 20], "LF"),
    (0x0D0000, "_OP0D", FIXED, 8, [4], "LF"),
    (0x0E0000, "_OP0E", FIXED, 8, [4, 8], "LF"),
    (0x0F0000, "_OP0F", FIXED, 32, [4, 8, 12, 16, 20, 24, 28], "LF"),
    (0x100000, "_MSG", FIXED, 16, [4, 8, 12], "LFS"),
    (0x110000, "_OP11", UNKNOWN, None, [], "?"),
    (0x120000, "_OP12", EXPR, None, [4, 8, 12], "LFS"),
    (0x150000, "_OP15", FIXED, 8, [4], "LFS"),
    (0x160000, "_OP16", FIXED, 8, [4], "LFS"),
    (0x170000, "_OP17", FIXED, 8, [4], "LFS"),
    (0x180000, "_OP18", FIXED, 8, [4], "LFS"),
    (0x1A0000, "_STR", EXPR, None, [4, 12, 16], "LFS"),
    (0x1B0000, "_LOOP", BLOCK, None, [4, 8], "LFS"),
    (0x1D0000, "_OP1D", FIXED, 8, [4], "LF"),
    (0x1E0000, "_OP1E", UNKNOWN, None, [], "?"),
    (0x1F0000, "_OP1F", FIXED, 8, [4], "LF"),
    (0x200000, "_OP20", FIXED, 8, [4], "LF"),
    (0x210000, "_OP21", FIXED, 4, [], "L"),
    (0x220000, "_OP22", FIXED, 4, [], "L"),
    (0x230000, "_OP23", FIXED, 16, [4, 8, 12], "LFS"),
    (0x240000, "_OP24", FIXED, 4, [], "L"),
    (0x250000, "_OP25", FIXED, 4, [], "L"),
    (0x260000, "_OP26", FIXED, 8, [4], "LFS"),
    (0x270000, "_OP27", UNKNOWN, None, [], "?"),
    (0x280000, "_OP28", UNKNOWN, None, [], "?"),
    (0x290000, "_OP29", UNKNOWN, None, [], "?"),
    (0x2A0000, "_OP2A", UNKNOWN, None, [], "?"),
    (0x2B0000, "_OP2B", FIXED, 4, [], "L"),
    (0x2D0000, "_OP2D", FIXED, 4, [], "L"),
    (0x300000, "_OP30", FIXED, 4, [], "L"),
    (0x310000, "_OP31", FIXED, 4, [], "L"),
    (0x320000, "_OP32", FIXED, 24, [4, 8, 12, 16, 20], "LF"),
    (0x330000, "_OP33", FIXED, 24, [4, 8, 12, 16, 20], "LF"),
    (0x340000, "_OP34", FIXED, 8, [4], "LF"),
    (0x390000, "_OP39", FIXED, 12, [4, 8], "LF"),
    (0x3A0000, "_OP3A", FIXED, 24, [4, 8, 12, 16, 20], "LF"),
    (0x400000, "_OP40", FIXED, 8, [4], "LFS"),
    (0x4C0000, "_OP4C", FIXED, 4, [4], "LFS"),
    (0x4D0000, "_OP4D", FIXED, 8, [4], "LFS"),
    (0x4E0000, "_OP4E", FIXED, 8, [4], "LFS"),
    (0x510000, "_OP51", FIXED, 8, [4, 8], "LF"),
    (0x520000, "_OP52", FIXED, 4, [], "L"),
    (0x540000, "_OP54", FIXED, 4, [], "L"),
    (0x550000, "_OP55", FIXED, 4, [], "L"),
    (0x560000, "_OP56", FIXED, 4, [], "L"),
    (0x590000, "_OP59", FIXED, 8, [4, 8], "LF"),
    (0x5E0000, "_OP5E", FIXED, 44, [4, 8, 12, 16, 20, 24, 28, 32, 36], "LF"),
    (0x600000, "_OP60", FIXED, 8, [4], "LF"),
    (0x610000, "_OP61", FIXED, 4, [], "L"),
    (0x620000, "_OP62", FIXED, 48, [4, 8, 12, 16, 20, 24, 28, 32, 36, 48], "LF"),
    (0x630000, "_OP63", FIXED, 80, list(range(4, 84, 4)), "LF"),
    (0x640000, "_OP64", FIXED, 84, list(range(4, 88, 4)), "LF"),
    (0x650000, "_OP65", FIXED, 16, [4, 8, 12], "LF"),
    (0x700000, "_OP70", FIXED, 36, list(range(4, 40, 4)), "LF"),
    (0x740000, "_OP74", FIXED, 28, list(range(4, 32, 4)), "LF"),
    (0x750000, "_OP75", FIXED, 40, list(range(4, 40, 4)), "LF"),
    (0x760000, "_OP76", FIXED, 32, list(range(4, 36, 4)), "LF"),
    (0x7D0000, "_OP7D", FIXED, 4, [], "L"),
    (0x7E0000, "_OP7E", FIXED, 8, [4, 8], "LF"),
    (0x7F0000, "_OP7F", UNKNOWN, None, [], "?"),
    (0x800000, "_IF", COND, None, [12, 16], "LFS"),
    (0x810000, "_OP81", FIXED, 8, [4], "LF"),
    (0x850000, "_OP85", UNKNOWN, None, [], "?"),
    (0x900000, "_OP90", FIXED, 4, [], "L"),
    (0x910000, "_OP91", FIXED, 12, [4, 8], "LF"),
    (0x80000000, "_OP80", FIXED, 4, [], "L"),
]

OPCODES = {}
for _op, _mn, _kind, _len, _fields, _status in _T:
    OPCODES[_op] = {
        "mnemonic": _mn,
        "kind": _kind,
        "length": _len,
        "fields": _fields,
        "text_fields": TEXT_RAW_FIELDS.get(_op, []),
        "status": _status,
    }
    if _op == 0x100000:      # 消息表: +8 文本, +12 标签
        OPCODES[_op]["text_fields"] = [8, 12]

# 值操作数里的文本引用: u16 kind=16, u16 sub=0x100, u32 offset
VALUE_OPERAND_KIND = 16
VALUE_OPERAND_SUB = 0x100
VALUE_OPERAND_SIZE = 8

TEXT_REF_CLASSES = (
    "value_operand",   # kind=16 / sub=0x100
    "message_record",  # 0x00100000 +8/+12
    "opcode_field",    # TEXT_RAW_FIELDS
)


def mnemonic(op):
    e = OPCODES.get(op)
    return e["mnemonic"] if e else "_OP%08X" % op


def length_of(op):
    e = OPCODES.get(op)
    if not e:
        return None
    return e["length"]
