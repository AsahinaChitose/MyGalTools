# -*- coding: utf-8 -*-
"""
SDT 脚本 VM 指令集定义 —— 鎖－クサリ－ (kusari.exe)

本文件是 disassembler.py / assembler.py 的唯一真值源。
表格来源：kusari.exe 内 0x4A2770 处的“操作数 schema 表”，
每 17 字节描述一个命令（下标 17*(opcode-64)）：
    字节 0..14  操作数类型序列，0 表示结束
    字节 15     指令执行后是否阻塞（sub_406ED0 的返回值）
    字节 16     变体值个数（x16，仅供参考）
与 sub_403A70 / sub_403A90 / sub_403C90 的反编译结果一致。

操作数类型:
    1,7  imm8      1 字节立即数
    2    variant   变体值：类型字节 0=寄存器(4字节下标) / 1=立即数(4字节) / 2=字符串(1字节长度)
    3    str8      1 字节长度 + 字节串
    4    str16     2 字节长度 + 字节串
    5    reg8      1 字节寄存器号（执行后写回）
    6    cmp       寄存器号 + 条件码 + 变体值
    8,9  imm16     2 字节立即数

低号指令（0x01..0x28）由 sub_41E090 直接分派；
高号指令（>=0x40，实际 >=0x2A）由 sub_406ED0 按本表解析后再分派。
"""

ENCODING = "cp932"
REG_COUNT = 50
ENTRY_TABLE_SIZE = 256
CODE_OFFSET = 1032

COND_NAMES = {0: "LT", 1: "LE", 2: "GT", 3: "GE", 4: "EQ", 5: "NE"}
COND_VALUES = {v: k for k, v in COND_NAMES.items()}

# 每个操作数类型对应的文本写法
OPERAND_KIND = {
    "imm8": "u8", "imm16": "u16", "imm32": "u32", "label32": "label",
    "reg8": "reg", "variant": "variant", "str8": "str", "str16": "str",
    "cond": "cond", "cmp": "cmp", "callargs": "callargs",
}

# 已知语义的命令名（其余保持 CMD_xxxx；可在 vm_analysis.md 中查表）
NAME_OVERRIDES = {
    0x0078: "CHANGE_SCRIPT",    # 载入 "%s.sdt" 并切换（sub_403E30）
    0x00B8: "MESSAGE",          # 信息窗文本：字符串 + 字节 + 字（消息序号）
    0x00BC: "MESSAGE_ALT",      # 文本变体（sub_4045C0(1)）
    0x010D: "MOVIE",            # 播放动画（sub_406440）
    0x011D: "SET_SCRIPT_NAME",  # 保存脚本名到全局（sub_41ABA0）
}

LOW_OPCODES = {
    0x01: {"mnemonic": "END",        "ops": [],                          "size": 2,  "desc": "结束脚本：PC=0，状态=0，栈指针必须为 0"},
    0x02: {"mnemonic": "MOV",        "ops": ["reg8", "reg8"],            "size": 4,  "desc": "Rd = Rs"},
    0x03: {"mnemonic": "MOVI",       "ops": ["reg8", "imm32"],           "size": 7,  "desc": "Rd = imm32"},
    0x04: {"mnemonic": "SWAP",       "ops": ["reg8", "reg8"],            "size": 4,  "desc": "交换两个寄存器"},
    0x05: {"mnemonic": "RAND",       "ops": ["reg8"],                    "size": 3,  "desc": "Rd = rand() % 0xFFFF"},
    0x06: {"mnemonic": "JCC_RR",     "ops": ["reg8", "cond", "reg8", "label32"], "size": 9,  "desc": "比较两寄存器，条件成立则跳到 target"},
    0x07: {"mnemonic": "JCC_RI",     "ops": ["reg8", "cond", "imm32", "label32"], "size": 12, "desc": "比较寄存器与立即数，条件成立则跳到 target"},
    0x08: {"mnemonic": "JNCC_RR",    "ops": ["reg8", "cond", "reg8", "label32"], "size": 9,  "desc": "比较两寄存器，条件不成立则跳到 target"},
    0x09: {"mnemonic": "JNCC_RI",    "ops": ["reg8", "cond", "imm32", "label32"], "size": 12, "desc": "比较寄存器与立即数，条件不成立则跳到 target"},
    0x0A: {"mnemonic": "LOOP",       "ops": ["reg8", "label32"],          "size": 7,  "desc": "Rd-=1；若 Rd>0 跳到 target，否则继续"},
    0x0B: {"mnemonic": "JMP",        "ops": ["label32"],                  "size": 6,  "desc": "无条件跳转"},
    0x0C: {"mnemonic": "INC",        "ops": ["reg8"],                     "size": 3,  "desc": "Rd += 1"},
    0x0D: {"mnemonic": "DEC",        "ops": ["reg8"],                     "size": 3,  "desc": "Rd -= 1"},
    0x0E: {"mnemonic": "NOT",        "ops": ["reg8"],                     "size": 3,  "desc": "Rd = ~Rd"},
    0x0F: {"mnemonic": "NEG",        "ops": ["reg8"],                     "size": 3,  "desc": "Rd = -Rd"},
    0x10: {"mnemonic": "ADD_RR",     "ops": ["reg8", "reg8"],             "size": 4,  "desc": "Rd = Rd + Rs"},
    0x11: {"mnemonic": "ADD_RI",     "ops": ["reg8", "imm32"],            "size": 7,  "desc": "Rd = Rd + imm32"},
    0x12: {"mnemonic": "SUB_RR",     "ops": ["reg8", "reg8"],             "size": 4,  "desc": "Rd = Rd - Rs"},
    0x13: {"mnemonic": "SUB_RI",     "ops": ["reg8", "imm32"],            "size": 7,  "desc": "Rd = Rd - imm32"},
    0x14: {"mnemonic": "MUL_RR",     "ops": ["reg8", "reg8"],             "size": 4,  "desc": "Rd = Rd * Rs"},
    0x15: {"mnemonic": "MUL_RI",     "ops": ["reg8", "imm32"],            "size": 7,  "desc": "Rd = Rd * imm32"},
    0x16: {"mnemonic": "DIV_RR",     "ops": ["reg8", "reg8"],             "size": 4,  "desc": "Rd = Rd / Rs（除数为 0 时结果为 0）"},
    0x17: {"mnemonic": "DIV_RI",     "ops": ["reg8", "imm32"],            "size": 7,  "desc": "Rd = Rd / imm32"},
    0x18: {"mnemonic": "MOD_RR",     "ops": ["reg8", "reg8"],             "size": 4,  "desc": "Rd = Rd % Rs"},
    0x19: {"mnemonic": "MOD_RI",     "ops": ["reg8", "imm32"],            "size": 7,  "desc": "Rd = Rd % imm32"},
    0x1A: {"mnemonic": "AND_RR",     "ops": ["reg8", "reg8"],             "size": 4,  "desc": "Rd = Rd & Rs"},
    0x1B: {"mnemonic": "AND_RI",     "ops": ["reg8", "imm32"],            "size": 7,  "desc": "Rd = Rd & imm32"},
    0x1C: {"mnemonic": "OR_RR",      "ops": ["reg8", "reg8"],             "size": 4,  "desc": "Rd = Rd | Rs"},
    0x1D: {"mnemonic": "OR_RI",      "ops": ["reg8", "imm32"],            "size": 7,  "desc": "Rd = Rd | imm32"},
    0x1E: {"mnemonic": "XOR_RR",     "ops": ["reg8", "reg8"],             "size": 4,  "desc": "Rd = Rd ^ Rs"},
    0x1F: {"mnemonic": "XOR_RI",     "ops": ["reg8", "imm32"],            "size": 7,  "desc": "Rd = Rd ^ imm32"},
    0x20: {"mnemonic": "CALLX",      "ops": ["reg8", "callargs"],        "size": None, "desc": "带参数表调用表达式，结果写入 Rd"},
    0x21: {"mnemonic": "PUSHREGS",   "ops": [],                           "size": 2,  "desc": "把 50 个工作寄存器压栈"},
    0x22: {"mnemonic": "POPREGS",    "ops": [],                           "size": 2,  "desc": "从栈恢复 50 个工作寄存器"},
    0x23: {"mnemonic": "CALLBLK",    "ops": ["imm8"],                     "size": 3,  "desc": "调用脚本块（入口表下标）"},
    0x24: {"mnemonic": "RET",        "ops": [],                           "size": 2,  "desc": "从脚本块返回"},
    0x25: {"mnemonic": "WAITF",      "ops": ["imm16"],                    "size": 4,  "desc": "等待 N 帧"},
    0x26: {"mnemonic": "WAITT",      "ops": ["imm16"],                    "size": 4,  "desc": "等待 N 毫秒"},
    0x27: {"mnemonic": "START_SCRIPT", "ops": [],                        "size": 2,  "desc": "脚本段起始标记（每个文件开头）"},
    0x28: {"mnemonic": "CALLFILE",   "ops": ["str8"],                     "size": None, "desc": "载入并执行另一个 .sdt 脚本"},
}

HIGH_OPCODES = {
    0x0040: {"mnemonic": "CMD_40", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 5, "desc": ""},
    0x0041: {"mnemonic": "CMD_41", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 5, "desc": ""},
    0x0042: {"mnemonic": "CMD_42", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 4, "desc": ""},
    0x0043: {"mnemonic": "CMD_43", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 4, "desc": ""},
    0x0044: {"mnemonic": "CMD_44", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0045: {"mnemonic": "CMD_45", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0046: {"mnemonic": "CMD_46", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0047: {"mnemonic": "CMD_47", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 5, "desc": ""},
    0x0048: {"mnemonic": "CMD_48", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 5, "desc": ""},
    0x0049: {"mnemonic": "CMD_49", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x004A: {"mnemonic": "CMD_4A", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x004B: {"mnemonic": "CMD_4B", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x004C: {"mnemonic": "CMD_4C", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x004D: {"mnemonic": "CMD_4D", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x004E: {"mnemonic": "CMD_4E", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x004F: {"mnemonic": "CMD_4F", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0050: {"mnemonic": "CMD_50", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0051: {"mnemonic": "CMD_51", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0052: {"mnemonic": "CMD_52", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0053: {"mnemonic": "CMD_53", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0054: {"mnemonic": "CMD_54", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0055: {"mnemonic": "CMD_55", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0056: {"mnemonic": "CMD_56", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 8, "desc": ""},
    0x0057: {"mnemonic": "CMD_57", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0058: {"mnemonic": "CMD_58", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x0059: {"mnemonic": "CMD_59", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x005A: {"mnemonic": "CMD_5A", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x005B: {"mnemonic": "CMD_5B", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x005C: {"mnemonic": "CMD_5C", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x005D: {"mnemonic": "CMD_5D", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 4, "desc": ""},
    0x005E: {"mnemonic": "CMD_5E", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 1, "desc": ""},
    0x005F: {"mnemonic": "CMD_5F", "ops": ["variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x0060: {"mnemonic": "CMD_60", "ops": ["variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x0061: {"mnemonic": "CMD_61", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0062: {"mnemonic": "CMD_62", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0063: {"mnemonic": "CMD_63", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x0064: {"mnemonic": "CMD_64", "ops": ["variant"], "size": None, "flag": 1, "x16": 1, "desc": ""},
    0x0065: {"mnemonic": "CMD_65", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0066: {"mnemonic": "CMD_66", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0067: {"mnemonic": "CMD_67", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0068: {"mnemonic": "CMD_68", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 1, "desc": ""},
    0x0069: {"mnemonic": "CMD_69", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x006A: {"mnemonic": "CMD_6A", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x006B: {"mnemonic": "CMD_6B", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x006C: {"mnemonic": "CMD_6C", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x006D: {"mnemonic": "CMD_6D", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x006E: {"mnemonic": "CMD_6E", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x006F: {"mnemonic": "CMD_6F", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0070: {"mnemonic": "CMD_70", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0071: {"mnemonic": "CMD_71", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0072: {"mnemonic": "CMD_72", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x0073: {"mnemonic": "CMD_73", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0074: {"mnemonic": "CMD_74", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0075: {"mnemonic": "CMD_75", "ops": ["variant", "reg8"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0076: {"mnemonic": "CMD_76", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0077: {"mnemonic": "CMD_77", "ops": ["variant", "reg8"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0078: {"mnemonic": "CMD_78", "ops": ["str8"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0079: {"mnemonic": "CMD_79", "ops": ["variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x007A: {"mnemonic": "CMD_7A", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 14, "desc": ""},
    0x007B: {"mnemonic": "CMD_7B", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x007C: {"mnemonic": "CMD_7C", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x007D: {"mnemonic": "CMD_7D", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x007E: {"mnemonic": "CMD_7E", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x007F: {"mnemonic": "CMD_7F", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0080: {"mnemonic": "CMD_80", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0081: {"mnemonic": "CMD_81", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0082: {"mnemonic": "CMD_82", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0083: {"mnemonic": "CMD_83", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x0084: {"mnemonic": "CMD_84", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0085: {"mnemonic": "CMD_85", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0086: {"mnemonic": "CMD_86", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0087: {"mnemonic": "CMD_87", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0088: {"mnemonic": "CMD_88", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0089: {"mnemonic": "CMD_89", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x008A: {"mnemonic": "CMD_8A", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x008B: {"mnemonic": "CMD_8B", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x008C: {"mnemonic": "CMD_8C", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x008D: {"mnemonic": "CMD_8D", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x008E: {"mnemonic": "CMD_8E", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x008F: {"mnemonic": "CMD_8F", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0090: {"mnemonic": "CMD_90", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0091: {"mnemonic": "CMD_91", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0092: {"mnemonic": "CMD_92", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0093: {"mnemonic": "CMD_93", "ops": ["variant", "reg8", "reg8"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0094: {"mnemonic": "CMD_94", "ops": ["variant", "reg8", "reg8"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0095: {"mnemonic": "CMD_95", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0096: {"mnemonic": "CMD_96", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0097: {"mnemonic": "CMD_97", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0098: {"mnemonic": "CMD_98", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x0099: {"mnemonic": "CMD_99", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x009A: {"mnemonic": "CMD_9A", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x009B: {"mnemonic": "CMD_9B", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x009C: {"mnemonic": "CMD_9C", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x009D: {"mnemonic": "CMD_9D", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x009E: {"mnemonic": "CMD_9E", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x009F: {"mnemonic": "CMD_9F", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00A0: {"mnemonic": "CMD_A0", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00A1: {"mnemonic": "CMD_A1", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00A2: {"mnemonic": "CMD_A2", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00A3: {"mnemonic": "CMD_A3", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00A4: {"mnemonic": "CMD_A4", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00A5: {"mnemonic": "CMD_A5", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00A6: {"mnemonic": "CMD_A6", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00A7: {"mnemonic": "CMD_A7", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00A8: {"mnemonic": "CMD_A8", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x00A9: {"mnemonic": "CMD_A9", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x00AA: {"mnemonic": "CMD_AA", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x00AB: {"mnemonic": "CMD_AB", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x00AC: {"mnemonic": "CMD_AC", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00AD: {"mnemonic": "CMD_AD", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00AE: {"mnemonic": "CMD_AE", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 8, "desc": ""},
    0x00AF: {"mnemonic": "CMD_AF", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x00B0: {"mnemonic": "CMD_B0", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00B1: {"mnemonic": "CMD_B1", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00B2: {"mnemonic": "CMD_B2", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00B3: {"mnemonic": "CMD_B3", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00B4: {"mnemonic": "CMD_B4", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00B5: {"mnemonic": "CMD_B5", "ops": ["variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x00B6: {"mnemonic": "CMD_B6", "ops": ["variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x00B7: {"mnemonic": "CMD_B7", "ops": ["variant", "str8", "imm16"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00B8: {"mnemonic": "CMD_B8", "ops": ["str16", "imm8", "imm16"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00B9: {"mnemonic": "CMD_B9", "ops": ["variant", "variant", "str8", "variant", "imm16"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00BA: {"mnemonic": "CMD_BA", "ops": ["str8", "imm16"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00BB: {"mnemonic": "CMD_BB", "ops": ["variant", "str8"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00BC: {"mnemonic": "CMD_BC", "ops": ["str16", "imm8"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00BD: {"mnemonic": "CMD_BD", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00BE: {"mnemonic": "CMD_BE", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00BF: {"mnemonic": "CMD_BF", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00C0: {"mnemonic": "CMD_C0", "ops": ["str8", "variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x00C1: {"mnemonic": "CMD_C1", "ops": ["str8", "str8", "variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x00C2: {"mnemonic": "CMD_C2", "ops": ["reg8"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00C3: {"mnemonic": "CMD_C3", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00C4: {"mnemonic": "CMD_C4", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00C5: {"mnemonic": "CMD_C5", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00C6: {"mnemonic": "CMD_C6", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00C7: {"mnemonic": "CMD_C7", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00C8: {"mnemonic": "CMD_C8", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00C9: {"mnemonic": "CMD_C9", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00CA: {"mnemonic": "CMD_CA", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00CB: {"mnemonic": "CMD_CB", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00CC: {"mnemonic": "CMD_CC", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00CD: {"mnemonic": "CMD_CD", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00CE: {"mnemonic": "CMD_CE", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00CF: {"mnemonic": "CMD_CF", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00D0: {"mnemonic": "CMD_D0", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00D1: {"mnemonic": "CMD_D1", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00D2: {"mnemonic": "CMD_D2", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 3, "desc": ""},
    0x00D3: {"mnemonic": "CMD_D3", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00D4: {"mnemonic": "CMD_D4", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 1, "desc": ""},
    0x00D5: {"mnemonic": "CMD_D5", "ops": ["variant", "variant", "str8", "variant", "variant", "str8", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x00D6: {"mnemonic": "CMD_D6", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00D7: {"mnemonic": "CMD_D7", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00D8: {"mnemonic": "CMD_D8", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00D9: {"mnemonic": "CMD_D9", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00DA: {"mnemonic": "CMD_DA", "ops": ["variant", "str8", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 7, "desc": ""},
    0x00DB: {"mnemonic": "CMD_DB", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00DC: {"mnemonic": "CMD_DC", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00DD: {"mnemonic": "CMD_DD", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00DE: {"mnemonic": "CMD_DE", "ops": ["variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00DF: {"mnemonic": "CMD_DF", "ops": ["variant", "str8", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00E0: {"mnemonic": "CMD_E0", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00E1: {"mnemonic": "CMD_E1", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00E2: {"mnemonic": "CMD_E2", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00E3: {"mnemonic": "CMD_E3", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00E4: {"mnemonic": "CMD_E4", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00E5: {"mnemonic": "CMD_E5", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00E6: {"mnemonic": "CMD_E6", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 1, "desc": ""},
    0x00E7: {"mnemonic": "CMD_E7", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00E8: {"mnemonic": "CMD_E8", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x00E9: {"mnemonic": "CMD_E9", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00EA: {"mnemonic": "CMD_EA", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00EB: {"mnemonic": "CMD_EB", "ops": ["variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00EC: {"mnemonic": "CMD_EC", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00ED: {"mnemonic": "CMD_ED", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x00EE: {"mnemonic": "CMD_EE", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00EF: {"mnemonic": "CMD_EF", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00F0: {"mnemonic": "CMD_F0", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00F1: {"mnemonic": "CMD_F1", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00F2: {"mnemonic": "CMD_F2", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 5, "desc": ""},
    0x00F3: {"mnemonic": "CMD_F3", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x00F4: {"mnemonic": "CMD_F4", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 3, "desc": ""},
    0x00F5: {"mnemonic": "CMD_F5", "ops": ["reg8"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00F6: {"mnemonic": "CMD_F6", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00F7: {"mnemonic": "CMD_F7", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00F8: {"mnemonic": "CMD_F8", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 10, "desc": ""},
    0x00F9: {"mnemonic": "CMD_F9", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00FA: {"mnemonic": "CMD_FA", "ops": ["variant", "str8"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00FB: {"mnemonic": "CMD_FB", "ops": ["str8"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00FC: {"mnemonic": "CMD_FC", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00FD: {"mnemonic": "CMD_FD", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x00FE: {"mnemonic": "CMD_FE", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x00FF: {"mnemonic": "CMD_FF", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0100: {"mnemonic": "CMD_100", "ops": ["reg8", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0101: {"mnemonic": "CMD_101", "ops": ["variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0102: {"mnemonic": "CMD_102", "ops": ["variant", "variant", "variant"], "size": None, "flag": 0, "x16": 2, "desc": ""},
    0x0103: {"mnemonic": "CMD_103", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 1, "desc": ""},
    0x0104: {"mnemonic": "CMD_104", "ops": [], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0105: {"mnemonic": "CMD_105", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0106: {"mnemonic": "CMD_106", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0107: {"mnemonic": "CMD_107", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 1, "desc": ""},
    0x0108: {"mnemonic": "CMD_108", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0109: {"mnemonic": "CMD_109", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x010A: {"mnemonic": "CMD_10A", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x010B: {"mnemonic": "CMD_10B", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 5, "desc": ""},
    0x010C: {"mnemonic": "CMD_10C", "ops": ["variant", "variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 0, "x16": 5, "desc": ""},
    0x010D: {"mnemonic": "CMD_10D", "ops": ["str8", "variant", "variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x010E: {"mnemonic": "CMD_10E", "ops": ["str8"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x010F: {"mnemonic": "CMD_10F", "ops": ["str8", "str8"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x0110: {"mnemonic": "CMD_110", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0111: {"mnemonic": "CMD_111", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0112: {"mnemonic": "CMD_112", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0113: {"mnemonic": "CMD_113", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x0114: {"mnemonic": "CMD_114", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x0115: {"mnemonic": "CMD_115", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x0116: {"mnemonic": "CMD_116", "ops": ["variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x0117: {"mnemonic": "CMD_117", "ops": ["variant", "variant", "variant", "variant", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x0118: {"mnemonic": "CMD_118", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x0119: {"mnemonic": "CMD_119", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 1, "desc": ""},
    0x011A: {"mnemonic": "CMD_11A", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 2, "desc": ""},
    0x011B: {"mnemonic": "CMD_11B", "ops": ["variant", "variant", "variant"], "size": None, "flag": 1, "x16": 3, "desc": ""},
    0x011C: {"mnemonic": "CMD_11C", "ops": ["variant"], "size": None, "flag": 0, "x16": 0, "desc": ""},
    0x011D: {"mnemonic": "CMD_11D", "ops": ["str8"], "size": None, "flag": 1, "x16": 0, "desc": ""},
    0x011E: {"mnemonic": "CMD_11E", "ops": ["variant", "variant"], "size": None, "flag": 1, "x16": 1, "desc": ""},
    0x011F: {"mnemonic": "CMD_11F", "ops": [], "size": None, "flag": 0, "x16": 0, "desc": ""},
}


# 应用命名覆盖
for _op, _name in NAME_OVERRIDES.items():
    if _op in HIGH_OPCODES:
        HIGH_OPCODES[_op]["mnemonic"] = _name

DESC_OVERRIDES = {
    0x0078: "载入 \"%s.sdt\" 并切换脚本（字符串为脚本号/文件名）",
    0x00B8: "信息窗文本：Shift-JIS 字符串 + 字节 + 消息序号",
    0x00BC: "信息窗文本变体（sub_4045C0(1)）",
    0x010D: "播放动画文件：文件名 + 标志 + 参数",
    0x011D: "把脚本名写入全局（sub_41ABA0）",
}
for _op, _desc in DESC_OVERRIDES.items():
    if _op in HIGH_OPCODES:
        HIGH_OPCODES[_op]["desc"] = _desc

ALL_OPCODES = {}
ALL_OPCODES.update(LOW_OPCODES)
ALL_OPCODES.update(HIGH_OPCODES)

BY_MNEMONIC = {}
for _op, _info in ALL_OPCODES.items():
    _m = _info["mnemonic"]
    if _m in BY_MNEMONIC:
        raise RuntimeError("duplicate mnemonic: %s" % _m)
    BY_MNEMONIC[_m] = _op


def get_opcode(op):
    return ALL_OPCODES.get(op)


def iter_opcodes():
    return sorted(ALL_OPCODES)


def schema_types(op):
    info = HIGH_OPCODES.get(op)
    if info is None:
        return None
    return info["ops"]


def instruction_size(op, data=None, pos=0):
    """返回指令总长度；data 用于变长操作数（字符串/变体值）。"""
    if op in LOW_OPCODES:
        info = LOW_OPCODES[op]
        if info["size"] is not None:
            return info["size"]
        if op == 0x20:
            n = struct.unpack_from("<h", data, pos + 3)[0]
            return 5 + n
        if op == 0x28:
            return 3 + data[pos + 2]
        raise ValueError("bad low opcode")
    types = schema_types(op)
    if types is None:
        return None
    q = pos + 2
    for t in types:
        if t == "imm8":
            q += 1
        elif t == "imm16":
            q += 2
        elif t == "imm32":
            q += 4
        elif t == "reg8":
            q += 1
        elif t == "str8":
            q += 1 + data[q]
        elif t == "str16":
            q += 2 + (data[q] | (data[q + 1] << 8))
        elif t == "variant":
            q += variant_size_at(data, q)
        elif t == "cmp":
            q += 2 + variant_size_at(data, q + 2)
        else:
            raise ValueError("bad operand type %r" % t)
    return q - pos


def variant_size_at(data, pos):
    if data[pos] == 2:
        return 2 + data[pos + 1]
    return 1 + 4


# ---------------------------------------------------------------------------
# Shift-JIS / CP932 字符串 <-> 语义文本
# ---------------------------------------------------------------------------
def _escape_char(ch):
    if ch == '"':
        return '\\"'
    if ch == "\\":
        return "\\\\"
    return ch


def decode_string(raw, encoding=ENCODING):
    """把字节串转成可编辑文本；不可解码字节/控制字节写成 {{XX}} 占位符。

    不假定具体编码的字节范围：按 1..4 字节尝试用 encoding 解码，
    解出的单个字符若是控制字符则退回占位符。
    """
    out = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b < 0x20 or b == 0x7F:
            out.append("{{%02X}}" % b)
            i += 1
            continue
        if b < 0x80:
            out.append(_escape_char(chr(b)))
            i += 1
            continue
        decoded = None
        for ln in (4, 3, 2, 1):
            if i + ln > n:
                continue
            try:
                ch = raw[i:i + ln].decode(encoding)
            except UnicodeDecodeError:
                continue
            if len(ch) == 1:
                decoded = (ch, ln)
                break
        if decoded is None:
            out.append("{{%02X}}" % b)
            i += 1
            continue
        ch, ln = decoded
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            for k in range(ln):
                out.append("{{%02X}}" % raw[i + k])
        else:
            out.append(_escape_char(ch))
        i += ln
    return "".join(out)


def encode_string(text, encoding=ENCODING):
    """把语义文本编码回字节；支持 \\ " \n 与 {{XX}} 占位符。"""
    out = bytearray()
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "n":
                out.append(0x0A)
                i += 2
                continue
            if nxt == "r":
                out.append(0x0D)
                i += 2
                continue
            if nxt == "\\":
                out.append(0x5C)
                i += 2
                continue
            if nxt == '"':
                out.append(0x22)
                i += 2
                continue
            raise ValueError("无法识别的转义: \\%s" % nxt)
        if c == "{" and text.startswith("{{", i):
            j = text.find("}}", i + 2)
            if j < 0:
                raise ValueError("占位符缺少 }}: %s" % text[i:i + 8])
            hx = text[i + 2:j]
            if len(hx) != 2:
                raise ValueError("占位符必须是 {{XX}}: %s" % text[i:j + 2])
            out.append(int(hx, 16))
            i = j + 2
            continue
        try:
            out.extend(c.encode(encoding))
        except UnicodeEncodeError:
            raise ValueError("字符 %r (U+%04X) 无法用 %s 编码" % (c, ord(c), encoding))
        i += 1
    return bytes(out)
