#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""opcodelist.py -- こんなアタシでも… (Konna.exe) 脚本 VM 指令表

脚本文件（SCR.ifx 里的每个块）是定长 20 字节的记录数组：

    +0x00 u16  opcode
    +0x02 u16  (保留，恒 0)
    +0x04 u32  P1
    +0x08 u16  P2
    +0x0A u16  P3
    +0x0C u16  P4
    +0x0E u16  P5
    +0x10 u16  FLAGS  （参数解引用标志）
    +0x12 u16  P6

FLAGS 位含义（由 sub_46C660 / 0x46C660 的参数预取逻辑得出）：
    bit0  P1 取 word_5EED76[...]   bit1  P1 取 word_5EF746[...]
    bit2  P2 取 word_5EED76[...]   bit3  P2 取 word_5EF746[...]
    bit4  P3 取 word_5EED76[...]   bit5  P3 取 word_5EF746[...]
    bit6  P4 取 word_5EED76[...]   bit7  P4 取 word_5EF746[...]
    bit8  P5 取 word_5EED76[...]   bit9  P5 取 word_5EF746[...]
    opcode 500..599 不套用这些表（参数当立即数用）。

每条指令的定义：
    mnemonic   助记符
    operands   依次使用的字段名（P1/P2/P3/P4/P5/P6）
    kind       normal / jump / text / end / raw
    note       语义说明与证据位置（Konna.pseudocode.c 行号）
"""

# 字段名 -> 记录内偏移
FIELD_ORDER = ("P1", "P2", "P3", "P4", "P5", "P6")
FIELD_TYPES = {"P1": "u32", "P2": "u16", "P3": "u16", "P4": "u16", "P5": "u16", "P6": "u16"}

# 脚型类型字段（SCR.ifx 目录里的 type）-> VM 槽位类型 -> 记录基址
# 槽位容量 100000 word = 200000 字节 = 10000 条记录
SCRIPT_TYPE_TO_VMTYPE = {11: 1, 12: 2, 13: 3}
VM_SLOT_RECORDS = 10000

END_MARKER = 0xFFFF


def record_base(vmtype: int) -> int:
    """脚本在 VM 内存里的起始记录号。"""
    return (vmtype - 1) * VM_SLOT_RECORDS


OPCODES = {
    0: {"mnemonic": "TICK_0", "operands": ("P1", "P2"), "kind": "normal",
        "note": "tick/计时控制（P2 为子命令：-1/0/1..）"},
    1: {"mnemonic": "TICK_1", "operands": ("P1", "P2"), "kind": "normal",
        "note": "tick/计时控制"},
    2: {"mnemonic": "TICK_2", "operands": ("P1", "P2"), "kind": "normal",
        "note": "tick/计时控制"},
    3: {"mnemonic": "TICK_3", "operands": ("P1", "P2"), "kind": "normal",
        "note": "tick/计时控制"},
    101: {"mnemonic": "BG", "operands": ("P1", "P2", "P3", "P4"), "kind": "normal",
          "note": "背景；P1=图片 id（0 时用 P2/P3/P4 组成填充色）"},
    111: {"mnemonic": "LAYER1", "operands": ("P1", "P2", "P3"), "kind": "normal",
          "note": "角色图层 1（sub_469378(this,1,P1)）"},
    112: {"mnemonic": "LAYER2", "operands": ("P1", "P2", "P3"), "kind": "normal",
          "note": "角色图层 2（sub_469378(this,2,P1)）"},
    181: {"mnemonic": "NOP", "operands": (), "kind": "normal", "note": "空指令"},
    191: {"mnemonic": "WINDOW", "operands": ("P1", "P2", "P3"), "kind": "normal",
          "note": "文本窗口/画面分割模式（P1=1/2/3 选择布局）"},
    201: {"mnemonic": "JUMP", "operands": ("P1",), "kind": "jump",
          "note": "无条件跳转到记录 P1（dword_5EF178 = P1-1）"},
    202: {"mnemonic": "IF_EQ", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "若 P2 == P1 跳到 P3（sub_46C660 内比较）"},
    203: {"mnemonic": "IF_NE", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "若 P2 != P1 跳到 P3"},
    204: {"mnemonic": "IF_GT", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "若 P2 > P1 跳到 P3"},
    205: {"mnemonic": "IF_GE", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "若 P2 >= P1 跳到 P3"},
    206: {"mnemonic": "IF_LT", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "若 P2 < P1 跳到 P3"},
    207: {"mnemonic": "IF_LE", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "若 P2 <= P1 跳到 P3"},
    211: {"mnemonic": "GOTO", "operands": ("P1",), "kind": "jump",
          "note": "跳转到记录 P1（先 sub_46EBF0 收尾）"},
    212: {"mnemonic": "IF2_EQ", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "第二组比较：P2 == P1 跳到 P3"},
    213: {"mnemonic": "IF2_NE", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "第二组比较：P2 != P1 跳到 P3"},
    214: {"mnemonic": "IF2_GT", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "第二组比较：P2 > P1 跳到 P3"},
    215: {"mnemonic": "IF2_GE", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "第二组比较：P2 >= P1 跳到 P3"},
    216: {"mnemonic": "IF2_LT", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "第二组比较：P2 < P1 跳到 P3"},
    217: {"mnemonic": "IF2_LE", "operands": ("P2", "P1", "P3"), "kind": "jump",
          "note": "第二组比较：P2 <= P1 跳到 P3"},
    251: {"mnemonic": "TICKCTL", "operands": ("P1", "P2"), "kind": "normal",
          "note": "tick/等待控制（P2=-1/0/1.. 子命令）"},
    271: {"mnemonic": "GOSUB", "operands": ("P1",), "kind": "jump",
          "note": "跳到 P1+10000（跨槽位调用，sub_46EBF0 压栈）"},
    272: {"mnemonic": "CALLSCRIPT", "operands": ("P1",), "kind": "jump",
          "note": "加载脚本 P1 到槽位 3 并跳过去（sub_46A8BC(3,P1)）"},
    281: {"mnemonic": "CHOICE", "operands": ("P1",), "kind": "normal",
          "note": "选择肢相关（仅 1 处使用，semantic 未完全确认）"},
    291: {"mnemonic": "RET", "operands": (), "kind": "normal",
          "note": "从返回栈弹出一条记录号"},
    295: {"mnemonic": "STOP", "operands": (), "kind": "normal",
          "note": "中断当前执行（等待外部状态）"},
    301: {"mnemonic": "MSG", "operands": ("P1",), "kind": "text",
          "note": "显示消息 P1（MSG.dat 文本）；P1=0 关闭窗口"},
    311: {"mnemonic": "MSG2", "operands": ("P1",), "kind": "text",
          "note": "另一路文本显示（sub_46DCA4）"},
    401: {"mnemonic": "EFFECT", "operands": ("P1", "P2"), "kind": "normal",
          "note": "演出/效果（sub_46F1B8(P3) 路径，具体子类型未全确认）"},
    405: {"mnemonic": "SETMODE", "operands": ("P1",), "kind": "normal",
          "note": "设置模式值 dword_5EFF94（默认 100）"},
    411: {"mnemonic": "EFFECT2", "operands": ("P1", "P2"), "kind": "normal",
          "note": "sub_46EE08(P2)"},
    412: {"mnemonic": "EFFECT3", "operands": ("P1", "P2"), "kind": "normal",
          "note": "sub_46EE08(P2)"},
    501: {"mnemonic": "SET", "operands": ("P1", "P2"), "kind": "normal",
          "note": "赋值：变量[P1] = P2"},
    502: {"mnemonic": "ADD", "operands": ("P1", "P2"), "kind": "normal",
          "note": "变量[P1] += P2"},
    503: {"mnemonic": "SUB", "operands": ("P1", "P2"), "kind": "normal",
          "note": "变量[P1] -= P2"},
    504: {"mnemonic": "MUL", "operands": ("P1", "P2"), "kind": "normal",
          "note": "变量[P1] *= P2"},
    505: {"mnemonic": "DIV", "operands": ("P1", "P2"), "kind": "normal",
          "note": "变量[P1] /= P2（除零得 0）"},
    506: {"mnemonic": "MOD", "operands": ("P1", "P2"), "kind": "normal",
          "note": "变量[P1] %= P2"},
    507: {"mnemonic": "POW", "operands": ("P1", "P2"), "kind": "normal",
          "note": "变量[P1] = P2 次方（sub_402AF4）"},
    601: {"mnemonic": "FLAG2", "operands": ("P1",), "kind": "normal",
          "note": "sub_46A8BC(2,P1)，标志/变量操作"},
    602: {"mnemonic": "FLAG3", "operands": ("P1",), "kind": "normal",
          "note": "sub_46A8BC(3,P1)"},
    609: {"mnemonic": "EXC609", "operands": (), "kind": "normal",
          "note": "sub_46EBD4（异常/收尾）"},
    619: {"mnemonic": "EXC619", "operands": (), "kind": "normal",
          "note": "sub_469108"},
    701: {"mnemonic": "UI701", "operands": ("P1",), "kind": "normal",
          "note": "byte_5EF241 开关（P1 非 0 开启）"},
    702: {"mnemonic": "UI702", "operands": ("P1",), "kind": "normal",
          "note": "byte_5EF240 开关"},
    703: {"mnemonic": "UI703", "operands": ("P1",), "kind": "normal",
          "note": "byte_5EF242 开关"},
    801: {"mnemonic": "WAIT", "operands": ("P1",), "kind": "normal",
          "note": "等待 P1 毫秒（sub_46B298）"},
    802: {"mnemonic": "FADE802", "operands": ("P1",), "kind": "normal",
          "note": "dword_5EFED0 = 8021（画面过渡状态）"},
    803: {"mnemonic": "FADE803", "operands": ("P1",), "kind": "normal",
          "note": "dword_5EFED0 = 8031"},
    901: {"mnemonic": "CLEAR", "operands": (), "kind": "normal",
          "note": "清空 word_5EED78[512]（变量区）"},
    941: {"mnemonic": "TEXTMODE", "operands": ("P1",), "kind": "normal",
          "note": "文本显示模式：P1=1/2/3 切换 byte_5EF243/244"},
    999: {"mnemonic": "QUIT", "operands": (), "kind": "normal",
          "note": "dword_5EFED0 = 999（退出/结束状态）"},
    END_MARKER: {"mnemonic": "END", "operands": (), "kind": "end",
                 "note": "脚本结束标记（整条记录全 0xFF）"},
}

MNEMONIC_TO_OPCODE = {spec["mnemonic"]: op for op, spec in OPCODES.items()}

# 未在表中出现的 opcode：反汇编输出 RAW，汇编按原始字段写回
FIELD_NAMES_BY_LETTER = {"P1": "P1", "P2": "P2", "P3": "P3", "P4": "P4", "P5": "P5", "P6": "P6"}
