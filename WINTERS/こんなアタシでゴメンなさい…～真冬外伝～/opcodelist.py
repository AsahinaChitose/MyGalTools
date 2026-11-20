# -*- coding: utf-8 -*-
"""
opcodelist.py -- IAGS_ISD_01 脚本字节码定义（真冬外伝 / IAGS 引擎）

结构来源：exe 逆向（IDA 9.1）+ 31 个样本块实测。详见 vm_analysis.md。

一条指令固定 8 字节，小端：

    +0x00  u8   opcode
    +0x01  u8   flags        ; 三个操作数的间接寻址位
    +0x02  i16  op1
    +0x04  i16  op2
    +0x06  i16  op3

flags 位 → 操作数间接寻址（sub_48DC00 的取指部分）：

    bit0 (0x01)  op1 = bankV[op1]
    bit1 (0x02)  op1 = bankW[op1]      ; 两个都置位时是 bankW[bankV[op1]]
    bit2 (0x04)  op2 = bankV[op2]
    bit3 (0x08)  op2 = bankW[op2]
    bit4 (0x10)  op3 = bankV[op3]
    bit5 (0x20)  op3 = bankW[op3]

bankV = word_51863C，bankW = word_518FAA（两个 16 位变量数组）。
反汇编里用 V[...] / W[...] 包裹操作数表示这两种间接。
"""

MAGIC = b"IAGS_ISD_01 "
INSTRUCTION_SIZE = 8
CHUNK_COUNT = 5

# 分块顺序（文件里 5 段「u32 长度 + 数据」）
CHUNK_CODE = 0     # 指令流
CHUNK_NAMES = 1    # 标签名表（0x4E 的 op1 是这里的下标）
CHUNK_CALLS = 2    # 跳转目标名表（0x40/0x41 的 op1 是这里的下标）
CHUNK_VOICES = 3   # 语音文件名表（0x60 的 op2 是这里的下标）
CHUNK_TEXTS = 4    # 正文表（0x60/0x68 的 op1 是行号）

CHUNK_LABELS = ("code", "names", "calls", "voices", "texts")

# flags 位：(操作数下标, 变量组)
FLAG_BITS = {
    0x01: (0, "V"),
    0x02: (0, "W"),
    0x04: (1, "V"),
    0x08: (1, "W"),
    0x10: (2, "V"),
    0x20: (2, "W"),
}


def v_bit(op_index):
    return 1 << (2 * op_index)


def w_bit(op_index):
    return 1 << (2 * op_index + 1)


# kind 说明：
#   plain  普通指令，操作数按数值输出
#   label  0x7F 标签定义点，反汇编成 "loc_XXXX:" 一行，汇编器生成 0x7F 记录
#   goto   0x7E 跳转到标签 id
#   call   0x40/0x41 按名字跳转/调用（op1 是 calls 表下标）
#   deflab 0x4E 标签定义（op1 是 names 表下标）
#   msg    0x60/0x68 正文，op1 是 texts 行号，op2 是 voices 下标
#   end    0xFF 结束，整条记录固定 FF*8
# min_args 是语义上最少要写的操作数个数；超出的尾部若为非 0，反汇编器会补写出来。
OPCODES = {
    0x10: dict(mnemonic="IMG", kind="plain", min_args=1,
               desc="显示图片：op1 = GRP 槽号（0 表示清空该层）"),
    0x11: dict(mnemonic="IMG2", kind="plain", min_args=3,
               desc="显示图片到指定层：op1 = 层(0/1)，op2 = 图片 id，op3 = 偏移"),
    0x20: dict(mnemonic="GFX", kind="plain", min_args=2,
               desc="图形/动画：op1 = 子命令(1, 41..46)，op2/op3 = 参数"),
    0x30: dict(mnemonic="BG", kind="plain", min_args=2,
               desc="背景/画面切换：op1 = 通道(0..7)，op2 = 参数"),
    0x31: dict(mnemonic="BG2", kind="plain", min_args=2,
               desc="背景切换变体：op1 = 1，op2 = 参数(1..5)"),
    0x40: dict(mnemonic="JUMP", kind="call", min_args=2,
               desc="跳转到 op1 指向的标签名（op2 非 0 时先切换脚本）"),
    0x41: dict(mnemonic="CALL", kind="call", min_args=2,
               desc="调用 op1 指向的标签名（压返回栈，op2 非 0 时切换脚本）"),
    0x4E: dict(mnemonic="LABEL", kind="deflab", min_args=1,
               desc="标签定义：op1 = names 表下标"),
    0x4F: dict(mnemonic="RET", kind="plain", min_args=0,
               desc="从 CALL 返回"),
    0x50: dict(mnemonic="SET", kind="plain", min_args=2,
               desc="赋值：op1 ← op2"),
    0x51: dict(mnemonic="ADD", kind="plain", min_args=3,
               desc="op1 ← op2 + op3"),
    0x52: dict(mnemonic="SUB", kind="plain", min_args=3,
               desc="op1 ← op2 - op3"),
    0x53: dict(mnemonic="MUL", kind="plain", min_args=3,
               desc="op1 ← op2 * op3"),
    0x54: dict(mnemonic="DIV", kind="plain", min_args=3,
               desc="op1 ← op2 / op3（op3=0 时结果 0）"),
    0x55: dict(mnemonic="MOD", kind="plain", min_args=3,
               desc="op1 ← op2 % op3（op3=0 时结果 0）"),
    0x60: dict(mnemonic="MSG", kind="msg", min_args=2,
               desc="显示正文：op1 = texts 行号，op2 = voices 下标（-1 = 无语音）"),
    0x68: dict(mnemonic="MSG_H", kind="msg", min_args=2,
               desc="正文变体（0x68）：op1 = texts 行号，op2 = voices 下标；两者差异未完全确认"),
    0x70: dict(mnemonic="JNE", kind="plain", min_args=3,
               desc="若 op2 != op3 则跳转到标签 op1"),
    0x71: dict(mnemonic="JE", kind="plain", min_args=3,
               desc="若 op2 == op3 则跳转到标签 op1"),
    0x72: dict(mnemonic="JGE", kind="plain", min_args=3,
               desc="若 op2 >= op3 则跳转到标签 op1"),
    0x73: dict(mnemonic="JLE", kind="plain", min_args=3,
               desc="若 op2 <= op3 则跳转到标签 op1"),
    0x7E: dict(mnemonic="GOTO", kind="goto", min_args=1,
               desc="跳转到标签 op1（同 op1 的 0x7F/0x7E 记录处）"),
    0x7F: dict(mnemonic="LOC", kind="label", min_args=1,
               desc="标签定义点，id = op1；运行时无动作"),
    0x80: dict(mnemonic="WAIT", kind="plain", min_args=1,
               desc="等待 op1 毫秒（0 = 等待点击/按键）"),
    0x88: dict(mnemonic="SYS", kind="plain", min_args=3,
               desc="系统命令：op1 = 子命令(101/111/121/141/777)，op2/op3 = 参数"),
    0xFF: dict(mnemonic="END", kind="end", min_args=0,
               desc="脚本结束，整条记录 8 字节全 FF"),
}

# 条件跳转：mnemonic -> 比较关系（仅用于文档/反汇编注释）
COND_JUMPS = {0x70: "!=", 0x71: "==", 0x72: ">=", 0x73: "<="}


# ---------------------------------------------------------------------------
# 文本编解码（反汇编/汇编共用）
# ---------------------------------------------------------------------------

def decode_bytes(data, encoding):
    """按 encoding 解码；无法解码的单字节保留为代理字符，转义时写成 {{XX}}。"""
    return data.decode(encoding, "surrogateescape")


def escape_text(text):
    """把解码后的字符串转成 asm 里的转义形式。"""
    out = []
    for ch in text:
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:          # surrogateescape 保留的原始字节
            out.append("{{%02X}}" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        else:
            out.append(ch)
    return "".join(out)


def unescape_text(text, encoding):
    """把 asm 里的转义形式还原成原始字节。"""
    res = bytearray()
    run = []

    def flush():
        if run:
            try:
                res.extend("".join(run).encode(encoding, "surrogateescape"))
            except UnicodeEncodeError as e:
                s = "".join(run)
                bad = s[e.start:e.end] or "?"
                raise ValueError(
                    "字符 %r (U+%04X) 无法用 %s 编码；请换成该编码里存在的字符，"
                    "或改用 --encoding 指定别的编码" % (bad, ord(bad[0]), encoding))
            del run[:]

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            flush()
            if nxt == "\\":
                res.append(0x5C)
            elif nxt == '"':
                res.append(0x22)
            elif nxt == "n":
                res.extend(b"\r\n")
            elif nxt == "r":
                res.append(0x0D)
            else:
                res.extend(("\\" + nxt).encode(encoding, "surrogateescape"))
            i += 2
            continue
        if ch == "{" and text.startswith("{{", i):
            j = text.find("}}", i + 2)
            if j > 0:
                hexs = text[i + 2:j].replace(":", "").strip()
                try:
                    raw = bytes.fromhex(hexs)
                except ValueError:
                    raw = None
                if raw is not None:
                    flush()
                    res.extend(raw)
                    i = j + 2
                    continue
        run.append(ch)
        i += 1
    flush()
    return bytes(res)


def get_opcode(op):
    return OPCODES.get(op)


def mnemonic(op):
    info = OPCODES.get(op)
    return info["mnemonic"] if info else None
