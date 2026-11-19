# -*- coding: utf-8 -*-
"""wwadv.id 脚本 VM（WWA/wwadv 32 位 dword 栈式虚拟机）指令集定义。

本模块是反汇编器与汇编器共享的唯一真值来源，内容来自对 wwadv.exe 的
逆向分析（sub_42F590 解释器主循环 + 结构自校验），详见 vm_analysis.md。

容器结构（全部小端）::

    +-----------------+ 0x00
    | u32 hdr[8]      |   hdr[0] = 文本区起始（dword 下标）
    +-----------------+        hdr[1] = 文本区结束（dword 下标）
    | 代码区          |        hdr[2] = 代码区起始 dword 下标 = 8
    | [8, hdr[0])     |        hdr[3] = 跳转表 A 起始 dword 下标
    +-----------------+        hdr[4] = 跳转表 B 起始 dword 下标
    | 文本区          |        hdr[5..7] = 0
    | [4*hdr[0], ...) |   跳转表 A：文本类指令（13/65/69/70）偏移，升序
    |   u16 单元      |   跳转表 B：所有 CALL 的返回地址 (pc+3)，升序
    |   XOR 0x0001    |   跳转表 C：场景入口偏移表（来源未完全确认，原样保留）
    +-----------------+
    | 跳转表 A / B / C|
    +-----------------+

指令编码：每条指令占 1 个 dword 操作码 + N 个操作数 dword。
“值描述符（DESC）”占 2 个 dword：``type`` 与 ``value``：

    type = 0  立即数，value 就是数值
    type = 1  变量槽，value 是槽位下标（<10000）或标志位（>=10000）
    type >= 2 间接引用，先取变量槽 value 的内容，再以其为下标取值
"""

# ---------------------------------------------------------------- 常量

CODE_START = 8              # 代码区起始 dword 下标（hdr[2]）
HEADER_WORDS = 8            # 文件头 u32 个数
TEXT_XOR = 0x0001           # 文本区每个 u16 与 0x0001 异或（加密/解密同一运算）
CONTROL_CODES = frozenset(range(0x0000, 0x0007))  # 文本流中的控制码

# 跳转表 A 由这些指令的偏移构成（升序）；它们是“文本页”入口
TABLE_A_OPS = (13, 65, 69, 70)

# 文本流中出现的控制码语义（由渲染器 switch 推断）
TEXT_CONTROL_NAMES = {
    0x0000: "END",       # 记录结束（不写入 .str，其零字节由汇编器自动补）
    0x0001: "BR",        # 换行/选项分隔
    0x0002: "PAGE",      # 分页
    0x0003: "TAG",       # 语音/说话人标记，后随 2 个 16 位参数（二进制，非正文）
    0x0004: "COLOR",     # 颜色，后随 1 个参数
    0x0005: "SIZE",      # 字号，后随 1 个参数
    0x0006: "WAIT",      # 等待
}

# 控制码后随的参数个数。参数是二进制元数据（语音编号 / 说话人槽位等），
# 不是正文；反汇编一律输出 {{XX:YY}} 占位符，绝不按字符解码。
TEXT_CONTROL_PARAMS = {
    0x0003: 2,
    0x0004: 1,
    0x0005: 1,
}

# ---------------------------------------------------------------- 操作数模式
#
# ops 列表元素为 (kind, extra)：
#   ("imm",)            1 个 dword 立即数
#   ("desc",)           2 个 dword：type, value
#   ("jref", delta)     1 个 dword：代码偏移（目标 = 值 + delta），汇编为标签
#   ("tref",)           1 个 dword：文本区 u16 偏移，汇编为文本标签
#   ("count", n)        1 个 dword 计数，暂存为变量 n
#   ("rep", n, sub)     重复 n 次 sub 模式
#   ("str",)            内联字符串：1 个 dword 长度 + N 个 dword（每 dword 一个字节）
#   ("group", n)        文本分组表：n 组，每组 = 1 个 dword 计数 + 计数个 DESC
#   ("cond5",)          条件项：DESC + imm + DESC（5 个 dword）

OPCODES = {
    0x02: {"mnemonic": "RET", "ops": [],
           "note": "子程序返回：弹出返回标签下标，pc = 跳转表A[下标]"},
    0x03: {"mnemonic": "MOV", "ops": [("desc",), ("desc",)],
           "note": "赋值 dst = src"},
    0x04: {"mnemonic": "ADD", "ops": [("desc",), ("desc",)], "note": "dst += src"},
    0x05: {"mnemonic": "SUB", "ops": [("desc",), ("desc",)], "note": "dst -= src"},
    0x06: {"mnemonic": "MUL", "ops": [("desc",), ("desc",)], "note": "dst *= src"},
    0x07: {"mnemonic": "DIVMOD", "ops": [("desc",), ("desc",)],
           "note": "dst /= src，余数写入内部槽 116"},
    0x08: {"mnemonic": "OR", "ops": [("desc",), ("desc",)], "note": "dst |= src"},
    0x09: {"mnemonic": "AND", "ops": [("desc",), ("desc",)], "note": "dst &= src"},
    0x0A: {"mnemonic": "SETFLAG", "ops": [("desc",)], "note": "标志位置 1"},
    0x0B: {"mnemonic": "CLRFLAG", "ops": [("desc",)], "note": "标志位置 0"},
    0x0C: {"mnemonic": "MARK", "ops": [("imm",)],
           "note": "脚本标记点；记录到 dword_93B394 并刷新画面"},
    0x0D: {"mnemonic": "SET_MODE", "ops": [("imm",)],
           "note": "设置模式/立绘编号并刷新"},
    0x0F: {"mnemonic": "JMP", "ops": [("jref", 0)], "note": "无条件跳转（绝对代码偏移）"},
    0x10: {"mnemonic": "CALL", "ops": [("jref", 0), ("imm",)],
           "note": "调用：压入返回标签下标，跳到目标偏移"},
    0x11: {"mnemonic": "RET2", "ops": [], "note": "返回（与 RET 同体）"},
    0x12: {"mnemonic": "DRAW", "ops": [("desc",), ("desc",)],
           "note": "以两个操作数调用 sub_40A310（绘制/合成）"},
    0x13: {"mnemonic": "SOUND", "ops": [("desc",)], "note": "播放音效/语音（参数为资源号）"},
    0x15: {"mnemonic": "SCREEN", "ops": [("desc",)], "note": "画面模式切换（sub_422AF0 后设置）"},
    0x16: {"mnemonic": "CVT_MOV", "ops": [("desc",), ("desc",)],
           "note": "带转换的赋值（sub_422950 转换后写入 dst）"},
    0x17: {"mnemonic": "TEXT", "ops": [("tref",), ("imm",), ("imm",)],
           "note": "显示一段文本（块模式）"},
    0x18: {"mnemonic": "CJMP", "ops": [("desc",), ("imm",), ("desc",), ("jref", 0)],
           "note": "比较跳转：比较码 0:< 1:<= 2:> 3:>= 4:== 5:!="},
    0x1A: {"mnemonic": "SKIP_IF", "ops": [("desc",), ("imm",)],
           "note": "条件命中时 pc = imm + 4（原始偏移语义，未标签化）"},
    0x1B: {"mnemonic": "PUSH", "ops": [("desc",)],
           "note": "压入变量栈 dword_9332DC（最多 8 层）"},
    0x1C: {"mnemonic": "ANIM", "ops": [("desc",), ("desc",), ("desc",)],
           "note": "背景/动画过渡（三个操作数含时长）"},
    0x1D: {"mnemonic": "YIELD", "ops": [],
           "note": "让出：首次执行挂起，再次进入后前进 1 条"},
    0x1E: {"mnemonic": "BGM", "ops": [("desc",)],
           "note": "播放 BGM（996/997/998/999 为内置色示例分支）"},
    0x1F: {"mnemonic": "WAIT_CLICK", "ops": [("desc",)],
           "note": "等待点击/按键，参数为等待类型"},
    0x20: {"mnemonic": "DELAY", "ops": [("desc",)], "note": "延时（毫秒）"},
    0x21: {"mnemonic": "WAIT_KEY", "ops": [], "note": "等待按键后前进 1 条"},
    0x22: {"mnemonic": "LOAD_FILE", "ops": [("str",), ("desc",)],
           "note": "加载文件：内联文件名字符串 + 1 个操作数"},
    0x24: {"mnemonic": "POP_SWITCH", "ops": [],
           "note": "switch 结束时弹出层级并前进 1 条"},
    0x27: {"mnemonic": "SWITCH", "ops": [("jref", 0), ("count", "n"),
                                          ("rep", "n", [("desc",)])],
           "note": "分派：遍历 n 个候选，命中则落到表后，否则跳到目标"},
    0x28: {"mnemonic": "SETVARS", "ops": [("count", "n"),
                                           ("rep", "n", [("desc",)])],
           "note": "批量写变量槽 10..（选项/参数表）"},
    0x29: {"mnemonic": "INC", "ops": [("desc",)], "note": "自增（含间接引用）"},
    0x2A: {"mnemonic": "SET", "ops": [("desc",), ("imm",)],
           "note": "直接写入立即数（不经过描述符求值）"},
    0x2B: {"mnemonic": "MOVI", "ops": [("desc",), ("desc",)],
           "note": "赋值 dst = 变量值（直接取槽，不递归求值）"},
    0x2C: {"mnemonic": "FLAG_CMD", "ops": [("desc",)],
           "note": "自动/跳过等流程控制，参数 1~3"},
    0x2D: {"mnemonic": "LIMIT", "ops": [("desc",)],
           "note": "参数 > 35 则直接退出程序（保护性检查）"},
    0x32: {"mnemonic": "YIELD2", "ops": [], "note": "让出（与 YIELD 同体，前进 1 条）"},
    0x35: {"mnemonic": "SE", "ops": [("desc",)], "note": "播放音效（子分支含 990/993/996~999）"},
    0x36: {"mnemonic": "SLEEP", "ops": [("desc",)], "note": "等待若干帧/毫秒"},
    0x37: {"mnemonic": "TEXT_GROUP", "ops": [("tref",), ("imm",), ("count", "n"),
                                              ("group", "n")],
           "note": "带分组选项的文本（每组 = 计数 + 计数个操作数）"},
    0x39: {"mnemonic": "MSGBOX", "ops": [("desc",)], "note": "MessageBox 调试输出"},
    0x3A: {"mnemonic": "MODE_CMD", "ops": [("desc",)],
           "note": "0/1/2 三种子命令（对应 sub_423DD0/4246F0/423E60）"},
    0x3B: {"mnemonic": "SWAP", "ops": [("desc",), ("desc",)], "note": "交换两个变量的值"},
    0x3C: {"mnemonic": "WAIT13", "ops": [], "note": "等待 13 帧后前进 1 条"},
    0x3D: {"mnemonic": "OP_3D", "ops": [("imm",), ("imm",)], "note": "未观测到的指令（前进 3 条）"},
    0x3E: {"mnemonic": "OP_3E", "ops": [("imm",), ("imm",)], "note": "未观测到的指令（前进 3 条）"},
    0x3F: {"mnemonic": "TEXT_CHOICE", "ops": [("tref",), ("imm",), ("count", "n"),
                                               ("rep", "n", [("desc",)])],
           "note": "带 n 个选项行的文本"},
    0x40: {"mnemonic": "MULTI_CMP", "ops": [("count", "n"),
                                            ("rep", "n", [("cond5",)]), ("jref", 0)],
           "note": "多条件比较跳转（全部命中才落到表后）"},
    0x41: {"mnemonic": "TEXT_SCROLL", "ops": [("tref",), ("imm",)],
           "note": "显示滚动文本（正文主用指令）"},
    0x43: {"mnemonic": "OP_43", "ops": [("imm",), ("imm",)],
           "note": "未观测到的指令（前进 3 条）"},
    0x45: {"mnemonic": "TEXT_SCROLL2", "ops": [("tref",), ("imm",)],
           "note": "显示滚动文本（第二变体）"},
    0x46: {"mnemonic": "TEXT_ID", "ops": [("imm",)],
           "note": "设置当前文本页编号（无正文引用）"},
    0x3DE: {"mnemonic": "DBG_990", "ops": [("imm",), ("imm",)], "note": "调试/内置分支（未观测）"},
    0x3E1: {"mnemonic": "DBG_993", "ops": [("imm",), ("imm",)], "note": "调试/内置分支（未观测）"},
    0x3E4: {"mnemonic": "DBG_996", "ops": [("imm",), ("imm",)], "note": "调试/内置分支（未观测）"},
    0x3E5: {"mnemonic": "DBG_997", "ops": [("imm",), ("imm",)], "note": "调试/内置分支（未观测）"},
    0x3E6: {"mnemonic": "DBG_998", "ops": [("imm",), ("imm",)], "note": "调试/内置分支（未观测）"},
    0x3E7: {"mnemonic": "DBG_999", "ops": [("imm",), ("imm",)], "note": "调试/内置分支（未观测）"},
}

# 按助记符反查
BY_MNEMONIC = {}
for _code, _def in OPCODES.items():
    _m = _def["mnemonic"]
    if _m in BY_MNEMONIC:                     # 同体指令（RET/RET2、YIELD/YIELD2）
        BY_MNEMONIC[_m] = min(BY_MNEMONIC[_m], _code)
    else:
        BY_MNEMONIC[_m] = _code


def _size_of(specs, words, pos):
    """返回 (dword 长度, 变量字典)，specs 从文件 dword 位置 pos 开始。"""
    n = 0
    vars_ = {}
    for spec in specs:
        kind = spec[0]
        if kind in ("imm", "jref", "tref"):
            n += 1
        elif kind == "desc":
            n += 2
        elif kind == "cond5":
            n += 5
        elif kind == "str":
            ln = words[pos + n]
            n += 1 + ln
        elif kind == "count":
            vars_[spec[1]] = words[pos + n]
            n += 1
        elif kind == "rep":
            cnt = vars_[spec[1]]
            for _ in range(cnt):
                sub, subvars = _size_of(spec[2], words, pos + n)
                vars_.update(subvars)
                n += sub
        elif kind == "group":
            cnt = vars_[spec[1]]
            for _ in range(cnt):
                k = words[pos + n]
                n += 1 + 2 * k
        else:
            raise ValueError("未知操作数类型: %r" % (kind,))
    return n, vars_


def instruction_size(words, pc):
    """words 为代码区 dword 序列（下标 0 对应文件 dword 0）。返回指令长度。"""
    op = words[pc]
    spec = OPCODES.get(op)
    if spec is None:
        raise ValueError("偏移 0x%X 处出现未定义操作码 0x%X" % (pc * 4, op))
    n, _ = _size_of(spec["ops"], words, pc + 1)
    return 1 + n


def _walk(specs, words, pos, vars_):
    """按 specs 消费 dword 流，返回 ([(kind, extra, values)], 新位置)。"""
    out = []
    for spec in specs:
        kind = spec[0]
        if kind == "imm":
            out.append(("imm", None, (words[pos],))); pos += 1
        elif kind == "jref":
            out.append(("jref", spec[1], (words[pos],))); pos += 1
        elif kind == "tref":
            out.append(("tref", None, (words[pos],))); pos += 1
        elif kind == "desc":
            out.append(("desc", None, (words[pos], words[pos + 1]))); pos += 2
        elif kind == "cond5":
            out.append(("desc", None, (words[pos], words[pos + 1])))
            out.append(("imm", None, (words[pos + 2],)))
            out.append(("desc", None, (words[pos + 3], words[pos + 4])))
            pos += 5
        elif kind == "str":
            ln = words[pos]
            out.append(("str", None, (ln,) + tuple(words[pos + 1:pos + 1 + ln])))
            pos += 1 + ln
        elif kind == "count":
            vars_[spec[1]] = words[pos]
            out.append(("count", spec[1], (words[pos],))); pos += 1
        elif kind == "rep":
            for _ in range(vars_[spec[1]]):
                sub, pos = _walk(spec[2], words, pos, vars_)
                out.extend(sub)
        elif kind == "group":
            for _ in range(vars_[spec[1]]):
                k = words[pos]
                out.append(("count", "_g", (k,))); pos += 1
                for _i in range(k):
                    out.append(("desc", None, (words[pos], words[pos + 1]))); pos += 2
        else:
            raise ValueError("未知操作数类型: %r" % (kind,))
    return out, pos


def iter_operands(words, pc):
    """产出 (kind, extra, values)，用于反汇编渲染。"""
    spec = OPCODES[words[pc]]
    items, _pos = _walk(spec["ops"], words, pc + 1, {})
    for item in items:
        yield item


