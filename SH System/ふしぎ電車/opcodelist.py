#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
opcodelist.py -- HIMAURI(SH System) 脚本字节码指令集定义

唯一依据：FUSHIGI.EXE（HIMAURI Script Engine 2.0）
  - 主分发循环 sub_403D11（switch 101 个 case，0x00-0x64）
  - 操作数表达式求值 sub_401985
  - 字符串取用 sub_401D05
  - 单字节 tag sub_40159F
  - 24 位跳转目标 sub_4015B1

脚本文件结构
  0x00  char magic[8]  "Himauri\\0"
  0x08  u8   size[3]   整个文件 BE24 长度（含头）
  0x0B  u8   flag      0=无标题；非 0 时 0x10 起为 NUL 结尾标题
  0x0C  u8   reserved[4]
  0x10  指令流，0xFF 结束

指令格式
  [opcode u8] [操作数...]；跳转目标为 3 字节大端绝对偏移（相对文件头）

表达式记号（RPN，0xFF 结束）
  0x00-0x07 立即数 0..7          0x08-0x0C 立即数 -1..-5
  0x0D nn   立即数 0..127        0x0E nn nn 立即数 BE16   0x0F nn*4 立即数 BE32
  0x1y/0x2y/0x3y  读变量 V1/V2/V3[y]（y=0x0E 时下字节为下标，0x0F 时下两字节 BE16）
  0x40-0x47 赋值与复合赋值       0x50-0x55 比较
  0x60-0x6C 算术/逻辑            0x70-0x76 一元/数学函数
"""

VERSION = '1.0'
ENGINE = 'HIMAURI / SH System'
MAGIC = b'Himauri\0'
HEADER_SIZE = 16
MAX_OPCODE = 0x64
TOK_END = 0xFF

# ---------------------------------------------------------------------------
# 表达式
# ---------------------------------------------------------------------------
ASSIGN_OPS = {0x40: '=', 0x41: '+=', 0x42: '-=', 0x43: '*=', 0x44: '/=', 0x45: '%=',
              0x46: '&=', 0x47: '|='}

BIN_OPS = {
    0x50: ('==', 7), 0x51: ('!=', 7), 0x52: ('<', 8), 0x53: ('<=', 8),
    0x54: ('>', 8), 0x55: ('>=', 8),
    0x60: ('+', 9), 0x61: ('-', 9), 0x68: ('*', 10), 0x69: ('/', 10), 0x6A: ('%', 10),
    0x6B: ('&&', 4), 0x6C: ('||', 3),
}

UN_OPS = {0x70: 'neg', 0x71: 'not', 0x72: 'rand', 0x73: 'atan2', 0x74: 'sin', 0x75: 'cos', 0x76: 'sqrt'}
UN_FUNCS = {v: k for k, v in UN_OPS.items()}

# 间接变量引用：0x78->V1[下标] 0x79->V2[下标] 0x7A->V3[下标]
# 下标取自表达式栈顶（sub_401985 的 case 'p' 且低半字节 >= 8）
INDEX_VAR_OPS = {0x78: 1, 0x79: 2, 0x7A: 3}
INDEX_VAR_CODE = {v: k for k, v in INDEX_VAR_OPS.items()}

OP_TO_SYM = dict(ASSIGN_OPS)
OP_TO_SYM.update({k: v[0] for k, v in BIN_OPS.items()})
OP_TO_SYM.update(UN_OPS)

SYM_TO_OP = {}
for _k, _v in ASSIGN_OPS.items():
    SYM_TO_OP[_v] = _k
for _k, _v in BIN_OPS.items():
    SYM_TO_OP.setdefault(_v[0], _k)

VAR_TYPE_DESC = {1: '全局整型变量', 2: '脚本上下文变量', 3: '系统整型变量'}

# ---------------------------------------------------------------------------
# 指令表
# ---------------------------------------------------------------------------
# schema 记号： E=表达式 S=字符串 T=3字节目标 B=1字节计数 P=参数表(0x00/0x01str/0x02expr)
#             M=参数个数+参数表达式+目标(CALLADDR)  W=表达式+计数+目标表(SWITCH)
SCHEMA_CHARS = {'E': 'expr', 'S': 'str', 'T': 'target', 'B': 'count',
                'P': 'params', 'M': 'calladdr', 'W': 'switch', 'A': 'tagarg'}

_TABLE = [
    # opcode, mnemonic, schema, verified, desc
    (0x00, 'EVAL',       'E',      True,  '求值表达式（赋值/语句），结果丢弃'),
    (0x01, 'JTRUE',      'ET',     False, '表达式非 0 跳转，否则跳过目标'),
    (0x02, 'BRANCH',     'ETT',    False, '表达式非 0 跳第一个目标，否则跳第二个'),
    (0x03, 'JFALSE',     'ET',     True,  '表达式为 0 跳转，否则继续'),
    (0x04, 'JMP',        'T',      True,  '无条件跳转'),
    (0x05, 'SWITCH',     'EW',     True,  '按表达式值选择目标，越界跳过整表'),
    (0x06, 'CALLADDR',   'M',      False, '带参调用脚本内地址'),
    (0x07, 'RETVAL',     'E',      False, '结束脚本并返回表达式值'),
    (0x08, 'RET',        'E',      False, '结束脚本（弹栈）'),
    (0x09, 'CALLHXP',    'SEEP',   True,  '按文件名调用外部脚本，如 "INITIAL.HXP"'),
    (0x0A, 'CALLSCRIPT', 'EP',     True,  '按脚本编号调用脚本'),
    (0x0B, 'SETSTR',     'ES',     False, '设置字符串变量'),
    (0x0C, 'APPENDSTR',  'ES',     False, '字符串变量追加'),
    (0x0D, 'STRCMP',     'SS',     False, '字符串比较'),
    (0x0E, 'STRLEN',     'S',      False, '字符串长度'),
    (0x0F, 'SUBSTR',     'ESEE',   False, '取子串'),
    (0x10, 'SETSTR2',    'ES',     False, '写字符串变量（经缓冲区转换）'),
    (0x11, 'INSTR',      'SEEE',   False, '查找子串（DBCS 感知）'),
    (0x12, 'STRCAT3',    'ES',     False, '字符串变量拼接'),
    (0x13, 'STRDUP',     'SE',     False, '字符串复制/分配'),
    (0x14, 'STRCHR',     'E',      False, '字符查找'),
    (0x15, 'SYSINFO', '', False, '填充系统信息变量（无操作数）'),
    (0x16, 'MESSAGE',    'E',      False, '消息框'),
    (0x17, 'GFXINFO', '', False, '填充显示/窗口信息变量（无操作数）'),
    (0x18, 'TIMER_RESET', '', False, '重置计时器（无操作数）'),
    (0x19, 'CHOICE',     'E',      False, '选择肢'),
    (0x1A, 'WAITKEY',    'E',      False, '等待按键'),
    (0x1B, 'CMD_1B',     'EE',     False, '未在样本中出现'),
    (0x1C, 'INVALID', '', False, '占位指令，引擎内为 JUMPOUT（无操作数）'),
    (0x1D, 'CMD_1D',     'EEE',    False, '未在样本中出现'),
    (0x1E, 'CMD_1E',     'E',      False, '未在样本中出现'),
    (0x1F, 'CMD_1F',     'SEEEEE', False, '未在样本中出现'),
    (0x20, 'PIC_HIDE', '', False, '关闭当前图片（无操作数）'),
    (0x21, 'INPUT_POLL', '', False, '读取输入状态到变量（无操作数）'),
    (0x22, 'CMD_22',     'EE',     False, '未在样本中出现'),
    (0x23, 'CMD_23',     'E',      False, '未在样本中出现'),
    (0x24, 'CMD_24',     'EE',     False, '未在样本中出现'),
    (0x25, 'CMD_25',     'ESEE',   False, '未在样本中出现'),
    (0x26, 'CMD_26',     'E',      False, '未在样本中出现'),
    (0x27, 'CMD_27',     'EEE',    False, '未在样本中出现'),
    (0x28, 'CMD_28',     'ESE',    False, '未在样本中出现'),
    (0x29, 'CMD_29',     'EEEEE',  False, '未在样本中出现'),
    (0x2A, 'CMD_2A',     'E',      False, '未在样本中出现'),
    (0x2B, 'CMD_2B',     'EE',     False, '未在样本中出现'),
    (0x2C, 'CMD_2C',     'EEE',    False, '未在样本中出现'),
    (0x2D, 'CMD_2D',     'EEE',    False, '未在样本中出现'),
    (0x2E, 'CMD_2E',     'EE',     False, '未在样本中出现'),
    (0x2F, 'CMD_2F',     'EE',     False, '未在样本中出现'),
    (0x30, 'CMD_30',     'ESE',    False, '未在样本中出现'),
    (0x31, 'CMD_31',     'ESEEEEE', False, '未在样本中出现'),
    (0x32, 'CMD_32',     'EEEE',   False, '未在样本中出现'),
    (0x33, 'CMD_33',     'EEEEEEEE', False, '未在样本中出现'),
    (0x34, 'CMD_34',     'EE',     False, '未在样本中出现'),
    (0x35, 'CMD_35',     'EEE',    False, '未在样本中出现'),
    (0x36, 'CMD_36',     'ESESE',  False, '未在样本中出现'),
    (0x37, 'PIC_LOAD',   'E',      False, '载入图片'),
    (0x38, 'CMD_38',     'EEEEEEEEE', False, '未在样本中出现'),
    (0x39, 'CMD_39',     'BEESEE', False, '未在样本中出现'),
    (0x3A, 'FILE_CLOSE', '', False, '关闭文件（无操作数）'),
    (0x3B, 'CMD_3B',     'S',      False, '未在样本中出现'),
    (0x3C, 'CMD_3C',     'S',      False, '未在样本中出现'),
    (0x3D, 'CMD_3D',     'EE',     False, '未在样本中出现'),
    (0x3E, 'CMD_3E',     'S',      False, '未在样本中出现'),
    (0x3F, 'CMD_3F',     'EE',     False, '未在样本中出现'),
    (0x40, 'CMD_40', '', False, '未在样本中出现（无操作数）'),
    (0x41, 'CMD_41',     'EEEEEEEE', False, '未在样本中出现'),
    (0x42, 'CMD_42',     'EEESEEEE', False, '未在样本中出现'),
    (0x43, 'CMD_43',     'EEEEEEEEEEEE', False, '未在样本中出现'),
    (0x44, 'CMD_44',     'E',      False, '未在样本中出现'),
    (0x45, 'MISC_QUERY', '', False, '查询引擎状态到变量（无操作数）'),
    (0x46, 'CMD_46',     'SS',     False, '未在样本中出现'),
    (0x47, 'CMD_47',     'S',      False, '未在样本中出现'),
    (0x48, 'CMD_48',     'SS',     False, '未在样本中出现'),
    (0x49, 'CMD_49',     'S',      False, '未在样本中出现'),
    (0x4A, 'CMD_4A',     'SS',     False, '未在样本中出现'),
    (0x4B, 'CMD_4B',     'ES',     False, '未在样本中出现'),
    (0x4C, 'CMD_4C',     'E',      False, '未在样本中出现'),
    (0x4D, 'CMD_4D',     'E',      False, '未在样本中出现'),
    (0x4E, 'CMD_4E',     'EE',     False, '未在样本中出现'),
    (0x4F, 'CMD_4F',     'EE',     False, '未在样本中出现'),
    (0x50, 'CMD_50',     'EEE',    False, '未在样本中出现'),
    (0x51, 'CMD_51',     'EE',     False, '未在样本中出现'),
    (0x52, 'CMD_52',     'E',      False, '未在样本中出现'),
    (0x53, 'CMD_53',     'E',      False, '未在样本中出现'),
    (0x54, 'CMD_54',     'EE',     False, '未在样本中出现'),
    (0x55, 'CTX_QUERY', '', False, '遍历脚本上下文查询状态（无操作数）'),
    (0x56, 'KEYS_READ', '', False, '读 256 个键值到变量（无操作数）'),
    (0x57, 'CMD_57',     'ES',     False, '未在样本中出现'),
    (0x58, 'CMD_58',     'ESE',    False, '未在样本中出现'),
    (0x59, 'CMD_59',     'ES',     False, '未在样本中出现'),
    (0x5A, 'CMD_5A',     'EEE',    False, '未在样本中出现'),
    (0x5B, 'CMD_5B',     'SSS',    False, '未在样本中出现'),
    (0x5C, 'CMD_5C',     'EEEEEE', False, '未在样本中出现'),
    (0x5D, 'LIST_QUERY', '', False, '查询列表数据到变量（无操作数）'),
    (0x5E, 'CMD_5E',     'ET',     False, '未在样本中出现'),
    (0x5F, 'CMD_5F',     'E',      False, '未在样本中出现'),
    (0x60, 'CMD_60',     'EE',     False, '未在样本中出现'),
    (0x61, 'TABLE_LOOKUP', 'EA',    False, '查表：表号, 键(字符串或序号)'),
    (0x62, 'CMD_62',     'EEE',    False, '未在样本中出现'),
    (0x63, 'CMD_63',     'E',      False, '未在样本中出现'),
    (0x64, 'CMD_64',     'SE',     False, '未在样本中出现'),
]

OPCODES = {}
for _code, _mn, _schema, _ver, _desc in _TABLE:
    OPCODES[_code] = {
        'mnemonic': _mn,
        'schema': None if _schema is None else [SCHEMA_CHARS[c] for c in _schema.replace(' ', '')],
        'schema_text': _schema,
        'verified': _ver,
        'desc': _desc,
    }

MNEMONICS = {v['mnemonic']: k for k, v in OPCODES.items()}


def by_mnemonic(name):
    try:
        return MNEMONICS[name.upper()]
    except KeyError:
        raise KeyError('未知助记符: %s' % name)


def describe():
    out = []
    for code in sorted(OPCODES):
        info = OPCODES[code]
        out.append('0x%02X  %-11s %-12s %s%s' % (
            code, info['mnemonic'], info['schema_text'] or '??',
            info['desc'], '' if info['verified'] else '  [未验证]'))
    return '\n'.join(out)


if __name__ == '__main__':
    print(describe())
