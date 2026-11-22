# 《凌辱ニュータウン ～人妻狩り～》汉化工具

## 游戏与引擎

| 项目 | 内容 |
|---|---|
| 游戏名 | 凌辱ニュータウン ～人妻狩り～ |
| 厂商 | MAIKA |
| 发售 | [2002 年 11 月 1 日（Windows 版）](https://www.suruga-ya.jp/kaitori/kaitori_detail/145007369) |
| VNDB | [v7129](https://vndb.org/v7129) |
| 引擎 | `MAIKA` |
| 脚本格式 | `.ADB`，原版显示文本使用 CP932 |
| 封包格式 | `MIK01`（`.DAT`）。文本包 `MIK3.DAT` 直接存储条目。图包 `RAPNTWN.DAT` 的图片经过 `E1` 字节重排、LZSS 和 `BPR01` 解码后得到 BMP。 |

## 工具一览

| 工具 | 用途 |
|---|---|
| [`dat_tool.py`](dat_tool.py) | 列出、校验、解包和重封 `MIK3.DAT`、`RAPNTWN.DAT`。自动解码图片，回封时重新编码修改过的 BMP。 |
| [`disassembler.py`](disassembler.py) / [`assembler.py`](assembler.py) | 在 `.ADB` 和可编辑的 UTF-8 `.asm.txt` 之间转换。回编时重算受文本长度影响的跳转和偏移。 |
| [`asm_json.py`](asm_json.py) | 从 ASM 提取人名、正文和选项到 UTF-8 JSON，再按原有脚本结构回填。 |

[`opcodelist.py`](opcodelist.py) 是 ADB 工具使用的指令表，[`rapntwn_pe.py`](rapntwn_pe.py) 是两个 EXE 补丁共用的模块。ADB 格式和指令细节见 [`vm_analysis.md`](vm_analysis.md)。