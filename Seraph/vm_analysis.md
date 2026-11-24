# SERAPH VM

## 证据

`SERAPH.c` 的 `0x40BB10` 是场景指令分派器。`0x408E00` 单独分派文本指令。`0x4081F0` 是后缀表达式求值器，`0x408680` 读取赋值目的地和运算子码。场景与文本流共享一个按字节寻址的 PC。`0x41` 进入文本模式，文本 `0xFF` 恢复场景模式。`0x50` 的子结构由 `0x4094D0` 读取。

`ScnPac` 的编号 2 是辅助代码，编号 3–170 是场景代码。解包工具已还原 LZ 层。场景内没有独立的字符串池和字节对齐。C 字符串和选择肢紧跟各自指令，字段终止符为 NUL。`0x4081B0` 与 `0x4081D0` 分别读取小端 16 位和 32 位值。3 字节字段保留处理器实际采用的字节序。

## 操作码与操作数

`opcodelist.py` 的 `SCENE`、`TEXT`、`DEST`、`ASSIGN` 和 `EXPR` 与分派器的编号对应。指令首字节是表的索引。`u8`、`u16`、`u24`、`u32` 和 `s32` 读取指定宽度，`u24be` 用大端。`expr` 以 `END_EXPRESSION` 结束。`ifFF`、`unlessFF`、`if0`、`if2` 根据前一字段选择变体。`resource` 读取归档编号和一个 `u16` 条目编号，`254` 单独表示继承当前资源基本编号。

场景跳转和调用使用相对于当前解包条目开头的绝对字节偏移。`CALL_AUX` 和 `SET_EVENT_HANDLER` 的基址是辅助条目。带指定入口的场景切换及条件跳转资源使用目标场景的基址。选择肢块包含各变体的选择键、下一个变体的偏移和若干 NUL 字符串。通过标签回填各字节偏移。

## 编辑与回封

在工程目录运行下列命令。`-o` 在单文件模式可指定文件或现有目录，在目录模式指定输出目录。也可把多个输入文件路径传给同一个工具，适用于 Windows 已将 `.py` 关联到 Python 的拖放方式。

```powershell
python .\disassembler.py .\ScnPac_unpack\00003 -o .\00003.asm.txt --encoding cp932
python .\assembler.py .\00003.asm.txt -o .\00003.rebuild --encoding cp932
python .\disassembler.py .\ScnPac_unpack -o .\ScnPac_asm_merged --encoding cp932
python .\assembler.py .\ScnPac_asm_merged -o .\ScnPac_rebuild --encoding gbk
```

最后一行用于已准备好 GBK 文本的目录。省略 `--encoding` 时汇编使用 `.seraph` 头中记录的源编码。`--encoding gbk` 改变二进制字符串的编码，编辑中的 `.asm.txt` 始终保存为 UTF-8。目标编码无法表示某个字符时，汇编报告文件和行号。`{{XX:XX}}` 保留指定字节，原始 CR、LF 分别可写成 `{{0D}}`、`{{0A}}`。引擎对话换行使用单独的 `TEXT_NEWLINE` 指令。引号和反斜杠使用 JSON 双引号字符串语法。

正文和人名可在 `TEXT_RUN` 的引号内按显示顺序编辑。选择肢在各自的 `CHOICE_TEXT` 中编辑。交给翻译 AI 时，限定它修改这两种指令的引号内文本，并要求保留 `{{XX:XX}}` 占位符、全角缩进和 `.text_layout` 行。汇编器兼容先前的 `TEXT` 写法。`.seraph` 记录源文件名、源编码、条目号、长度及 SHA-256。目录反汇编选取 `00002–00170`，也支持 `.scn`、`.sc` 和 `.bin` 的自定义脚本名。批量汇编到 `-o` 指定的目录时，产物使用可直接放回解包目录的文件名。省略 `-o` 时在输入文件旁生成 `.rebuild` 文件。`example.asm.txt` 使用自制短样本演示格式。

选择肢组按 `SELECT_CHOICE`、`CHOICE_GROUP`、`CHOICE_TEXT`、`CHOICE_END` 和 `.end_choice` 表示，组内字符串数量在汇编时生成。`loc_…` 标记指令边界，`["LABEL", "expr_…"]` 标记表达式子码边界，`choice_…` 标记选择肢组边界。保留这些标签和对它们的引用，汇编器会按编辑后的字节长度计算偏移。

`00002::loc_…` 是对其他场景条目的引用。批量汇编时按目标条目的实际标签解析。单文件模式保留未参与汇编的外部条目地址。若改动影响了其他脚本引用的标签地址，请将整个脚本目录一起回编，然后把编号文件覆盖到解包目录的副本，用 `dat_tool.py pack` 生成新封包。

### 正文合并与回编

`TEXT_RUN` 将连续的 `TEXT` 和 `TEXT_SPEED` 折叠为一个可编辑的字符串。游戏显示的全角空格直接写为 `　`。实际换行、等待、语音、动态插字、其他文本控制和跳转标签都是合并边界，因此人名和台词可分别编辑。

```asm
    TEXT_RUN "文字、続き。"
    .text_layout [11], 2, [30], "、", [11], 2, [50], "。", [11, 11]
```

紧随 `TEXT_RUN` 的 `.text_layout` 按原指令顺序保存各片段。数字表示原 `TEXT` 片段的字符数，每个字节占位符算一个单位。引号中的标点表示单独显示的标点片段，方括号内列出该位置的速度指令，包含重复设置。

回编变长文本时，按标点类别和出现顺序匹配停顿位置，例如 `、` 可匹配译文中的 `，`。两侧普通文字按原片段长度重新切分。没有等价标点时，切分按片段比例分配，速度设置仍按原顺序执行。每条实际写入的 `TEXT` 继续检查 255 字节的编码长度上限，超限报出源文件和行号。

## 验收范围

- 新版 `TEXT_RUN` 对全部 169 个脚本条目通过 CP932 逐字节往返检查。合入剩余条目重新封包后，639 项封包与原始 `ScnPac.Dat` 逐字节一致。旧版汇编目录也通过兼容回编检查。
- 用 `00019` 的首句验证了 GBK 变长译文。三处逗号和一处句号继承原停顿，等待与速度指令的顺序一致，后续跳转随新字节长度重定位。
- 验证了 GBK 文本和控制字节的往返、变长后的本地跳转、辅助条目调用及选择肢重定位。编辑测试用的场景回包后再次解包，字节与汇编结果一致。
- 验证了未定义标签和无效字节占位符报错。指令表涵盖可执行文件中的分派分支，原包未出现的指令未逐条做运行时验证。GBK 编码测试覆盖二进制和重反汇编，游戏实机显示待测。

## 分派表索引

最短长度包含操作码本身。表达式以一字节终止，字符串含 NUL。赋值目标另有一字节分隔字段。带跳转表或子块的最短长度按最短可表示的结构计算。无操作字节的分派表列在表后。

### 场景

| Opcode | 助记符 | 最短字节数 | 操作数与变体 | 伪 C 证据 | 原包次数 |
| --- | --- | ---: | --- | --- | ---: |
| `0x00` | `ASSIGN` | 4 | `dest assign` | `0x40BB10`，第 11632 行 | 39217 |
| `0x01` | `BRANCH_FALSE` | 6 | `expr jump` | `0x40BB10`，第 11635 行 | 646 |
| `0x03` | `BRANCH_FALSE_AND` | 6 | `expr jump` | `0x40BB10`，第 11636 行 | 0 |
| `0x04` | `BRANCH_FALSE_OR` | 6 | `expr jump` | `0x40BB10`，第 11637 行 | 19 |
| `0x05` | `SET_SWITCH_VALUE` | 2 | `expr` | `0x40BB10`，第 11694 行 | 0 |
| `0x06` | `SWITCH_BRANCH_UNEQUAL` | 6 | `expr jump` | `0x40BB10`，第 11697 行 | 0 |
| `0x0A` | `JUMP` | 5 | `jump` | `0x40BB10`，第 11702 行 | 900 |
| `0x0B` | `CALL` | 5 | `jump` | `0x40BB10`，第 11704 行 | 57 |
| `0x0C` | `RETURN` | 1 | `无` | `0x40BB10`，第 11713 行 | 83 |
| `0x0D` | `SWITCH_JUMP` | 4 | `expr targets` | `0x40BB10`，第 11718 行 | 7 |
| `0x0E` | `SWITCH_CALL` | 4 | `expr targets` | `0x40BB10`，第 11732 行 | 4 |
| `0x0F` | `CALL_AUX` | 5 | `aux` | `0x40BB10`，第 11759 行 | 29890 |
| `0x10` | `RETURN_AUX` | 1 | `无` | `0x40BB10`，第 11766 行 | 30 |
| `0x11` | `READ_UNUSED_WORD` | 5 | `u32` | `0x40BB10`，第 11781 行 | 2 |
| `0x12` | `SET_RESUME_TARGET` | 6 | `expr jump` | `0x40BB10`，第 11785 行 | 18 |
| `0x13` | `SET_EVENT_HANDLER` | 6 | `aux expr` | `0x40BB10`，第 11792 行 | 0 |
| `0x14` | `RETURN_EVENT` | 2 | `u8` | `0x40BB10`，第 11796 行 | 0 |
| `0x15` | `YIELD_SCENE` | 2 | `u8` | `0x40BB10`，第 11805 行 | 0 |
| `0x16` | `LOAD_ARCHIVE_INDEX` | 2 | `expr` | `0x40BB10`，第 11816 行 | 1 |
| `0x17` | `CLEAR_FLAGS_AND_VARS` | 1 | `无` | `0x40BB10`，第 11821 行 | 3 |
| `0x18` | `WRITE_FLAG` | 3 | `u8 ifFF:expr else:u16,u8 u8` | `0x40BB10`，第 11824 行 | 86 |
| `0x19` | `DEFINE_AUDIO_FILES` | 2 | `filenames` | `0x40BB10`，第 11845 行 | 1 |
| `0x1A` | `DEFINE_VOICE_FILES` | 2 | `filenames` | `0x40BB10`，第 11848 行 | 1 |
| `0x1B` | `DEFINE_PALETTE` | 2 | `palette` | `0x40BB10`，第 11851 行 | 1 |
| `0x1C` | `SET_RESOURCE_BASE` | 5 | `u8 u16 expr` | `0x40BB10`，第 11867 行 | 51 |
| `0x1D` | `SET_BASE_INDEX` | 4 | `u8 u16` | `0x40BB10`，第 11873 行 | 1 |
| `0x1E` | `SET_RELATIVE_INDEX` | 4 | `u8 u16` | `0x40BB10`，第 11877 行 | 402 |
| `0x1F` | `SET_VOICE_ID` | 6 | `u32 u8 unlessFF:expr` | `0x40BB10`，第 11881 行 | 5060 |
| `0x20` | `SET_FRAME_PARAMETERS` | 3 | `expr expr` | `0x40BB10`，第 11887 行 | 2 |
| `0x21` | `RESIZE_SURFACE` | 3 | `expr expr` | `0x40BB10`，第 11891 行 | 5 |
| `0x22` | `RESET_PALETTE` | 1 | `无` | `0x40BB10`，第 11897 行 | 2 |
| `0x23` | `LOAD_PALETTE_BANK` | 2 | `u8` | `0x40BB10`，第 11900 行 | 5 |
| `0x24` | `SET_SKIP_ENABLED` | 2 | `u8` | `0x40BB10`，第 11907 行 | 9 |
| `0x25` | `STOP_SKIP` | 1 | `无` | `0x40BB10`，第 11922 行 | 1 |
| `0x26` | `SET_TRANSITION` | 3 | `expr u8 unlessFF:transition` | `0x40BB10`，第 11925 行 | 104 |
| `0x27` | `SET_TEXT_MODE` | 2 | `u8` | `0x40BB10`，第 11994 行 | 327 |
| `0x28` | `MARK_SCENE_ENTRY` | 1 | `无` | `0x40BB10`，第 11998 行 | 23518 |
| `0x29` | `SET_REPLAY_TARGET` | 5 | `jump` | `0x40BB10`，第 12001 行 | 0 |
| `0x2A` | `END_REPLAY` | 1 | `无` | `0x40BB10`，第 12007 行 | 0 |
| `0x2B` | `REGISTER_IMAGE_SOURCE` | 2 | `u8 ifFF:expr,expr,expr else:resource` | `0x40BB10`，第 12017 行 | 1 |
| `0x2C` | `ADD_IMAGE_REGION` | 8 | `expr expr expr expr expr expr u8 unlessFF:expr,expr` | `0x40BB10`，第 12033 行 | 6 |
| `0x2D` | `CLEAR_IMAGE_REGIONS` | 1 | `无` | `0x40BB10`，第 12059 行 | 6 |
| `0x2E` | `SET_REGION_MODE` | 2 | `u8` | `0x40BB10`，第 12064 行 | 18 |
| `0x2F` | `ADD_IMAGE_ANCHOR` | 3 | `expr expr` | `0x40BB10`，第 12067 行 | 6 |
| `0x30` | `LOAD_RESOURCE_BUFFER` | 2 | `resource` | `0x40BB10`，第 12074 行 | 0 |
| `0x31` | `ALLOCATE_ARRAY` | 6 | `u16 u16 expr` | `0x40BB10`，第 12085 行 | 0 |
| `0x32` | `LOAD_ARRAY` | 6 | `resource u16 u16` | `0x40BB10`，第 12093 行 | 1 |
| `0x33` | `SET_TEXT_EFFECT` | 3 | `expr u8 if0:expr` | `0x40BB10`，第 12107 行 | 15 |
| `0x34` | `SET_INPUT_ENABLED` | 2 | `expr` | `0x40BB10`，第 12113 行 | 0 |
| `0x35` | `SET_TEXT_DISPLAY_MODE` | 2 | `expr` | `0x40BB10`，第 12127 行 | 1 |
| `0x36` | `WAIT_TIME` | 2 | `expr` | `0x40BB10`，第 12130 行 | 9 |
| `0x37` | `SET_TIMER` | 3 | `expr expr` | `0x40BB10`，第 12134 行 | 3 |
| `0x38` | `WAIT_TIMER` | 2 | `expr` | `0x40BB10`，第 12139 行 | 3 |
| `0x39` | `START_CLOCK` | 1 | `无` | `0x40BB10`，第 12145 行 | 2 |
| `0x3A` | `WAIT_CLOCK` | 2 | `expr` | `0x40BB10`，第 12148 行 | 2 |
| `0x3B` | `DEFINE_TEXT_WINDOW` | 7 | `expr expr expr expr expr expr` | `0x40BB10`，第 12155 行 | 10 |
| `0x3C` | `POSITION_TEXT_WINDOW` | 3 | `expr u8 if0:expr` | `0x40BB10`，第 12166 行 | 22 |
| `0x3D` | `SELECT_TEXT_WINDOW` | 3 | `expr expr` | `0x40BB10`，第 12186 行 | 5 |
| `0x3E` | `CLOSE_TEXT_WINDOW` | 2 | `u8` | `0x40BB10`，第 12205 行 | 8 |
| `0x3F` | `CLEAR_TEXT_WINDOW` | 2 | `u8` | `0x40BB10`，第 12222 行 | 2 |
| `0x40` | `CLOSE_ALL_TEXT_WINDOWS` | 1 | `无` | `0x40BB10`，第 12230 行 | 0 |
| `0x41` | `BEGIN_TEXT` | 1 | `无` | `0x40BB10`，第 12257 行 | 23588 |
| `0x42` | `SET_TEXT_RENDER_FLAGS` | 4 | `expr expr expr` | `0x40BB10`，第 12263 行 | 1 |
| `0x43` | `SET_FONT_PITCH` | 3 | `expr expr` | `0x40BB10`，第 12268 行 | 0 |
| `0x44` | `SET_NUMBER_WIDTH` | 2 | `expr` | `0x40BB10`，第 12272 行 | 3 |
| `0x45` | `SET_TEXT_BACKGROUND` | 2 | `expr` | `0x40BB10`，第 12275 行 | 15 |
| `0x46` | `BLIT_SOURCE_RECT` | 4 | `expr expr u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 12278 行 | 15 |
| `0x47` | `DISPLAY_SOURCE_RECT` | 3 | `expr u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 12299 行 | 2 |
| `0x48` | `COPY_PALETTE` | 1 | `无` | `0x40BB10`，第 12318 行 | 14 |
| `0x49` | `DRAW_RECT_BORDER` | 4 | `expr expr u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 12332 行 | 0 |
| `0x4A` | `SET_PALETTE_RGB` | 4 | `expr expr expr` | `0x40BB10`，第 12349 行 | 1 |
| `0x4B` | `SAVE_SCREEN` | 1 | `无` | `0x40BB10`，第 12355 行 | 2 |
| `0x4C` | `RESTORE_SCREEN` | 2 | `u8` | `0x40BB10`，第 12362 行 | 2 |
| `0x4D` | `REPLAY_TEXT` | 2 | `expr` | `0x40BB10`，第 12382 行 | 4 |
| `0x4E` | `CLEAR_TEXT_REGIONS` | 1 | `无` | `0x40BB10`，第 12419 行 | 0 |
| `0x4F` | `RESET_TEXT_LOG` | 1 | `无` | `0x40BB10`，第 12422 行 | 1 |
| `0x50` | `SELECT_CHOICE` | 10 | `expr expr expr expr expr choices` | `0x40BB10`，第 12435 行 | 108 |
| `0x51` | `GET_INPUT` | 1 | `无` | `0x40BB10`，第 12459 行 | 0 |
| `0x52` | `WAIT_INPUT` | 1 | `无` | `0x40BB10`，第 12463 行 | 6 |
| `0x53` | `ADD_HIT_REGION` | 6 | `expr expr expr expr expr` | `0x40BB10`，第 12473 行 | 0 |
| `0x54` | `GET_HIT_INPUT` | 1 | `无` | `0x40BB10`，第 12480 行 | 1 |
| `0x55` | `GET_HIT_REGION` | 1 | `无` | `0x40BB10`，第 12484 行 | 0 |
| `0x56` | `CLEAR_HIT_REGIONS` | 1 | `无` | `0x40BB10`，第 12489 行 | 0 |
| `0x57` | `GET_MOUSE_POSITION` | 1 | `无` | `0x40BB10`，第 12492 行 | 0 |
| `0x58` | `SAMPLE_PIXEL` | 2 | `u8` | `0x40BB10`，第 12523 行 | 0 |
| `0x59` | `LOAD_IMAGE` | 7 | `resource expr expr expr expr u8 unlessFF:expr,expr` | `0x40BB10`，第 12568 行 | 96 |
| `0x5A` | `LOAD_IMAGE_VARIANT` | 7 | `resource expr expr expr expr u8 unlessFF:expr,expr` | `0x40BB10`，第 12571 行 | 0 |
| `0x5B` | `RESTORE_RECT` | 3 | `expr u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 12574 行 | 31 |
| `0x5C` | `CAPTURE_LAYER_RECT` | 6 | `expr expr expr expr expr` | `0x40BB10`，第 12600 行 | 7 |
| `0x5D` | `CLEAR_LAYER` | 2 | `expr` | `0x40BB10`，第 12615 行 | 2 |
| `0x5E` | `SET_LAYER_TOGGLE` | 2 | `u8 unlessFF:expr` | `0x40BB10`，第 12619 行 | 8 |
| `0x5F` | `DISPLAY_RECT` | 6 | `expr expr expr expr expr` | `0x40BB10`，第 12627 行 | 0 |
| `0x60` | `LOAD_LAYER_BUFFER` | 2 | `resource` | `0x40BB10`，第 12635 行 | 0 |
| `0x61` | `DELETE_IMAGE_LAYER` | 2 | `expr` | `0x40BB10`，第 12640 行 | 0 |
| `0x62` | `DRAW_IMAGE_LAYER` | 5 | `expr expr u8 u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 12652 行 | 13 |
| `0x63` | `SET_IMAGE_LAYER_MODE` | 2 | `u8` | `0x40BB10`，第 12677 行 | 0 |
| `0x64` | `RESET_IMAGE_LAYERS` | 1 | `无` | `0x40BB10`，第 12682 行 | 0 |
| `0x65` | `SET_SCROLL_POSITIVE` | 4 | `expr expr expr` | `0x40BB10`，第 12685 行 | 0 |
| `0x66` | `SET_SCROLL_NEGATIVE` | 4 | `expr expr expr` | `0x40BB10`，第 12707 行 | 0 |
| `0x67` | `DRAW_COLOR_EFFECT` | 10 | `expr expr expr expr expr expr u24be` | `0x40BB10`，第 12729 行 | 6 |
| `0x68` | `START_FADE` | 9 | `expr expr expr expr expr u24be` | `0x40BB10`，第 12742 行 | 0 |
| `0x69` | `APPLY_FADE` | 3 | `expr u8 unlessFF:u24be` | `0x40BB10`，第 12755 行 | 2 |
| `0x6A` | `LOAD_PALETTE_RESOURCE` | 3 | `resource expr` | `0x40BB10`，第 12784 行 | 14 |
| `0x6B` | `FILL_PALETTE_RANGE` | 6 | `expr expr u24be` | `0x40BB10`，第 12787 行 | 0 |
| `0x6C` | `DEFINE_ANIMATION_RECT` | 9 | `expr expr expr expr expr u24be` | `0x40BB10`，第 12807 行 | 0 |
| `0x6D` | `ANIMATION_RESET` | 1 | `无` | `0x40BB10`，第 12827 行 | 0 |
| `0x6E` | `ANIMATION_SET_LAYER` | 3 | `expr u8 unlessFF:expr` | `0x40BB10`，第 12830 行 | 0 |
| `0x6F` | `ANIMATION_DRAW` | 3 | `expr u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 12843 行 | 0 |
| `0x70` | `LOAD_SPRITE` | 3 | `resource expr` | `0x40BB10`，第 12865 行 | 20 |
| `0x71` | `SET_SPRITE_POSITION` | 4 | `expr expr expr` | `0x40BB10`，第 12879 行 | 6 |
| `0x72` | `SHOW_SPRITE` | 2 | `u8 unlessFF:expr` | `0x40BB10`，第 12884 行 | 7 |
| `0x73` | `HIDE_SPRITE` | 2 | `u8 unlessFF:expr` | `0x40BB10`，第 12919 行 | 16 |
| `0x74` | `DELETE_SPRITE` | 2 | `u8 unlessFF:expr` | `0x40BB10`，第 12944 行 | 14 |
| `0x75` | `SET_TRANSITION_FLAG` | 2 | `u8` | `0x40BB10`，第 12996 行 | 14 |
| `0x76` | `LOAD_OVERLAY` | 2 | `resource` | `0x40BB10`，第 13001 行 | 0 |
| `0x77` | `FREE_OVERLAY` | 2 | `expr` | `0x40BB10`，第 13006 行 | 0 |
| `0x78` | `DRAW_OVERLAY` | 7 | `expr expr expr expr expr expr` | `0x40BB10`，第 13010 行 | 0 |
| `0x79` | `DRAW_FULL_OVERLAY` | 2 | `expr` | `0x40BB10`，第 13019 行 | 0 |
| `0x7A` | `UPDATE_OVERLAY` | 1 | `无` | `0x40BB10`，第 13023 行 | 0 |
| `0x7B` | `RESET_OVERLAY` | 1 | `无` | `0x40BB10`，第 13026 行 | 0 |
| `0x7C` | `POSITION_OVERLAY` | 2 | `u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 13029 行 | 0 |
| `0x7D` | `SELECT_OVERLAY` | 2 | `expr` | `0x40BB10`，第 13045 行 | 0 |
| `0x7E` | `DEFINE_OVERLAY_GEOMETRY` | 7 | `expr expr expr expr expr expr` | `0x40BB10`，第 13050 行 | 0 |
| `0x7F` | `BLIT_OVERLAY` | 5 | `expr expr expr u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 13059 行 | 0 |
| `0x80` | `BLIT_OVERLAY_VARIANT` | 5 | `expr expr expr u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 13060 行 | 0 |
| `0x81` | `ENABLE_OVERLAY_EFFECT` | 3 | `u8 expr` | `0x40BB10`，第 13081 行 | 0 |
| `0x82` | `CLEAR_OVERLAY_EFFECT` | 1 | `无` | `0x40BB10`，第 13096 行 | 0 |
| `0x83` | `LOAD_FRAME` | 2 | `resource` | `0x40BB10`，第 13101 行 | 2 |
| `0x84` | `DRAW_FRAME` | 7 | `expr expr expr expr expr expr` | `0x40BB10`，第 13105 行 | 5 |
| `0x85` | `SET_FRAME_MODE` | 2 | `u8` | `0x40BB10`，第 13114 行 | 3 |
| `0x86` | `INIT_FRAME` | 2 | `u8 ifFF:expr,expr,expr else:resource` | `0x40BB10`，第 13119 行 | 18 |
| `0x87` | `LOAD_FRAME_IMAGE` | 3 | `resource u8 unlessFF:expr,expr` | `0x40BB10`，第 13135 行 | 0 |
| `0x88` | `DRAW_FRAME_RECT` | 6 | `expr expr expr expr expr` | `0x40BB10`，第 13152 行 | 73 |
| `0x89` | `MOVE_FRAME` | 3 | `expr expr` | `0x40BB10`，第 13160 行 | 19 |
| `0x8A` | `ENTER_INTERACTIVE_MODE` | 3 | `expr u8 unlessFF:expr` | `0x40BB10`，第 13165 行 | 10 |
| `0x8B` | `TEST_MOUSE_REGION` | 1 | `无` | `0x40BB10`，第 13175 行 | 0 |
| `0x8C` | `REMOVE_MOUSE_REGION` | 2 | `expr` | `0x40BB10`，第 13180 行 | 20 |
| `0x8D` | `CLEAR_MOUSE_REGIONS` | 1 | `无` | `0x40BB10`，第 13184 行 | 0 |
| `0x8E` | `RESET_MOUSE_REGIONS` | 1 | `无` | `0x40BB10`，第 13186 行 | 17 |
| `0x8F` | `MOVE_IMAGE_ANCHOR` | 3 | `expr expr` | `0x40BB10`，第 13191 行 | 0 |
| `0x90` | `MOVE_TEXT_ORIGIN` | 3 | `expr expr` | `0x40BB10`，第 13196 行 | 1 |
| `0x91` | `COPY_SCREEN_RECT` | 9 | `expr expr expr expr expr expr expr expr` | `0x40BB10`，第 13201 行 | 5 |
| `0x92` | `REFRESH_SCREEN` | 1 | `无` | `0x40BB10`，第 13212 行 | 0 |
| `0x93` | `BLIT_WINDOW_RECT` | 7 | `expr expr expr expr expr expr` | `0x40BB10`，第 13214 行 | 0 |
| `0x94` | `CLEAR_BACK_BUFFER` | 1 | `无` | `0x40BB10`，第 13225 行 | 8 |
| `0x95` | `COPY_LAYER_RECT` | 8 | `expr expr expr expr expr expr expr` | `0x40BB10`，第 13228 行 | 0 |
| `0x96` | `SAVE_BACK_BUFFER` | 1 | `无` | `0x40BB10`，第 13243 行 | 0 |
| `0x97` | `PLAY_MUSIC` | 2 | `expr` | `0x40BB10`，第 13246 行 | 3 |
| `0x98` | `STOP_MUSIC` | 2 | `u8` | `0x40BB10`，第 13278 行 | 3 |
| `0x99` | `PAUSE_MUSIC` | 1 | `无` | `0x40BB10`，第 13315 行 | 3 |
| `0x9A` | `RESUME_MUSIC` | 1 | `无` | `0x40BB10`，第 13335 行 | 0 |
| `0x9B` | `RESTART_MUSIC` | 1 | `无` | `0x40BB10`，第 13347 行 | 0 |
| `0x9C` | `UPDATE_AUDIO` | 1 | `无` | `0x40BB10`，第 13351 行 | 0 |
| `0x9D` | `PLAY_VOICE_EFFECT` | 4 | `expr expr expr` | `0x40BB10`，第 13354 行 | 3 |
| `0x9E` | `SET_AUDIO_PARAMETER` | 2 | `expr` | `0x40BB10`，第 13366 行 | 11 |
| `0x9F` | `PLAY_VOICE` | 3 | `expr u8 unlessFF:u32` | `0x40BB10`，第 13371 行 | 0 |
| `0xA0` | `WAIT_VOICE` | 1 | `无` | `0x40BB10`，第 13386 行 | 0 |
| `0xA1` | `SET_AUDIO_PATH` | 2 | `string` | `0x40BB10`，第 13389 行 | 0 |
| `0xA2` | `STOP_SOUND_EFFECT` | 1 | `无` | `0x40BB10`，第 13398 行 | 0 |
| `0xA3` | `PLAY_SOUND_EFFECT` | 2 | `expr` | `0x40BB10`，第 13400 行 | 0 |
| `0xA4` | `RELEASE_SOUND_EFFECT` | 1 | `无` | `0x40BB10`，第 13410 行 | 0 |
| `0xA5` | `PLAY_WAVE_FILE` | 2 | `expr` | `0x40BB10`，第 13412 行 | 0 |
| `0xA6` | `STOP_WAVE_FILE` | 1 | `无` | `0x40BB10`，第 13437 行 | 0 |
| `0xA7` | `GET_VOLUME` | 2 | `expr` | `0x40BB10`，第 13450 行 | 2 |
| `0xA8` | `SET_VOLUME` | 3 | `expr expr` | `0x40BB10`，第 13472 行 | 4 |
| `0xA9` | `PLAY_MOVIE` | 2 | `string` | `0x40BB10`，第 13499 行 | 0 |
| `0xAA` | `LOAD_SCENE` | 3 | `resource u8 if2:scenejump` | `0x40BB10`，第 13525 行 | 20 |
| `0xAB` | `CALL_SCENE` | 3 | `resource u8 if2:scenejump` | `0x40BB10`，第 13526 行 | 223 |
| `0xAC` | `RETURN_SCENE` | 1 | `无` | `0x40BB10`，第 13586 行 | 195 |
| `0xAD` | `RESET_SCENE_STACK` | 1 | `无` | `0x40BB10`，第 13605 行 | 1 |
| `0xAE` | `HALT` | 1 | `无` | `0x40BB10`，第 13608 行 | 4 |
| `0xAF` | `SAVE_GAME` | 2 | `expr` | `0x40BB10`，第 13610 行 | 1 |
| `0xB0` | `LOAD_GAME` | 2 | `expr` | `0x40BB10`，第 13614 行 | 1 |
| `0xB1` | `COPY_SAVE_BLOCK` | 2 | `expr` | `0x40BB10`，第 13618 行 | 5 |
| `0xB2` | `RESET_SAVE_STATE` | 1 | `无` | `0x40BB10`，第 13643 行 | 3 |
| `0xB3` | `UPDATE_SAVE_STATE` | 1 | `无` | `0x40BB10`，第 13646 行 | 5 |
| `0xB4` | `SET_SAVE_SCALE` | 3 | `expr expr` | `0x40BB10`，第 13649 行 | 0 |
| `0xB5` | `RELEASE_SAVE_BITMAP` | 1 | `无` | `0x40BB10`，第 13654 行 | 1 |
| `0xB6` | `LOAD_SAVE_THUMBNAIL` | 4 | `expr expr expr` | `0x40BB10`，第 13662 行 | 2 |
| `0xB7` | `RELEASE_SAVE_THUMBNAIL` | 1 | `无` | `0x40BB10`，第 13694 行 | 0 |
| `0xB8` | `LOAD_SAVE_IMAGE` | 2 | `expr` | `0x40BB10`，第 13700 行 | 0 |
| `0xB9` | `RELEASE_SAVE_IMAGE` | 1 | `无` | `0x40BB10`，第 13731 行 | 0 |
| `0xBA` | `LOAD_CONDITIONAL_SCENE` | 2 | `resource` | `0x40BB10`，第 13736 行 | 0 |
| `0xBB` | `POST_MENU_COMMAND` | 1 | `无` | `0x40BB10`，第 13739 行 | 0 |
| `0xBC` | `SET_MENU_MODE` | 2 | `u8` | `0x40BB10`，第 13742 行 | 17 |
| `0xBE` | `ENTER_MENU` | 1 | `无` | `0x40BB10`，第 13748 行 | 0 |
| `0xBF` | `SET_MESSAGE_FILTER` | 13 | `expr expr expr expr expr expr u24be u24be` | `0x40BB10`，第 13755 行 | 0 |
| `0xC0` | `APPLY_DRAW_MODE` | 3 | `expr expr` | `0x40BB10`，第 13772 行 | 0 |
| `0xC1` | `DEFINE_FONT` | 13 | `expr expr expr expr expr u24 u24 string` | `0x40BB10`，第 13777 行 | 0 |
| `0xC2` | `STORE_FONT_NAME` | 2 | `expr` | `0x40BB10`，第 13796 行 | 0 |
| `0xC3` | `COPY_STRING_SLOT` | 3 | `expr expr` | `0x40BB10`，第 13801 行 | 0 |
| `0xC4` | `APPEND_STRING_SLOT` | 3 | `expr expr` | `0x40BB10`，第 13806 行 | 0 |
| `0xC5` | `SET_STRING_SLOT` | 3 | `expr slottext` | `0x40BB10`，第 13811 行 | 291 |
| `0xC6` | `APPEND_STRING_TEXT` | 3 | `expr slottext` | `0x40BB10`，第 13817 行 | 0 |
| `0xC7` | `RESET_FONT` | 1 | `无` | `0x40BB10`，第 13823 行 | 0 |
| `0xC8` | `SET_WAVE_EFFECT` | 2 | `u8 unlessFF:expr` | `0x40BB10`，第 13826 行 | 0 |
| `0xC9` | `UPDATE_WAVE_EFFECT` | 2 | `expr` | `0x40BB10`，第 13888 行 | 0 |
| `0xCB` | `LOAD_NUMBERED_BITMAP` | 3 | `string expr` | `0x40BB10`，第 13901 行 | 0 |
| `0xCC` | `LOAD_RGBA_PLANE` | 2 | `resource` | `0x40BB10`，第 13908 行 | 0 |
| `0xCD` | `RELEASE_RGBA_PLANE` | 1 | `无` | `0x40BB10`，第 13913 行 | 0 |
| `0xCE` | `LOAD_MASK_PLANE` | 2 | `resource` | `0x40BB10`，第 13916 行 | 0 |
| `0xCF` | `RELEASE_MASK_PLANE` | 1 | `无` | `0x40BB10`，第 13921 行 | 0 |
| `0xD0` | `RENDER_RGB_PLANE` | 3 | `expr u8 unlessFF:expr,expr,expr,expr` | `0x40BB10`，第 13924 行 | 0 |
| `0xD1` | `RELEASE_RGB_PLANE` | 2 | `u8 unlessFF:expr` | `0x40BB10`，第 13940 行 | 0 |
| `0xFF` | `END_SCENE` | 1 | `无` | `0x40BB10`，第 11624 行 | 171 |

`02`、`07–09`、`BD`、`CA`、`D2–FE` 走 `0x40BB10` 的空操作分支，各占一字节。

### 文本

| Opcode | 助记符 | 最短字节数 | 操作数与变体 | 伪 C 证据 | 原包次数 |
| --- | --- | ---: | --- | --- | ---: |
| `0x00` | `TEXT` | 2 | `text` | `0x408E00`，第 9057 行 | 110937 |
| `0x01` | `TEXT_VALUE` | 2 | `expr` | `0x408E00`，第 9061 行 | 0 |
| `0x02` | `TEXT_STYLE` | 2 | `u8` | `0x408E00`，第 9084 行 | 22 |
| `0x03` | `TEXT_COLOR` | 2 | `u8` | `0x408E00`，第 9090 行 | 0 |
| `0x04` | `TEXT_SHADOW` | 2 | `u8` | `0x408E00`，第 9096 行 | 0 |
| `0x05` | `TEXT_PITCH_X` | 2 | `u8` | `0x408E00`，第 9102 行 | 7 |
| `0x06` | `TEXT_PITCH_Y` | 2 | `u8` | `0x408E00`，第 9108 行 | 7 |
| `0x07` | `TEXT_EFFECT` | 2 | `u8` | `0x408E00`，第 9114 行 | 1 |
| `0x08` | `TEXT_SPEED` | 2 | `u8` | `0x408E00`，第 9120 行 | 154878 |
| `0x09` | `TEXT_DELAY` | 2 | `u8` | `0x408E00`，第 9126 行 | 2 |
| `0x0A` | `TEXT_TARGET` | 2 | `u8` | `0x408E00`，第 9132 行 | 6 |
| `0x0B` | `TEXT_HIGHLIGHT` | 2 | `u8` | `0x408E00`，第 9139 行 | 7 |
| `0x0E` | `TEXT_INDENT` | 2 | `s8` | `0x408E00`，第 9145 行 | 0 |
| `0x0F` | `TEXT_PLAY_VOICE_SLOT` | 2 | `u8` | `0x408E00`，第 9151 行 | 17 |
| `0x10` | `TEXT_TIMING` | 2 | `u8` | `0x408E00`，第 9169 行 | 2 |
| `0x11` | `TEXT_STRING_SLOT` | 2 | `u8` | `0x408E00`，第 9175 行 | 1 |
| `0x14` | `TEXT_NEWLINE` | 1 | `无` | `0x408E00`，第 9182 行 | 23848 |
| `0x15` | `TEXT_WAIT` | 1 | `无` | `0x408E00`，第 9187 行 | 23521 |
| `0x16` | `TEXT_CENTER` | 1 | `无` | `0x408E00`，第 9218 行 | 30 |
| `0x17` | `TEXT_RESTART_WINDOW` | 1 | `无` | `0x408E00`，第 9221 行 | 8 |
| `0x18` | `TEXT_PLAY_VOICE_ID` | 5 | `u32` | `0x408E00`，第 9242 行 | 5060 |
| `0x19` | `TEXT_CLEAR` | 1 | `无` | `0x408E00`，第 9277 行 | 11 |
| `0xFF` | `END_TEXT` | 1 | `无` | `0x408E00`，第 9282 行 | 23588 |

文本表中其余值走 `0x408E00` 的默认继续分支，各占一字节。

### 表达式

| Opcode | 助记符 | 最短字节数 | 操作数与变体 | 伪 C 证据 | 原包次数 |
| --- | --- | ---: | --- | --- | ---: |
| `0x00` | `LOCAL` | 2 | `u8` | `0x4081F0`，第 8422 行 | — |
| `0x01` | `FLAG` | 2 | `u8 if0:u16,u8 else:expr` | `0x4081F0`，第 8427 行 | — |
| `0x02` | `GLOBAL` | 3 | `u16` | `0x4081F0`，第 8442 行 | — |
| `0x03` | `ARRAY_CELL` | 6 | `u16 u16 expr` | `0x4081F0`，第 8445 行 | — |
| `0x04` | `MATRIX_CELL` | 9 | `u16 u16 expr u16 expr` | `0x4081F0`，第 8450 行 | — |
| `0x05` | `INT` | 5 | `s32` | `0x4081F0`，第 8457 行 | — |
| `0x06` | `BUFFER_CELL` | 11 | `u16 u16 expr u8 u16 u16` | `0x4081F0`，第 8460 行 | — |
| `0x07` | `RANDOM` | 5 | `s32` | `0x4081F0`，第 8529 行 | — |
| `0x08` | `ADD` | 1 | `无` | `0x4081F0`，第 8549 行 | — |
| `0x09` | `SUB` | 1 | `无` | `0x4081F0`，第 8552 行 | — |
| `0x0A` | `MUL` | 1 | `无` | `0x4081F0`，第 8555 行 | — |
| `0x0B` | `DIV` | 1 | `无` | `0x4081F0`，第 8558 行 | — |
| `0x0C` | `MOD` | 1 | `无` | `0x4081F0`，第 8561 行 | — |
| `0x0D` | `BIT_AND` | 1 | `无` | `0x4081F0`，第 8564 行 | — |
| `0x0E` | `BIT_OR` | 1 | `无` | `0x4081F0`，第 8567 行 | — |
| `0x0F` | `BIT_XOR` | 1 | `无` | `0x4081F0`，第 8570 行 | — |
| `0x10` | `SHORT_CIRCUIT_TRUE` | 1 | `无` | `0x4081F0`，第 8533 行 | — |
| `0x11` | `EQ` | 1 | `无` | `0x4081F0`，第 8573 行 | — |
| `0x12` | `NE` | 1 | `无` | `0x4081F0`，第 8576 行 | — |
| `0x13` | `LE` | 1 | `无` | `0x4081F0`，第 8579 行 | — |
| `0x14` | `GE` | 1 | `无` | `0x4081F0`，第 8582 行 | — |
| `0x15` | `LT` | 1 | `无` | `0x4081F0`，第 8585 行 | — |
| `0x16` | `GT` | 1 | `无` | `0x4081F0`，第 8588 行 | — |
| `0x17` | `BOOL_AND` | 1 | `无` | `0x4081F0`，第 8591 行 | — |
| `0x18` | `BOOL_OR` | 1 | `无` | `0x4081F0`，第 8594 行 | — |
| `0x19` | `GO_TO_TOKEN` | 5 | `exprjump` | `0x4081F0`，第 8539 行 | — |
| `0xFF` | `END_EXPRESSION` | 1 | `无` | `0x4081F0` | — |

`SHORT_CIRCUIT_TRUE` 从栈顶取条件。非零时跳过紧随的五字节。`GO_TO_TOKEN` 使用当前条目内的绝对字节偏移，常与该条件子码配对。

### 赋值目标

| Opcode | 助记符 | 最短字节数 | 操作数与变体 | 伪 C 证据 | 原包次数 |
| --- | --- | ---: | --- | --- | ---: |
| `0x00` | `LOCAL` | 2 | `u8` | `0x408680` | — |
| `0x01` | `FLAG` | 2 | `u8 if0:u16,u8 else:expr` | `0x408680`，第 8671 行 | — |
| `0x02` | `GLOBAL` | 3 | `u16` | `0x408680`，第 8688 行 | — |
| `0x03` | `ARRAY_CELL` | 6 | `u16 u16 expr` | `0x408680`，第 8692 行 | — |
| `0x04` | `MATRIX_CELL` | 9 | `u16 u16 expr u16 expr` | `0x408680`，第 8698 行 | — |
| `0x06` | `BUFFER_CELL` | 11 | `u16 u16 expr u8 u16 u16` | `0x408680`，第 8706 行 | — |

### 赋值运算

| Opcode | 助记符 | 最短字节数 | 操作数与变体 | 伪 C 证据 | 原包次数 |
| --- | --- | ---: | --- | --- | ---: |
| `0x00` | `SET` | 2 | `expr` | `0x408680`，第 8748 行 | — |
| `0x01` | `ADD` | 2 | `expr` | `0x408680`，第 8751 行 | — |
| `0x02` | `SUBTRACT` | 2 | `expr` | `0x408680`，第 8754 行 | — |
| `0x03` | `MULTIPLY` | 2 | `expr` | `0x408680`，第 8757 行 | — |
| `0x04` | `DIVIDE` | 2 | `expr` | `0x408680`，第 8760 行 | — |
| `0x05` | `AND` | 2 | `expr` | `0x408680`，第 8763 行 | — |
| `0x06` | `OR` | 2 | `expr` | `0x408680`，第 8766 行 | — |
| `0x07` | `XOR` | 2 | `expr` | `0x408680`，第 8769 行 | — |
| `0x08` | `INCREMENT` | 1 | `无` | `0x408680`，第 8772 行 | — |
| `0x09` | `DECREMENT` | 1 | `无` | `0x408680`，第 8775 行 | — |
| `0x0A` | `COPY_TEXT` | 2 | `string` | `0x408680`，第 8778 行 | — |
| `0x0B` | `CONCAT_TEXT` | 2 | `string` | `0x408680`，第 8785 行 | — |
| `0x0C` | `STORE_BYTE_WORD` | 4 | `u8 u16` | `0x408680`，第 8792 行 | — |

