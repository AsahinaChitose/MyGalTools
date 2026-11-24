# RSA.SD VM 格式

工具针对当前 `RSA.EXE` 的脚本格式，Python 3.10+，使用标准库。下方的 `RSA.c` 与 `RSA.asm` 指 `exe` 中的 IDA 导出文件。助记符按宿主行为拟定，未发现原始指令名。

## 文件布局与执行模型

- 载入函数直接 `ReadFile` 到脚本缓冲区，将 `dword_673174`（文件基址）与 `dword_66C148`（PC）设为缓冲区起点。入口是文件偏移 0。依据 `RSA.c:31896`、`35019`、`sub_42D6A0`。没有封装头、加密、压缩、独立文本池或对齐填充。
- `sub_4016C0`（`RSA.c:10700`，`RSA.asm:987`）读取小端 u16 opcode，通过 `jpt_4017DC` 分派。脚本由 PC、状态变量、u16 变量表 `word_676000` 和返回地址栈 `dword_675D40` 驱动。脚本与状态分开存储。指令和字段允许奇数偏移。
- `sub_401520` 读取小端 u16，`sub_401000` 读取小端 u32，`sub_4010C0` 逐字节读取 NUL 结尾字符串并消费结束符。实际字节按操作数宽度接续。
- `0x00B6` 是样本后段的内嵌资源元数据，偏移 `0xD30DC`。观察到三个 NUL 字符串，分别为短标识、资源名和说明。前一指令无条件跳转，文件里没有指向此记录的代码目标，`jpt_4017DC` 对此值走默认停止分支。元数据字段的宿主消费函数尚未确认，此布局的依据是样本边界和前后指令。汇编视图使用 `RESOURCE_METADATA`。
- `0x00B7` 走 VM 停止分支，也由宿主运行期强制触发。样本尾部连续出现两次，均保留。其他走同一默认分支的值并非已知磁盘记录，遇到它们报错。

## 指令变体与重定位

| 记录 | 格式和语义 | 依据 |
| --- | --- | --- |
| `CALL` | `A` 指向脚本内的 u32 文件偏移。将后继 PC 压栈，转到 `base+A`。`0xFFFFFFFF` 保留当前 PC，语法 `CALL NEXT`。 | `sub_4010F0`，case 31 |
| `JMP` / `JMP_ALT` | `A` 指向脚本内的 u32 文件偏移。直接设置 PC。 | case 32 / 59 |
| `RET` | 从返回栈取目标。磁盘指令没有地址字段。 | `sub_401130`，case 135 |
| `IF` | 紧跟连续的高位为 1 的 u16 条件词。条件读取器回拨到首个高位为 0 的词。样本 272 处均以 `JMP` 为下一条指令，条件为真时 VM 跳过这条六字节跳转。 | `sub_401540`，case 58 |
| `SWITCH` / `SWITCH_ALT` | u16 变量编号，u16 条目数，随后相同数量的 u32 文件偏移。变量值 0 时顺序执行，非 0 时按从 1 开始的索引选目标。 | case 146 / 147 |
| `MESSAGE` | u16 段数 + NUL 串记录。段数可为 0。 | case 72 |
| `CHOICES` | u16 选项数 + NUL 串列表。`N/V/M/W/@` 在选择肢中作普通文本处理。 | case 73 |
| `TIMER` | 3 个 u16。首字段为 0 时等待现有定时器，非 0 时更新截止时间。两个分支各读取两个余下字段。 | case 149 |
| `DEFINE_AUDIO_RESOURCE` | 3 个 u16 + u32。最后一个值由音频加载函数消费，采用资源偏移语义。 | case 128，`RSA.c:40571` |
| `LOAD_SCRIPT` | 一个 NUL 串路径。加载该文件后设置 PC 为基址。 | case 167，`sub_42D6A0` |
| `ADD_VARIABLE` 至 `MOD_VARIABLE` 中的算术指令 | 第二操作数高位为 1 时低 15 位索引变量表，否则是立即数。保留这两个变体的原始词。`SET_VARIABLE` 使用第二操作数的低 15 位索引变量表。 | case 136/137/139/140/141/142 |

标签是指令起始地址的符号名。文件偏移均相对文件起点，标签名字里的旧地址仅用于定位编辑点。汇编从偏移 0 布局两遍，按新位置写入跳表和跳转字段。语音及音频资源偏移保持资源坐标。场景计数器和变量编号同样按其原类型保存。

### 条件词

`IF` 使用 `flag=… cmp=… imm=… join=…` 等字段。高位统一由汇编器补回。

- 偶数位置的布尔输入是变量表编号 `flag`。`cmp` 的右操作数插入一个词，占用比较位置后面的字段，随后恢复到逻辑连接词。
- 操作词低 15 位的 bit 4 置位表示比较。低四位 `2/3/4/5/6/7` 分别为 `EQ/GT/LT/GE/LE/NE`。`0/1/8–15` 走恒假分支。右操作数 bit 14 置位表示变量 `var`，否则是 `imm`。
- 连接词 bit 3 取反左侧值。低三位 `0/1` 为 `AND/OR`，`2–7` 在折叠时跳过合并。原脚本通常使用末尾 `END`（值 2）。组合或保留位可以用带类型的数值写法保留。

### 消息子码

| 首字节 | asm 子记录 | 作用 |
| --- | --- | --- |
| `N/n` | `NAME` | 解析数字作为运行期姓名表索引，姓名表由宿主管理。 |
| `M/m` | `PAGE` | 消息分隔，交还控制给消息状态机。 |
| `V/v` | `VOICE` | NUL 串后接 u16 资源编号、u32 音频资源偏移。 |
| `W/w` | `WAIT` | 数字参数控制播放等待或定时等待。 |
| `@` | `CONTROL` | 跳过该段的正文显示。 |
| 其他（含空串） | `LINE` | 交给正文渲染。一条 `LINE` 对应一个物理段。 |

### 姓名注释与 MS.MHU

宿主从 `MS.MHU` 的 `//NameStr` 至 `//END` 读取零基姓名表，并在 `sub_41CDD0` 中按 `N/n` 的数值查名（`RSA.c:31374`、`31513`、`31588`、`30324`）。`N0` 表示清空姓名。样本表有 26 项，`N1` 是羽山　卓，`N2` 是麗佳，`N3` 是玲。宿主还支持运行期启用备用表，当前 `RSAN.SD` 没有启用该表的指令。

`MS.MHU` 以小端 u32 解包长度开头。样本走 `sub_4133A0` 的 LZSS 分支，初始窗口为 4096 字节全零，写指针为 4078。标志按低位到高位读取，1 表示字面字节，0 表示引用。引用为 12 位窗口偏移和 4 位长度码，实际长度为长度码加 3。按头部长度解出 5184 字节后，从 NUL 之前的逗号分隔字段取姓名表。

反汇编 SD 时依次在同目录和上一级目录寻找 `MS.MHU`。找到后同时导出 UTF-8 文件 `MS.MHU.asm.txt`，并把姓名显示在 SD 的 `NAME` 行尾，例如 `NAME "N3"  ; 玲`。汇编器忽略该注释。修改游戏中的姓名时，编辑 MHU 汇编文件 `//NameStr` 节内相应的 `NAME 3 "　　玲　　　"`，保留槽位编号。重新反汇编生成的二进制对即可刷新 SD 中的姓名注释。

MHU 按逗号分隔的字段顺序输出，姓名表之外的菜单和其余配置写为 `FIELD`。引号里的空格用于原有排版。字段内部不能使用 ASCII 逗号。解包长度根据字段重新编码后的字节数写入文件头。原始 LZSS 的字面段和引用位置保存在 `.lzss` 块内，解包内容的 SHA-256 一致时重用此布局以逐字节还原。编辑字段后重新压缩。样本在压缩流末尾有全零填充，`.pad_to` 记录重建后的最小文件长度。

## asm.txt 编辑与命令

在工作区根目录运行以下命令。第一个命令输出 `RSAN.asm.txt` 和 `MS.MHU.asm.txt`，第二个命令在 `rebuilt` 目录生成 `RSAN.SD` 和 `MS.MHU`。

```powershell
python disassembler.py RSAN.SD -o asm_out/ --encoding cp932
python assembler.py asm_out -o rebuilt
```

也可以直接用当前工作区的 `asm.txt` 和同目录的 `MS.MHU.asm.txt`。传入 SD 汇编文件时会自动找到这一份 MHU 汇编文件，并将两份二进制写到指定文件所在的目录。

```powershell
python assembler.py asm.txt -o rebuilt/RSAN.SD
```

`-o` 可指定单个输出文件或目录。单输入时，已存在的目录或以斜杠结尾的路径解析为输出目录。多输入或输入目录时，`-o` 解析为输出目录。目录反汇编搜寻当前层的 `.SD` 和 `MS.MHU`。目录汇编搜寻 `*.asm.txt` 或 `asm.txt`。同目录回装以 `.rebuild` 命名，成对写入其他目录时采用游戏文件名。可单独传入 MHU 文件导出，也可单独传入其汇编文件回装。Windows 已关联 `.py` 时支持多文件拖放。

- 汇编文本固定 UTF-8，读取时也允许 BOM。`.encoding` 声明二进制字符串的编码。反汇编默认 CP932。汇编未给 `--encoding` 时使用 `.encoding`，显式指定 `gbk` 时，两份文件的可见字符串均采用 GBK。Python GBK 无法表示原样本的 `・` 和 `､`，转换时可在译文中换成目标编码支持的符号。汇编遇到不可表示字符会报告行号和码点。
- 同一 `MESSAGE` 中连续的正文合并到一条 `LINE`。用 `\n` 表示原来的物理分行，例如 `LINE "第一行\n第二行"`。`NAME`、`VOICE`、`PAGE`、`WAIT` 和 `CONTROL` 结束当前正文组并单独输出。编辑时可增减 `\n`，汇编器会重建各自以 NUL 结尾的段并重算段数。旧版逐段书写的 `LINE` 仍可汇编。选择项单独改写 `OPTION`。主程序的 ANSI/DBCS 环境仍需能解释所用码页（`sub_412700` 调用 `IsDBCSLeadByte`）。
- 字符串结束 NUL 自动补齐。反斜杠、双引号和字面花括号可写为 `\\`、`\"`、`\{`、`\}`。控制字节、不可显示字节和非规范编码字节使用 `{{XX}}` 或 `{{XX:YY}}`，占位符按字节原样写入。CR/LF 使用 `{{0D}}` / `{{0A}}`。分段标记 `\n` 仅适用于 `LINE`，字面反斜杠加字母 n 则写作 `\\n`。字符串内禁止嵌入 NUL。
- `.end` 关闭 `MESSAGE`、`CHOICES` 或 `SWITCH/SWITCH_ALT` 块。`TARGET` 后可连续写多个标签。`IF` 的下一条指令按其本身的语法保留。标签前空行，`；` 可作为文字，ASCII 分号在引号外开启注释。

## Opcode 定义表

`W` = 小端 u16，`D` = 小端 u32 非代码偏移，`S` = NUL 结尾串，`A` = 小端 u32 代码地址。每条记录先写小端 u16 opcode。定长为 `2 + 2×W + 4×(D+A)`，`S` 再加编码长度及 1 字节结束符。`I/T/C/J` 是上节定义的 `IF/MESSAGE/CHOICES/SWITCH` 变长格式。`—` 表示没有操作数。表中列出了分派器全部 163 个非默认 case，并附两种在样本中使用默认分支的记录。

| 十进制 | 字节模式（u16 值） | 助记符 | 操作数 | 依据 |
| ---: | --- | --- | --- | --- |
| 1 | `0x0001` | `RESET_SCENE` | `W` | `RSA.c:10720` |
| 5 | `0x0005` | `OPEN_MOVIE` | `SWWW` | `RSA.c:10733` |
| 6 | `0x0006` | `READ_SCENE_WORDS` | `WWW` | `RSA.c:10760` |
| 7 | `0x0007` | `WAIT_INPUT_RESULT` | `WW` | `RSA.c:10765` |
| 8 | `0x0008` | `SKIP_WORD` | `W` | `RSA.c:10783` |
| 9 | `0x0009` | `SCROLL_BACKGROUND` | `W` | `RSA.c:10785` |
| 10 | `0x000A` | `TEST_SCROLL_BACKGROUND` | `W` | `RSA.c:10801` |
| 11 | `0x000B` | `RESET_HISTORY_AND_YIELD` | `-` | `RSA.c:10815` |
| 12 | `0x000C` | `SET_TEXT_COLORS` | `WWWWWW` | `RSA.c:10819` |
| 13 | `0x000D` | `GET_DISPLAY_STATE` | `W` | `RSA.c:10837` |
| 14 | `0x000E` | `SET_DISPLAY_MODE` | `W` | `RSA.c:10842` |
| 15 | `0x000F` | `SET_EFFECT_FLAG` | `W` | `RSA.c:10845` |
| 16 | `0x0010` | `FADE_SCREEN` | `WWW` | `RSA.c:10848` |
| 17 | `0x0011` | `WAIT_FADE` | `W` | `RSA.c:10855` |
| 18 | `0x0012` | `SET_INPUT_EFFECT_MODE` | `W` | `RSA.c:10868` |
| 21 | `0x0015` | `OPEN_SYSTEM_DIALOG` | `-` | `RSA.c:10881` |
| 22 | `0x0016` | `CAPTURE_RECTANGLE` | `WWWWWWW` | `RSA.c:10900` |
| 23 | `0x0017` | `TRANSITION_RECTANGLE` | `WWWWWWW` | `RSA.c:10912` |
| 24 | `0x0018` | `SET_WINDOW_INPUT` | `W` | `RSA.c:10945` |
| 25 | `0x0019` | `SKIP_SIX_WORDS` | `WWWWWW` | `RSA.c:10949` |
| 26 | `0x001A` | `SET_FONT` | `WWW` | `RSA.c:10958` |
| 27 | `0x001B` | `DRAW_RESOURCE_PAIR` | `SSWWWW` | `RSA.c:10972` |
| 28 | `0x001C` | `TRACK_TRANSITION` | `W` | `RSA.c:10981` |
| 30 | `0x001E` | `RUN_SYSTEM_ACTION` | `W` | `RSA.c:10995` |
| 31 | `0x001F` | `CALL` | `A` | `RSA.c:10999` |
| 32 | `0x0020` | `JMP` | `A` | `RSA.c:11060` |
| 33 | `0x0021` | `DRAW_BACKGROUND_RECT` | `SWWWWWWW` | `RSA.c:11064` |
| 34 | `0x0022` | `DRAW_OVERLAY_RECT` | `SWWWWWWW` | `RSA.c:11096` |
| 35 | `0x0023` | `DRAW_RESOURCE_AT` | `SWWWW` | `RSA.c:11112` |
| 36 | `0x0024` | `DRAW_BACKGROUND` | `SWWW` | `RSA.c:11120` |
| 37 | `0x0025` | `DRAW_LAYER_PAIR` | `SSWWW` | `RSA.c:11237` |
| 38 | `0x0026` | `DRAW_BACKGROUND_EFFECT` | `SWWW` | `RSA.c:11121` |
| 39 | `0x0027` | `DRAW_LAYER_PAIR_EFFECT` | `SSWWW` | `RSA.c:11238` |
| 40 | `0x0028` | `DRAW_THREE_RESOURCES` | `SSSWWWWW` | `RSA.c:11387` |
| 41 | `0x0029` | `DRAW_RESOURCE_EFFECT` | `SWWWWWWWWW` | `RSA.c:11430` |
| 42 | `0x002A` | `DRAW_FOUR_RESOURCES` | `SSSSWWWWWW` | `RSA.c:11445` |
| 43 | `0x002B` | `DRAW_FOREGROUND` | `SWWW` | `RSA.c:11520` |
| 44 | `0x002C` | `DRAW_LAYER_PAIR_SIMPLE` | `SSWWW` | `RSA.c:11548` |
| 45 | `0x002D` | `DRAW_SCROLLING_BACKGROUND` | `SWWWWWWWWW` | `RSA.c:11581` |
| 46 | `0x002E` | `REFRESH_DISPLAY` | `-` | `RSA.c:11607` |
| 47 | `0x002F` | `DRAW_RESOURCE_OFFSET` | `SWWWW` | `RSA.c:11609` |
| 48 | `0x0030` | `DRAW_PAIR_OFFSET` | `SSWWWW` | `RSA.c:11631` |
| 49 | `0x0031` | `DRAW_PAIR_SWITCH` | `SSWWWW` | `RSA.c:11662` |
| 50 | `0x0032` | `DRAW_AND_STORE_RESULT` | `SWWWWWWWWWWW` | `RSA.c:11675` |
| 51 | `0x0033` | `DRAW_PAIR_AND_STORE_RESULT` | `SSWWWWWWWWWWW` | `RSA.c:11693` |
| 52 | `0x0034` | `DRAW_BLACK_REGION_AND_STORE` | `WWWWWWWWWWW` | `RSA.c:11724` |
| 53 | `0x0035` | `SET_BACKDROP_MODE` | `W` | `RSA.c:11742` |
| 54 | `0x0036` | `REFRESH_TEXT_WINDOW` | `-` | `RSA.c:11772` |
| 55 | `0x0037` | `CLEAR_TEXT_WINDOW` | `-` | `RSA.c:11775` |
| 56 | `0x0038` | `TEST_INPUT_SETTING` | `WW` | `RSA.c:11778` |
| 57 | `0x0039` | `RESET_INPUT_SETTING` | `W` | `RSA.c:11783` |
| 58 | `0x003A` | `IF` | `I` | `RSA.c:11788` |
| 59 | `0x003B` | `JMP_ALT` | `A` | `RSA.c:11061` |
| 60 | `0x003C` | `MARK_SCENE` | `W` | `RSA.c:11856` |
| 61 | `0x003D` | `READ_SCENE_COUNTER` | `WW` | `RSA.c:11879` |
| 62 | `0x003E` | `RESUME_SCENE` | `-` | `RSA.c:11895` |
| 63 | `0x003F` | `SET_SYSTEM_BUTTON_STATE` | `W` | `RSA.c:11934` |
| 64 | `0x0040` | `CLEAR_RESUME_OPCODE` | `-` | `RSA.c:11938` |
| 65 | `0x0041` | `SET_TEXT_METRICS` | `WW` | `RSA.c:11940` |
| 66 | `0x0042` | `TEST_BIT` | `WW` | `RSA.c:11944` |
| 67 | `0x0043` | `ENABLE_SYSTEM_CONTROL` | `W` | `RSA.c:11956` |
| 68 | `0x0044` | `ENABLE_SKIP_CONTROL` | `W` | `RSA.c:11962` |
| 69 | `0x0045` | `CLEAR_MENU_STATE` | `-` | `RSA.c:11966` |
| 70 | `0x0046` | `NOP` | `-` | `RSA.c:11969` |
| 72 | `0x0048` | `MESSAGE` | `T` | `RSA.c:11974` |
| 73 | `0x0049` | `CHOICES` | `C` | `RSA.c:12363` |
| 77 | `0x004D` | `FADE_SCREEN_ALT` | `WWW` | `RSA.c:10849` |
| 79 | `0x004F` | `SET_PAGE_MODE` | `W` | `RSA.c:12409` |
| 80 | `0x0050` | `GET_INPUT_STATUS` | `W` | `RSA.c:12422` |
| 81 | `0x0051` | `MESSAGE_WAIT` | `-` | `RSA.c:12426` |
| 82 | `0x0052` | `TITLE_PANEL` | `-` | `RSA.c:12438` |
| 83 | `0x0053` | `MENU_YIELD` | `-` | `RSA.c:12456` |
| 84 | `0x0054` | `WINDOW_INPUT_YIELD` | `-` | `RSA.c:12487` |
| 85 | `0x0055` | `SET_MODE_TABLE_ENTRY` | `WW` | `RSA.c:12503` |
| 86 | `0x0056` | `SAVE_CONTEXT` | `-` | `RSA.c:12508` |
| 87 | `0x0057` | `REFRESH_SYSTEM_MENU` | `-` | `RSA.c:12536` |
| 89 | `0x0059` | `SET_SELECTION_STYLE` | `W` | `RSA.c:12542` |
| 90 | `0x005A` | `DRAW_TEXT_RESOURCE` | `WWWS` | `RSA.c:12546` |
| 91 | `0x005B` | `MENU_INPUT_RESULT` | `WW` | `RSA.c:12553` |
| 92 | `0x005C` | `NOP_ALT1` | `-` | `RSA.c:11970` |
| 93 | `0x005D` | `ENABLE_MESSAGE_CONTROL` | `W` | `RSA.c:12613` |
| 94 | `0x005E` | `SET_SAVE_TITLE` | `S` | `RSA.c:12617` |
| 95 | `0x005F` | `MENU_RESULT` | `W` | `RSA.c:12620` |
| 96 | `0x0060` | `MENU_WITH_FLAG` | `WW` | `RSA.c:12653` |
| 97 | `0x0061` | `TEST_MENU_RESULT` | `W` | `RSA.c:12723` |
| 98 | `0x0062` | `MENU_WITH_SCENE` | `WW` | `RSA.c:12761` |
| 99 | `0x0063` | `GALLERY_SELECT` | `WW` | `RSA.c:12794` |
| 100 | `0x0064` | `OPEN_MAIN_MENU` | `W` | `RSA.c:12836` |
| 101 | `0x0065` | `OPEN_TITLE_MENU` | `W` | `RSA.c:12867` |
| 102 | `0x0066` | `SHOW_SYSTEM_MENU` | `WWWWWWW` | `RSA.c:12884` |
| 103 | `0x0067` | `SHOW_SYSTEM_MENU_ALT` | `WWWWWWW` | `RSA.c:12885` |
| 104 | `0x0068` | `OPEN_GALLERY` | `WW` | `RSA.c:12980` |
| 106 | `0x006A` | `OPEN_CHARACTER_MENU` | `WWW` | `RSA.c:13011` |
| 107 | `0x006B` | `OPEN_LOAD_MENU` | `W` | `RSA.c:13057` |
| 108 | `0x006C` | `OPEN_VOICE_MENU` | `WWW` | `RSA.c:13078` |
| 109 | `0x006D` | `SET_INPUT_MAP` | `WWWWW` | `RSA.c:13139` |
| 110 | `0x006E` | `CONFIG_TEXT_INPUT` | `WWWWWW` | `RSA.c:13151` |
| 111 | `0x006F` | `CONFIG_MESSAGE_WINDOW` | `WWWWWW` | `RSA.c:13159` |
| 112 | `0x0070` | `CONFIG_TEXT_STYLE` | `WWWWWW` | `RSA.c:13167` |
| 113 | `0x0071` | `CONFIG_SCENE_FLAGS` | `WWWWWW` | `RSA.c:13175` |
| 114 | `0x0072` | `CONFIG_TEXT_EFFECTS` | `WWWWWW` | `RSA.c:13183` |
| 115 | `0x0073` | `CONFIG_MENU_BEHAVIOR` | `WWWWWW` | `RSA.c:13191` |
| 116 | `0x0074` | `CONFIG_INPUT_BEHAVIOR` | `WWWWWW` | `RSA.c:13199` |
| 117 | `0x0075` | `CONFIG_MESSAGE_FLAGS` | `WWWWWW` | `RSA.c:13207` |
| 118 | `0x0076` | `CONFIG_WINDOW_LAYOUT` | `WWWWWW` | `RSA.c:13215` |
| 119 | `0x0077` | `CONFIG_SCREEN_LAYOUT` | `WWWWWWWW` | `RSA.c:13223` |
| 121 | `0x0079` | `CONFIG_UI_RESOURCES` | `SSWWWWWWW` | `RSA.c:13233` |
| 122 | `0x007A` | `CONFIG_GEOMETRY` | `WWWWWWWWWWW` | `RSA.c:13244` |
| 123 | `0x007B` | `CONFIG_MENU_LAYOUT` | `WWWWWWWW` | `RSA.c:13257` |
| 124 | `0x007C` | `CONFIG_BUTTON_LAYOUT_A` | `WWWWWW` | `RSA.c:13267` |
| 125 | `0x007D` | `CONFIG_BUTTON_LAYOUT_B` | `WWWWWW` | `RSA.c:13279` |
| 126 | `0x007E` | `CONFIG_BUTTON_LAYOUT_C` | `WWWWWW` | `RSA.c:13291` |
| 128 | `0x0080` | `DEFINE_AUDIO_RESOURCE` | `WWWD` | `RSA.c:13305` |
| 129 | `0x0081` | `SET_STARTUP_OPTION` | `W` | `RSA.c:13312` |
| 130 | `0x0082` | `SET_PLAYBACK_MODE` | `W` | `RSA.c:13315` |
| 131 | `0x0083` | `ENABLE_AUTO_CONTROL` | `W` | `RSA.c:13324` |
| 132 | `0x0084` | `SET_AUDIO_MODE` | `W` | `RSA.c:13328` |
| 133 | `0x0085` | `OPEN_SETTINGS_PANEL` | `-` | `RSA.c:13341` |
| 134 | `0x0086` | `NOP_ALT2` | `-` | `RSA.c:11971` |
| 135 | `0x0087` | `RET` | `-` | `RSA.c:13359` |
| 136 | `0x0088` | `ADD_VARIABLE` | `WW` | `RSA.c:13421` |
| 137 | `0x0089` | `SUB_VARIABLE_FLOOR_ZERO` | `WW` | `RSA.c:13432` |
| 138 | `0x008A` | `NOP_ALT3` | `-` | `RSA.c:11972` |
| 139 | `0x008B` | `DIV_VARIABLE` | `WW` | `RSA.c:13446` |
| 140 | `0x008C` | `MUL_VARIABLE` | `WW` | `RSA.c:13457` |
| 141 | `0x008D` | `MOD_VARIABLE` | `WW` | `RSA.c:13468` |
| 142 | `0x008E` | `SET_VARIABLE` | `WW` | `RSA.c:13479` |
| 143 | `0x008F` | `TEST_RANDOM_THRESHOLD` | `WW` | `RSA.c:13487` |
| 144 | `0x0090` | `SELECT_WEIGHTED_INDEX` | `WWWW` | `RSA.c:13492` |
| 145 | `0x0091` | `SELECT_RANGE_INDEX` | `WWWW` | `RSA.c:13521` |
| 146 | `0x0092` | `SWITCH` | `J` | `RSA.c:13573` |
| 147 | `0x0093` | `SWITCH_ALT` | `J` | `RSA.c:13574` |
| 148 | `0x0094` | `PLAY_SYSTEM_VOICE` | `WWW` | `RSA.c:13600` |
| 149 | `0x0095` | `TIMER` | `WWW` | `RSA.c:13665` |
| 150 | `0x0096` | `PLAY_RANDOM_VOICE` | `W` | `RSA.c:13691` |
| 152 | `0x0098` | `WAIT_VOICE_RESULT` | `WW` | `RSA.c:13761` |
| 153 | `0x0099` | `SET_VOICE_WAIT_MODE` | `W` | `RSA.c:13812` |
| 154 | `0x009A` | `CONTROL_CURSOR` | `W` | `RSA.c:13825` |
| 155 | `0x009B` | `TIMED_INPUT_RESULT` | `WWW` | `RSA.c:13851` |
| 156 | `0x009C` | `RESTORE_DRAW_STATE` | `-` | `RSA.c:13864` |
| 157 | `0x009D` | `UPDATE_SCENE_STATE` | `W` | `RSA.c:13867` |
| 158 | `0x009E` | `SCREEN_EFFECT` | `WWW` | `RSA.c:13907` |
| 159 | `0x009F` | `COPY_RECTANGLE` | `WWWWWWW` | `RSA.c:13913` |
| 160 | `0x00A0` | `TRANSITION_TO_WHITE` | `WWWWWWW` | `RSA.c:13924` |
| 161 | `0x00A1` | `CLEAR_TO_BLACK` | `-` | `RSA.c:13948` |
| 162 | `0x00A2` | `DRAW_BASE_REGION` | `WWWW` | `RSA.c:13952` |
| 163 | `0x00A3` | `READ_RESOURCE_PARAMETERS` | `SWWWW` | `RSA.c:13960` |
| 164 | `0x00A4` | `DRAW_EFFECT_RESULT` | `WWWWWW` | `RSA.c:13967` |
| 167 | `0x00A7` | `LOAD_SCRIPT` | `S` | `RSA.c:13979` |
| 168 | `0x00A8` | `REPLACE_BACKGROUND` | `SW` | `RSA.c:13985` |
| 169 | `0x00A9` | `REPLACE_LAYER_PAIR` | `SSW` | `RSA.c:14005` |
| 170 | `0x00AA` | `APPLY_SCENE_EFFECT` | `W` | `RSA.c:14038` |
| 171 | `0x00AB` | `LOAD_BACKGROUND` | `S` | `RSA.c:14084` |
| 172 | `0x00AC` | `SHOW_BACKGROUND_EFFECT` | `SW` | `RSA.c:14102` |
| 173 | `0x00AD` | `SHOW_LAYER_PAIR_EFFECT` | `SSW` | `RSA.c:14198` |
| 174 | `0x00AE` | `LOAD_FOREGROUND` | `S` | `RSA.c:14328` |
| 175 | `0x00AF` | `LOAD_LAYER_PAIR` | `SS` | `RSA.c:14347` |
| 176 | `0x00B0` | `REPLACE_FOREGROUND` | `SW` | `RSA.c:14374` |
| 177 | `0x00B1` | `REPLACE_FOREGROUND_PAIR` | `SSW` | `RSA.c:14390` |
| 178 | `0x00B2` | `WAIT_CHOICE_RESULT` | `W` | `RSA.c:14416` |
| 179 | `0x00B3` | `UPDATE_BACKGROUND_REGION` | `SW` | `RSA.c:14542` |
| 180 | `0x00B4` | `UPDATE_LAYER_PAIR_REGION` | `SSW` | `RSA.c:14563` |
| 181 | `0x00B5` | `APPLY_WHITE_EFFECT` | `W` | `RSA.c:14585` |
| 182 | `0x00B6` | `RESOURCE_METADATA` | `SSS` | `RSA.asm:9007 + RSAN.SD` |
| 183 | `0x00B7` | `HALT` | `-` | `RSA.asm:9007 + RSAN.SD` |
