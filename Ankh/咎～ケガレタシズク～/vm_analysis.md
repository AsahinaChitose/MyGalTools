# Ankh SNR VM 分析

## 范围与证据

本分析适用于本工程的 `toga.exe`，以及从本作 `snr.dat` 提取的 109 个成员。静态证据来自 IDA 导出的 `exe/toga.c`、`exe/toga.asm`；可重复的样本证据来自对 `snr_unpack/` 下全部脚本的线性解码。引擎名称为 **Ankh**。`toga.exe`、`.format toga-snr-v1` 和 `.toga_asm_meta.json` 属于既有文件名或格式标识，为兼容性保留，不因引擎名称更正而改名。

- `0x414B40` 从 DAT 成员读取 8 字节的 `snr\0` / 解压后大小头部，再调用 `0x40E220` 执行 LZSS 解压。`snr_unpack/` 中的脚本已是解压后的字节码，VM 工具不处理 DAT 封包层。
- `0x414EC0` 读取小端 32 位命令编号，分发编号 0 至 43 并调用相应处理器。编号 13 没有处理器，会进入不前进的默认分支。
- `0x414E20` 对脚本流执行有界读取。数值参数是小端 u32。带长度的文本/资源字段由 u32 字节长度及其后恰好该长度的字节构成，流中不带终止符。
- `0x414E70` 按字节数推进脚本游标。跳转和调用处理器会将游标重置到脚本起始位置，再前进到操作数给出的绝对字节偏移。
- 脚本流没有文件头或对齐填充。命令边界由各命令处理器读取的字段决定。文本内嵌于命令，不在独立字符串池中。
- 成员加载路径中未发现额外加密。文本默认按 CP932 显示。汇编源文件本身是 UTF-8；汇编器编辑文本时使用 `.encoding` 声明，除非通过 `--encoding` 覆盖。

该 VM 更接近事件/记录解释器，而不是常规通用寄存器 VM。它维护引擎变量和返回偏移栈。下表助记符是根据处理器行为定义的描述性名称，并非厂商公布的正式名称。对语义尚未完全命名的绘制命令，工具仍原样保留其数值字段。

## 编码与布局

- 命令编号：`u32le`，占 4 字节。
- 整数和表计数：`u32le`，按无符号位模式保留。
- 文本/资源：`u32` 字节长度，后接指定长度的字节；没有对齐或 NUL 终止符。
- 控制流目标：相对于解码后脚本首字节的绝对字节偏移。工具要求目标落在命令边界或 EOF，并以标签表示。
- `MESSAGE`、`MESSAGE_NO_ID`、`MESSAGE_NAMED` 在命令中携带带长度的文本，显示处理器直接消费这些字节。
- `CHOICE` 保存选项数、选择变量，随后重复保存带长度的选项文本和 flag 编号。
- `DRAW_DIALOG` 先保存四个长度，再保存对应的四段字节串。处理器使用四个 10 字节局部槽位，工具拒绝超过 10 字节的槽位。
- 不插入隐式对齐。未知编号和截断字段均视为错误。

反汇编器输出 UTF-8 语义汇编。控制字节、无法解码或无法往返的字节及私用区字符以 `{{XX}}` 或 `{{XX:YY}}` 表示。每段文本的源哈希保存在 `.toga_asm_meta.json`，不再重复写在汇编行中。汇编器将全部可读文本（包括未编辑的人名、标点和对话）按 `--encoding` 指定的编码写入。省略参数时使用 `.encoding`，显式的字节占位符仍按原始字节写回。目标编码无法表示某个字符时，工具报出源文件、行号和字符。旧版汇编中的行内 `@src=sha256:...` 标注仍兼容。

`NAME <message_id>, "<speaker>"` 是 opcode 1 / `wait_mode=2` 的反汇编伪助记符，汇编时还原为同一条二进制指令。原有识别保留：前一条命令是 `SET_NAME`，或文本恰好是独立的 `N1`。当前样本中，3,454 条 `SET_NAME` 后均紧跟 opcode 1 / mode 2 消息；独立 `N1` 共 1,303 条，均为 mode 2。

没有 `SET_NAME` 的时候，不靠 mode 2 或文本长度猜人名。只有文本恰好是本作已核对的 7 种称呼之一，且下一条命令是编号连续、直接以 `「` 或 `『` 开头的 `MESSAGE`，两者之间没有跳转标签，才补标 `NAME`。109 个脚本中，12 个文件共补标 77 处：`女子生徒` 26、`男` 24、`？？？` 11、`男子生徒` 8、`寮母` 4、`女の声` 3、`生徒` 1。带全角缩进的引号正文等不触发该规则。此词表只针对当前游戏版本，不是 Ankh 的通用人名表。

`asm_json.py` 将对话、人名和选项提取为翻译 JSON。它去掉每个文本字段开头的一个全角空格 `　`，并在注入时按源记录恢复；只有连续编号的 `MESSAGE` 尚未闭合的 `「」` / `『』` 对话片段，且后续片段以全角空格开头时，才合并为带 `\n` 的 JSON 消息。`NAME` 会关联到紧随其后的引号对话。`CHOICE` 的每个选项单独成为一条 JSON 记录，注入时仍写回原有的一条 `CHOICE` 命令。每个 JSON 均配有 `.json.meta.json`，记录源哈希、指令行和操作数位置；源文件或换行记录数不匹配时注入器会报错。

opcode 41（`DRAW_INLINE_RESOURCE`）也用于绘制提示框以外的剧情文字。处理器 `0x419670` 读入带长度的数据和坐标，再交由 `0x401B50` 绘制。全库 7 条：只提取 `s_001` 开场的 2 条作为 `kind: "draw-inline"`，分别编辑，不与对白合并；`start` 的 5 条测试内容不纳入此规则。注入只替换第一个文本参数，不调整坐标和其余参数。若译文长度变化，实际画面是否仍对齐需要进游戏确认。

## Opcode 表

所有命令编号均为 4 字节小端整数。字段名及条件/重复布局由 `opcodelist.py` 定义；此处列出处理器和命令编号之后的字段。`TEXT(n)` 表示 u32 字节长度后接 n 字节文本。`TARGET` 是绝对脚本偏移。

| ID | 助记符 | 处理器 | 命令编号后的字段 |
|---:|---|---|---|
| 0 | `MESSAGE_NO_ID` | `0x419130` | `TEXT(text), u32(wait_mode)` |
| 1 | `MESSAGE` | `0x419130` | `u32(message_id), TEXT(text), u32(wait_mode)` |
| 2 | `JUMP` | `0x418B90` | `TARGET(destination)` |
| 3 | `CALL` | `0x418BF0` | `TARGET(destination)` |
| 4 | `RETURN` | `0x418CB0` | 无 |
| 5 | `VAR_SET` | `0x4199B0` | `u32(destination_var), u32(source_is_var), u32(source)` |
| 6 | `VAR_ADD` | `0x419A40` | 同 5；算术变体 0 |
| 7 | `VAR_SUB` | `0x419A40` | 同 5；算术变体 1 |
| 8 | `VAR_MUL` | `0x419A40` | 同 5；算术变体 2 |
| 9 | `VAR_DIV` | `0x419A40` | 同 5；算术变体 3 |
| 10 | `IF_VAR` | `0x418D50` | `u32(left_var), u32(comparison), u32(right_is_var), u32(right), TARGET(destination)` |
| 11 | `DRAW_BACKGROUND` | `0x418010` | `TEXT(resource), u32(mode), u32(arg0), u32(arg1)`；mode=8 时追加 `TEXT(alternate_resource)` |
| 12 | `SET_EVENT` | `0x4197F0` | `u32(event_id)` |
| 13 | 无效/保留 | 无 | 分发器中没有处理器；不接受 |
| 14 | `PLAY_VOICE` | `0x419830` | `TEXT(resource), u32(wait_after_playback)` |
| 15 | `SET_NAME` | `0x4198E0` | `u32(name_id), TEXT(name)` |
| 16 | `CHOICE` | `0x4194B0` | `u32(choice_count), u32(selection_var)`，重复的 `TEXT(choice_text), u32(flag_id)`；数量不大于 4 |
| 17 | `DRAW_TEXT` | `0x418280` | `TEXT(text), u32(arg0..arg3)` |
| 18 | `LOAD_SNR` | `0x418F20` | `TEXT(script_name)` |
| 19 | `SLEEP` | `0x417B40` | `u32(milliseconds)` |
| 20 | `SET_MOVIE_NAME` | `0x417B90` | `TEXT(movie_name)` |
| 21 | `SWITCH_VAR` | `0x418F80` | `u32(variable), u32(target_count)`，重复的 `TARGET(destination)`；数量不大于 256 |
| 22 | `SET_FLAG` | `0x417BE0` | `u32(flag_id)` |
| 23 | `IF_FLAG` | `0x419070` | `u32(flag_id), TARGET(destination)` |
| 24 | `SET_TEXT_MODE` | `0x417C20` | `u32(mode)` |
| 25 | `DRAW_TEXT_PANEL` | `0x418490` | 3 个 u32 值 |
| 26 | `RESET_TEXT_SLOT` | `0x418550` | `u32(slot)` |
| 27 | `DRAW_DIALOG` | `0x4185A0` | 4 个 u32 长度、对应的 4 段字节串、`u32(mode), u32(arg0..arg4)`；mode=8 时追加 `TEXT(alternate_text)` |
| 28 | `SET_PANEL_POSITION` | `0x4183C0` | 4 个 u32 值 |
| 29 | `DRAW_TEXT_ALT` | `0x418280` | `TEXT(text), u32(arg0..arg1)` |
| 30 | `DRAW_EFFECT` | `0x418780` | 2 个 u32 值 |
| 31 | `SET_VIEW_RANGE` | `0x418810` | 6 个 u32 值 |
| 32 | `MESSAGE_NAMED` | `0x419130` | `u32(message_id), TEXT(text), u32(wait_mode), u32(name_id), TEXT(name)` |
| 33 | `START_MOVIE` | `0x417DB0` | `TEXT(movie_name)` |
| 34 | `INVALIDATE_DISPLAY` | `0x4188B0` | `u32(region)` |
| 35 | `SET_SCREEN_COLOR` | `0x4188F0` | 3 个 u32 值 |
| 36 | `CLEAR_TEXT` | `0x417CB0` | 无 |
| 37 | `WAIT_INPUT` | `0x417CD0` | 无 |
| 38 | `CLEAR_DISPLAY` | `0x419660` | 无 |
| 39 | `DRAW_TEXT_CONFIG` | `0x418950` | 7 个 u32 值 |
| 40 | `DRAW_TEXT_STYLE` | `0x418A50` | 3 个 u32 值 |
| 41 | `DRAW_INLINE_RESOURCE` | `0x419670` | `TEXT(resource_data), u32(duration), u32(x), u32(y)` |
| 42 | `SET_DRAW_COLOR` | `0x418B00` | 5 个 u32 值 |
| 43 | `RESET_DISPLAY` | `0x417D50` | 无 |

`IF_VAR` 的比较码根据 `0x418D50` 的处理器行为为：0 `<`、1 `<=`、2 `==`、3 `>`、4 `>=`。`right_is_var` 非零时，`right` 表示变量编号；为零时表示立即数。opcode 5 使用相同的来源选择规则。opcode 6 至 9 分别执行加、减、乘、除。

## 验证

初始结构扫描解码了 `snr_unpack/` 中的全部 109 个脚本：共 28,057 条命令；未知/保留编号、截断字段和不落在命令边界上的控制流目标均为 0。实现的完整 opcode 表用于该次扫描；即使当前样本未出现，表中仍按 IDA 处理器定义其他编号。

补标版 `snr_unpack_asm_names/` 通过提取和空注入验证：109 份汇编逐字节一致。以 `--encoding cp932` 原样汇编，全部 109 个成员与 `snr_unpack/` 的源文件逐字节一致；`dat_tool.py` 回包后的 `snr.dat` 也与原包逐字节一致。另对 `s_001` 的两条绘制文本做不同长度的中文试改，确认两条修改后的绘制文本编码正确，跳转仍指向同一指令。静态格式往返验证不等于游戏运行时验证，也不证明所有绘制参数的显示语义。

## 用法

```powershell
python disassembler.py snr_unpack -o snr_unpack_asm_names --encoding cp932
python asm_json.py extract --src snr_unpack_asm_names -o snr_json_draw --encoding cp932
python asm_json.py inject --src snr_unpack_asm_names --json snr_json_draw -o snr_unpack_asm_draw_cn --encoding gbk
python assembler.py snr_unpack_asm_draw_cn -o snr_rebuild_draw_cn --encoding gbk
python dat_tool.py pack snr_rebuild_draw_cn snr_draw_cn.dat
```

单文件时，将目录参数替换为单个脚本或 `.asm.txt` / `.json` 文件。提取目录和注入目录按相对路径对应；JSON 和 `.json.meta.json` 都使用 UTF-8。注入器拒绝覆盖已有输出，要求 `pre_jp` 保持不变，并要求分段文本的 `\n` 数量与源 `MESSAGE` 数一致。保留 `.toga_asm_meta.json` 才能在汇编时复用未编辑文本的原始 CP932 字节；DAT 回包目录须同时保留 `.dat_tool.json`。汇编源文件本身始终是 UTF-8，`--encoding gbk` 只影响有修改的文本字段。

前两条命令用于生成源汇编和 JSON；工程里已有产物，不用重复生成。补提版 `snr_json_draw/` 与现存 `snr_json/` 都配套使用 `snr_unpack_asm_names/`。每份 JSON 必须与同目录的 `.json.meta.json` 成对使用，不要混用两个目录里的元数据。旧汇编 `snr_unpack_asm/` 不用于这两套 JSON。

## EXE 补丁分析

本节针对 `exe/toga_nodvd.exe`。补丁点已与 IDA 导出的 `exe/toga.c`、`exe/toga.asm` 核对；输入文件 SHA-256 为 `91F09760A92381C052B344F2B227F228BC072F9B67E6E8FE69F2E604817A25A0`。

- `GBK.py` 将 `0x40C5E5` 的 `CreateFontA` 字符集参数从 `0x80` 改为 `GB2312_CHARSET (0x86)`，并将字体枚举回调 `0x41159B` 的 `lfCharSet` 筛选值同步改为 `0x86`。中文默认字体、换行禁则标点、人名默认值及人名输入提示改为 GBK 字节；资源 ID 103（字体设置）和 121（姓名输入）的 UTF-16 控件文字改为中文。对话框资源按模板结构重建并同步调整资源数据长度，未移动其他 PE 节或资源。
- 人名输入函数 `0x411A80` 使用 `GetWindowTextA`，限制每栏 1 至 8 字节，并按每两个字节一组接受高位字节；在 CP936 下可输入每栏最多四个双字节汉字。CRT 的 `_setmbcp(-3)` 依赖 `GetACP()`，且程序使用 Windows A 系列 API，因此必须在 ANSI 代码页为 936 的 Windows 环境运行。补丁不声称支持 ACP 65001 或其他代码页。
- `patch_voice.py` 只修改 `0x41396B` 的短条件跳转：原 `JE` 指向 `0x413993` 的 `sub_41B0C0` 停播调用，补丁后指向 `0x41399E` 的消息回调返回路径。鼠标左键松开推进对白时因此不再停语音；回车确认分支、滚轮处理、退出清理和自动播放逻辑不变。新语音由 `sub_41B210` 播放，仍先调用 `sub_41B0C0`，因此只在下一段语音开始时停止当前语音。
- 默认生成 `exe/toga_nodvd_gbk.exe` 与 `exe/toga_nodvd_voice.exe`。组合版用法：

```powershell
python GBK.py
python patch_voice.py exe\toga_nodvd_gbk.exe
```

补丁脚本默认拒绝覆盖现有输出；需要重建时显式加 `--force`。静态验收确认四个 EXE 大小均保持 200,704 字节，语音补丁仅更改一个相对位移字节；GBK 补丁的差异只落在所列指令、字符串、两个对话框资源及 PE 校验和。组合版 SHA-256 为 `EA6C92D0661816F3C4E1793D37178211DDDFCD84001D6355F1496DCB35E16197`。尚未做游戏运行时验证。
