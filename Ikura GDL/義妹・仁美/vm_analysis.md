# HITOMI 的 Ikura GDL VM

分析对象为 `exe/HITOMI.exe`，SHA-256 为 `D3CB375FB0A53BB7C21B966D997FC448B7B969E2DF13312E551A386471DFC6D9`。以同目录的 IDA 伪 C、汇编和 `ISF_unpack` 中的 152 份成员为证据。通用 Ikura 脚本只用于对照。本作未匹配工作区历史案例中的任何二进制布局。已核对外层编码、内嵌字符串、入口槽、条件跳转、选择菜单与消息控制流。GBK 字形与实际运行待单独验收。

## 文件和执行模型

| 位置 | 类型 | 含义 | 证据 |
| --- | --- | --- | --- |
| `0x00` | 6 字节 | ASCII 签名 `HITOMI` | 装载器和全部成员 |
| `0x06` | u32le | 从 `0x06` 到代码起点的大小 H | 装载器及入口实验 |
| `0x0A` | 4 字节 | 模式和参数，当前成员均为 `95 97 00 00` | 全部成员 |
| `0x0E` 至 `6+H` | u32le 数组 | 按槽排列的代码相对偏移，可指向同一位置 | `4488B0` 和全部成员 |
| `6+H` 起 | 变长记录 | 指令流 | `447BF0` 和全部成员 |

VM 使用独立变量区和标志区、指令指针以及调用返回栈。操作通过显式操作数和变量索引完成。`05/08` 保存返回位置，`06` 从返回栈恢复代码相对位置。`01/02/03` 操作脚本上下文，外部脚本按名称查找。两层返回均无静态目的地址。原档的 35,283 条外部跳转或调用都能按名称匹配档内成员。汇编时保留名称，允许单独构建成员，也允许其调用目标由外部封包提供。同一文件内的操作数 `j` 为 `u16le` 入口槽。`.entry` 保留槽位顺序与重复目标，指令引用 `loc_XXXXXXXX@N` 同时指定目的标签和槽。重建时先计算代码位置，再生成入口表。偏移落在指令内部、尾部数据或文件外均报错。

一条记录先取 `u8 opcode`，再取包含头部在内的长度。长度字节小于 128 时头部两字节。否则头部三字节，总长为 `((首长度字节 & 127) << 8) | 次长度字节`。短头总长上限为 127，长头上限为 32767。普通记录保留原头宽度，变长时自动扩展。消息处理器按总长是否超过 127 推导头宽，要求头宽与总长匹配。`25` 的处理器固定按 `总长 - 4` 拷贝正文，按短头生成。无对齐要求。`START.ISF` 在代码偏移 `0x29C` 后有 6 个零字节，输出 `.tail_zero 6`。样本中的 `00 02` 是有效停机指令，`GLOAD.ISF` 的 `FE 02` 是默认分支跳过的空记录。其他默认分支值和带载荷的 `FE` 暂无对应样本契约，工具会提供偏移和原始记录诊断。

## 操作数和内嵌文字

`b/w/d` 是无符号 `u8/u16le/u32le`，`v` 是变量槽 `u16le`，`j` 是入口槽 `u16le`，`x` 是 `u32le` 表达式。`452D30` 对低 30 位有符号扩展，位 31 取变量，位 30 取随机数。ASM 使用 `17`、`v17`、`rand(17)`、`rand(v17)`。`s13/s28` 是达到长度上限或读到 NUL 时停止的内嵌资源名，上限宽度内保留终止。`t` 是 `447600` 家族读取的 NUL 或 CR 结尾普通字符串，默认上限 255 字节。`t64` 的上限为 64 字节。`q` 指 `4476D0` 读取的短串，`z` 指 EF 子码 8 中按 NUL 或 CR 定界的内嵌串。资源标识符使用源编码，显示文字使用选定的目标编码。命令静态名称依据处理效果命名，尚未确认的引擎功能按所在子系统或模式编号命名。

- `25` 先读消息窗和名字槽，后面的完整记录内容为名字。`44A800 → 45B750 → 40FF60` 将它复制到清零后的暂存区。`27` 按窗口和表达式查名字槽，保留共享引用。`CHOICES.ISF` 的菜单逻辑装载 `sel_s.GGD`，由 `84/85/88` 配置及处理菜单槽，再用 `08` 按选择结果调用入口。该脚本的菜单槽没有内嵌文字。
- `2B/2C` 先读窗口字节。`44AAD0/44AB20` 传给渲染器的长度是 `总长 - 4 - (总长 > 127)`，因此末尾一字节在渲染流之外。样本尾字节为零。`40B200` 在控制状态解码控制码。`FF` 切换到显示文本状态，`00` 在文本态退出。在控制态，`03` 清除，`06` 换行，`08/11` 各读一个 u32，`13` 读最多 28 字节的语音名。其余控制码和操作数在 `MESSAGE_CONTROLS` 中。
- 显示状态下，高于 `0x80` 的值与下一字节组成宽字符。小值查 `49C154` 的映射。`7F` 是直写前缀，`5C` 可引用字典中的「イ」，并有后接文本终止符时连同消耗终止符的特例。样本正文只用普通双字节和不带前缀的字典字形。`TEXT` 在引用处显示可编辑内容。该构建的 CP932 消息用字典作为默认拼写。少数同字异形以 `form=` 保留，例如明确宽字、重复字典槽。源字符变动后重新验证标记，有变化的字形使用新编码。不能显示的字节用 `{{XX}}` 或 `{{XX:XX}}`。
- `D7` 为表达式、`u16` 字符串数量和 `4476D0` 短串列表，读取到 NUL 或 CR，最多读取 13 字节内容后再跳过一字节。`40C180` 可引用已注册短串。`B3/E1/F7` 等未出现的普通字符串仍按静态读取器处理。
- GBK 模式直接编码消息正文的宽字符，名字和内嵌短串也重新编码。全量样本有两种字符不在 GBK 中，`・` → `·`，`♪` → `☆`。第二项是装饰符号替代。其他无法编码的字符报错并显示指令位置。ASCII 资源名独立处理。GBK 输出保留原控制流，仍需本作的 GBK 字形和运行环境配合。

## 变体规则

| 指令或布局 | 识别条件和载荷 |
| --- | --- |
| `dispatch` | 表达式、u8 个数、该数量的入口槽 |
| `skins` | 2 个 u8 加 1、3、4、5 或 6 个 s28，按记录剩余长度读可选皮肤 |
| `arithmetic` | 变量槽，重复算术子码 0–4 和表达式，停止值大于 4。样本停止值 5。保留实际停止值 |
| `conditions` | 比较项 `x + u8 比较码 + x`。比较码 0–5 对应等于、小于、小于等于、大于、大于等于、不等于。动作 0 读跳转槽，1 读变量和表达式，255 结束，其他值续读条件。样本的动作 0/1 均后接一个 `FF` 尾值 |
| `blit` | 模式字节加 8 个表达式。15–18 加 2 个表达式，20–21 加 1 个表达式，28–29 加 4 个表达式。其他未列模式走默认复制分支 |
| `layer` | 模式字节和基本表达式组。15–18 与 28–29 附加不同数量参数，详见子表 |
| `system_test/system_get/system_set` | 由一字节子码分派。已识别子码和语义见 Python 子表 |
| `menu_mode` | 处理器读一字节模式。两个样本记录都另带三个零字节 |
| `menu_run` | 两个 u16 变量、一个 u8 和位标志。位 1 选处理路径，位 0 / 位 2 是独立设置，保留其他标志位 |
| `system` | EF 子码 1–8 分派。分支 3 再读 0–3 面板子码。分支 8 按 u16 个数读取内嵌字符串 |
| `file_action` | F0 首字节选择装载对象 0–5，随后为 s13 |
| `data` | 长度来自指令边界的局部二进制载荷，保留其字节。此布局无本作样本用于核对 |

## 指令表

以下列出派发器全部 170 个显式分支和样本中的 `FE`。计数来自 301,232 条指令。无观测样本的行依据静态处理器，游戏内效果仍有待核对。

| Opcode | 助记符 | 格式 | 处理器 | 样本次数 |
| --- | --- | --- | --- | ---: |
| `00` | `HALT` | `header + 0 /  / fixed` | `0x447BF0` | 1 |
| `01` | `JUMP_SCRIPT` | `header + encoded operands / s13 / fixed` | `0x449710` | 11 |
| `02` | `CALL_SCRIPT` | `header + encoded operands / s13 / fixed` | `0x449750` | 35272 |
| `03` | `RETURN_SCRIPT` | `header + 0 /  / fixed` | `0x4497D0` | 158 |
| `04` | `JUMP` | `header + 2 / j / fixed` | `0x449870` | 934 |
| `05` | `CALL` | `header + 2 / j / fixed` | `0x449890` | 464 |
| `06` | `RETURN` | `header + 0 /  / fixed` | `0x449910` | 755 |
| `07` | `SWITCH_JUMP` | `header + encoded operands / x / dispatch` | `0x449970` | 301 |
| `08` | `SWITCH_CALL` | `header + encoded operands / x / dispatch` | `0x4499D0` | 83 |
| `09` | `SET_SCRIPT_BASE` | `header + encoded operands / s13 / fixed` | `0x449A80` | 0 |
| `0A` | `SCRIPT_STRING_ACTION` | `header + encoded operands / t / fixed` | `0x449B20` | 0 |
| `10` | `CREATE_IMAGE_WINDOW` | `header + 18 / b x x x x b / fixed` | `0x449BB0` | 0 |
| `11` | `LOAD_WINDOW_IMAGE` | `header + encoded operands / b b s13 / fixed` | `0x449D80` | 0 |
| `12` | `LOAD_WINDOW_REGION` | `header + encoded operands / b b s13 / fixed` | `0x449E20` | 0 |
| `13` | `CONFIGURE_MESSAGE_STYLE` | `header + 20 / b b b b b b b b b b b b b b b b b b b b / fixed` | `0x449EB0` | 0 |
| `14` | `PLACE_WINDOW_REGION` | `header + 14 / b b x x x / fixed` | `0x44A070` | 0 |
| `15` | `DEFINE_MESSAGE_REGION` | `header + encoded operands / b b x x x x t / fixed` | `0x44A0F0` | 0 |
| `16` | `SET_MESSAGE_WAIT` | `header + 6 / b x b / fixed` | `0x44A1D0` | 0 |
| `17` | `RESET_MESSAGE_WINDOW` | `header + 1 / b / fixed` | `0x44A230` | 0 |
| `18` | `CONFIGURE_MESSAGE_KEY` | `header + 4 / b w b / fixed` | `0x44A270` | 0 |
| `1A` | `ENABLE_MESSAGE_SYSTEM` | `header + 0 /  / fixed` | `0x44A2E0` | 0 |
| `1B` | `DISABLE_MESSAGE_SYSTEM` | `header + 0 /  / fixed` | `0x44A310` | 0 |
| `1C` | `CONFIGURE_TEXT_REGION` | `header + encoded operands / b x x x x t x x x x x x / fixed` | `0x44A340` | 0 |
| `20` | `CREATE_MESSAGE_WINDOW` | `header + 18 / b x x x x b / fixed` | `0x44A480` | 1 |
| `21` | `LOAD_MESSAGE_SKIN` | `header + encoded operands / b b / skins` | `0x44A4F0` | 1 |
| `22` | `SET_WINDOW_RESOURCE` | `header + encoded operands / b s13 / fixed` | `0x44A6A0` | 0 |
| `23` | `POSITION_MESSAGE_WINDOW` | `header + 10 / b x x b / fixed` | `0x44A700` | 0 |
| `24` | `SET_MESSAGE_WINDOW_MODE` | `header + 2 / b b / fixed` | `0x44A7A0` | 0 |
| `25` | `DEFINE_SPEAKER` | `header + encoded operands / b b / speaker` | `0x44A800` | 19 |
| `26` | `SET_MESSAGE_DELAY` | `header + 5 / b x / fixed` | `0x44A860` | 14501 |
| `27` | `SELECT_SPEAKER` | `header + 5 / b x / fixed` | `0x44A8D0` | 29145 |
| `28` | `SET_MESSAGE_ATTRIBUTE` | `header + 2 / b b / fixed` | `0x44A910` | 0 |
| `29` | `SHOW_MESSAGE_WINDOW` | `header + 1 / b / fixed` | `0x44A970` | 1 |
| `2A` | `HIDE_MESSAGE_WINDOW` | `header + 1 / b / fixed` | `0x44AA20` | 4 |
| `2B` | `MESSAGE` | `header + encoded operands / b / message` | `0x44AAD0` | 14925 |
| `2C` | `CONDITIONAL_MESSAGE` | `header + encoded operands / b / message` | `0x44AB20` | 0 |
| `2D` | `MESSAGE_LAYER_ENABLE` | `header + 4 / x / fixed` | `0x44AB90` | 0 |
| `2E` | `MESSAGE_LAYER_DISABLE` | `header + 4 / x / fixed` | `0x44ABC0` | 0 |
| `30` | `ALLOCATE_FLAGS` | `header + 2 / w / fixed` | `0x44AC00` | 0 |
| `31` | `SET_FLAG` | `header + 3 / w b / fixed` | `0x44AC50` | 434 |
| `32` | `SET_FLAG_RANGE` | `header + 5 / w w b / fixed` | `0x44AC90` | 73 |
| `33` | `JUMP_IF_FLAG_NONZERO` | `header + 4 / w j / fixed` | `0x44ACF0` | 14627 |
| `34` | `COPY_FLAG_RANGE` | `header + 6 / w w w / fixed` | `0x44AD50` | 8 |
| `35` | `SET_FLAG_TABLE` | `header + encoded operands / b / data` | `0x44ADA0` | 0 |
| `36` | `JUMP_ON_INPUT` | `header + 3 / b j / fixed` | `0x44ADF0` | 0 |
| `37` | `RUN_SYSTEM_EVENT` | `header + 8 / x x / fixed` | `0x44AE90` | 36 |
| `38` | `SAVE_FLAG_RANGE` | `header + 4 / w w / fixed` | `0x44B460` | 0 |
| `39` | `LOAD_FLAG_RANGE` | `header + 4 / w w / fixed` | `0x44B5E0` | 0 |
| `3A` | `JUMP_IF_SYSTEM_STATE` | `header + encoded operands /  / system_test` | `0x44B6B0` | 3 |
| `3B` | `JUMP_IF_FLAG_NOT_ONE` | `header + 4 / w j / fixed` | `0x44ACF0` | 0 |
| `3C` | `JUMP_ON_INPUT_MODE` | `header + 4 / b b j / fixed` | `0x44ADF0` | 0 |
| `40` | `ALLOCATE_VARIABLES` | `header + 2 / w / fixed` | `0x44B990` | 0 |
| `41` | `SET_VARIABLE` | `header + 6 / v x / fixed` | `0x44B9E0` | 78379 |
| `42` | `INCREMENT_VARIABLE` | `header + 2 / v / fixed` | `0x44BA20` | 4 |
| `43` | `DECREMENT_VARIABLE` | `header + 2 / v / fixed` | `0x44BA50` | 1 |
| `44` | `CALCULATE` | `header + encoded operands / v / arithmetic` | `0x44BA80` | 29295 |
| `45` | `ASSIGN_INDIRECT` | `header + 8 / v v x / fixed` | `0x44BB90` | 0 |
| `46` | `COPY_VARIABLE_RANGE` | `header + 6 / v v w / fixed` | `0x44BC30` | 0 |
| `47` | `IF` | `header + encoded operands /  / conditions` | `0x44BC80` | 29298 |
| `48` | `LOAD_SYSTEM_BLOCK` | `header + 4 / w w / fixed` | `0x44BD80` | 1 |
| `49` | `SAVE_STATE_RANGE` | `header + 13 / x x x b / fixed` | `0x44C120` | 337 |
| `4A` | `LOAD_STATE_RANGE` | `header + 13 / x x x b / fixed` | `0x44C180` | 8 |
| `4B` | `READ_SYSTEM_VALUE` | `header + encoded operands / v / system_get` | `0x44C2F0` | 0 |
| `4C` | `WRITE_SYSTEM_VALUE` | `header + encoded operands / v / system_set` | `0x44C440` | 1 |
| `50` | `CREATE_SURFACE` | `header + 12 / x x x / fixed` | `0x44C490` | 9 |
| `51` | `SET_SURFACE_ORIGIN` | `header + 12 / x x x / fixed` | `0x44C4F0` | 1 |
| `52` | `RESET_SURFACES` | `header + 0 /  / fixed` | `0x44C530` | 0 |
| `53` | `SET_SURFACE_COLOR` | `header + 7 / x b b b / fixed` | `0x44C560` | 3 |
| `54` | `FADE_SURFACE_TO_COLOR` | `header + 11 / x x b b b / fixed` | `0x44C5E0` | 0 |
| `55` | `TRANSITION_TO_COLOR` | `header + 8 / x b b b b / fixed` | `0x44C690` | 156 |
| `56` | `LOAD_SURFACE_IMAGE` | `header + encoded operands / x s28 / fixed` | `0x44C810` | 788 |
| `57` | `BLIT` | `header + encoded operands /  / blit` | `0x44C8E0` | 4180 |
| `58` | `DEFINE_SPRITE_REGION` | `header + 24 / x b b b b x x x x / fixed` | `0x44CBB0` | 0 |
| `59` | `RESET_SPRITE_REGION` | `header + 4 / x / fixed` | `0x44CC70` | 0 |
| `5A` | `SET_SPRITE_REGION_MODE` | `header + 1 / b / fixed` | `0x44CCA0` | 0 |
| `5B` | `WRITE_SPRITE_DATA` | `header + encoded operands / x x x / data` | `0x44CCF0` | 0 |
| `5C` | `SET_LAYER_PARAMETER` | `header + 9 / b x x / fixed` | `0x44CD50` | 0 |
| `5D` | `UPDATE_LAYER_PARAMETER` | `header + 9 / b x x / fixed` | `0x44CDC0` | 0 |
| `5E` | `DRAW_LAYER` | `header + encoded operands /  / layer` | `0x44CE10` | 0 |
| `5F` | `DRAW_LAYER_WAIT` | `header + encoded operands /  / layer` | `0x44D0A0` | 0 |
| `60` | `LOAD_EFFECT` | `header + encoded operands / x x x x x s13 / fixed` | `0x44D2F0` | 58 |
| `61` | `STRETCH_SURFACE` | `header + 41 / b x x x x x x x x x x / fixed` | `0x44D3A0` | 0 |
| `62` | `FILTER_SURFACE` | `header + 57 / b x x x x x x x x x x x x x x / fixed` | `0x44D4D0` | 0 |
| `63` | `SET_EFFECT_PARAMETER` | `header + 8 / w b b x / fixed` | `0x44D600` | 10 |
| `64` | `SET_LAYER_MODE` | `header + 5 / x b / fixed` | `0x44D660` | 0 |
| `65` | `LOAD_ALPHA_RESOURCE` | `header + encoded operands / x s13 / fixed` | `0x44D6B0` | 0 |
| `66` | `SET_LAYER_RECT` | `header + 16 / x x x x / fixed` | `0x44D700` | 0 |
| `67` | `CONFIGURE_ANIMATION` | `header + 8 / x w w / fixed` | `0x44D760` | 0 |
| `68` | `RESET_ANIMATION` | `header + 0 /  / fixed` | `0x44D7B0` | 0 |
| `69` | `CLEAR_EFFECT` | `header + 4 / x / fixed` | `0x44D7E0` | 0 |
| `6F` | `SET_IMAGE_GEOMETRY` | `header + 16 / x x x x / fixed` | `0x44D810` | 0 |
| `70` | `PLAY_MUSIC` | `header + encoded operands / s13 b / fixed` | `0x44D880` | 38 |
| `71` | `FADE_MUSIC` | `header + 5 / b x / fixed` | `0x44DC60` | 38 |
| `72` | `STOP_AUDIO_CHANNEL` | `header + 4 / x / fixed` | `0x44DE70` | 2 |
| `73` | `STOP_AUDIO` | `header + 0 /  / fixed` | `0x44DF00` | 43 |
| `74` | `LOAD_SOUND` | `header + encoded operands / s13 x / fixed` | `0x44DF60` | 282 |
| `75` | `PLAY_SOUND` | `header + 8 / x x / fixed` | `0x44E0A0` | 18 |
| `76` | `RELEASE_SOUND` | `header + 4 / x / fixed` | `0x44E220` | 13 |
| `77` | `SET_AUDIO_OUTPUT_MODE` | `header + 1 / b / fixed` | `0x44E290` | 0 |
| `78` | `PLAY_VOICE_FILE` | `header + encoded operands / s13 / fixed` | `0x44E3A0` | 0 |
| `79` | `RESET_AUDIO_CHANNEL` | `header + 4 / x / fixed` | `0x44E4F0` | 1 |
| `7A` | `AUDIO_COMMAND_NOP` | `header + 0 /  / fixed` | `0x44E550` | 1 |
| `7B` | `FADE_AUDIO_CHANNEL` | `header + 8 / x x / fixed` | `0x44E580` | 14622 |
| `7C` | `READ_AUDIO_STATE` | `header + 3 / b w / fixed` | `0x44E5F0` | 0 |
| `7D` | `READ_CHANNEL_STATE` | `header + 7 / x b w / fixed` | `0x44E710` | 0 |
| `7E` | `READ_AUDIO_DEVICE` | `header + 3 / b w / fixed` | `0x44E7E0` | 0 |
| `7F` | `AUDIO_OUTPUT_NOP` | `header + 0 /  / fixed` | `0x44E8A0` | 0 |
| `80` | `SET_MENU_LAYOUT` | `header + encoded operands / b s13 / fixed` | `0x44E8D0` | 1 |
| `81` | `SELECT_CURSOR` | `header + encoded operands / b / menu_mode` | `0x44E920` | 2 |
| `82` | `UPDATE_MENU_RECT` | `header + 16 / x x x x / fixed` | `0x44E950` | 0 |
| `83` | `SET_MENU_OFFSET` | `header + 8 / x x / fixed` | `0x44EA40` | 0 |
| `84` | `DEFINE_MENU_REGION` | `header + 23 / b x x x x b w b b b / fixed` | `0x44EAA0` | 46 |
| `85` | `RUN_MENU` | `header + encoded operands / v v b / menu_run` | `0x44EBB0` | 15 |
| `86` | `SHOW_MENU` | `header + 0 /  / fixed` | `0x44EC50` | 0 |
| `87` | `HIDE_MENU` | `header + 0 /  / fixed` | `0x44EC70` | 0 |
| `88` | `SET_MENU_STATES` | `header + 33 / b x x x x x x x x / fixed` | `0x44EC90` | 46 |
| `89` | `SELECT_MENU` | `header + 4 / x / fixed` | `0x44EDE0` | 2 |
| `8A` | `MOUNT_IMAGE_ARCHIVE` | `header + encoded operands / s28 x x / fixed` | `0x44EE10` | 3 |
| `8B` | `UNMOUNT_IMAGE_ARCHIVE` | `header + 0 /  / fixed` | `0x44EE80` | 3 |
| `8C` | `DRAW_ARCHIVE_REGION` | `header + 32 / x x x x x x x x / fixed` | `0x44EEA0` | 0 |
| `8D` | `UPDATE_UI_STATE` | `header + 5 / b x / fixed` | `0x44EF40` | 14463 |
| `8E` | `READ_UI_STATE` | `header + 4 / x / fixed` | `0x44EF50` | 0 |
| `90` | `SET_AUDIO_LEVELS` | `header + 8 / x x / fixed` | `0x44EF90` | 0 |
| `91` | `SWITCH_AUDIO_CHANNEL` | `header + 9 / x b x / fixed` | `0x44EFD0` | 0 |
| `92` | `RESET_SOUND_CHANNEL` | `header + 4 / x / fixed` | `0x44F130` | 0 |
| `9F` | `SYNC_AUDIO_CHANNEL` | `header + 5 / b x / fixed` | `0x44F150` | 0 |
| `A0` | `RESET_OVERLAY` | `header + 0 /  / fixed` | `0x44F2C0` | 4 |
| `A1` | `SET_OVERLAY_COLOR` | `header + 6 / b b b b b b / fixed` | `0x44F2F0` | 0 |
| `A2` | `CONFIGURE_OVERLAY` | `header + 13 / b b b b b b w b w w / fixed` | `0x44F3A0` | 0 |
| `A3` | `BASIC_FLAG_STORAGE` | `header + 4 / d / fixed` | `0x44F490` | 0 |
| `A4` | `RESET_BASIC_FLAG_STATE` | `header + 0 /  / fixed` | `0x44F500` | 0 |
| `A5` | `INIT_PERSISTENT_FLAGS` | `header + 4 / d / fixed` | `0x44F540` | 1 |
| `A6` | `UPDATE_OVERLAY` | `header + 5 / b w w / fixed` | `0x44F5B0` | 0 |
| `A7` | `SET_SYSTEM_VAR_FROM_FLAG` | `header + 6 / w x / fixed` | `0x44F620` | 1 |
| `AD` | `CONFIGURE_COLOR_EFFECT` | `header + 12 / x x x / fixed` | `0x44F690` | 0 |
| `AE` | `SET_DRAWING_RECT` | `header + 17 / b x x x x / fixed` | `0x44F6D0` | 0 |
| `AF` | `SET_MESSAGE_CLIP` | `header + 17 / b x x x x / fixed` | `0x44F780` | 1 |
| `B3` | `SET_MENU_CAPTION` | `header + encoded operands / x t b / fixed` | `0x44F830` | 0 |
| `B4` | `UPDATE_AUDIO_DEVICE` | `header + 4 / x / fixed` | `0x44F8F0` | 0 |
| `BD` | `SET_UI_RESOURCES` | `header + 16 / x x x x / fixed` | `0x430F40` | 1 |
| `BE` | `RESERVED_DISPATCH_A` | `header + 0 /  / fixed` | `0x447BF0` | 0 |
| `BF` | `RESERVED_DISPATCH_B` | `header + 0 /  / fixed` | `0x447BF0` | 0 |
| `D6` | `ADD_TEXT_TABLE` | `header + encoded operands / b b / data` | `0x44FB30` | 0 |
| `D7` | `ADD_SHORT_STRINGS` | `header + encoded operands / x / short_strings` | `0x44FBD0` | 3 |
| `DA` | `CLEAR_SHORT_STRINGS` | `header + 4 / x / fixed` | `0x44FC30` | 1 |
| `E0` | `OPEN_DATA_FILE` | `header + encoded operands / b s28 / fixed` | `0x44FC60` | 0 |
| `E1` | `WRITE_DATA_STRING` | `header + encoded operands / b b t64 / fixed` | `0x44FD50` | 0 |
| `E2` | `READ_DATA_VARIABLE` | `header + encoded operands / b b b v s28 / fixed` | `0x44FE10` | 0 |
| `E3` | `WRITE_DATA_VARIABLE` | `header + encoded operands / b b b v s28 / fixed` | `0x44FFF0` | 0 |
| `E4` | `COMPUTE_DATA_VALUE` | `header + encoded operands / b b b b s28 s28 s28 b x x x b v v / fixed` | `0x450190` | 0 |
| `E5` | `CONFIGURE_UI_RESOURCE` | `header + 1 / b / fixed` | `0x450440` | 1 |
| `E6` | `RESET_UI_RESOURCES` | `header + 0 /  / fixed` | `0x450490` | 1 |
| `E7` | `SET_UI_COLOR` | `header + 3 / b b b / fixed` | `0x4504B0` | 0 |
| `E8` | `SET_UI_COLOR_ALT` | `header + 3 / b b b / fixed` | `0x450540` | 0 |
| `E9` | `UPDATE_UI_RESOURCES` | `header + 4 / x / fixed` | `0x4505D0` | 1 |
| `EF` | `SYSTEM` | `header + encoded operands /  / system` | `0x450600` | 1 |
| `F0` | `SYSTEM_FILE_ACTION` | `header + encoded operands /  / file_action` | `0x450F00` | 0 |
| `F1` | `START_TIMER` | `header + 4 / x / fixed` | `0x4513C0` | 29 |
| `F2` | `WAIT_TIMER` | `header + 0 /  / fixed` | `0x4513F0` | 29 |
| `F3` | `PLAY_MOVIE` | `header + encoded operands / x x x x s13 / fixed` | `0x451400` | 1 |
| `F4` | `SET_SKIP_MODE` | `header + 1 / b / fixed` | `0x4515E0` | 4 |
| `F5` | `SET_MESSAGE_ADVANCE` | `header + 1 / b / fixed` | `0x451610` | 14468 |
| `F7` | `DISPLAY_SYSTEM_STRING` | `header + encoded operands / t / fixed` | `0x451650` | 0 |
| `F8` | `SET_TEXT_STYLE` | `header + 2 / b b / fixed` | `0x451690` | 1 |
| `F9` | `SET_TEXT_COLOR` | `header + 5 / b b b b b / fixed` | `0x451720` | 2707 |
| `FA` | `START_MEASUREMENT` | `header + 4 / x / fixed` | `0x4517B0` | 17 |
| `FB` | `STOP_MEASUREMENT` | `header + 0 /  / fixed` | `0x4517D0` | 17 |
| `FC` | `READ_MEASUREMENT` | `header + 2 / v / fixed` | `0x4517F0` | 17 |
| `FD` | `SET_MOVIE_RESOURCES` | `header + encoded operands / x s13 b b s13 s13 / fixed` | `0x451830` | 0 |
| `FE` | `SKIP_DEFAULT` | `header + 0 /  / fixed` | `0x447BF0` | 1 |
| `FF` | `WAIT_TIMER_ALT` | `header + 0 /  / fixed` | `0x4513F0` | 0 |

## 工具用法和示例

需要 Python 3.10 或更高版本，依赖标准库。在汉化工作区运行下述命令。

```powershell
python disassembler.py ISF_unpack -o ISF_asm --encoding cp932
python assembler.py ISF_asm -o ISF_rebuild
python assembler.py ISF_asm -o ISF_gbk --encoding gbk
```

反汇编单个文件时，默认输出同目录的 `<basename>.asm.txt`。汇编单个文件时，默认输出 `<basename>.rebuild`，也可用 `-o` 写成明确命名的 `.ISF`。两个 CLI 都可用多个输入路径，支持 Windows 已关联 `.py` 时的拖放。目录输入会递归处理对应脚本文件并保持相对目录。目录反汇编默认输出到相邻的 `<目录>_asm`，目录汇编默认输出到 `<目录>_rebuild`，文件名采用 `.script` 中的成员名。工具会拒绝用输出覆盖任何一项输入。

`asm.txt` 取自 `S08X.ISF`，演示 `MESSAGE`、算术表达式、条件跳转和多个入口槽位共享标签。只编辑 `| TEXT` 里的引号内容即可修改正文。引号中的 `\n` 为消息流中的换行，工具写入该格式的换行控制和文本状态切换。其他控制可保留为同行组中的独立 `|` 记录，确保语音等事件留在原来的位置。`form=` 保存少数字符的原拼写，可在修改相关文本时整体删除。CP932 原样重建时保留该字段。显式 GBK 重编码会从可读字符生成目标字节。

```powershell
python disassembler.py ISF_unpack/S08X.ISF -o asm.txt
python assembler.py asm.txt -o S08X.rebuild.ISF
```

如需回封，原 `ikura.json` 给出外层成员索引。把它复制到对应的全量输出目录，再用已有工具打包。

```powershell
Copy-Item ISF_unpack/ikura.json ISF_gbk/ikura.json
python ikura_tool.py pack ISF_gbk ISF.gbk
```

### 名牌注释

`MESSAGE` 的控制码 `0x11` 在 ASM 中沿用 `SET_POSITION`。它的参数经 `40B200 → 40AC70 → 40F3B0` 选择 `FWnnn.GG2` 名牌，而 `SELECT_SPEAKER` 使用引擎中的另一组名字槽。用 `GGD` 内的 `FW000.GG2` 至 `FW018.GG2` 逐张核实了图面，并和 `START.ISF` 的名字槽交叉核对。`FW000.GG2` 是空白底图，本作有图名的台词会在 `| TEXT` 上一行生成 `; NAME "原文人名"`。超出已核实名单的编号显示对应资源名。控制码缺失时不出具人名判断。

`NAME` 是汇编器忽略的 `;` 注释，可以编辑或删除。回看姓名读取 `START.ISF` 的 `DEFINE_SPEAKER` 槽。`44A800 → 45B750 → 40FF60 → 40F9E0` 把定义存入活动消息窗的字符表，`SELECT_SPEAKER` 设置姓名索引，回看读取该索引后调用 `406F10` 绘出姓名。`ISF_asm` 全部 152 份脚本已检查并补入 7,404 条注释。原 ASM 剥除新注释后逐字节相同。新增注释后的 152 份 CP932 重建脚本与原成员逐字节一致，回封后的整档也一致。152 份 GBK 输出与增加注释前的 GBK 结果逐字节一致。

## 验证记录

| 检查 | 结果 |
| --- | --- |
| CP932 默认反汇编、汇编 | 152 份成员逐字节一致，逐份核对 SHA-256 |
| CP932 回封 | 整档 SHA-256 与 `ISF` 一致，值为 `CD9BB00BA3D349C10A32367478A645EFB0238E0A6D23224CE2BBF275F80BBC76` |
| 原文显式 GBK 汇编 | 152 份全部成功，130 份成员的字节发生改变。其余成员没有需要改变字节的文字 |
| GBK 结构、内容 | 按观测到的五种消息控制重新读取全部 14,925 条消息记录，检查 14,571 段正文的 339,589 个字符、19 条姓名定义、3 条短串。逐条比较非文本载荷、入口表目的指令与重复目标。393 条消息自动升级长度头 |
| GBK 编码替换 | `・` → `·` 共 22 次，`♪` → `☆` 共 121 次，包含姓名定义 |
| GBK 二次反汇编、汇编及回封复解 | 三条路径均通过，分别逐字节比较 152 份成员 |
| 中文变长 | 在 `S08X.ISF` 扩写正文后，单条消息升级长度头，后续和共享入口仍指向原指令。改稿重新反汇编后逐字节往返通过 |
| 错误用例 | 拒绝非法入口、未知 opcode、标签冲突、入口引用不符、未知消息控制、错误占位符和 GBK 不可编码字 |
| 游戏实测 | 待验证原游戏中的显示、菜单和语音。GBK 字节、长度与重定位已验证，游戏内字形适配待独立处理 |

本轮仅在临时目录验证回封和变长修改。原档及 `ISF_unpack` 可直接用于恢复。

## ASM 与翻译 JSON

`asm_json.py` 使用 Python 3.10+。可单独处理一个 `.asm.txt` 或整目录，注入时为原 ASM 保留独立输出目录。以下命令从汉化工作区执行。

```powershell
python asm_json.py extract --src ISF_asm --out ISF_json
python asm_json.py report --src ISF_asm
python asm_json.py verify --src ISF_asm
python asm_json.py inject --src ISF_asm --json ISF_json --out ISF_asm_cn --encoding gbk
python assembler.py ISF_asm_cn -o ISF_gbk --encoding gbk
```

- 每个脚本导出 UTF-8 `<脚本>.json` 数组。`id` 由脚本名和正文序号组成。`name` 取自 `TEXT` 上方的 `; NAME`，无名牌的条目省略该字段。翻译只需编辑 `message`，保留 `pre_jp` 与 `id`。名字作为上下文，图形菜单仍由素材管理。
- 同目录的 `<脚本>.json.meta.json` 记录源 ASM 的 SHA-256、原始字面量、位置、控制码、缩进和折行位置。保留它可在注入时核验源文件。只提供翻译 JSON 时，工具逐条核对 ID 和 `pre_jp` 并报告缺少 meta。批处理支持只翻译部分脚本，未匹配的 ASM 会原样复制。
- 提取从 `TEXT` 去除句首全角空格及正文的双全角空格排版组。连续三个全角空格时保留其中一个。原稿也有少数偏离 26 字边界的排版组，meta 记录其位置。单个正文空格保留。修改过的译文恢复该条原有句首缩进，并将缩进计入第一行，每满 26 个字符且还有后文时插入两个全角空格。插入的空格不计入下一行。缺失、留空或未改动的 `message` 复用原 ASM 行，包括原排版及字符拼写。
- 注入保留消息控件、标签、语音与名牌注释。先检查改动的文字和控制占位符，再调用现有汇编器校验长度和重定位。`--encoding` 默认 `gbk`，负责验证汇编目标，生成的 ASM 继续用 UTF-8。运行 `assembler.py` 时使用相同的目标编码。
- 全量提取范围为 152 份脚本、14,571 条正文、7,404 个名牌字段。过滤 8,119 条句首缩进和 4,670 组段中空格。19 条 `DEFINE_SPEAKER` 供历史记录等文本姓名显示，可在 `START.asm.txt` 修改。三个 `ADD_SHORT_STRINGS` 短串由 `40CEE0/40E3E0` 用于语音资源前缀匹配。JSON 流程保留这两类指令。
- 回归验证覆盖 152 份 `ASM → JSON → ASM → ISF` 空注入逐字节一致，回封 SHA-256 与原档相同。27 个组合覆盖 0、1、2 字缩进、26/52 字边界和多行长文本。另用修改过的译文完成 GBK 汇编、二次反汇编和重新提取，复核目标正文、其他指令载荷、语音控制和入口重定位。游戏内排版待实测。
