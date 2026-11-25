# 傷モノの学園 · Sceplay `.sce` VM

## 源码证据与文件布局

分析对象是本地 `exe/kizumono.c`、`exe/kizumono.asm` 和 `sce_unpack` 的 162 个脚本。指令结构以 `sub_419010`、`sub_419AD0` 和 `sub_405F10` 为依据。命令助记符是根据处理函数起的分析名称。宿主将脚本载入字节缓冲，从场景起点读取首条指令。脚本是小端、按字节连续排列的变长指令流，共用局部 PC、条件标志、三个变量区、算术结果寄存器、局部返回栈和场景栈。`PUSH_VALUE` / `POP_VALUE` 另外操作游戏命令的数据栈。样本的第一条指令在偏移零，没有文件头、代码段表、磁盘字符串池、填充或脚本级封包变换。

指令开头是一个 `u8` 类型与一个 `u16le` 编号。类型 0 表示立即数游戏命令，`sub_405F10` 按命令号选择 `jpt_405F05` 中的 192 个处理函数。类型 4 由 VM 核心直接分派。类型 1、2、3 表示从对应变量区取值，作为命令的 16 位槽号所指向的运行时命令。脚本样本仅用类型 0 和 4 作为指令头。运行时命令号决定参数长度，所以工具对出现在指令头的 1–3 给出明确错误。作为 `V` 参数时，0–3 均可完整编解码。

| 参数 | 编码、长度及证据 |
| --- | --- |
| `V` | 3 字节，由 `sub_419AD0` 读取 `u8` 类型和 `u16le`。0 是无符号立即数，1/2/3 分别为变量区 `a`、`b`、`t` 的索引。写回由 `sub_419B60` 执行。 |
| `K` | 与 `V` 同布局，表示运行时字符串槽号。立即量显示为 `str[n]`，变量间接槽号照常显示为 `a[n]` 等。 |
| `S` | 内嵌 NUL 结尾的字节字符串，长度为编码后字节数加 1。`sub_419A70` 扫描 NUL 并推进 PC。 |
| `X` | 与 `S` 同布局，语义为跨文件场景名。`sub_4193A0` 和 `sub_419430` 去掉扩展名并把目标场景载入后从开头执行。文件名作为符号保存。 |
| `J` | `u32le`，4 字节，由 `sub_419A00` 读取，基准为**当前场景起点**。出现在核心 0–3，目标必须是指令起点。 |
| `E` | 编码长度 8。`sub_419720` 读取 `u8` 运算、`u8` 左类型、`u8` 右类型、`u8` 结果槽，再读两个 `u16le` 源操作数。结果写到 `t[结果槽]`，并刷新非零标志。赋值另写回左变量。 |

## 核心指令与重定位

| 识别模式 | 助记符 | 参数 / 长度 | 定义与证据 |
| --- | --- | --- | --- |
| `04 00 00` | `JUMP_IF_ZERO` | `J` / 7 | 上次运算标志为零时跳转。`419130` |
| `04 01 00` | `JUMP_IF_NONZERO` | `J` / 7 | 上次运算标志为非零时跳转。`419160` |
| `04 02 00` | `JUMP` | `J` / 7 | 无条件跳转。`419190` |
| `04 03 00` | `CALL` | `J` / 7 | 保存下一条指令的场景内偏移后跳转。`4191B0` |
| `04 04 00` | `RETURN` | 无 / 3 | 从局部返回栈恢复 PC。栈为空则触发结束处理。`419200` |
| `04 05 00` | `JUMP_SCENE` | `X` / 3 + 字符串 | 替换当前场景。`4193A0` |
| `04 06 00` | `CALL_SCENE` | `X` / 3 + 字符串 | 保存父场景和续执行位置，载入子场景。`419430` |
| `04 07 00` | `RETURN_SCENE` | 无 / 3 | 从场景栈恢复场景和 PC。`4196C0` |
| `04 08 00` | `EVAL.*` | `E` / 11 | 运算子码和两个源参数类型共同决定变体。`419720` |

`EVAL` 子码按 0–18 依次为 `MUL DIV MOD ADD SUB SHL SAR LT LE GT GE EQ NE AND XOR OR BOOL_AND BOOL_OR ASSIGN`。二元运算使用左、右操作数。比较和逻辑运算写入 0 或 1。`SAR` 是算术右移。`ASSIGN` 取右操作数，同时更新左变量（左侧为立即量则跳过写回）。源码中的结果槽、左、右顺序独立于二进制字节布局。

汇编先按最终编码生成每条指令、登记标签位置，然后回填 `J`。跨文件调用、返回地址和存档中的现场是宿主运行时维护的值。场景调用的符号命名来自文件名。目录验收检查样本中的直接场景目标，单文件工具允许保留当前目录之外的符号。已生成的旧存档可能仍保存原脚本中的 PC，变长后的兼容性未做运行时验证。

## 文本、字符串槽与编码

`TEXT`（607）通过 `sub_408D80` 读取并显示内联正文。`SET_STRING`（200）写入 32 个运行时字符串槽之一。`TEXT_FROM_STRING`（608）、`TEXT_CUSTOM_GLYPH`（609）、`TEXT_APPEND_TO_STRING`（610）分别显示槽内字符串、显示编号指定的自定义字形、显示并追加到字符串槽。`SHOW_CHOICES`（3000，`sub_422140`）从三个运行时字符串槽拷贝选项，并额外读取三条内联资源名。槽可能在不同分支被写入、清空或拼接，定义与引用由 `str[n]` 表示同一槽，槽引用行不复制正文。当前样本中 `SHOW_CHOICES` 本身未出现，定义来自宿主读取序列。

反汇编输出固定 UTF-8，`.encoding` 标明脚本原编码。汇编默认取 `.encoding`。`--encoding gbk` 对包括未修改字符串在内的内容全量重新编码。汇编会列出 GBK 无法直接编码的三种样本字符及其替换次数。`--strict-gbk` 可要求遇到这些字符时报错。其他不可编码字符直接报错。内联 `\\` 是实际反斜杠。控制字节、私有区或无法规范往返的原始字节以 `{{XX:YY}}` 表示。结尾 NUL 由汇编器写入。渲染器解释的文本内控制串仍留在字符串内。

## 游戏命令表

识别模式为 `00 <命令号 u16le>`。长度是 3 加此行各参数字节数。读取器证据见处理函数列，通用值和字符串参数分别追溯到 `sub_419AD0` 与 `sub_419A70`。命令参数的有效操作路径以宿主处理函数为准。越界或错误分支上的提前退出不属于有效脚本格式。105/106 的两个互斥分支各读一个操作数。901/1001 把文件名放在最后，902/1002 读取字符串槽号。1700 的跳转表第 168 项调用 IDA 标注的 `std::locale::classic(void)`，无脚本参数。

| 命令号 | 助记符 | 参数 | 处理函数 |
| --- | --- | --- | --- |
| 100 | `ARRAY_READ_INDIRECT` | `VVV` | `41BD60` |
| 101 | `ARRAY_WRITE_INDIRECT` | `VVV` | `41BE30` |
| 102 | `ARRAY_ADDRESS` | `VV` | `41BEF0` |
| 103 | `ARRAY_READ_INDEXED` | `VVV` | `41BF90` |
| 104 | `ARRAY_WRITE_INDEXED` | `VVV` | `41C060` |
| 105 | `PUSH_VALUE` | `V` | `41C110` |
| 106 | `POP_VALUE` | `V` | `41C170` |
| 107 | `RESET_SCRIPT_VARIABLES` | `—` | `41C1F0` |
| 108 | `STOP_WITH_ERROR` | `—` | `41C250` |
| 109 | `DISCARD_LOCAL_RETURNS` | `—` | `41C270` |
| 110 | `STOP_WITH_DEBUG_ERROR` | `—` | `41C2A0` |
| 111 | `KEEP_CURRENT_SCENE` | `—` | `41C2C0` |
| 200 | `SET_STRING` | `KS` | `426D10` |
| 201 | `SET_STRING_BYTE` | `KVV` | `426D60` |
| 202 | `CLEAR_STRING` | `K` | `426DE0` |
| 203 | `COPY_STRING` | `KK` | `426E30` |
| 204 | `APPEND_STRING` | `KK` | `426ED0` |
| 205 | `FORMAT_NUMBER_STRING` | `KVVVV` | `426F70` |
| 206 | `COMPARE_STRINGS` | `KKV` | `427220` |
| 207 | `STRING_BYTE_LENGTH` | `KV` | `4272F0` |
| 300 | `CONFIGURE_IMAGE_MODES` | `VV` | `401000` |
| 301 | `CREATE_SURFACE` | `VVV` | `401030` |
| 302 | `FREE_SURFACE` | `V` | `401150` |
| 303 | `LOAD_IMAGE` | `VVVS` | `4011F0` |
| 304 | `LOAD_IMAGE_FROM_STRING` | `VVVK` | `401390` |
| 305 | `GET_SURFACE_DIMENSIONS` | `VVV` | `401580` |
| 306 | `SET_COLOR_KEY` | `VVVV` | `401620` |
| 307 | `COPY_SURFACE_DESCRIPTOR` | `VVVV` | `4016B0` |
| 308 | `BLIT_RECT` | `VVVVVVVVV` | `4017B0` |
| 309 | `BLIT_STRETCHED` | `VVVVVVVVVVV` | `4018B0` |
| 310 | `BLIT_EFFECT` | `VVVVVVVVVVVV` | `4019F0` |
| 311 | `BLIT_KEYED_STRETCHED` | `VVVVVVVVVVV` | `401B40` |
| 312 | `BLIT_MASKED` | `VVVVVVVVVVVVV` | `401C60` |
| 313 | `BLIT_MASKED_SCALED` | `VVVVVVVVVVVVVVV` | `401DB0` |
| 314 | `BLIT_ALPHA` | `VVVVVVVVVVVVV` | `401F40` |
| 315 | `BLIT_ALPHA_SCALED` | `VVVVVVVVVVVVVVV` | `4020A0` |
| 316 | `BLIT_TRANSFORMED` | `VVVVVVVVVVVVVVVVV` | `402250` |
| 317 | `CAPTURE_OR_PRESENT` | `VVVVVVVVV` | `402430` |
| 318 | `TRANSITION_SINGLE` | `VVVVVVVVVV` | `402580` |
| 319 | `TRANSITION_PAIR` | `VVVVVVVVVVV` | `402BA0` |
| 320 | `PRESENT_RECT` | `VVVVVVVVV` | `403840` |
| 400 | `SET_TEXT_ORIGIN` | `VV` | `41A920` |
| 401 | `GET_TEXT_ORIGIN` | `VV` | `41A9B0` |
| 402 | `SET_TEXT_SPACING` | `VV` | `41AA10` |
| 403 | `GET_TEXT_SPACING` | `VV` | `41AAA0` |
| 404 | `SET_TEXT_GRID` | `VV` | `41AB00` |
| 405 | `GET_TEXT_GRID` | `VV` | `41AB90` |
| 406 | `SET_TEXT_PIXEL_OFFSET` | `VV` | `41ABF0` |
| 407 | `GET_TEXT_PIXEL_OFFSET` | `VV` | `41AC80` |
| 408 | `SET_TEXT_BASE_EXTENT` | `VV` | `41ACE0` |
| 409 | `GET_TEXT_BASE_EXTENT` | `VV` | `41AD70` |
| 410 | `SET_TEXT_RELATIVE_OFFSET` | `VV` | `41ADD0` |
| 411 | `GET_TEXT_RELATIVE_OFFSET` | `VV` | `41AE60` |
| 412 | `SET_TCY_MODE` | `V` | `41AEC0` |
| 413 | `GET_TCY_MODE` | `V` | `41AF40` |
| 414 | `SET_TEXT_COLUMN` | `V` | `41AF70` |
| 415 | `GET_TEXT_COLUMN` | `V` | `41AFF0` |
| 416 | `SET_TEXT_COLUMN_LIMIT` | `V` | `41B020` |
| 417 | `GET_TEXT_COLUMN_LIMIT` | `V` | `41B0A0` |
| 418 | `SET_GLYPH_SIZE_OFFSET` | `VV` | `41B0D0` |
| 419 | `GET_GLYPH_SIZE_OFFSET` | `VV` | `41B160` |
| 420 | `SET_TEXT_COLOR` | `VVV` | `41B1C0` |
| 421 | `GET_TEXT_COLOR` | `VVV` | `41B280` |
| 422 | `SET_SHADOW_COLOR` | `VVV` | `41B300` |
| 423 | `GET_SHADOW_COLOR` | `VVV` | `41B3C0` |
| 424 | `SET_TEXT_FLAG_M` | `V` | `41B440` |
| 425 | `GET_TEXT_FLAG_M` | `V` | `41B4C0` |
| 426 | `SET_TEXT_FLAG_N` | `V` | `41B4F0` |
| 427 | `GET_TEXT_FLAG_N` | `V` | `41B570` |
| 428 | `SET_TEXT_FLAG_O` | `V` | `41B5A0` |
| 429 | `GET_TEXT_FLAG_O` | `V` | `41B620` |
| 430 | `SET_TEXT_FLAG_P` | `V` | `41B650` |
| 431 | `GET_TEXT_FLAG_P` | `V` | `41B6D0` |
| 432 | `SET_TEXT_WRAP_MODE` | `V` | `41B700` |
| 433 | `GET_TEXT_WRAP_MODE` | `V` | `41B780` |
| 434 | `SET_TEXT_FLAG_R` | `V` | `41B7B0` |
| 435 | `GET_TEXT_FLAG_R` | `V` | `41B830` |
| 436 | `SET_TEXT_FLAG_S` | `V` | `41B860` |
| 437 | `GET_TEXT_FLAG_S` | `V` | `41B8E0` |
| 438 | `SET_TEXT_FLAG_T` | `V` | `41B910` |
| 439 | `GET_TEXT_FLAG_T` | `V` | `41B990` |
| 440 | `SET_TEXT_FLAG_U` | `V` | `41B9C0` |
| 441 | `GET_TEXT_FLAG_U` | `V` | `41BA40` |
| 442 | `SET_TEXT_FLAG_V` | `V` | `41BA70` |
| 443 | `GET_TEXT_FLAG_V` | `V` | `41BAF0` |
| 444 | `TEXT_WAIT` | `V` | `41BB20` |
| 445 | `TEXT_NEWLINE` | `—` | `41BBA0` |
| 446 | `TEXT_NEW_PAGE` | `—` | `41BC00` |
| 500 | `REFRESH_DRAWING_CONTEXT` | `VVV` | `429FC0` |
| 600 | `CONFIGURE_MESSAGE_SURFACE` | `VVVVVVVV` | `408B20` |
| 601 | `CONFIGURE_MESSAGE_SHADOW` | `VVVV` | `408BA0` |
| 602 | `SET_GLYPH_DRAW_MODE` | `V` | `408BF0` |
| 603 | `SET_MESSAGE_WAIT_SCENE` | `X` | `408C10` |
| 604 | `SET_MESSAGE_AFTER_SCENE` | `X` | `408C30` |
| 605 | `DEFINE_CUSTOM_GLYPH` | `VVVVVVVV` | `408C50` |
| 606 | `DRAW_MESSAGE_BACKGROUND` | `—` | `408D20` |
| 607 | `TEXT` | `S` | `408D80` |
| 608 | `TEXT_FROM_STRING` | `K` | `408E40` |
| 609 | `TEXT_CUSTOM_GLYPH` | `V` | `408F30` |
| 610 | `TEXT_APPEND_TO_STRING` | `KS` | `409000` |
| 611 | `GET_MESSAGE_STATE` | `VVVVVV` | `40C3F0` |
| 612 | `REDRAW_LOG_TEXT` | `—` | `40C4F0` |
| 613 | `RETURN_FROM_TEXT_CALLBACK` | `—` | `40C660` |
| 700 | `CLEAR_MESSAGE_LOG` | `—` | `411A60` |
| 701 | `START_MESSAGE_LOG_ENTRY` | `—` | `411AA0` |
| 702 | `FINISH_MESSAGE_LOG_ENTRY` | `—` | `411B00` |
| 703 | `TOGGLE_MESSAGE_LOG` | `—` | `411B40` |
| 704 | `GET_MESSAGE_LOG_COUNT` | `V` | `411B60` |
| 705 | `DRAW_MESSAGE_LOG_ENTRY` | `VVVV` | `411B90` |
| 800 | `PLAY_STREAM` | `VVVVVVV` | `41C3A0` |
| 801 | `PLAY_STREAM_ALTERNATE` | `VVVVVVV` | `41C880` |
| 802 | `STOP_STREAM` | `VV` | `41C890` |
| 803 | `PAUSE_RESUME_STREAM` | `VV` | `41CAB0` |
| 804 | `GET_STREAM_STATE` | `VV` | `41CCE0` |
| 900 | `PLAY_MEDIA_BY_NAME` | `VSVVVVVV` | `4180D0` |
| 901 | `PLAY_MEDIA_QUEUED_BY_NAME` | `VVVVVVVS` | `4187F0` |
| 902 | `PLAY_MEDIA_FROM_STRING` | `VKVVVVVV` | `418800` |
| 903 | `STOP_MEDIA` | `VV` | `418810` |
| 904 | `PAUSE_RESUME_MEDIA` | `VV` | `418A30` |
| 905 | `GET_MEDIA_STATE` | `VV` | `418C60` |
| 1000 | `PLAY_WAVE_BY_NAME` | `VSVVVVVV` | `417410` |
| 1001 | `PLAY_WAVE_QUEUED_BY_NAME` | `VVVVVVVS` | `417B60` |
| 1002 | `PLAY_WAVE_FROM_STRING` | `VKVVVVVV` | `417B70` |
| 1003 | `STOP_WAVE` | `VV` | `417B80` |
| 1004 | `PAUSE_RESUME_WAVE` | `VV` | `417DD0` |
| 1005 | `GET_WAVE_STATE` | `VV` | `418000` |
| 1100 | `LOAD_AUX_SOUND` | `VVS` | `417290` |
| 1101 | `PLAY_AUX_SOUND` | `VV` | `417320` |
| 1200 | `PLAY_BLOCKING_MEDIA` | `VSVVV` | `408920` |
| 1300 | `MARK_BANK_A_PERSISTENT` | `V` | `40C690` |
| 1301 | `MARK_BANK_B_PERSISTENT` | `V` | `40C700` |
| 1302 | `SET_BANK_A_PERSISTENCE_RANGE` | `VV` | `40C770` |
| 1303 | `SET_BANK_B_PERSISTENCE_RANGE` | `VV` | `40C7B0` |
| 1304 | `SET_BANK_A_DEBUG_NAME` | `VV` | `40C7E0` |
| 1305 | `SET_BANK_B_DEBUG_NAME` | `VV` | `40C830` |
| 1306 | `READ_SAVE_HEADER` | `VV` | `40C880` |
| 1307 | `LOAD_SAVE_SLOT` | `V` | `40C940` |
| 1308 | `VALIDATE_SAVE_SLOT` | `V` | `40CAC0` |
| 1309 | `READ_SAVE_METADATA` | `V` | `40CC40` |
| 1310 | `WRITE_SAVE_SLOT` | `—` | `40CD30` |
| 1311 | `SNAPSHOT_RENDER_STATE` | `—` | `40CE90` |
| 1312 | `SNAPSHOT_MESSAGE_STATE` | `—` | `40CEB0` |
| 1313 | `SNAPSHOT_TEXT_STATE` | `—` | `40CED0` |
| 1314 | `SNAPSHOT_STREAM_STATE` | `—` | `40CEF0` |
| 1315 | `SNAPSHOT_MEDIA_STATE` | `—` | `40CF10` |
| 1316 | `SNAPSHOT_WAVE_STATE` | `—` | `40CF30` |
| 1317 | `SNAPSHOT_VALUE_STACK` | `—` | `40CF50` |
| 1318 | `SNAPSHOT_SCENE_STACK` | `—` | `40CF70` |
| 1319 | `RESTORE_IMAGE_RESOURCES` | `—` | `40CFF0` |
| 1320 | `RESTORE_MESSAGE_STATE` | `—` | `40D1D0` |
| 1321 | `RESTORE_STREAM_STATE` | `—` | `40D1F0` |
| 1322 | `RESTORE_MEDIA_STATE` | `—` | `40D2A0` |
| 1323 | `RESTORE_WAVE_STATE` | `—` | `40D350` |
| 1324 | `RESTORE_BANK_A` | `—` | `40D420` |
| 1325 | `RESTORE_BANK_B` | `—` | `40D450` |
| 1326 | `RESTORE_SCENE_STACK` | `—` | `40D480` |
| 1400 | `CONFIGURE_INPUT_MAPPING` | `VVVVVVVVVVVVVVVVVVVVVVVVVV` | `421610` |
| 1401 | `POLL_MAPPED_INPUT` | `—` | `421970` |
| 1402 | `SET_INPUT_BINDING` | `VV` | `421D40` |
| 1403 | `GET_INPUT_BINDING` | `VV` | `421D90` |
| 1404 | `ENABLE_INPUT_FEATURE` | `V` | `421E00` |
| 1405 | `DISABLE_INPUT_FEATURE` | `V` | `421ED0` |
| 1406 | `TEST_CURSOR_IN_REGION` | `VVVVVVVV` | `421FA0` |
| 1500 | `UPDATE_MOUSE_TRACKER` | `VVV` | `4294D0` |
| 1600 | `WAIT_TIMER` | `VV` | `41CDB0` |
| 1601 | `SET_TIMER_BASE` | `VV` | `41CE90` |
| 1602 | `READ_ELAPSED_TIME` | `VV` | `41CF00` |
| 1700 | `LOCALE_CLASSIC_STUB` | `—` | `jump-table case 168` |
| 1701 | `SET_DELAY_INTERVAL` | `V` | `425200` |
| 1702 | `WAIT_DELAY` | `—` | `425220` |
| 1800 | `SEED_RANDOM` | `V` | `427370` |
| 1801 | `RANDOM_RANGE` | `VVV` | `427390` |
| 1900 | `READ_LOCAL_TIME` | `VVVVVVVVV` | `4273F0` |
| 2000 | `QUERY_CPU_FEATURES` | `VV` | `4250F0` |
| 2100 | `CONFIRM_RESOURCE_PATH` | `VVSS` | `40ED50` |
| 2200 | `MESSAGE_BOX` | `SSVVV` | `41C320` |
| 2300 | `READ_REGISTRY_DWORD` | `SV` | `414510` |
| 2301 | `WRITE_REGISTRY_DWORD` | `SV` | `4145C0` |
| 2400 | `DESTROY_GAME_WINDOW` | `—` | `41C300` |
| 2500 | `CONFIGURE_RESOURCE_ROOT` | `VVSSV` | `403A90` |
| 2501 | `OPEN_PAK` | `VVSVSV` | `403BA0` |
| 2502 | `CONFIGURE_RESOURCE_LOOKUP` | `VVSV` | `403CC0` |
| 2503 | `SET_STARTUP_SCENE` | `X` | `403DE0` |
| 2504 | `STARTUP_NOOP` | `—` | `403E00` |
| 2505 | `SET_SAVE_DIRECTORY` | `S` | `403E10` |
| 2506 | `SYNC_STARTUP_IO` | `—` | `403E30` |
| 2507 | `QUERY_STARTUP_FLAG` | `V` | `403E60` |
| 2600 | `SET_BUTTON_CONFIG` | `VVVVVVV` | `4292A0` |
| 2601 | `GET_BUTTON_CONFIG` | `VVVVVVV` | `429340` |
| 2602 | `POLL_BUTTON_CONFIG` | `VV` | `429480` |
| 3000 | `SHOW_CHOICES` | `VVKKKSSSV` | `422140` |
| 3100 | `LOAD_COLOR_AND_MASK_IMAGES` | `VVVVVS` | `405BD0` |


## 命令行与输出位置

以下命令从本工作区根目录运行。`-o` 对目录输入指定生成目录，对单文件输入指定生成文件或已有的生成目录。目录输入递归扫描并保留相对路径。单文件默认输出同目录下的 `<场景名>.asm.txt` 或 `<场景名>.rebuild`。目录默认输出到同级的 `<目录名>_asm` 或 `<目录名>_rebuild`。批量回编的文件后缀为 `.sce`。多个文件或目录可以同时作为输入，适用于拖放调用。

```powershell
python disassembler.py sce_unpack -o sce_asm --encoding cp932
python assembler.py sce_asm -o sce_rebuild_cp932 --encoding cp932
python assembler.py sce_asm -o sce_rebuild_gbk --encoding gbk
python disassembler.py sce_unpack/menu.sce -o menu.asm.txt
python assembler.py menu.asm.txt -o menu.rebuild.sce --encoding gbk
```

在汇编文本里可以直接编辑引号内的文字。标签名字固定为逻辑标识，文本长度变化后由汇编器计算位置。已有显式输出路径可以重新生成，工具拒绝输出与任一输入复用同一路径。

标准 GBK 的默认替换为 `・ → ·`、`♪ → ～`、`｢ → 「`。使用 `--strict-gbk` 便可定位需要手工处理的文本行。用相同编码往返时，原始字节占位符按字面字节写回。验收记录见 `translation-state.md`。
