# Kimitomo `.sce` 文本格式分析

## 结论与范围

本文件记录当前工作区样本 `kimitomo.sce` 与同目录 `exe/kimitomo.exe` 的静态分析结论。它替代旧的二进制 opcode/语义汇编分析；本作脚本是**加密的文本命令流**，不是定长二进制 opcode 表，故不再维护 `disassembler.py`、`assembler.py` 或 opcode 清单。

- 脚本：`kimitomo.sce`，659,596 bytes，SHA-256 `10c5ead49bdaa3c89fddb1ef23edb59b85391b19601338e2002c7a32706cb7a6`。
- EXE：`exe/kimitomo.exe`，499,712 bytes，SHA-256 `514a39315aad8dad9cc41df0c9528429f3acf618cad953f5ae8643dba1ce51ab`。
- 源码/汇编证据：`exe/kimitomo_pseudoc.c`、`exe/kimitomo.asm`；IDA 导出报告见 `exe/kimitomo_analysis_report.txt`。
- 本节只适用于以上样本和确认过相同格式的同版本 `.sce`。同引擎不代表所有游戏/文件类型都通用。

## 加密与编码

**事实：**文件载荷由滚动 XOR 变换保护；解密和加密是同一个对称变换。解密后是 CP932（Windows-31J）文本。

**静态证据：**IDA `sub_4078D0` (`0x4078D0`) 逐字节调用 `sub_407790` (`0x407790`)；`sub_407790` 的位表达式 `(a | b) & ~(a & b)` 等价于 XOR。`sub_4078D0` 的调用点传入 key 长度 `0x12`，并按滚动状态和当前位置访问 key。EXE 中可见 ASCII key `crowd script yeah `（18 bytes，样本 EXE 文件偏移 `0x6AA54`）。同引擎参考 `sce_tool.py` 也含该 key/滚动变换，但本工具实现以本作 IDA 逻辑和本样本逐字节测试为准，不沿用参考工具的 `.asc` 分支。

等价的实现步骤（全程按 unsigned byte）：

1. 初始 `state = 0`、`counter = 0`。
2. 对文件偏移 `i`，`key_pos = (state + i) % 18`。
3. `mask = KEY[key_pos] | (state & (counter & 0xFF))`；输出字节为输入字节 XOR `mask`。
4. 若 `key_pos == 0`，先以旧状态计算 `state = KEY[(state + counter) % 18]`，再递增 `counter`。

**样本实验：**解密字节严格按 CP932 解码，再按 CP932 编码可逐字节还原明文；重新加密后与原文件 SHA-256 一致。密文中可见 4,151 个 `0x00`、1,298 个 CR、1,102 个 LF 和 1,036 个 TAB；解密明文中这些字节均为 0 次。故不能把密文字节的零值或换行计数误判为明文记录边界。

## 明文文本语法（已观察到的子集）

词法器位于 `sub_4082D0` (`0x4082D0`)，调用包装包括 `sub_408B00`/`sub_408B20`；命令按文本字符串由 `sub_414CE0` (`0x414CE0`) 进行不区分大小写的分派。标签索引由 `sub_414B60` (`0x414B60`) 读取 `$` 或 `#` 后的名字。

在当前样本中可重复观察到的基本形态是：

```text
$ main $ 00-000 SS "场景标题" CB bg08 V 10 MP 11 WPL wlp00001 正文文本  0
```

这是解释性示意，不是完整语法定义。它包含：

- `$`/`#` 标签 marker 和标签名；脚本中也存在 `G`、`JP` 等命令后的标签引用。引用/跳转语义尚未完整恢复。
- 命令名是普通文本 token；命令后参数由相应运行时处理器继续读取。
- `"..."` 是 lexer 支持的引号字符串；样本中 `SS` 后的字符串用于场景/标题文字，`SP` 与 `*` 后的字符串组成选项。引号内部的 `@"` 表示转义双引号。引号字符串里的 CR/LF 会被词法器跳过/计行，本工具为避免改写边界而拒绝注入换行。
- 正文是无引号文本，紧接在命令/参数之后；当前样本的每段正文以**两个 ASCII 空格 + 连续递增的十进制文本序号**结束。序号覆盖 `0..10737`，总计 10,738 条。两空格/数字现象由当前样本完整扫描验证，是本作提取器的边界锚点，不声称是所有 Crowd 文件的普适规律。
- 说话人正文常以 `@!姓名@n` 开始；部分效果音正文含 `wse...@?` 前缀；还观察到内嵌 `@n` 等显示控制串。提取 JSON 将可识别的说话人名放入 `name`，并把可识别前缀保存在 meta；消息内部控制串仍留在 `pre_jp`，其中 `@n` 可在译文中直接增删或移动。
- 文本命令流同时使用空白、逗号/分号等 lexer 分隔符。注入器通过原文字符跨度替换目标字段并保留其它明文，不生成完整的命令 AST。

IDA 反编译代码还显示词法器支持 `//` 与 `/* ... */` 注释分支、引号中的 `@"` 转义，并会为 CR/LF 更新行计数。上述是宿主 lexer 的行为；本样本提取器只针对样本观测到的正文索引和字符串类别工作，不声称已形式化所有注释、分隔符和转义组合。

## 命令名证据及语义边界

`sub_414CE0` 包含 79 个由 dispatcher 比较的命令文本（大小写不敏感）：

`RT ED SSt SS Recs Rece Face FS FC FSet FAdd FSub FMul FDiv FExc FInc FDec FRnd GSC JP JPZ JZ JNZ JMI JMZ JSP JSPZ JSZ JSNZ JSMI JSMZ GS G R SR SP SL SD SC TE T W KW OP MV CF CMaskD CMask CB CMC CMD CM CMA CMCC EL EW V MC Ng CFill CFAdd CFSub CFD CFL SHD MOS CGF MP MPS MM MF MPause WP WPD WPL WStop WOStop WLStop EOF`

这些是 dispatcher 字符串，不是 byte opcode。命令名表能说明某 token 可被分派器识别，但**不能单凭名称推导其完整操作数 schema、副作用、控制流条件或参数边界**。参数语法需进一步逐条追踪对应分支；本工具只在已确认的正文/引号文本边界上提取，不把 79 个命令伪装为已解析的 AST。

## `sce_tool.py` 的 JSON 与 meta

提取命令：

```powershell
python sce_tool.py extract kimitomo.sce -o kimitomo_text.json --encoding cp932
```

JSON 是 UTF-8、缩进 2 格的对象数组，字段顺序与项目约定一致：

```json
[
  {
    "id": "kimitomo.sce#00000:text",
    "pre_jp": "原文正文",
    "message": "待翻译文本"
  },
  {
    "id": "kimitomo.sce#00007:text",
    "name": "海斗",
    "pre_jp": "「原文台词」",
    "message": "「待翻译台词」"
  },
  {
    "id": "kimitomo.sce#choice:0000",
    "kind": "choice-1",
    "pre_jp": "选项原文",
    "message": "待翻译选项"
  }
]
```

- 正文 ID 使用脚本 basename 与源文本序号，稳定对应原脚本文本记录；引号字符串 ID 另用 `title`/`choice` 稳定序号。`kind` 仅用于区分标题和选项。无说话人的旁白不生成空 `name`。
- `pre_jp` 是只读原文，编辑只改 `message`；`message` 缺失、null 或空串时回退原文。`name` 可编辑，但仅当源文本存在说话人控制前缀时可用。
- 同目录 sidecar `<json文件名>.meta.json` 保存源 SHA-256/长度、编码、记录类别、原文 payload、明文字符/字节区间、说话人/效果控制前缀及控制标记签名。注入器要求 JSON 与 meta 的 ID 集合完全相同，并验证输入原脚本 SHA-256 与 sidecar 一致，防止将旧位置应用到不同脚本。
- 输入目录时递归处理 `.sce`；输出 JSON 保持相对目录结构。每个 JSON 有独立 meta 文件。

重新注入命令：

```powershell
python sce_tool.py inject kimitomo.sce kimitomo_text.json -o kimitomo_cn.sce --encoding cp932
```

省略 `--encoding` 时沿用 meta 的源编码；显式 `--encoding gbk` 会把**整个明文脚本流**（包括未改动的命令、资源名和普通文本）重新编码为 GBK 后重新加密，不会只对翻译字段编码，也不会混留旧 CP932 字节。无法编码的字符会报错且不写出目标文件。翻译应先完成全文件字符审查，再选择目标编码。

提取目录/默认输出示例：

```powershell
python sce_tool.py extract kimitomo.sce
python sce_tool.py extract .\sce_dir -o .\json_dir --encoding cp932
python sce_tool.py inject .\sce_dir .\json_dir -o .\rebuilt_dir --encoding gbk
```

## 已执行的静态验收

| 检查 | 结果 | 说明 |
|---|---|---|
| 源哈希保护 | 通过 | 注入前检查 sidecar 里的长度和 SHA-256；禁止覆盖源脚本 |
| CP932 提取/空注入回环 | 通过 | 10,738 条索引正文 + 149 条引号文本，共 10,887 条；重建长度 659,596 bytes，SHA-256 与原样本完全相同 |
| CP932 编辑后再提取 | 通过 | 合成正文、说话人名、标题、选项编辑后回提，目标字段和顺序一致 |
| GBK 全文重新编码 | 通过（合成测试） | 将全部目标文本设为 GBK 可编码内容，连同未编辑脚本流重新编码；再按 GBK 提取验证 10,887 条记录 |
| 未修改原始资产 | 通过 | 本轮不写入 `kimitomo.sce`、`exe/kimitomo.exe` 或 IDA 数据/导出 |
| 游戏运行验证 | 未执行 | 尚未将修改后的脚本加载到游戏中验证文字、换行、控制串和画面行为 |

## GBK 注入卡死排查（2026-11-26）

### 已确认的 SCE 注入结果

- 对 `kimitomo.sce + kimitomo_text_chs.json --encoding gbk` 重新运行注入，输出与用户提供的 `kimitomo_cn.sce` 逐字节相同：659,596 bytes；因此本轮没有证据显示 JSON→文本替换→滚动 XOR 加密步骤产生错位。
- 本作解密结果与 `Crowd/sce_tool.py` 的 XOR 解密结果逐字节一致；输出明文可严格按 GBK 解码后再编码回原字节。对输出再提取为 10,887 项，记录顺序/类型、正文和人名均与输入 JSON 一致（ID basename 随输出文件名变化属预期）。
- `Crowd` 当前提供 `sce_tool.py` 与 `SExtractor正则表达式.txt`，未发现独立 SExtractor 可执行文件；参考解密器已用于核验密文变换。

### 与 EXE 的 DBCS 分词差异

- IDA `sub_404960 @ 0x404960` 返回字符位置是普通单字节、CP932 双字节 lead/trail 还是 NUL。原码比较范围是 `0x81–0x9F`、`0xE0–0xFC`，只适合当前原版 CP932 明文。
- GBK lead 范围为 `0x81–0xFE`。当前 GBK 明文中找到 1,211 处模式：一个 GBK 双字节字符的 lead 不在旧 CP932 范围，trail 却落入旧 CP932 lead 范围，随后紧接 `@n`。旧扫描器逐字节扫描时会把这个真实 `@` 当成前一字节的 trail；显示文本/说话人控制码扫描可能因此失步。原 CP932 文本同一检测为 0 处。此为脚本正确编码但运行时 EXE 仍按旧代码页分词的证据，实际造成启动卡死的因果尚待游戏测试。
- 候选修复位于 EXE `sub_404960` 的 `cmp eax, 0x9F`（VA `0x40498A`）：将立即数 `0x9F` 改为 `0xFE`，使第一 lead 区覆盖 `0x81–0xFE`。`patch_exe.py` 将此处与另外五处字符边界修复一并写入 EXE。
- 候选文件及 SHA、运行 A/B 建议和未执行的游戏测试记录见 `exe_patch_analysis.md` 与 `translation-state.md`。原始 `kimitomo.sce`、用户 `kimitomo_cn.sce` 及原版 EXE 均保持不变。

## 已知限制/风险

1. `$`/`#` 标签名与 `G`/`JP` 等命令引用关系、全部分支跳转语义、完整命令参数 schema 均未知；不要用本工具重命名标签或重排命令。
2. 提取边界依赖当前样本确认的双空格递增序号和已观察的引号字符串用法。工具遇到缺序号、乱序、非 CP932 可往返、NUL 明文、未知引号上下文或正文边界异常会中止，不会静默丢弃。
3. 正文记录跨度可能含游戏内控制串，且某些未确认的 ASCII token/参数可能与正文同处一个 span。翻译前应检查 `pre_jp` 和配套 meta；不认识的 `@` 控制标记不得删除。
4. 为避免破坏 token 边界，当前注入器拒绝无引号正文里的 ASCII `"`、记录首尾空白、NUL/CR/LF；引号字符串虽保留 lexer 的 `@"` 规则，仍拒绝 NUL/CR/LF。消息里的 `@n` 可直接编辑。其余控制标记默认与原文序列一致，`--allow-control-change` 可放开这项限制。
5. 变长文本被允许并重新生成加密流，但未独立验证引擎是否对文本长度、页面排版或脚本总大小另有限制。长度扩张、字库覆盖、自动换行与实际显示仍须游戏实测。

静态 round-trip 证明当前样本字节流程可逆，不等于修改文本后运行正确。