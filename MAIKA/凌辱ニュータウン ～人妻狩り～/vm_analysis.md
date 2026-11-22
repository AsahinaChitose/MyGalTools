# RAPNTWN ADB VM

Scope: `MIK3_unpack/*.ADB` from the current RAPNTWN release. Evidence is the local IDA export of `RAPNTWN.EXE`, not an engine-family guess.

## Layout and dispatch

- `sub_40C82D` loads an ADB unchanged into `dword_499054`; `sub_406C70` allocates a 1 MiB buffer. `StartAddress` fetches an unaligned little-endian `u16` at `base + PC`, advances PC by 2, and dispatches at `0x40CC0D`. Normal entry is offset zero. The VM has global word-variable banks, host-side state, and separate stacks for local and inter-script calls; there is no general operand stack in the observed instruction set.
- No general script header, text pool, alignment, checksum, or script-layer compression is present in the corpus. `TEXT` (0) and `CHOICE` (1) carry inline NUL-terminated strings; `CHOICE` also reads a `u32` branch target before the string and registers it in `dword_4889E8`. `CHOICE_RECT` (64) registers the same target format plus four coordinate words. Dynamic selection/call returns have no serialized target in the return instruction itself.
- Static branch and local call fields are `u32le` absolute offsets from the start of the current script. Script load/call fields are NUL-terminated resource names without `.ADB`; the loader resolves them by name. Target labels must distinguish instruction starts, data table starts, and the file-end boundary.
- `MAIN.ADB` code ends at `0x4550`; 42 contiguous tables follow. Case 243 and `sub_445F93` read each table at its `u32le` offset; zero disables the table. Rows are five `u16le` fields; first two are screen coordinates, last selects the gallery unlock flag, middle two are preserved. A standalone `u16 0xFFFF` terminates each table. The first table offset is discovered from references rather than hard-coded. No alignment bytes occur.
- `STAFF.ADB` case 146 reads one NUL string: the same operand is read in either branch (MIDI or WAV). Case 186 `RETURN_SCRIPT` consumes no string even though the decompiler shows an unused pointer assignment. Case 176 reads its flag ID and conditionally skips the following 14-byte instruction span; preserve that span's instruction boundaries and length.
- `TYOKYO01.ADB` ends with a conditional control path targeting exactly original EOF. Preserve that observed edge explicitly as a boundary label, not an instruction, and do not generalize it into permission for arbitrary out-of-range branches.

## Operands and variants

- `w`: unsigned 16-bit word; `b`: unsigned byte; `d`: unsigned 32-bit scalar; `p`: `u32le` code label; `g`: `u32le` gallery table label (with `NONE` only where the EXE checks zero); `s`: inline display string; `r`: inline resource/identifier string (retains its source codec on GBK output); `e`: external script symbol; `a`: one-byte arithmetic selector; `c`: one-byte condition selector; `v`: `u16` expression operand, bit 15 chooses a variable index rather than a literal.
- Case 4 and 279 arithmetic subcodes: `$` AND, `*` multiply, `+` add, `-` subtract/clamp, `.` modulo, `/` divide, `=` assign, `|` OR. Cases 16 and 278 compare `=`, `{`, `}`, `~` and jump when the comparison fails. See the corresponding switches in `StartAddress`. Conditions are unsigned equality, less-or-equal, greater-or-equal, and inequality.
- C-strings are rendered as quoted UTF-8 assembly. Undefined/non-round-trippable bytes are represented by `{{XX}}` atoms; literal backslash, double quote and braces are escaped. NUL is structural and cannot be injected into a C-string. No `\n` shortcut is defined because there is no single confirmed VM-level newline byte; literal control bytes use the explicit placeholder notation.
- For the unobserved named-entry variant (case 102), the EXE uses an entry table at offset `+8` in the target script (`+6` word `0xFFF0`, then name/absolute offset records, terminator `0xFFFF`; `sub_429DAF`, `sub_429CF5`). It is not used by the present ADBs. Unobserved out-of-line resource block formats and fixed/dynamic skip encodings are not guessed; unsupported variants stop with a byte-offset diagnostic.

- `j`: an implicit code target, not stored in the file. For case 176 the target is `instruction_end + 14` (one `CHOICE_RECT` in this corpus). Both tools check its instruction boundary; the assembler rejects edits that change that VM-fixed span.

## Observed opcode table

Numbers are hexadecimal u16 opcodes; the byte pattern is their little-endian representation. Widths are in bytes including the opcode. `NUL` lengths include the terminator; `j` uses zero bytes. The final column is the IDA dispatch target inside `StartAddress`. The complete dispatch index and operand widths are in `opcodelist.py`: 277 entries match the non-default IDs at `0x40CC0D` (45 observed, 19 unobserved and guarded as unsupported, remaining EXE-only schemas not corpus-tested). Mnemonics are descriptive, not original engine symbols.

| Opcode | Mnemonic | Operands | Width | EXE handler |
| --- | --- | --- | --- | --- |
| `0000` | `TEXT` | `s` | 2 + NUL string | `40CC14` |
| `0001` | `CHOICE` | `ps` | 6 + NUL string | `40F112` |
| `0002` | `JUMP` | `p` | 6 | `40E346` |
| `0003` | `FILL_VARS` | `www` | 8 | `40EDFC` |
| `0004` | `VAR_OP` | `wav` | 7 | `40EA90` |
| `0005` | `WAIT_INPUT` | | 2 | `40E57E` |
| `0006` | `BEGIN_CHOICES` | | 2 | `40F069` |
| `0007` | `SHOW_CHOICES` | | 2 | `40F1AC` |
| `0010` | `JUMP_UNLESS` | `wcvp` | 11 | `40EECE` |
| `0011` | `DELAY_OR_INPUT` | `w` | 4 | `40E53B` |
| `0014` | `PRESENT_FRAME` | `w` | 4 | `40EA33` |
| `0018` | `JUMP_SCRIPT` | `e` | 2 + NUL string | `40E35E` |
| `0026` | `PLAY_BGM` | `r` | 2 + NUL string | `40F561` |
| `0028` | `STOP_BGM` | | 2 | `40F5CF` |
| `0035` | `PLAY_VOICE` | `r` | 2 + NUL string | `40F5D9` |
| `0036` | `STOP_VOICE` | | 2 | `40F69C` |
| `0037` | `LOAD_BG_VARIANTS` | `rrr` | 2 + 3 NUL strings | `40F6B6` |
| `0038` | `BEGIN_HOTSPOTS` | | 2 | `40F885` |
| `0040` | `CHOICE_RECT` | `pwwww` | 14 | `40F90B` |
| `0041` | `SHOW_HOTSPOTS` | | 2 | `40FA0F` |
| `0046` | `LOAD_BG` | `r` | 2 + NUL string | `40E5B4` |
| `0050` | `ENABLE_GAME_MENU` | | 2 | `4100B1` |
| `0062` | `SET_IMAGE_SLOT` | `wr` | 4 + NUL string | `41094E` |
| `007E` | `JUMP_VAR_EQ` | `wwp` | 10 | `41114E` |
| `008D` | `SET_TRANSITION_GEOMETRY` | `www` | 8 | `411873` |
| `008E` | `APPLY_TRANSITION` | `ww` | 6 | `4118F2` |
| `0092` | `PLAY_STAFF_AUDIO` | `r` | 2 + NUL string | `411A59` |
| `0093` | `STOP_STAFF_AUDIO` | | 2 | `411C06` |
| `0094` | `SET_STAFF_FRAME` | `w` | 4 | `411C6F` |
| `00B0` | `SKIP_HOTSPOT_IF_LOCKED` | `wj` | 4 | `41240A` |
| `00B9` | `CALL_SCRIPT` | `e` | 2 + NUL string | `41265C` |
| `00BA` | `RETURN_SCRIPT` | | 2 | `412881` |
| `00BC` | `SET_RGB_EFFECT` | `www` | 8 | `412A8E` |
| `00BE` | `RESET_SCRIPT_STACK` | | 2 | `412B43` |
| `00F3` | `DRAW_GALLERY` | `wwgwwwwwwww` | 26 | `4139E8` |
| `00FC` | `CLOSE_GALLERY_SCREEN` | | 2 | `413E6A` |
| `0102` | `JUMP_ON_MENU_REQUEST` | `p` | 6 | `4140D8` |
| `010E` | `DISABLE_GAME_MENU` | | 2 | `4143DC` |
| `0111` | `SET_DRAW_REGION` | `wwww` | 10 | `4144AC` |
| `0112` | `SET_GALLERY_ITEM_LAYOUT` | `wwwwww` | 14 | `414551` |
| `0116` | `JUMP_SYS_UNLESS` | `wcvp` | 11 | `414801` |
| `0117` | `SYSVAR_OP` | `wav` | 7 | `414995` |
| `011E` | `DISABLE_TEXT_EFFECTS` | | 2 | `414ECD` |
| `0123` | `SET_RENDER_RGB` | `www` | 8 | `415041` |
| `012F` | `LOAD_IMAGE_SLOTS` | | 2 | `41568E` |

## Usage and validation

```powershell
python disassembler.py MIK3_unpack -o work_asm --encoding cp932
python disassembler.py MIK3_unpack\SPH01.ADB -o SPH01.asm.txt
python assembler.py work_asm -o work_rebuilt --encoding cp932
python assembler.py SPH01.asm.txt -o SPH01.cn.ADB --encoding gbk
python -B -m unittest discover -s scripts -v
```

Use `TEXT "..."` and `CHOICE label, "..."` for editing. The `--encoding` flag on assembly changes only display strings, not resource names or explicit byte placeholders; the assembly file itself stays UTF-8. Without the flag, `.encoding` is used for both kinds of string (default `cp932` if absent). GBK cannot encode all of the original Japanese characters, including U+30FB and U+266A; resolve them explicitly rather than expecting a lossy conversion. Filenames, labels and section directives are not display strings. The tools do not overwrite existing output. With no `-o`, a single file produces `<stem>.asm.txt` or `<stem>.rebuild.ADB`; a directory produces a sibling `_asm` or `_rebuild` directory. Multiple files can be passed in one invocation, including by a file association that passes dragged paths to Python.

- The 161 source ADBs (1,178,377 bytes) fully parse: 40,326 instructions, 14,423 `TEXT`, 157 `CHOICE`, 42 gallery tables and 168 gallery rows.
- All 161 CP932 round-trips matched the originals and the corresponding `MIK3.DAT` payloads byte for byte. All 11 regression tests passed (6 ADB tests and 5 DAT tests), including GBK growth with control-flow fixups and relocation of all `MAIN.ADB` gallery tables.
- Runtime rendering, font coverage, native layout with longer translated text, and scripts outside this corpus were not tested. ADB repacking is separate from this tool.
