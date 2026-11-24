# LunaSoft SEQF VM analysis (current evidence)

> **Status: partial reverse engineering, not a complete semantic disassembler.**
> The executable dispatch table is recovered, but the operand schemas and
> relocation rules for the whole VM are not. The tools therefore expose only
> the two statically confirmed inline-text instruction forms; all remaining
> bytes are explicitly retained as `.byte` definitions. Do not treat the output
> as a complete opcode listing or assume arbitrary length-changing edits are
> safe.

## Examined inputs and evidence

- Sample set: `Seq_unpack/data/**/*.seq` (156 files).
- Host executable: `exe/lus004.exe`.
- Static evidence: `exe/lus004.exe.asm`, `exe/lus004_pseudoc.c`.
- The IDA decompilation identifies a `CSeq` VM. `sub_435620` dispatches through
  `funcs_435644` indexed by the first byte at the current instruction pointer.
  Handlers commonly switch on the next byte (`BYTE1(word)`), so the low two
  bytes act as primary opcode and subopcode. The dispatch pointer and helper
  functions treat instruction-stream positions as 32-bit words in the paths
  examined.
- This VM should not be confused with PAC archive layout or the PAC unpacker.

## Confirmed SEQF outer header

All 156 examined files satisfy this layout:

| Offset | Width | Confirmed interpretation |
|---|---:|---|
| `0x00` | 4 | ASCII magic `SEQF` |
| `0x04` | 4 | fixed bytes `05 03 10 20` (little-endian dword `0x20100305`) |
| `0x08` | 4 | header size; value is `0x14` |
| `0x0C` | 4 | body size; `file_size == 0x14 + body_size` in all samples |
| `0x10` | 4 | body-relative offset to an embedded CSeq task header in 155 story samples; zero in the distinct menu/logo sample |
| `0x14` | — | beginning of the body; the top-level stream/data begins here |

The loader evidence is `sub_436110`: it uses the dword at `0x08` as the source
slice start, the dword at `0x0C` as its size, and passes the dword at `0x10` as
an offset into that slice. For these SEQF files, the slice begins at file
`0x14`, so `0x10` is body-relative, not file-relative. `sub_435F50` reads the
embedded task header at `body + field_0x10` and initializes its first task PC
at `body + field_0x10 + 0x10`. All 155 nonzero story offsets point in bounds;
their first task opcode is `0x02`. The menu/logo sample with a zero offset is
a different layout and is not evidence against the story layout.

The stream is directly readable in samples and contains inline resource names
and CP932 text. No per-SEQF decompression or decryption transform has been
identified. The tools do not invent one.

## Recovered dispatch table (not a semantic opcode dictionary)

The following primary-byte-to-handler mapping was transcribed from
`funcs_435644` in the IDA listing. Subopcode cases were recorded from switches
in the corresponding pseudocode. This is **coverage evidence only**: the
handler names are not user-facing mnemonics, and operand schemas are still
missing.

| Primary byte(s) | Handler | Subopcode cases observed |
|---|---|---|
| `00` | `sub_4C09D0` | `00–0B` |
| `01` | `sub_4C01D0` | `00–11` |
| `02` | `sub_4BF9B0` | `00–21` |
| `03` | `sub_4BF7B0` | `00–06` |
| `04–06` | `sub_4BF790`, `sub_4BF770`, `sub_4BF750` | no `BYTE1` switch recovered |
| `07` | `sub_4BEE60` | `00–15` |
| `08` | `sub_4C0C00` | `00–14` |
| `09` | `sub_4BEB50` | `00–0A` |
| `0A` | `sub_4BE660` | `00–0F` |
| `0B` | error handler `sub_42FFD0` | — |
| `0C` | `sub_4BD690` | no `BYTE1` switch recovered |
| `0D` | `sub_4BD710` | `00–05` |
| `0E` | `sub_4BE3B0` | `00–03`, `06–07`, `0D–0E` |
| `0F` | `sub_4BE1B0` | `00–03`, `0A` |
| `10` | `sub_4BD900` | `00–0A`, `64–67`, `AA–AD`, `B4–B6` |
| `11` | error handler `sub_42FFD0` | — |
| `12` | `sub_4ACE60` | `00–09` |
| `13` | `sub_4ACDF0` | no `BYTE1` switch recovered |
| `14` | `sub_4AD100` | `64–69`, `6E`, `78–7D`, `C8` |
| `15–17` | error handler `sub_42FFD0` | — |
| `18` | `sub_42FB20` | `00–0C` |
| `19` | `sub_42DCD0` | `00–21` |
| `1A` | `sub_42BF50` | `00` |
| `1B` | `sub_42F970` | `00–03` |
| `1C` | `sub_42EDF0` | `00–1D`, `40–46`, `60` |
| `1D` | `sub_42D560` | `00–08`, `0A–0F` |
| `1E` | `sub_42CDF0` | `00–07`, `0A–0F` |
| `1F` | `sub_42C6F0` | `00–07`, `0A–0F` |
| `20` | `sub_42BFB0` | `00–07`, `0A–0F` |
| `21–23` | error handler `sub_42FFD0` | — |

“No `BYTE1` switch recovered” does not mean that all subcodes are legal or
that only subcode zero is legal. It means the handler has not been modeled.

## Semantically exposed text instructions

sub_435600 advances one 32-bit word. sub_435560 scans words until it finds a
word containing a zero byte, then advances past that whole word. In the two
confirmed string forms this yields a NUL-terminated inline string followed by
zero bytes through the next 4-byte boundary.

| Full word low 16 bits | Assembly form | Operands | Evidence |
|---|---|---|---|
| 0x421C | .textop mnemonic=TEXT | one inline NUL string | opcode 0x1C, subcode 0x42, sub_42EDF0 case 0x42 calls sub_435600 then sub_435560 |
| 0x6514 | .textop mnemonic=TEXT_PAIR | two inline NUL strings | opcode 0x14, subcode 0x65, sub_4AD100 case 0x65 scans two strings |

The directive stores the exact 32-bit instruction word and the original byte
length of each string. Readable output uses this shape:

    .textop mnemonic=TEXT word=0x0000421C sizes=37
        "...readable text..."

    .textop mnemonic=TEXT_PAIR word=0x00006514 sizes=37,0
        "...first string..."
        ""

Long text is wrapped into quoted UTF-8 fragments. A trailing + means the next
quoted fragment continues the same string; concatenated fragments are assembled
as one operand. The byte 0A displays as the two visible characters \\n, while
CP932 bytes 81 40 display as a literal full-width space. Other unsafe bytes
remain byte placeholders. String terminators and zero alignment are generated
by the assembler. Other instructions are not semantically decoded. Candidate
detection is aligned on 4-byte boundaries and validates NUL termination and
padding; it is not a replacement for full VM instruction-boundary analysis.

## Text encoding and safe-edit limits

- asm.txt files are UTF-8, independent of the selected script codec.
- Disassembly defaults to cp932.
- Assembly defaults to gbk; every visible text operand is encoded using that
  codec, including unchanged text.
- CP932-only characters not representable by GBK are emitted as byte
  placeholders and remain their original source bytes. In this sample set the
  direct-text records contain 6 occurrences of U+30FB and 10 of U+266A.
  Replace these with GBK-supported text if the result must contain no CP932
  leftovers.
- A literal U+3000 is permitted and encoded using the selected codec: CP932
  yields 81 40, while GBK yields A1 A1.
- The assembler currently validates every string against its original byte
  length and rejects a length change. This is a conservative tool limitation,
  not evidence that the VM requires fixed-size text. Static analysis confirms
  NUL-terminated strings scanned in 32-bit words and a body-relative code base;
  changing length is feasible in principle if all affected references and
  section offsets are relocated. The complete instruction/operand map and all
  reference classes are not yet implemented, and no variable-length build has
  been tested in game.
- Bytes outside the two confirmed text forms remain opaque .byte definitions;
  they are not translated, decoded, or relocated.
- {{XX}} and {{XX:YY}} inside a text operand denote exact source bytes and are
  not encoded a second time. Ordinary characters use the assembler codec.

## Current verification

For all 156 files in Seq_unpack (verification of the current conservative prototype):

- 156 UTF-8 asm outputs were regenerated under the canonical asm_jp tree.
  Story files use story/<chapter>-<script>.seq.asm.txt; non-story paths retain
  the data/Seq prefix. The 153 older nested story asm files were left untouched.
  When flattened and nested copies are both in one asm_jp input root, the
  assembler selects the flattened copy.
- The aligned lexical candidate pass accepted 14,169 text-like records and 21,222
  string operands. This is not a CFG-validated instruction count; see the
  newly added corpus-layout evidence below.
- CP932 disassemble/assemble round-trip matched all 156 original scripts byte
  for byte.
- GBK assembly produced all 156 scripts at the original total sizes. Visible
  text was encoded with GBK when representable; CP932-only placeholders remain
  source bytes, while opaque spans and header fields are retained.
- Recursive assembly selected the 156 canonical scripts and mapped them to the
  correct source-relative paths. A single-file disassemble/assemble CLI
  round-trip also passed.
- Newline and full-width-space display tokens round-trip under CP932. A
  same-byte-length edit is accepted; a different-byte-length edit is rejected
  with an explicit relocation warning.

These results establish only preservation and the limited text behavior. They
do not establish complete VM decoding or successful execution of edited scripts
in game.

## Relocation analysis and remaining blockers

### Confirmed address-space result; decoding is still incomplete

The earlier uncertainty about the relocation base is resolved from the IDA
call chain, not from values guessed out of scripts:

- `sub_436110` passes the body slice (`file_base + 0x14`) and `field_0x10` to
  `sub_435F50`.
- `sub_435F50` stores the copied body pointer at CSeq offset `+0x80`, then
  calls `sub_4357D0` with the initial PC `body + field_0x10 + 0x10`.
- `sub_4357D0` calls `sub_435680`; the latter sets CSeq field `+0x6C` (the
  `this+27` field used by `sub_4355E0`) to the body pointer. Therefore
  `sub_4355E0(offset)` is exactly `body_base + offset`, and `sub_4355C0`
  converts a body pointer back to a body-relative byte offset.
- In `story/1000/0000.seq`, `field_0x10=0x1800`; the task header is at file
  `0x1814`, and its first instruction word is at file `0x1824`, i.e. body
  offset `0x1810`. That word is `02:00`; its following dword is `0x1818`.
  `sub_4BF9B0` case 0 returns `sub_4355E0(this, a3[1])`, so this branch lands
  at body offset `0x1818` / file offset `0x182C`, where the next word is the
  valid-looking `0A:03` instruction form. This independently checks the body
  coordinate and one concrete control-flow boundary. It does **not** prove
  every target/table boundary in the corpus.
- In `story/3100/0000.seq`, the `02:1E` table at body offset `0x3E64`
  contains candidate body-relative targets including `0x43E0`; those targets
  map inside the body. This is a computed table whose full span still requires
  VM-state/bound analysis; do not linear-scan its dwords as instructions.

### Operand descriptor and control-flow facts recovered from IDA

- `sub_436690` decodes one address/value operand from the descriptor byte at
  the current word's high byte. `sub_436340` decodes a pair: the first mode is
  byte 2 and the second mode is normally byte 3; when the first mode carries an
  extension or uses an indirect/inline mode, the second descriptor follows the
  consumed extension word(s). Both helpers return a pointer to the next
  dword-aligned descriptor/operand.
- Modes below `0x18` address the current execution frame; `0x18..0x2F` address
  CSeq context slots. Bits `0x40` and `0x80` select extended forms that consume
  a following dword. Mode `0x30` resolves the runtime object slot in
  `sub_435BB0`. Mode `0x3F` makes the output operand location point to the
  following inline dword and consumes that dword. Other `0x31..0x3E` values
  are not safely characterized as valid by this helper alone; the assembler
  must reject them unless a caller/handler proves their meaning.
- This distinction matters for relocation: a `0x3F` operand is not
  automatically an address. It is a value in an inline slot; only when its
  owning handler passes that value through `sub_4355E0` (or writes it to a task
  PC) is it a body-relative relocation. `sub_42BF00`'s `>=0x7FFF0000` branch
  instead selects a runtime table and must not be mistaken for a body pointer.
- Static xref inventory: the VM's body-base conversion `sub_4355E0` is called
  by the instruction handlers in `sub_40E8D0`, `sub_40F320`, `sub_40FDE0`,
  `sub_42DCD0`, `sub_4BE660`, `sub_4BF9B0`, and `sub_4C01D0` (besides VM
  initialization). This is the complete direct-call inventory in the IDA
  pseudocode export; each site still needs operand provenance to decide whether
  the serialized source is a relocatable inline field or a runtime value.
- `sub_40E8D0`, `sub_40F320`, and `sub_40FDE0` share conditional branch
  subcases `0x0B/0x0C`: they decode a single operand and, on one condition,
  convert the following dword through `sub_4355E0`; otherwise they skip that
  dword. These are primary opcodes `0x04/0x05/0x06`.
- `sub_4BF9B0` primary opcode `0x02`: subcase `0x00` is an unconditional
  direct branch; `0x01..0x12` are condition/loop-dependent forms using a
  direct target; `0x1E/0x1F` use `sub_436340` and a computed table; `0x20/0x21`
  choose between two direct target dwords. `sub_4BE660` primary opcode `0x0A`
  uses body-relative values in subcases `0x03/0x06`, branches in `0x0A..0x0D`,
  switches task PCs in `0x0E`, and reads a table base in `0x0F`. `sub_4C01D0`
  primary opcode `0x01` writes task PCs in subcases `0x02/0x03`.
- `sub_42DCD0` primary opcode `0x19` branches through a single converted value
  in subcase `0x0C`; subcases `0x1F/0x20` use tagged `sub_42BF00` operands to
  fetch the runtime index/bound slots, then traverse an inline table whose
  selected code target is passed through `sub_4355E0`. These are distinct
  operand forms: do not apply the `sub_436340` mode/`0x3F` rules to `0x19:0x1F`
  merely because neighboring handlers use them.

### Additional operand and corpus-layout evidence (IDA 9.5 + sample audit)

The IDA database `exe/lus004.exe.i64` was queried with IDAPython `XrefsTo` on
24 November 2026. This confirms the complete *direct xref inventory* for
`sub_4355E0` in that database (47 calls, including one VM initialization call):

| Caller | Direct xrefs (IDA EA) | Relevance |
|---|---|---|
| `sub_40E8D0` | `40EBE8, 40EC28` | primary `0x04` arithmetic/conditional operations |
| `sub_40F320` | `40F65D, 40F69F` | primary `0x05` operations |
| `sub_40FDE0` | `410122, 410164` | primary `0x06` operations |
| `sub_42DCD0` | `42E185, 42E1DE, 42EC25, 42ECEC` | primary `0x19`, including branch/table cases |
| `sub_4BE660` | `4BE756, 4BE7F1, 4BE8AC, 4BE8E2, 4BE920, 4BE965, 4BE9A1, 4BEABD` | primary `0x0A`, including code pointers and task switches |
| `sub_4BF9B0` | 26 sites from `4BF9E2` through `4C0115` | primary `0x02`, direct and computed branches |
| `sub_4C01D0` | `4C02C4, 4C03CD` | primary `0x01`, task-PC writes |
| `sub_436160` | `43619A` | VM reset/initialization, not a serialized operand |

The seven handler groups—not every `sub_4355E0` call in them—are the required
source families for body-relative references. The serialization site is still
handler/case-specific: a conversion may consume an inline word, a `0x3F`
operand, a runtime frame value, or a dynamically indexed table entry. Thus the
xref list bounds the audit; it does not by itself license a global integer
rewrite.

The operand helpers have the following exact cursor behavior in the IDA
pseudocode:

- `sub_435600` consumes exactly one 32-bit word.
- `sub_435560` examines consecutive 32-bit words until *any byte* in a word is
  zero, then returns the following word. It does not prove that the bytes after
  the first NUL in that word are zero padding; those bytes must be retained
  unless separately validated.
- `sub_436690` uses the current word's high byte as its single mode. Plain
  modes `0x00..0x17` resolve frame slots; `0x18..0x2F` resolve CSeq context
  slots; `0x30` resolves the runtime object slot. Plain modes consume one
  word. `0x3F` points at the following inline word and consumes both the mode
  word and inline word. A mode with bit `0x40` consumes one extension word and
  adds it to the selected base; a mode with bit `0x80` consumes one extension
  word encoding an index and displacement. Modes `0x31..0x3E` do not initialize
  a valid output pointer in `sub_435BB0` and are not valid schemas to emit.
- `sub_436340` decodes two modes. Normally they occupy bytes 2 and 3 of the
  current word. If the first mode is extended, its extension word is consumed
  before the second mode is read; a first-mode `0x3F` inline word likewise
  moves the second mode to the following word. Each mode's extension rule is
  the same as above. Cursor position must therefore be computed from the mode
  bits, not from a fixed instruction size.
- `sub_42BF00` always consumes one word. Values in
  `[0x7FFF0000,0x80000000)` select a runtime table entry at
  `table_base + 0x40000 + 4*value` under 32-bit arithmetic; values outside
  that tagged interval use the serialized dword itself. For tagged values
  `0x7FFF0000+n`, the `0x7FFF0000*4 + 0x40000` terms wrap to zero, so the
  effective address is `table_base + 4*n`; this is a runtime variable-table
  slot, not a body-relative offset.

A second corpus audit ran the existing aligned text-candidate parser over all
156 files. In all 155 files with a nonzero story task offset, every accepted
`0x421C`/`0x6514` text candidate ends before the initial task PC
(`file offset = 0x14 + field_0x10 + 0x10`): 14,169 candidates before the entry,
zero after it, zero crossing it. The menu/logo file has a zero task offset and
no accepted candidates. This locates the current candidates relative to the
initial PC; it does **not** establish a standalone string-pool section. For
example, in `story/3100/0000.seq`, an inline text record occurs earlier in the same pre-entry mixed stream, before
a `0x02:0x1E` computed-branch instruction at file `0x3E78` (body offset
`0x3E64`). Code, inline text and tables are interleaved before the initial task
PC. The lexical scanner has not proven that every candidate is reachable or
that it has identified all such text records.

A relocation map must therefore be piecewise, not a single uniform shift. If
an edited, word-aligned text record changes by `delta` bytes, every later body
address moves by that delta; addresses before it do not. Text strings are
word-scanned and each string operand advances to a dword boundary, so record
size deltas must include the NUL and the per-string alignment. A rebuild must
remap `field_0x10`, body size, direct branch/task addresses and computed-table
entries according to their old target positions. The current tools do none of
these and continue to reject byte-length changes.

### Primary `0x19` case-level cursor and relocation schema (IDA pseudocode audit)

The complete `sub_42DCD0` switch was audited case by case against the IDA
pseudocode on 24 November 2026. The low byte `0x19` selects this handler and
`BYTE1(word)` selects the case. `sub_435600` skips the opcode dword;
`sub_42BF00` consumes one following dword and returns the next cursor while
resolving tagged values to runtime slots. Consequently the cases below have
these cursor rules (all offsets are from the opcode start and are body-relative
when they denote serialized code):

| Cases | Serialized operands / cursor rule | Code relocation or control-flow effect |
|---|---|---|
| `00` | One `sub_42BF00` operand; next PC `+8`. | None; diagnostic/value operation. |
| `01` | Two `sub_42BF00` operands; next PC `+12`. | Copies source value through destination pointer; used by the corpus to write runtime slots. |
| `02..05` | Two `sub_42BF00` operands; next PC `+12`. | Arithmetic/bitwise state update only. |
| `06..07` | One `sub_42BF00` operand; next PC `+8`. | Increment/decrement the referenced value. |
| `08..0A` | One `sub_436690` mode operand followed by one `sub_42BF00` operand. Cursor after the first operand is descriptor-dependent; the latter operand is read at that cursor. | Memory/value operations; no `sub_4355E0` conversion in these cases. The first operand's mode must be decoded exactly, not treated as a fixed word. |
| `0B..0C` | One `sub_42BF00` condition/value, then one serialized target dword at `+8`; non-branch next PC is `+12`. | `0B` branches when the value is zero; `0C` branches when nonzero. Taken target is converted by `sub_4355E0`, so the dword at `+8` is a body-relative relocation. |
| `0D..18` | Three `sub_42BF00` operands; next PC `+16`. | Value/arithmetic operations; no body-base conversion in these cases. |
| `19..1A` | Four `sub_42BF00` operands; next PC `+20`. | Four-operand operations; no body-base conversion in these cases. |
| `1B` | Two `sub_42BF00` operands followed by an inline NUL-terminated comparison-operator string. The string begins at `+12`; `sub_435560` scans dwords until any byte is NUL and resumes after that whole dword. | Variable-length instruction; retain bytes after the first NUL within its terminating dword. |
| `1C..1E` | One `sub_436690` mode operand followed by one `sub_42BF00` operand. Cursor after the mode operand is descriptor-dependent. | Copy/conversion operations; no body-base conversion in these cases. |
| `1F..20` | Two `sub_42BF00` operands (runtime index and bound in the corpus forms), then `bound` dword table entries beginning at `+12`. | Each selected entry is converted by `sub_4355E0`. `1F` falls through to `table+bound` when it does not branch; `20` saves `table+bound` through `sub_435530` before the selected branch. Every table dword is a body-relative relocation; the table's byte extent is runtime-bound-dependent. |
| `21` | One `sub_42BF00` operand; next PC `+8`. | Stores handler state and saves the post-operand cursor through `sub_435530`; the saved cursor is derived from instruction layout, not an encoded target. |

This makes the `0x19` relocation sites precise without generalizing the
`sub_42BF00` tagged-value rule to other handlers. For a safe rewriter, `0B`
and `0C` target dwords and all entries in `1F`/`20` tables must be mapped from
old body offsets to new body offsets. A changed `1B` operator string changes
later layout even though it is not a dialogue text operand. The case `20`
remains part of the schema despite the current aligned corpus scan finding no
candidate instance.

The same corpus scan also provides a useful but **not yet reaching-definition**
constraint for the `1F` table's variable slots. In the 155 non-menu SEQF files,
an aligned-word scan found three candidate `19:01` writes to slot 4 in each
file, with immediate values `2`, `3`, and `4`; it found three candidate writes
to slot 7, two from immediate `-1` and one copied from slot 5. This is
consistent with `sub_42DCD0` case `1` and the tagged-slot arithmetic recovered
above. These repeated forms lie at/after the initial task PC in the audited
samples. Their existence does not prove which write reaches any preceding
`19:1F` site: instruction-boundary recovery, task/branch reachability, and
path-sensitive slot state are still required.

### Cross-handler control-flow relocation inventory (IDA pseudocode audit)

The next pass audited the other direct `sub_4355E0` call families that can
supply serialized control-flow addresses. The key rule is provenance: a handler
calling `sub_4355E0` on a runtime value does **not** make the operand that
produced that value a relocation. Only an inline serialized value (for example,
a `sub_436690`/`sub_436340` mode-`0x3F` value, or an explicit following dword)
is patchable as a static relocation. Register/frame/context modes are runtime
values and must not be rewritten as offsets merely because they later become a
PC.

| Handler / cases | Confirmed serialized layout and effect | Relocation consequence |
|---|---|---|
| Primary `0x02`, cases `00..12` | Each case has a direct target dword immediately after the opcode. Depending on the condition/counter, the handler either returns after the two-dword form or converts `a3[1]` with `sub_4355E0`. Case `00` is an unconditional jump; `01..09` are conditional jumps. Case `0A` is an unconditional call, and `0B..12` are condition-dependent calls. | The target field is at `+4` for every such form, whether taken or not. Patch it as body-relative; retain the full 8-byte instruction when the branch is not taken at runtime. Calls save the post-instruction cursor (`+8`) through `sub_435530` before transferring. |
| Primary `0x02`, cases `13..1D` | These are return/loop-stack cases. They either pop/use a PC previously saved by the VM or advance over the opcode; case `1C` decodes a mode operand and saves the resulting cursor with `sub_435530`, and case `1D` returns to a saved PC or pops the loop stack. | No statically encoded body-target field is identified in these cases; runtime stack PCs are produced by other instructions and are remapped by relocating their original source instruction/target. |
| Primary `0x02`, cases `1E..1F` | `sub_436340` resolves index and bound operands, returning the cursor at the start of a variable-length dword target table. The bound determines table extent; selected entries go through `sub_4355E0`. Case `1F` also saves the table-end cursor with `sub_435530` on the taken path. | Every table entry is a body-relative target. Table start is descriptor-dependent, not a fixed `opcode+N`; remap its selected targets and compute its extent only after decoding the operand modes and bound source. |
| Primary `0x02`, cases `20..21` | Two direct target dwords follow the opcode; the condition selects `a3[1]` or `a3[2]`. Case `21` saves the cursor after both targets (`opcode+12`) through `sub_435530`. | Both target fields at `+4` and `+8` are body-relative relocations, including the unselected one. |
| Primary `0x0A`, cases `0A..0D` | A `sub_436690` operand supplies a possible target. `0A` directly sets the next PC to `body_base + *operand`; `0B/0C` conditionally do so; `0D` saves the post-operand cursor then branches. | First decode the mode. A mode-`0x3F` inline dword is a static body-relative relocation; frame/context values are dynamic and must not be patched. The `0D` saved return cursor is derived from the instruction end and follows layout automatically. |
| Primary `0x0A`, cases `03/06/07/0E` | These use `sub_436340`; cases `03/06` convert the second resolved value through `sub_4355E0`, case `07` converts a pointer back through `sub_4355C0`, and case `0E` stores a converted value as a task PC. | Static patching is conditional on the operand mode/provenance. Do not mark all pair operands as offsets. Case `07` is a runtime pointer-to-offset conversion, not itself a file relocation. |
| Primary `0x0A`, case `0F` | After the descriptor-dependent operand pair, an explicit dword at the returned cursor is converted by `sub_4355E0` and used as a table base; the handler consumes that base dword. | The explicit base at the returned cursor is a body-relative data-pointer relocation. The pointed-to table contents require separate use analysis before classifying its entries as code pointers. |
| Primary `0x01`, case `02` | A task-index byte is followed by one explicit body offset at `+4`; `sub_4355E0` stores the resulting pointer in that task's PC. The serialized cursor advances by two dwords. | The dword at `+4` is a definite body-relative relocation. |
| Primaries `0x04..0x06`, cases `0B..0C` | Each handler decodes one condition operand with `sub_436690`; the returned cursor points to a direct target dword. Case `0B` branches when the value is zero; case `0C` branches when nonzero. A taken branch converts that dword with `sub_4355E0`; otherwise the handler skips it. | For both cases the dword at the descriptor-dependent post-operand cursor is a body-relative relocation. The site is not a fixed `opcode+N`; mode `0x3F` consumes its own inline value before this target. |
| Primary `0x01`, case `03` | A `sub_436690` operand supplies the value converted by `sub_4355E0` and stored as a task PC. | Patch only if descriptor decoding proves that the value is inline (not a frame/context/runtime operand); cursor size is descriptor-dependent. |

The same operand-provenance caution applies to task switches: task-PC writes in
`0x01:02/03`, `0x0A:0E`, and related forms may carry either encoded body
offsets or values computed at runtime. The currently known direct-relocation
inventory is therefore not yet a complete relocation table: the static
instruction-boundary decoder must report, for each decoded operand, its source
mode and whether it points into the file, before an assembler is allowed to
rewrite it.

### Call-generated continuation and slot-state follow-up

A concrete call edge was recovered in `story/6051/0000.seq`, which explains why
a same-file search for a dword equal to the `0x19:0x1F` opcode offset was not a
sufficient reachability test. In body coordinates, the instruction at `0x1744`
is primary `0x02`, case `0x0A`, and its explicit target operand is `0x4558`.
`sub_4BF9B0` case `0x0A` pushes `a3+2` (the address after the two-dword call,
`0x174C`) via `sub_435530`, then transfers to `body_base + target`. Therefore
`0x174C` is a call-return continuation and is exactly the aligned
`0x19:0x1F` candidate previously inventoried there. This establishes a valid
call-generated entry mechanism, but not yet that the call at `0x1744` is
reachable from the file's initial PC or that every path through `0x4558`
returns to it.

The nearby structure is consistent with, but does not yet prove, the switch's
reaching definitions: another `0x02:0x0A` at `0x173C` calls `0x4240` and would
resume at `0x1744`; an aligned `0x19:0x01` candidate at `0x4240` writes `3` to
slot 4; and a candidate `0x19:0x01` at `0x4848` copies slot 5 to slot 7 within
the `0x4558` region. Resolving whether those are the actual reaching writes
requires decoding all intervening branch/loop and return paths (including
whether the `0x4558` region returns normally), not merely matching offsets.
This is now a concrete path to trace rather than an unresolved generic
possibility.

A separate entry-seeded prefix trace is now established for the same script.
Its header has `field_0x10=0x3794`, so the initial task PC is body offset
`0x37A4`. The `0x02:0x00` there targets `0x37AC`; the two following
`0x0A:0x03` pair-mode instructions use second mode `0x3F` and inline body
pointers `0x48C4` and `0x4CC4`, respectively. `sub_4BE660` case `03` converts
the second value with `sub_4355E0`, so these inline dwords are definite
body-relative data/code pointers to remap (the pointed-to words at those
coordinates begin with valid-looking `0x19:0x1B` and `0x04:0x03` forms).
The intervening `0x04:0x01` and `0x18:0x04/06/08` instructions consume their
confirmed operand-mode layouts and return to the next cursor. The instruction
at `0x37E4` is `0x02:0x0A` with target `0x3E64`; case `0A` saves return PC
`0x37EC` and transfers there. This proves one direct path from the initial PC
to an earlier body region and confirms that body-relative pointers are not
limited to the text opcodes. It does not yet trace beyond `0x3E64` or prove the
`0x173C`/`0x1744` call chain is reached on a game path.

### Computed-table corpus audit

Static handler analysis plus a bounded structural audit now recovers the table
span for every aligned `0x19:0x1F` candidate in this corpus. The bound value is
still a runtime slot, so this result does not by itself prove reachability or
reaching definitions:

- The corpus has 11 aligned `0x02:0x1E` candidates across seven files. All use
  mode pair `0x13,0x3F`: the first operand is a frame value, while the second
  is an inline bound. The inline bound is 2 in two samples and 3 in nine; that
  many following dwords are table entries passed through `sub_4355E0`. In
  `story/3100/0000.seq` the bound is 3 and the table at file `0x3E80` is
  `[0x43E0, 0x3E78, 0x488C]`; the next sequential instruction begins at
  `0x3E8C`. This observed form has a statically recoverable table span. The
  aligned candidate scan found no `0x02:0x1F` form in the 156-file corpus.
- It found 31 aligned `0x19:0x1F` candidates across 28 files. In each, the
  instruction is followed by the tagged dwords `0x7FFF0007` and `0x7FFF0004`.
  `sub_42BF00` accepts tags in `[0x7FFF0000,0x80000000)` and computes
  `*(root+0xE4) + 4*tag + 0x40000` using 32-bit x86 address arithmetic. For
  `tag=0x7FFF0000+n`, this simplifies modulo `2^32` to
  `*(root+0xE4) + 4*n`: these two operands therefore read runtime variable
  slots 7 and 4, respectively (index and bound), not large offsets or branch
  targets. In `sub_42DCD0` case `0x1F`, `sub_435600` advances over the opcode
  and the two `sub_42BF00` calls each consume one dword, so the inline target
  table starts exactly 12 bytes after the instruction start. If the table
  branch is not taken (including an out-of-range index), the handler returns
  `table + bound` as the next sequential PC; if taken, the selected table
  value is converted by `sub_4355E0` to a body-relative code address. Thus the
  bound controls both the table extent and the fall-through boundary.
- The table base at object offset `+0xE4` is allocated by `sub_435AC0`; that
  routine stores the element count at `+0xE8` and zero-initializes all
  `4*count` bytes. The slots are then mutable VM variables. An aligned corpus
  scan finds recurring `0x19:0x01` writes assigning constants 2, 3, and 4 to
  slot 4, and writes to slot 7; these raw writes are not yet a reaching-def or
  reachability proof for any particular table branch.
- For the 31 aligned candidates, a constraint pass considered candidate bounds
  against the handler's exact fall-through rule, dword alignment, in-body table
  targets, and the IDA-confirmed primary/subopcode dispatch cases at each
  target and fall-through. It yields a unique structurally valid bound for
  every candidate: 30 tables have 2 entries, and one table has 3. In
  `story/6051/0000.seq` at body offset `0x174C`, the table starts at `0x1758`
  and its three targets are `[0x1764, 0x1A84, 0x1D68]`. Bound 2 would resume at
  `0x1760`, whose bytes decode as invalid primary opcode `0x68`; bound 3 resumes
  at `0x1764`, a valid three-instruction sequence: `1C:00` at `0x1764`, its
  `09:00` operand dword at `0x1768`, and `1C:42` at `0x176C` (target + 8).
  Bound
  4 would treat the dword `0x1C` at `0x1764` as a target into the resource-path
  data at body offset `0x1C`. Bounds 1 and greater than 4 likewise violate the
  confirmed dispatch/target constraints. The two initially ambiguous forms
  also resolve using exact handler subcodes: `0x04:0x2B` is not a valid
  fall-through subcase of `sub_40E8D0`, and `0x0C:0x37` is invalid for
  `sub_4BD690`, ruling out a one-entry interpretation there. Across the 63
  selected table targets, the aligned starts are 40 `0x1C:0x00` records, 12
  `0x10:0x04` forms, 8 `0x14:0x78` forms, and 3 `0x02:0x00` branches; each
  matches a recovered handler/subopcode in IDA.
- All 31 candidates lie before their file's initial task PC. A same-file scan
  found no literal dword equal to any candidate's body offset elsewhere in
  that file. This rules out an obvious direct dword reference to the candidate
  start, but not call-generated continuation, fall-through, task-table/indirect
  entry, or cross-file/runtime setup. The two `6051` candidates at `0x10E4`
  and `0x174C` are now specifically explained as call-return continuations;
  the other 29 candidate entries remain unproved.
- This recovers the *serialized table spans* for these aligned corpus
  candidates without guessing from dword appearance. For the two `6051`
  candidates, the shared callee and its local control flow are additionally
  decoded below. Interprocedural entry reachability and slot 4/7 reaching
  definitions for every other candidate remain open. Runtime tracing is only
  a fallback if static data-flow cannot settle those paths. The aligned scan
  found no `0x19:0x20` form in this corpus.

The candidate inventory and structurally recovered entry count (body offsets):

| Script | Body offset | Entries |
|---|---:|---:|
| `story/1050/0000.seq` | `0x1D60` | 2 |
| `story/2100/0000.seq` | `0x90B8` | 2 |
| `story/3100/0000.seq` | `0x4068` | 2 |
| `story/3100/0000.seq` | `0x45B4` | 2 |
| `story/3100/0000.seq` | `0x4AC0` | 2 |
| `story/4100/0000.seq` | `0x4B7C` | 2 |
| `story/4110/0000.seq` | `0x4970` | 2 |
| `story/6051/0000.seq` | `0x10E4` | 2 |
| `story/6051/0000.seq` | `0x174C` | 3 |
| `story/8000/0000.seq` | `0x27EC` | 2 |
| `story/8010/0000.seq` | `0x3580` | 2 |
| `story/8020/0000.seq` | `0x26C8` | 2 |
| `story/8030/0000.seq` | `0x3284` | 2 |
| `story/8040/0000.seq` | `0x25FC` | 2 |
| `story/8041/0000.seq` | `0x2A48` | 2 |
| `story/8050/0000.seq` | `0x2550` | 2 |
| `story/8051/0000.seq` | `0x217C` | 2 |
| `story/8080/0000.seq` | `0x2680` | 2 |
| `story/8081/0000.seq` | `0x1E4C` | 2 |
| `story/8090/0000.seq` | `0x3010` | 2 |
| `story/8091/0000.seq` | `0x20F4` | 2 |
| `story/8100/0000.seq` | `0x1FDC` | 2 |
| `story/8101/0000.seq` | `0x2258` | 2 |
| `story/8120/0000.seq` | `0x2D0C` | 2 |
| `story/8121/0000.seq` | `0x1F30` | 2 |
| `story/8180/0000.seq` | `0x2DFC` | 2 |
| `story/8181/0000.seq` | `0x24A8` | 2 |
| `story/8220/0000.seq` | `0x2E0C` | 2 |
| `story/8221/0000.seq` | `0x2844` | 2 |
| `story/8230/0000.seq` | `0x20B4` | 2 |
| `story/8231/0000.seq` | `0x2118` | 2 |

This resolves the coordinate system only; it does not complete relocation.
The remaining blockers are concrete:

1. Produce an exact operand/length schema for every handler/subopcode used by
   the corpus and every valid VM addressing mode. `sub_436340` and
   `sub_436690` encode mode descriptors in instruction high bytes, with
   optional following words; the pointer they return depends on the descriptor
   (including the special `0x3F` inline-address mode).
2. Separate executable instructions from embedded data. The `0x02:0x1E` form
   and all aligned `0x19:0x1F` candidates now have structurally recovered spans
   in this corpus. Prove which candidates are executable by recovering task
   entries, task switches, and reaching definitions for slots 4 and 7. Analyze
   the handler's `0x20` sibling if it appears in future samples; no aligned
   instance appears in the current corpus.
3. Enumerate all entry points, task switches, computed branches and relocation
   sites; then prove every target is an instruction boundary and no data word
   was rewritten as a code offset.
4. Only after (1)-(3), implement two-pass layout and body-relative relocation,
   updating the SEQF body length and any affected embedded structures. Validate
   byte-identical round-trips for unchanged files, variable-length edits, and
   runtime behavior in the game.

The supplied IDA pseudo-C/assembly and unpacked corpus are enough to continue
static analysis; no additional static artifact has been identified as a
blocker. Runtime traces or a safe game test copy may be needed to settle
value-dependent table boundaries and to verify rendered translations. Until
then, `assembler.py` intentionally rejects changed text byte lengths. This is
a tool-safety restriction, not a claim that the engine forbids longer text.


### Inline NUL-scan call-site audit (IDA pseudocode, 24 November 2026)

The previous two-form text list is **not** the complete set of calls to
`sub_435560`. I audited every direct call in `lus004_pseudoc.c` and separated
actual string consumers from callers that merely use the helper to advance a
cursor. This matters because the helper scans 32-bit words until a zero byte;
its name/call alone does not prove that the input is a user-visible string.

| Primary / subcode | Cursor before scan | Static consumer/effect | Classification for translation / relocation |
|---|---|---|---|
| `0x1C:0x42` | opcode + one dword | `sub_487C10` receives the following pointer; handler then scans from the same pointer | Confirmed inline display-text form `TEXT`; NUL-terminated and word-padded. |
| `0x14:0x65` | opcode + one dword; scan string 1, then scan string 2 | `sub_46C5B0` receives the two string pointers | Confirmed two-inline-string form `TEXT_PAIR`; semantic consumer is static, but whether both fields are player-facing should be decided by script context. |
| `0x04/0x05/0x06:0x1B` | after `sub_436340`'s descriptor-dependent operand pair | Compares the inline bytes against `<`, `>`, `==`, `!=`, `<=`, `>=` and writes the comparison result | Operator token, not translatable prose. Cursor depends on both mode bytes/extensions; do not assume fixed `+12`. |
| `0x07:0x15` | after `sub_436340` operand pair | Same one-/two-byte relational operator vocabulary | Operator token, not prose; descriptor-dependent. |
| `0x19:0x1B` | opcode + 3 dwords (`sub_435600`, then two `sub_42BF00` operands) | Compares the inline bytes against the same relational operator vocabulary | Operator token; exact scan start is `+12` for this handler form. |
| `0x1B:0x00/0x01` | opcode + one dword, then a `sub_42BF00` value operand | Passes the following inline string to `sub_437750` / `sub_4376F0` | String-valued runtime operation; not confirmed UI text. Must be represented distinctly from `TEXT`. |
| `0x18:0x02/0x03` | after `sub_436340` operand pair | Passes the inline string to `sub_4300F0` / `sub_4300C0` and stores the returned value | String operation; semantics not established as display text. Descriptor-dependent. |
| `0x0F:0x02` | after `sub_436340` pair | Scans two consecutive inline strings and passes both to `sub_42BD60` | Two string operands; semantic role not proven as player-facing. Each string is word-terminated independently. |
| `0x0F:0x03` | opcode + one dword | Passes one following string to `sub_42B1C0` | String operand; role not proven as player-facing. |
| `0x0F:0x0A` | after `sub_436690` single operand | Passes the following string to `sub_42B9A0` | String operand; descriptor-dependent. |
| `0x0E:0x02/0x03` | after `sub_436340` pair | Passes the following string to `sub_430150` / `sub_430120`, then stores result | String operation; role not proven as UI text. Descriptor-dependent. |
| `0x10:0x03` | after `sub_436690` single operand | Sends following string to `sub_43B6B0` | Resource/manager string; not confirmed prose. Descriptor-dependent. |
| `0x10:0x06` | after `sub_436340` pair | Sends following string to `sub_43B4D0` | Resource/manager string; not confirmed prose. Descriptor-dependent. |
| `0x10:0x64` | after `sub_436690` single operand | Formats following string as `data/Sound/voice/%s.wav` | Voice resource name, not prose. Descriptor-dependent. |
| `0x10:0x66` | after `sub_436690` single operand | Passes the following pointer to `sub_428280` | String operand; purpose not resolved. Descriptor-dependent. |
| `0x10:0x67` | current opcode cursor in the decompilation | Passes current cursor to `sub_426F60`, then calls the scanner on that cursor | The call does not establish a string operand; likely cursor advancement for this form. Keep opaque until the surrounding handler semantics prove otherwise. |
| `0x00:0x04` | one dword after the opcode | Calls an unknown runtime helper, then scans from that dword | Possible inline string/word sequence, consumer unresolved; not promoted to translatable text. |
| `0x00:0x0B` | after `sub_436690`, plus one additional dword | Scans from the resulting cursor | Exact byte span is descriptor-dependent; semantic use unresolved. |
| `0x10:0xAA/0xAB` | current opcode cursor in the decompilation | Scanner is called on the current cursor, with no distinct string-pointer argument | A direct helper call is not sufficient evidence of a C-string operand; do not classify as editable text. |

The direct call-site inventory also includes nested/helper uses and the scanner
implementation itself. It does **not** prove that every listed form occurs on a
reachable path in the 156-script corpus. In particular, where a handler passes
a pointer through a descriptor resolver, the resolver's runtime value and its
serialized cursor are separate facts: use the descriptor rules above to
calculate the cursor, but never infer a body relocation from a string pointer.

This audit confirms that the current `TEXT` and `TEXT_PAIR` forms are the only
forms currently proven as the VM's player-facing inline text interfaces. It
also exposes additional serialized variable-length string operands that a
complete instruction-boundary decoder must skip correctly, even though they
are not safe translation targets. The assembler must remain length-preserving
until those forms, every task/branch/table target, and every entry into embedded
regions are modeled. No claim of arbitrary-length relocation follows from this
call-site inventory alone.

### Descriptor-cursor proof and variable-string corpus audit (24 November 2026)

A byte-by-byte reread of `sub_436690` and `sub_436340` corrected an important
cursor detail: ordinary pair operands do **not** automatically consume two
extra dwords. The mode descriptor(s) can be in the opcode dword itself; only
extended modes and the special inline mode add serialized dwords. Let `p` be
the opcode dword start and `M` a descriptor byte.

| Decoder | Descriptor location / mode | Cursor returned by helper |
|---|---|---:|
| `sub_436690` (single) | `M = byte[p+3]`; ordinary `M < 0x18`, `0x18..0x2F`, or `0x30..0x3E` | `p+4` |
| `sub_436690` (single) | `M & 0x40` or `M & 0x80` | `p+8` (one extension dword at `p+4`) |
| `sub_436690` (single) | `M == 0x3F` | `p+8` (the inline-value slot at `p+4` is consumed) |
| `sub_436340` (pair) | first descriptor `byte[p+2]` is ordinary and not `0x3F`; second descriptor is `byte[p+3]` and is ordinary | `p+4` |
| `sub_436340` (pair) | first descriptor is ordinary/non-`0x3F`; second descriptor `byte[p+3]` is extended or `0x3F` | `p+8` |
| `sub_436340` (pair) | first descriptor is `0x3F`; its inline dword is `p+4`; second descriptor is `byte[p+4]` | `p+8` if second is ordinary, `p+12` if second is extended/`0x3F` |
| `sub_436340` (pair) | first descriptor is extended (`&0x40`/`&0x80`); its extension is `p+4`; second descriptor is `byte[p+8]` | `p+12` if second is ordinary, `p+16` if second is extended/`0x3F` |

The returned cursor is the start of the next dword. `0x30` and `0x31..0x3E`
have no extra serialized dword in these helpers, although only `0x30` and
`0x3F` receive special handling in `sub_435BB0`; semantic validity of the
other mode values remains caller-dependent. This table is a cursor rule, not a
claim that the value resolved by a mode is a relocatable file address.

I then applied those cursor rules to every 4-byte-aligned raw opcode signature
in all 156 samples. These are signature/layout candidates, not CFG-confirmed
instruction counts. The direct dialogue-like forms have stronger validation:
all `0x1C:0x42` and `0x14:0x65` candidates have a CP932 NUL-terminated string
sequence in bounds, with zero bytes from the first NUL to the helper's next
word boundary. Counts are 7,116 `0x1C:0x42` records and 7,053 `0x14:0x65`
records (14,169 combined), matching the earlier lexical pass exactly.

The `0x14:0x65` consumer `sub_46C5B0` copies the first string into an object
text field, copies the second into a separate 16-byte field, and computes the
character count from the first. Corpus examples show the second operand has
voice IDs such as `0000_sies_0000`; thus the **first operand is translatable
line text and the second is a resource/synchronization ID that should remain
unchanged**. `0x1C:0x42` stores a string on a UI/runtime object and computes its
character count in the relevant object mode; it is also retained as an inline
text operand, but context should be reviewed before translating every instance.

Other confirmed variable-length scan sites produce non-prose or unresolved
operands in this corpus. The aligned candidate counts and representative
handler-level classifications are:

| Handler form | Aligned candidates | Evidence / consequence |
|---|---:|---|
| `0x19:0x1B` | 2,945 | Inline strings consumed only as relational operators (`<`, `>`, `==`, `!=`, `<=`, `>=`); never translate. |
| `0x1B:0x00` | 2,151 | `sub_437750` / `sub_4376F0` store string-valued slots; examples are `data/Pic/...` paths; preserve as resources. No `0x1B:0x01` candidate was found. |
| `0x10:0x03` | 157 | Audio manager receives inline names; examples include `data/Sound/SE/0003.wav`. |
| `0x10:0x06` | 151 | Audio/asset manager receives the string; corpus examples are the one-byte marker `?`; do not treat as prose. |
| `0x10:0x64` | 2,779 | Voice playback string; examples such as `0000_sies_0000` are resource IDs. |
| `0x10:0x66` | 21 | Video playback/resource paths such as `data/Movie/EV0000_01.wmv`. |
| `0x04/0x05/0x06:0x1B` | 13 | Comparison-operator path exists in IDA, but candidates did not yield the recognized ASCII operator vocabulary; boundary/reachability needs CFG confirmation. |
| `0x18:0x02/0x03` | 4 | String-based numeric/value helper; observed aligned candidates begin with control bytes, not prose. |
| `0x00:0x04` | 469 | Scanner starts at the next dword, which is empty in sampled candidates; unknown runtime-helper operand, not exposed as text. |
| `0x00:0x0B` | 3 | Mode-dependent skip plus scan; sampled candidate strings are empty; semantic role unresolved. |

The corpus contains no aligned signatures for the handler string cases
`0x0E:0x02/0x03`, `0x0F:0x02/0x03/0x0A`, `0x07:0x15`, or `0x1B:0x01`.
Their handlers still define possible variable-length operands and must be
modeled for engine completeness, but current script corpus gives no examples.
This audit therefore supports the practical translation target set for this
game without claiming every engine-valid string case has been discovered.

This analysis materially narrows the text-format scope, but it does **not**
complete relocation: a length change in either editable operand changes a
word-rounded record extent and shifts later body offsets. The script header's
body size and entry offset, direct branch/call targets, task PCs, computed
switch entries, and data/code pointers must all be rebuilt from proven
instruction boundaries. The byte-identical 156/156 round-trip remains the
current tool acceptance; the assembler continues to reject changed byte
lengths until the relocation graph is complete.

### `6051` switch-table target and text-block CFG follow-up

The earlier `story/6051/0000.seq` candidate was followed through the exact
serialized words rather than inferred from a same-file value search. This is
stronger than the former candidate-only evidence:

- At body `0x173C`, `02:0A` calls `0x4240`; its return continuation is `0x1744`.
  At body `0x1744`, another `02:0A` calls `0x4558`; its return continuation is
  `0x174C`.
- `0x4240` is `19:01` with operands `0x7FFF0004` (context slot 4) and literal
  `3`, so the handler's `sub_42BF00` semantics write `slot[4] = 3`.
- A second call-return site in the same script has the matching two-entry
  form: `02:0A` at `0x10DC` calls `0x4558` and saves continuation `0x10E4`.
  At `0x10E4`, `19:1F` reads slot 7/slot 4 and its table at `0x10F0` is
  `[0x10F8, 0x1418]`; at each target, `1C:00` begins at target + 0, the
  `09:00` operand dword is at +4, and `1C:42` begins at +8. The preceding code
  calls `0x413C`, whose first
  instruction `19:01` writes literal 2 to context slot 4. This is strong
  structural consistency with the two-entry table; the full path-sensitive
  proof that this definition reaches `0x10E4` is still pending.
- The continuation at `0x174C` is `19:1F`. Its two runtime operands are
  `0x7FFF0007` (slot 7, index) and `0x7FFF0004` (slot 4, bound). The dynamic
  table starts at `0x1758`, has the three dwords expected under the candidate
  `slot[4] = 3` definition at `0x4240`, and ends at `0x1764`:

      0x1758: 0x00001764
      0x175C: 0x00001A84
      0x1760: 0x00001D68

  Each target is 4-byte aligned and has `1C:00` at target + 0, the `09:00`
  operand dword at +4, and the structurally validated `1C:42` inline-text
  form at +8. The `0x1764` target is also
  the table-end fall-through used when slot 7 is negative/out of range. This
  confirms that the handler interprets this span as dispatch data and that its entries
  point at inline text command blocks—not arbitrary dword lookalikes.
- In the called region beginning at `0x4558`, the local instruction-boundary
  trace decodes the `19:1B` operator strings and direct `02` branches. The
  conditional branch at `0x478C` targets `0x47F8`; at `0x47F8`, `0x4810`, and
  `0x4828`, each `12:02` + `04:03` sequence is followed by a direct
  `02:02` edge to `0x4848`. The instruction at `0x4848` is `19:01`, copying
  context slot 5 to slot 7. Thus a concrete slot-7 reaching write exists on
  this local CFG path; the following compare/branch makes the distinction
  between a valid table index
  and the `-1` loop/sentinel state explicit.

A cursor-level decode of the shared callee range `[0x4558, 0x48C4)` using
its IDA handler schemas yields 94 instruction starts. Every direct branch
inside the range lands on one of those starts; conditional edges and call
continuations make the local CFG traverse all 94 starts. The terminal `02:13`
at `0x48C0` pops the saved PC, so on the call from `0x1744` it returns to
`0x174C`; on the call from `0x10DC` the same callee returns to `0x10E4`. A
third call at `0x4880` targets `0x4558` and saves continuation `0x4888`,
confirming the callee is re-entered from its own dispatch loop. This establishes
these return edges and local instruction boundaries without relying on raw
same-file dword xrefs. It does not prove that the outer callers are themselves
reachable from the SEQF initial task entry.

The post-store block at `0x4854` compares slot 7 with `-1` using `!=`; the
`02:01` at `0x4864` branches to `0x4874` when that comparison is false. The
non-sentinel path falls through to `02:00 -> 0x4884`, while the sentinel path
enters the `0x4874` task/loop block. This matches the consumer at `0x174C`:
indices 0, 1, and 2 select the three table entries; an index outside the bound
(including the loop sentinel) takes the table-end fall-through. The local trace
therefore proves an internally consistent index/bound/table interpretation.

This is now enough to prove the serialized table extent, all three table
relocations, the callee's local slot-7 writer and sentinel check, and the
opcode boundaries of these target blocks for this sample. It is **not yet**
enough to prove that the initial task entry reaches `0x173C` on every relevant
runtime path, or that all values reaching slot 7 at `0x174C` come from the
`0x4848` write. The target routine has loop/sentinel paths, task yields, and
additional callers; its full interprocedural reaching-definition proof remains
open.

### Entry-seeded task-0 prefix and definite pointer relocations (24 November 2026)

The loader-to-task initialization path was checked directly in the IDA pseudocode,
then audited against every non-menu story sample. `sub_436110` passes the SEQF
body, `field_0x10`, and body length to `sub_435F50`. The latter reads three
16-bit task-header values at header-relative offsets `+0`, `+4`, and `+8`, then
calls `sub_4357D0` with initial task PC `body + field_0x10 + 0x10`.
`sub_4357D0` initializes task state and calls `sub_435660(task=0, pc=initial_pc)`.
Thus this is a loader-proven task-0 seed, not a guessed aligned signature.

A conservative, handler-backed prefix trace was then performed on all 155
non-menu story scripts (the remaining menu/logo script has `field_0x10=0` and
is a different layout):

1. At the seeded PC, all 155 begin with `02:00`; the explicit body-relative
target at `+4` is in-bounds/aligned and begins with `0A:03`.
2. Two consecutive `0A:03` records follow. Their descriptor pairs are
`(0x01, 0x3F)` then `(0x1D, 0x3F)` in all 155 files. The `0A:03` case `3` in
`sub_4BE660` resolves the second operand through `sub_4355E0` and writes it to
the destination selected by the first descriptor. Therefore the inline dwords
at `+4` of both records are definite body-relative pointer relocations, not
values inferred from raw dword searches. Both targets are in-bounds; the first
has a `19:1B` word and the second a `04:03` word at its target. A follow-up IDA
scheduler audit establishes both as secondary code-entry roots: mode `0x01`
selects the current task record's `+4` callback PC, and mode `0x1D` selects the
CSeq object's `+36` global callback PC. `sub_436B10` runs those pointers via
`sub_435F20` (per-task callback before that task's `sub_435C00` PC; global
callback when its event/timer flags fire). These entries are not reached by
simply fall-through linear scanning from the task-0 initializer.
3. The prefix continues through two `04:01` pair-mode records, then
`18:04`, `18:06`, `18:08`, each with a `0x3F` inline-value descriptor, and an
`02:0A` direct call. These forms and extents are identical across the 155
samples. That call targets a `1B:00` resource-setting stream.
4. Each such stream contains four `1B:00` resource records (IDs `0x18..0x1B`),
whose NUL scans terminate at word boundaries, followed by an `02:0A` call to a
small wrapper. In all 155 samples, that wrapper is `02:0A <body-offset>; 02:13`:
it calls a nested resource stream, then returns. The outer resource stream's
call continuation is also `02:13`, which returns to the task-0 continuation.
The nested stream begins at a body-relative target (zero in the audited
examples), contains 0–24 `1B:00` records depending on the script, and terminates
at `02:13`. These call/return edges are decoded from the handler semantics,
not from coincidental dword values.
5. After the returns, the task-0 continuation has a stable handler-backed
sequence: `12:00`, `0A:01`, nine `12:08` pair-plus-single operations, another
`12:00`, another `0A:01`, then `19:01` writing 1 to context slot 8, `14:66`, and
six `19:01` context initializers (slots 9, 10, 11, 13, 14, 12 with values
0, 0, 1, 0, 0, 0). All 155 traces then reach a real `1C:00` dispatch word at
the recovered cursor. The `14:66` descriptor and the `19:01` operands were
cursor-checked against their IDA handlers.

The corpus trace therefore proves a loader-seeded, call/return-connected
prefix in every non-menu story sample, two `0A:03` inline body pointers per
file, and additional direct call relocations in the resource setup. The IDA
scheduler follow-up adds two typed callback roots per story file (per-task
record `+4` and CSeq `+36`) to the required CFG seed set. The task-0 linear
prefix itself still ends at the first post-initializer `1C:00`; these secondary
entries are reached through `sub_436B10`/event scheduling, not through a simple
linear walk from that PC. This does not prove reachability of later candidates
such as `6051`'s `0x173C` call site, nor any blanket boundary fact for unrelated
aligned words, other task-PC writes, or computed tables.

#### Exact target layout and round-trip checkpoint (24 November 2026)

A direct byte check of the five `6051` computed-table destinations confirms the
same exact 12-byte prefix at each target; this replaces the earlier imprecise
wording that implied adjacent opcodes:

| Target body offset | `1C:00` | operand dword | `1C:42` text opcode |
|---:|---:|---:|---:|
| `0x10F8` | `+0` | `+4 = 0x00000009` | `+8` |
| `0x1418` | `+0` | `+4 = 0x00000009` | `+8` |
| `0x1764` | `+0` | `+4 = 0x00000009` | `+8` |
| `0x1A84` | `+0` | `+4 = 0x00000009` | `+8` |
| `0x1D68` | `+0` | `+4 = 0x00000009` | `+8` |

The whole available corpus was re-run in memory through
`disassemble_bytes(..., "cp932")` and `assemble_text(..., "cp932")`: 156/156
files rebuilt byte-for-byte. This verifies only the existing no-edit
round-trip. It does **not** validate changed text lengths, relocation coverage,
GBK translation output, or runtime behavior. The assembler's length guard remains
required until the address-bearing fields and executable/data boundaries are
modeled comprehensively.

The location audit also found all 14,169 structurally valid inline text-form
records in the 155 task-header story scripts physically before
`field_0x10 + 0x10`, the
initial task PC (minimum gap after the last text record: 28 bytes). This is a
physical-order fact only—not proof of a separate non-executable text section.
The `6051` table above proves that code/data structures can reference these
pre-entry text blocks, so they must be treated as addressable code/data labels
by the eventual relocator. It is unsafe to simply append edited text to a new
pool or to shift the initial task entry alone.

### Task-PC writers, scheduler, and external-handler audit (24 November 2026)

This pass followed the executable task-PC field through the IDA pseudocode
rather than inferring task creation from code-looking dwords. Evidence is from
`exe/lus004_pseudoc.c` and the matching IDA database `exe/lus004.exe.i64`.

`sub_436B10 @ 0x436B10` is the outer VM tick. It first services global
event/timer flags and, when triggered, runs the CSeq callback pointer at
`this + 0x24` through `sub_435F20`; it then iterates the task records using the
header-derived task count and a `0x60`-byte stride. For each task, a non-null
callback at `record + 4` is run through `sub_435F20` before the normal task PC.
`sub_435C00 @ 0x435C00` is the per-task execution loop: it loads the selected
record's PC from `record + 0x58`, repeatedly dispatches through
`sub_435620 @ 0x435620`, saves each non-null returned cursor back to that PC,
and stops when a handler returns null. `sub_435F20` likewise dispatches from a
supplied cursor until a handler returns null. `sub_435620` selects the handler
by the first byte of the opcode dword. `sub_4355E0 @ 0x4355E0` is exactly
`body_base + value`; `sub_4355C0` performs the inverse. Thus a write to a PC
field is not by itself evidence that its serialized source is a relocation:
the source mode and conversion at the owning handler decide that.

`sub_435F50 @ 0x435F50` reads three 16-bit CSeq header values at header offsets
`+0`, `+4`, and `+8`, prepares VM state, and calls `sub_4357D0` with the initial
pointer `body + field_0x10 + 0x10`. `sub_4357D0` initializes task 0 through
`sub_435660 @ 0x435660`; this is the loader-proven seed described above. The
other task PCs are not established by that initialization sequence.

A complete search of task-record `+0x58` assignments in the IDA pseudocode
export, plus direct current-record writes through `a2[22]`, yields these
instruction-handler families:

| Serialized form | Handler-backed action | Relocation classification |
|---|---|---|
| `01:00` | Adds the immediate dword (scaled by 256) to the current wait/tick state, stores `opcode+8` in the current record PC (`a2[22]`), and yields by returning null. | The stored PC is the instruction's post-operand cursor, not an encoded target; layout relocation remaps it automatically. |
| `01:01` | Resolves one `sub_436690` operand, updates the wait/tick state, stores the helper-return cursor in `a2[22]`, and yields. | The stored PC is the descriptor-dependent instruction end; no static target dword is present. |
| `01:02` | Task index is byte 3 of the opcode dword; the following dword is passed through `sub_4355E0` and stored as that task's PC. The cursor consumes 8 bytes. | **Definite body-relative relocation** at opcode `+4`, regardless of which task index is selected. |
| `01:03` | `sub_436690` decodes the task index; the following decoded value is passed through `sub_4355E0` and stored as the PC. | Relocate the target source only when the mode proves it is an inline `0x3F` value. A frame/context value is runtime state; if it ultimately originates from a literal offset, relocate that literal at its own definition site instead. |
| `01:04`, `01:05` | Clear the selected task PC to null (direct task index or descriptor-decoded index). | No pointer operand. These are task termination/disable writes, not relocation sites. |
| `01:08` | Task index is byte 2; a `sub_436690`-resolved value is assigned directly to the PC, with no `sub_4355E0` conversion. | This is a runtime pointer handoff/scheduling form in the handler. Do not patch a raw operand as a body offset without proving its mode and reaching definition; the pseudocode alone does not establish a static address field. |
| `0A:0E` | `sub_436340` resolves a task index and target value; the target is converted with `sub_4355E0`, stored as that task PC, and task frame state is updated. If the destination is the currently executing task, the current cursor switches to that PC immediately. | Relocate the second pair value only when its descriptor/source is a statically encoded inline body offset (not a runtime frame/context slot). Pair cursor size depends on both operand modes. |
| `0A:0F` | Resolves a pair, then consumes an explicit dword converted by `sub_4355E0` as a body-relative table base and reads an indexed table element. | The explicit table-base dword is a definite body-relative **data pointer**. The table elements are not yet classified as code pointers; their consumer/reaching definitions must be followed before patching them. |

The surrounding `01:06/07/0B` cases test whether task PCs are null; `01:09/0A`
read a task PC into VM state. Those are useful for understanding dispatch but
do not add serialized pointer fields. `01:00/01` are important scheduler yield
points; their saved continuation is computed from the decoded instruction end,
so it is not patched as a serialized relocation. The auxiliary per-task dword at record
`+0x5C` is also written during task switching; its value is derived from VM
frame state and the CSeq header fields, not read as an inline code target in
these handlers. Separately, the per-task callback PC at `record + 4` is a real
secondary entry point: it is assigned by the `0A:03` form when its destination
mode is `0x01` and is invoked by the outer tick. It must be included in CFG
seeding and relocation, even though it is not the normal task PC at `+0x58`.

The `0x1C` handler `sub_42EDF0 @ 0x42EDF0` was checked as a suspected task
creator. Its cases resolve operands and call UI/object/scheduling-group
methods, but the pseudocode does not write the normal task PC at `+0x58`.
Serialized `0A:03` assignments instead install callback PCs into the current
task record at `+4` and the CSeq object at `+0x24`; `sub_436B10` and event
methods execute these callback streams through `sub_435F20`. Thus there is a
host-driven VM callback path, but it uses explicit body-pointer assignments,
not a hidden direct task-PC write in the `0x1C` handler. The outer tick does not
assign normal task PCs at `+0x58`; those are initialized for task 0 by the
loader or written by the `01`/`0A` handler forms above. The `01:00/01` rows are
current-task continuation updates, not task creation.

A separate aligned dword-signature census across all 156 SEQF bodies was used
only as a negative/lead check (not as instruction-boundary evidence). It found
310 `01:04` candidates, but zero candidates for `01:02`, `01:03`, `01:05`,
`01:08`, `0A:0E`, and `0A:0F`. The 310 `01:04` words have a zero descriptor
byte in the fourth byte and are consistent with task-PC clears, but are still
lexical candidates until a CFG proves each boundary. The absence of direct
set/switch forms in this aligned corpus means the sample set does not establish
that those task-PC mutation forms execute. It does **not** prove that task 0 is
the only VM task at runtime or rule out a host-side callback path.

In `story/6051/0000.seq`, the two task-0 `0A:03` writes store body pointers to
`0x48C4` and `0x4CC4`. Descriptor `0x01` makes the first destination
`current_task_record + 4`; descriptor `0x1D` makes the second destination
`CSeq + 0x24`. The outer tick loads and executes the former before the task's
normal PC, and executes the latter on the global event/timer path. These are
therefore handler-backed callback roots, not merely code-looking aligned words.
The CFG is still incomplete within and downstream of both routines, so their
actual successor graph and all branch/table relocations remain to be decoded.

**What this closes:** task state now has the loader seed, outer tick, normal
per-task PC loop, two independently invoked callback-PC fields, and a handler
write inventory. For the 155 story files, the two `0A:03` mode-`0x3F` values
are proven body-relative relocations and their targets are proven secondary
execution roots. It also distinguishes the definite `01:02` relocation from
mode-dependent `01:03`/`0A:0E`, raw runtime handoff `01:08`, null clears, and
`0A:0F` table-base pointer.

#### Callback-root CFG checkpoint: `story/6051/0000.seq`

The global callback root at body `0x4CC4` was followed through its first basic
blocks using the IDA cursor/branch semantics:

- `04:03` at `0x4CC4` is a pair-mode operation with mode bytes `0x1B,0x3F` and
  inline value at `0x4CC8`; the next instruction is `02:02` at `0x4CCC`, whose
  direct target at `0x4CD0` is body offset `0x4CE8`.
- The fall-through block has another `04:03` at `0x4CD4`, inline value at
  `0x4CD8`, then `02:02` at `0x4CDC` with target `0x4CEC` at `0x4CE0`.
  Both `02:02` target fields are definite body-relative branch relocations;
  both branch and fall-through edges are retained because the conditions are
  runtime-dependent.
- `00:00` terminators at `0x4CE4` and `0x4CE8` end the two early-return paths.
  The path at `0x4CEC` executes `02:0A` with target `0x4D3C` (field `0x4CF0`).
  At `0x4D3C`, another `02:0A` targets body offset `0x130` (field `0x4D40`),
  followed by `02:13` at `0x4D44`, which returns to the saved continuation
  `0x4CF4`. The continuation reaches a `00:00` at `0x4D08` after its
  descriptor/resource operations.

This is a verified local CFG slice and relocation set for the callback. It
proves those control fields are not arbitrary aligned dwords, but it does not
cover all successors of the per-task callback at `0x48C4`, the remaining event
paths, or unrelated blocks/tables in the file.


**What remains open:** no whole-script CFG/boundary proof has been obtained;
we have not shown that `story/6051/0000.seq`'s call at body `0x1744` is reached
from the task-0 entry; static/dynamic operand provenance for task switches has
not been resolved across reaching definitions; `0A:0F` table payloads and
other computed tables are not completely typed; nor are all code/data entry
points and all relocation fields enumerated. Therefore the assembler's
length-preservation guard remains mandatory and arbitrary-length editing is
not yet supported.

## CLI and output tree

    python disassembler.py <script-file-or-directory> [-o <output-directory-or-file>] [--encoding cp932]
    python assembler.py <asm.txt-or-directory> [-o <output-file/directory>] [--encoding gbk]

- Directory inputs recurse. For a Seq_unpack tree, story source paths
  data/Seq/story/<chapter>/<script>.seq map to asm_jp/story/<chapter>-<script>.seq.asm.txt.
- Default disassembly from Seq_unpack writes into the sibling asm_jp directory.
  An explicit -o directory writes the same canonical asm layout below it.
  Existing generated destination asm files are regenerated; other old files
  are not deleted.
- The assembler reverses the flattened story filename to its original
  data/Seq/story/<chapter>/<script>.seq path. By default it writes to sibling
  Seq_unpack_cn/data/Seq/... so the original files remain unchanged. With -o
  directory, it writes to the corresponding source-relative path below that
  directory. An explicit output filename is honored for one input.
- When both an old nested story asm and flattened counterpart are present in a
  directory input, the flattened file takes precedence. Use -o pointing to the
  original unpacked tree only when intentional replacement of sources is wanted.




### Per-task callback CFG slice, `story/6051/0000.seq` (continued, 24 November 2026)

The secondary task callback at body offset `0x48C4` was decoded from its
installed `0A:03` pointer and the scheduler call, then followed through a small
handler-backed basic-block slice. This is distinct from the global callback at
`0x4CC4`.

- `0x48C4` is primary `0x19`, case `0x1B`. Its two tagged operands select
  runtime slots 13 and 0; the inline comparison string at `0x48D0` is `==`.
  The variable-length operator scan ends at `0x48D4` because its dword
  contains a NUL byte. `0x48D4` is `02:02`, with target field `0x48D8` =
  `0x48E4`. Per `sub_4BF9B0` case 2, a nonzero comparison flag branches to
  `0x48E4`, while zero falls through to `0x48DC`.
- The fall-through instruction `0x48DC` is `19:07` with tagged slot 13;
  case 7 decrements that runtime slot and resumes at `0x48E4`.
- `0x48E4` is another `19:1B`, comparing slots 14 and 0 with `==`; its
  inline operator dword at `0x48F0` ends at `0x48F4`. `02:02` at `0x48F4`
  has a body-relative target field at `0x48F8` = `0x4904`; its zero-flag
  fall-through executes `19:07` at `0x48FC` (decrement tagged slot 14) and
  then reaches `0x4904`.
- `0x4904` is `19:1B`, comparing tagged slot 11 against slot 0 using the
  inline `==` at `0x4910`; the instruction ends at `0x4914`. `02:01` at
  `0x4914` has target field `0x4918` = `0x4A88`. Per case 1 it branches to
  `0x4A88` when the comparison flag is zero and otherwise falls through to
  `0x491C`.
- `0x491C` is primary `0x14`, case `0x69` (host operation; consumes only its
  opcode word, so next cursor `0x4920`). `02:20` at `0x4920` has both direct target
  fields: `0x4924` = `0x492C` and `0x4928` = `0x4974`. Case 20 chooses the
  first when the condition flag is nonzero and the second otherwise. The
  separate case-`0x21` behavior that saves a continuation must not be
  attributed to this case-`0x20` instruction.

These edges prove five more body-relative branch fields in this callback and
confirm that comparison strings use the VM's word-scanned termination rule,
not a guessed fixed instruction size. The path is still only a local slice:
`0x492C`, `0x4974`, and the later callback successors have not yet been fully
traced, and no global claim about other files follows from this one script.
In particular, this slice does not complete the inventory of body pointers or
make arbitrary-length rebuilding safe.


#### Per-task callback continuation and nested-call slice

The `0x492C`/`0x4974` successors were checked against their handler schemas,
which extends (but does not complete) the per-task callback CFG above:

- From `0x492C`, primary `0x12:0x02` consumes its opcode word; the `0x04:0x03`
  pair-mode operations at `0x4934` and `0x494C` each consume the mode word and
  inline second-mode dword. The conditional `02:02` fields at `0x4940` and
  `0x4958` both target `0x4964`; the fall-through from the second branch is an
  unconditional `02:00` at `0x495C` with target field `0x4960` = `0x4A88`.
  At `0x4964`, `14:66` has mode `0x3F` and inline operand at `0x4968`; the
  following `02:00` at `0x496C` targets `0x4A88` through field `0x4970`.
- The other conditional successor `0x4974` begins with `14:68`; `02:02` at
  `0x4978` targets `0x499C` via field `0x497C`. Its fall-through contains
  `1C:00` at `0x4980`, `08:00` at `0x4984`, and `1C:1D` at `0x4988`
  each consume only their opcode word in the observed mode/case forms. `02:02`
  at `0x498C` targets `0x499C` through field `0x4990`; its fall-through
  `02:00` at `0x4994` targets `0x49AC` through field `0x4998`. At `0x499C`,
  `14:66` uses descriptor mode `0x3F` and inline dword `0x49A0`; `02:00` at
  `0x49A4` targets `0x4A8C` through field `0x49A8`.
- At `0x4A88`, `14:67` consumes its opcode word and continues at `0x4A8C`,
  where the next opcode is followed by the comparison at `0x4A90`. The `19:1B` comparison there scans the `==` operator at `0x4A9C`;
  `02:01` at `0x4AA0` branches to `0x4ABC` via field `0x4AA4` when the
  comparison flag is zero. The other edge sets runtime slot 13 to 1 at
  `0x4AA8` and executes `02:0A` at `0x4AB4`, whose definite body-relative call
  field `0x4AB8` targets `0x4AD0`; its saved continuation is `0x4ABC`.
  Both paths through `0x4ABC`/`0x4AC0` reach the `02:13` return at `0x4AC8`
  or `0x4ACC`, so the callee's caller continuation is reached through the VM
  return stack rather than a serialized return address.
- `0x4AD0` is therefore a proven call target in this callback slice. Its
  conditional/computed successors beyond the first block are still being
  decoded; this checkpoint does not classify the rest of the `0x48C4` region.

All listed branch/call fields are confirmed from handler cursor semantics and
these concrete bytes; the mode-resolved operands are not relocations merely
because they are adjacent to control fields. The callback remains a partial CFG
and cannot yet certify a global relocation set.


## Analysis checkpoint — 静态逆向按用户要求暂停（2026-11-24）

本节汇总截至此日已有 IDA/样本证据，作为当前结论；“候选扫描”与“已证明边界”分开记录。暂停分析不等于格式逆向完成，也不改变工具现有的长度保护。

### 已有静态证据支持的结论

- **容器与地址空间：** SEQF 头为 `0x14` 字节；body 长度与文件总长一致。loader 将 body 基址传给 VM，`sub_4355E0(offset)` 将 body-relative offset 转为 body 指针，`sub_4355C0(pointer)` 执行反向转换。task 初始 PC 为 `body + field_0x10 + 0x10`；因此 `field_0x10` 指向 body 内 task header，而非直接指令入口。
- **VM 分派与操作数游标：** primary opcode 由低字节分派，次码由 `BYTE1` 选择 handler case。`sub_435600` 消耗一个 dword；`sub_436690` 和 `sub_436340` 的游标由描述符及扩展字决定；`sub_42BF00` 消耗一个 dword，但 `0x7FFF0000..0x7FFFFFFF` 是运行时变量槽标签，不是文件地址。不可把这些字段统一当作 offset。
- **变长字符串游标：** `sub_435560` 按 dword 扫描，遇到包含任意 NUL 字节的 dword 后返回下一 dword；NUL 所在 dword 的剩余字节不可未经证据丢弃。已确认 `1C:42` 与 `14:65` 文本形式，以及多种比较/资源字符串形式的 cursor 规则；只有前两类当前被工具作为玩家可编辑文本输出，其他字符串用途未全部证明。
- **控制流与回调：** `sub_435C00` 执行 task record `+0x58` 的普通 task PC；`sub_436B10` 还会通过 `sub_435F20` 执行 task record `+4` 的 callback PC 和 CSeq `+0x24` 的 global callback PC。155 个故事样本的 task-0 初始化前缀已核查。`6051/0000.seq` 的初始 PC 为 body `0x37A4`，两个 callback root 分别为 `0x48C4` 和 `0x4CC4`，均由 `0A:03` 的 inline `0x3F` 值经 `sub_4355E0` 转换，属于确定的 body-relative 指针。
- **局部 CFG 与表：** `6051` global callback `0x4CC4` 的若干条件分支、call 与返回路径已追踪；per-task callback `0x48C4` 已追踪至 `0x4AD0` 嵌套调用入口，涉及的局部分支/call 字段已在上文列出。`6051` body `0x174C` 的 `19:1F` 三项表目标为 `0x1764`、`0x1A84`、`0x1D68`。全语料对齐扫描中发现的候选表均有结构约束分析，但候选存在不等于该处已由 CFG 证明可达。
- **已有重定位分类：** 已静态确认若干直接分支、call、task-PC/callback-PC 和 switch-table entry 的 body-relative 字段；`01:02` 的目标字段是确定 relocation。`01:03`、`0A:0E` 需按 operand mode/source 判断；`01:08` 是运行时 PC handoff；`0A:0F` 的显式基址是 body-relative data pointer，但表项语义未完全解决。已确认的 handler/case 级规则见本文各节，不能推广成“所有 dword 都是指针”。
- **现有工具验证范围：** 当前反汇编器只将两种已确认形式呈现为文本，其余区域仍按原始数据定义保留。156/156 个样本的 CP932 未修改往返验证只证明当前表示可保字节，不证明全 VM 的边界或 relocation 覆盖，也不证明变长编辑可用。

### 仍未证明、因此不得宣称完成的事项

- 没有建立所有 156 个文件的完整指令/数据边界图；扫描到的 opcode 外观和文本候选不是边界证据。
- 没有从所有普通 task、callback、call continuation 和 computed-table 入口递归闭合整个 CFG；`6051` 两个 callback 也只是局部切片，其他后继及全局可达性未穷尽。
- 没有完整解决动态 operand 的 reaching definitions、所有计算表界限/表项类型、所有实际 task-PC 写入来源，也没有穷举所有可能的 body-relative 引用与被引用对象类型。
- 因而尚无证据证明：在任一文本增长或缩短后，所有受影响的分支、调用、表项、task/callback 指针、头字段及数据边界均能被识别并重定位；当前 opaque `.byte` 区也不能假定不含需修正的地址。
- 尚未实现或验证基于完整符号/重定位图的变长两遍布局汇编；没有长短文本、跨编码编辑的 relocation 验证，也没有游戏副本实测。

**操作结论：** 用户要求本轮在此停止继续分析。现阶段的正式结论是“记录到的局部静态规则已归档；全局边界/重定位证明未完成；任意字节长度变化暂不支持”。不得移除 `assembler.py` 的长度保护，除非未来补齐上述证据并完成相应测试。
