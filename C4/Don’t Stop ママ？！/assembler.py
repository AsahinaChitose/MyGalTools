"""Assemble editable UTF-8 C4 scenario listings into Mp17 files."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import groupby
import re
from struct import pack
import sys

from opcodelist import (
    FILE_LIMIT, GLOBAL_BASE, GBK_SUBSTITUTIONS, HEADER_SIZE, IDENT, MAGIC,
    OPCODES_BY_NAME, POOL_XOR, SUBOPS_BY_NAME, TERMINATORS, WIDTHS,
    FormatError, asm_tokens, cli, codec_name, encode_text, error_exit, jobs,
    text_tokens, write_output,
)
from disassembler import read_script


@dataclass
class TextUse:
    line: int
    chunks: list


@dataclass
class Operation:
    line: int
    name: str
    operands: list
    groups: dict = field(default_factory=dict)


@dataclass
class Assembly:
    header: dict = field(default_factory=dict)
    code: list = field(default_factory=list)
    labels: dict = field(default_factory=dict)
    text_order: dict = field(default_factory=dict)
    text_uses: dict = field(default_factory=lambda: defaultdict(list))
    extra: bytearray = field(default_factory=bytearray)
    symbols: list = field(default_factory=list)


def integer(token, lower, upper, name):
    try:
        base = 16 if token.lower().lstrip("+-").startswith("0x") else 10
        value = int(token, base)
    except ValueError as error:
        raise FormatError(f"{name}: expected an integer, got {token}") from error
    if not lower <= value <= upper:
        raise FormatError(f"{name}: {value} outside {lower}..{upper}")
    return value


def assert_ident(token, prefix=""):
    if not token.startswith(prefix) or not IDENT.fullmatch(token[len(prefix):]):
        raise FormatError(f"invalid {'text ID' if prefix else 'label'} {token}")
    return token


def digest(token):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", token):
        raise FormatError("expected a SHA-256 digest")
    return token.lower()


def record_text(asm, ident, token, line):
    assert_ident(ident, "@")
    use = TextUse(line, text_tokens(token))
    asm.text_uses[ident].append(use)
    return use.chunks


def read_operation(asm, tokens, line):
    name, *args = tokens
    if name not in OPCODES_BY_NAME:
        raise FormatError(f"unknown instruction {name}")
    _, spec = OPCODES_BY_NAME[name]
    expected = len(spec.operands) + spec.operands.count("text")
    if len(args) != expected:
        raise FormatError(f"{name}: expected {expected} argument fields, got {len(args)}")
    operands = []
    text = None
    index = 0
    for kind in spec.operands:
        token = args[index]
        index += 1
        if kind == "text":
            text = record_text(asm, token, args[index], line)
            index += 1
        operands.append(token)
    asm.code.append(Operation(line, name, operands))
    return text


def parse_assembly(text):
    asm = Assembly()
    sections = [".code", ".pool", ".extra", ".symbols", ".end"]
    section = 0
    current = None
    continued = None
    for number, line in enumerate(text.split("\n"), 1):
        try:
            fields = asm_tokens(line)
            if not fields:
                continue
            head, *args = fields
            if head == "|":
                if continued is None or len(args) != 1:
                    raise FormatError("text continuation needs an immediately preceding quoted field")
                continued.extend(text_tokens(args[0]))
                continue
            continued = None
            if head in sections:
                if section >= len(sections) or head != sections[section] or args:
                    raise FormatError(f"unexpected section {head}")
                section += 1
                continue
            if section == 0:
                if head not in (".format", ".encoding", ".locals", ".reserved", ".original_sha256"):
                    raise FormatError(f"unknown header directive {head}")
                if len(args) != 1 or head in asm.header:
                    raise FormatError(f"invalid or repeated header directive {head}")
                asm.header[head] = args[0]
            elif section == 1:
                if head.endswith(":"):
                    name = assert_ident(head[:-1])
                    if args or name in asm.labels:
                        raise FormatError(f"invalid or repeated label {name}")
                    asm.labels[name] = len(asm.code)
                    current = None
                elif head in (".when", ".update", ".expr"):
                    group = head[1:]
                    if current is None or group not in OPCODES_BY_NAME[current.name][1].groups:
                        raise FormatError(f"{head} has no matching instruction")
                    if group in current.groups:
                        raise FormatError(f"duplicate {head}")
                    current.groups[group] = (number, args)
                else:
                    continued = read_operation(asm, fields, number)
                    current = asm.code[-1]
            elif section == 2:
                if head not in (".text_id", ".text") or not (1 <= len(args) <= 2):
                    raise FormatError("expected .text_id @id [digest] or .text @id quoted-text")
                ident = assert_ident(args[0], "@")
                if ident in asm.text_order:
                    raise FormatError(f"duplicate pool record {ident}")
                if head == ".text":
                    if len(args) != 2:
                        raise FormatError(".text requires an inline definition")
                    continued = record_text(asm, ident, args[1], number)
                    asm.text_order[ident] = None
                else:
                    asm.text_order[ident] = digest(args[1]) if len(args) == 2 else None
            elif section == 3:
                if head != ".byte" or not args:
                    raise FormatError("expected a .byte data record in .extra")
                asm.extra.extend(integer(token, 0, 255, ".byte") for token in args)
            elif section == 4:
                if head != ".symbol" or len(args) != 1:
                    raise FormatError("expected .symbol with one quoted name")
                continued = text_tokens(args[0])
                asm.symbols.append(TextUse(number, continued))
            else:
                raise FormatError("unexpected content after .end")
        except FormatError as error:
            raise FormatError(f"line {number}: {error}") from error
    if section != len(sections) or not asm.code:
        raise FormatError("missing section or empty code")
    if asm.header.get(".format") != "Mp17":
        raise FormatError("missing or invalid .format Mp17 header")
    return asm


def canonical(chunks):
    return tuple((b"" if kind is bytes else "").join(parts)
                 for kind, parts in groupby(chunks, key=type))


def resolve_text(ident, occurrences, baseline, source_encoding):
    candidates = {}
    for use in occurrences:
        candidates[canonical(use.chunks)] = use.line
    if len(candidates) == 1:
        return next(iter(candidates.items()))
    changed = []
    for candidate, line in candidates.items():
        if baseline is not None:
            try:
                raw = encode_text(candidate, source_encoding)
            except UnicodeEncodeError:
                pass
            else:
                if sha256(raw).hexdigest() == baseline:
                    continue
        changed.append((candidate, line))
    if len(changed) == 1:
        return changed[0]
    lines = ", ".join(str(line) for line in candidates.values())
    raise FormatError(f"{ident}: conflicting text edits on lines {lines}; use one wording or create a new ID")


def build_pool(asm, source_encoding, target_encoding, substitutions):
    for ident, occurrences in asm.text_uses.items():
        if ident not in asm.text_order:
            raise FormatError(f"line {occurrences[0].line}: undefined pool ID {ident}")
    pool = bytearray()
    offsets = {}
    for ident, baseline in asm.text_order.items():
        occurrences = asm.text_uses.get(ident, [])
        if not occurrences:
            raise FormatError(f"{ident}: missing inline text or .text definition")
        content, line = resolve_text(ident, occurrences, baseline, source_encoding)
        offsets[ident] = len(pool)
        try:
            pool.extend(encode_text(content, target_encoding, substitutions))
        except (FormatError, UnicodeEncodeError) as error:
            raise FormatError(f"line {line}, {ident}: {error}") from error
        pool.append(0)
        if len(pool) > 0xFFFF:
            raise FormatError("text pool exceeds its 16-bit size field")
    return offsets, bytes(byte ^ POOL_XOR for byte in pool)


def symbol_indices(symbols):
    names = [raw.decode("ascii", "replace") for raw in symbols]
    counts = Counter(names)
    return {name: GLOBAL_BASE + index for index, name in enumerate(names)
            if IDENT.fullmatch(name) and counts[name] == 1 and not re.fullmatch(r"[lg]\d+", name)}


def variable_index(token, symbols):
    if not token.startswith("$"):
        raise FormatError(f"expected a $variable, got {token}")
    name = token[1:]
    if re.fullmatch(r"l\d+", name):
        return integer(name[1:], 0, 255, "local variable")
    if re.fullmatch(r"g\d+", name):
        return integer(name[1:], GLOBAL_BASE, 0x7FFF, "global variable")
    if name not in symbols:
        raise FormatError(f"unresolved variable {token}")
    return symbols[name]


def encode_group(group, tokens, symbols):
    result = bytearray()
    cursor = 0
    stack = 0
    stored = False
    table = SUBOPS_BY_NAME[group]
    while cursor < len(tokens):
        name = tokens[cursor]
        cursor += 1
        if name not in table or name.startswith("END_") or stored:
            raise FormatError(f"invalid {group} sub-opcode {name}")
        opcode, operands = table[name]
        if cursor + len(operands) > len(tokens):
            raise FormatError(f"{name}: missing operand")
        if opcode is not None:
            result.extend(opcode.to_bytes(2 if group == "expr" else 1, "little"))
        for kind in operands:
            token = tokens[cursor]
            cursor += 1
            if kind == "index":
                value = variable_index(token, symbols)
            elif kind == "var" or token.startswith("$"):
                value = ~variable_index(token, symbols)
            else:
                value = integer(token, 0, 0x7FFF, "VM immediate")
            if group == "expr" and name == "PUSH" and (value & 0xFFFF) in range(0xFDFA, 0xFE00):
                raise FormatError(f"{token}: expression operand overlaps an operator word")
            result.extend(pack("<h", value))
        if group == "expr":
            if name == "PUSH":
                stack += 1
                if stack > 32:
                    raise FormatError("expression stack exceeds the VM's 32 values")
            elif name == "STORE":
                if stack != 1:
                    raise FormatError("STORE requires exactly one expression result")
                stored = True
            else:
                if stack < 2:
                    raise FormatError(f"{name}: expression stack underflow")
                stack -= 1
    if group == "expr":
        if not stored:
            raise FormatError("expression needs a terminating STORE")
    else:
        result.append(TERMINATORS[group])
    return result


def build_code(asm, offsets, symbols):
    code = bytearray()
    addresses = []
    patches = []
    for operation in asm.code:
        addresses.append(HEADER_SIZE + len(code))
        opcode, spec = OPCODES_BY_NAME[operation.name]
        code.append(opcode)
        try:
            for kind, token in zip(spec.operands, operation.operands):
                if kind == "target":
                    patches.append((len(code), assert_ident(token), operation.line))
                    value = 0
                elif kind == "text":
                    value = offsets[token]
                elif kind == "i16":
                    value = integer(token, -32768, 32767, kind)
                elif kind == "counter":
                    value = integer(token, 0, 1023, kind)
                else:
                    value = integer(token, 0, 255, kind)
                code.extend(value.to_bytes(WIDTHS[kind], "little", signed=kind == "i16"))
            missing = set(spec.groups) - operation.groups.keys()
            if missing:
                raise FormatError(f"{operation.name} requires .{' and .'.join(sorted(missing))}")
        except FormatError as error:
            raise FormatError(f"line {operation.line}: {error}") from error
        for group in spec.groups:
            line, tokens = operation.groups[group]
            try:
                code.extend(encode_group(group, tokens, symbols))
            except FormatError as error:
                raise FormatError(f"line {line}: {error}") from error
    if HEADER_SIZE + len(code) > 0xFFFF:
        raise FormatError("code end exceeds the header's 16-bit offset field")
    for name, position in asm.labels.items():
        if position >= len(addresses):
            raise FormatError(f"label {name} is past the last instruction")
    for position, name, line in patches:
        if name not in asm.labels:
            raise FormatError(f"line {line}: unresolved branch target {name}")
        code[position:position + 2] = pack("<H", addresses[asm.labels[name]])
    return code


def assemble(asm, encoding=None, substitutions=None):
    source = codec_name(asm.header.get(".encoding", "cp932"))
    target = codec_name(encoding) if encoding is not None else source
    if target == "gbk" and substitutions is None:
        substitutions = Counter()
    offsets, pool = build_pool(asm, source, target, substitutions if target == "gbk" else None)
    raw_symbols = []
    for symbol in asm.symbols:
        try:
            raw_symbols.append(encode_text(canonical(symbol.chunks), source))
        except (FormatError, UnicodeEncodeError) as error:
            raise FormatError(f"line {symbol.line}: {error}") from error
    code = build_code(asm, offsets, symbol_indices(raw_symbols))
    locals_count = integer(asm.header.get(".locals", "0"), 0, 0xFFFF, "local count")
    reserved = integer(asm.header.get(".reserved", "0"), 0, 0xFFFF, "reserved header word")
    if ".original_sha256" in asm.header:
        digest(asm.header[".original_sha256"])
    if len(asm.extra) > 0xFFFF or len(raw_symbols) > 0xFFFF:
        raise FormatError("extra-section length or symbol count exceeds 16 bits")
    header = MAGIC + pack("<6H", HEADER_SIZE + len(code), len(pool), locals_count,
                          len(asm.extra), len(raw_symbols), reserved)
    data = header + code + pool + asm.extra + b"".join(raw + b"\0" for raw in raw_symbols)
    if len(data) > FILE_LIMIT:
        raise FormatError(f"output exceeds the engine's {FILE_LIMIT}-byte read buffer")
    read_script(data)
    return data


def main(argv=None):
    args = cli(__doc__, argv)
    try:
        encoding = codec_name(args.encoding) if args.encoding else None
        exports = []
        matched = 0
        for source, target in jobs(args, ".asm.txt", ".rebuild", ".MPX"):
            substitutions = Counter()
            try:
                text = source.read_text(encoding="utf-8-sig")
                listing = parse_assembly(text)
                data = assemble(listing, encoding, substitutions)
                original = listing.header.get(".original_sha256", "").lower()
                matched += sha256(data).hexdigest() == original
            except (FormatError, UnicodeError) as error:
                raise FormatError(f"{source}: {error}") from error
            exports.append((source, target, data, substitutions))
        for source, target, data, substitutions in exports:
            write_output(target, data)
            if substitutions:
                changes = ", ".join(f"{char} -> {GBK_SUBSTITUTIONS[char]} ({count})"
                                    for char, count in sorted(substitutions.items()))
                print(f"{source.name}: GBK character substitutions: {changes}", file=sys.stderr)
        print(f"Assembled {len(exports)} Mp17 file(s), {matched} matching source SHA-256.")
        return 0
    except (FormatError, OSError) as error:
        return error_exit(error)


if __name__ == "__main__":
    raise SystemExit(main())
