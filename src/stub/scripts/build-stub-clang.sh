#!/bin/bash
set -e
cd ~/project/upx/src/stub
T=arm64-win64.pe
GCC="clang --target=aarch64-linux-gnu -nostdinc -DWINDOWS_BACK=1 -fno-exceptions -fno-asynchronous-unwind-tables"
OBJCOPY=aarch64-linux-gnu-objcopy
OBJDUMP=aarch64-linux-gnu-objdump

$GCC -c -x assembler-with-cpp src/$T.S -o tmp/$T.bin
chmod a-x tmp/$T.bin
$OBJCOPY --strip-unneeded --keep-symbol=_start --keep-symbol=upx_main2 --keep-symbol=upx_so_main tmp/$T.bin
$OBJCOPY -R .text -R .data -R .bss -R .riscv.attributes -R .comment -R .note -R .note.GNU-stack -R .reginfo -R .mdebug.eabi32 -R .gcc_compiled_long32 tmp/$T.bin
LC_ALL=C $OBJDUMP -Dr tmp/$T.bin | sed -e 's/[ \t]*$//' > tmp/$T.bin.disasm
LC_ALL=C $OBJDUMP -htr -w tmp/$T.bin | cat --squeeze-blank | sed -e '1s/^.*: *file format/file format/' -e 's/\t/ /g' -e 's/ 00*/ 0/g' -e 's/CONTENTS.*/CONTENTS/' > tmp/$T.bin.dump
python3 - << 'PYEOF'
import re
p = 'tmp/arm64-win64.pe.bin.dump'
lines = open(p).read().splitlines(True)
sym_i = next(i for i, l in enumerate(lines) if l.startswith('SYMBOL TABLE:'))
have = set()
for l in lines[sym_i+1:]:
    toks = l.split()
    if toks and re.match(r'^[0-9a-f]+$', toks[0]) and len(toks) >= 4:
        have.add(toks[-1])  # 符号名在行尾(含 clang 的 "l d" 节符号行)
secs = []
for l in lines[:sym_i]:
    m = re.match(r'^\s*\d+\s+(\S+)\s', l)
    if m: secs.append(m.group(1))
inject = [f'0000000000000000 g       {s} 0 {s}\n' for s in secs if s not in have]
lines[sym_i+1:sym_i+1] = inject
open(p, 'w').writelines(lines)
print(f'注入 {len(inject)} 个节符号')
PYEOF
python3 ./scripts/xstrip.py --with-dump=tmp/$T.bin.dump tmp/$T.bin
cat tmp/$T.bin.dump >> tmp/$T.bin
python3 ./scripts/bin2h.py --ident=auto-stub --compress=0 tmp/$T.bin $T.h
echo "stub 构建完成: $(grep -m1 STUB_ARM64_WIN64_PE_SIZE $T.h)"
