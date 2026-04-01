/* ARM64 PE loader sections for UPX win64/arm64
 * Uses literal pools for symbol references.
 * UPX linker patches R_AARCH64_ABS32 relocations at pack time.
 */

.altmacro

.macro section name
    .section \name
.endm

/* Load a 32-bit symbol value into Wd via literal pool */
.macro LDSYM32 reg, sym
    ldr     \reg, 98f
    b       99f
98: .word   \sym
99:
.endm

/* Load a 64-bit symbol value into Xd via literal pool */
.macro LDSYM64 reg, sym
    ldr     \reg, 98f
    b       99f
    .balign 8
98: .quad   \sym
99:
.endm

// ============= ENTRY POINT =============

section START
section PEISDLL0
    stp     x0, x1, [sp, #-0x20]!
    str     x2, [sp, #0x10]
section PEISEFI0
    stp     x0, x1, [sp, #-0x10]!

section PEISDLL1
    cmp     w1, #1
    b.ne    reloc_end_jmp
section PEMAIN01
    stp     x19, x20, [sp, #-0x60]!
    stp     x21, x22, [sp, #0x10]
    stp     x23, x24, [sp, #0x20]
    stp     x25, x26, [sp, #0x30]
    stp     x27, x28, [sp, #0x40]
    stp     x29, x30, [sp, #0x50]
    adr     x19, start_of_compressed
    LDSYM32 w9, start_of_uncompressed
    add     x20, x19, x9

section PEICONS1
    LDSYM32 w10, icon_offset
    ldrh    w9, [x20, x10]
    add     w9, w9, #1
    strh    w9, [x20, x10]
section PEICONS2
    LDSYM32 w10, icon_offset
    LDSYM32 w11, icon_delta
    ldrh    w9, [x20, x10]
    add     w9, w9, w11
    strh    w9, [x20, x10]
section PETLSHAK
    LDSYM32 w9, tls_address
    add     x9, x20, x9
    ldr     w10, [x9]
    stp     x9, x10, [sp, #-0x10]!
    LDSYM32 w11, tls_value
    str     w11, [x9]

section PEMAIN02
    mov     x21, x20
section PEMAIN03

// Decompression sections provided by existing compiled stub

section PEMAIN10
    mov     x19, x21

section PETLSHAK2
    ldp     x9, x10, [sp], #0x10
    str     w10, [x9]

// ============= IMPORTS =============

section PEIMPORT
    LDSYM32 w9, compressed_imports
    add     x22, x19, x9
next_dll:
    ldr     w9, [x22]
    cbz     w9, imports_done
    ldr     w10, [x22, #4]
    add     x0, x19, x9
    LDSYM32 w11, start_of_imports
    add     x0, x0, x11
    add     x23, x19, x10
    add     x22, x22, #8
    LDSYM64 x9, LoadLibraryA
    blr     x9
    mov     x24, x0
next_func:
    ldrb    w9, [x22], #1
    cbz     w9, next_dll
section PEIBYORD
    tbz     w9, #7, byname
section PEK32ORD
    tbnz    w9, #5, not_kernel32
    ldr     w9, [x22]
    add     x22, x22, #4
    add     x9, x19, x9
    LDSYM32 w11, kernel32_ordinals
    add     x9, x9, x11
    ldr     x0, [x9]
    b       next_imp
not_kernel32:
section PEIMORD1
    ldrh    w1, [x22]
    add     x22, x22, #2
    b       first_imp
byname:
section PEIMPOR2
    mov     x1, x22
    sub     w9, w9, #1
0:  ldrb    w10, [x22], #1
    cbnz    w10, 0b
first_imp:
    mov     x0, x24
    LDSYM64 x9, GetProcAddress
    blr     x9
    cbz     x0, imp_failed
next_imp:
    str     x0, [x23], #8
    b       next_func
imp_failed:
section PEIERDLL
    ldp     x29, x30, [sp, #0x50]
    ldp     x27, x28, [sp, #0x40]
    ldp     x25, x26, [sp, #0x30]
    ldp     x23, x24, [sp, #0x20]
    ldp     x21, x22, [sp, #0x10]
    ldp     x19, x20, [sp], #0x60
    mov     x0, #0
    ret
section PEIEREXE
    LDSYM64 x9, ExitProcess
    br      x9
section PEIMDONE
imports_done:

// ============= RELOCATION =============

section PERELOC1
    LDSYM32 w9, start_of_relocs
    add     x22, x19, x9
section PERELOC2
    add     x22, x22, #4
section PERELOC3
    sub     x23, x19, #4
reloc_main:
    ldrb    w9, [x22], #1
    cbz     w9, reloc_endx
    cmp     w9, #0xEF
    b.hi    reloc_fx
reloc_add:
    add     x23, x23, x9
    ldr     x10, [x23]
    rev     x10, x10
    add     x10, x10, x19
    str     x10, [x23]
    b       reloc_main
reloc_fx:
    and     w9, w9, #0x0F
    lsl     w9, w9, #16
    ldrh    w10, [x22], #2
    orr     w9, w9, w10
section REL64BIG
    cbnz    w9, reloc_add
    ldr     w9, [x22], #4
section RELOC64J
    b       reloc_add
reloc_endx:

// ============= DEP HACK =============

section PEDEPHAK
    LDSYM64 x25, VirtualProtect
    LDSYM32 w9, vp_base
    add     x22, x19, x9
    LDSYM32 w23, vp_size

    sub     sp, sp, #0x10
    mov     x0, x22
    mov     x1, x23
    mov     w2, #4
    mov     x3, sp
    blr     x25

    LDSYM32 w9, swri
    add     x9, x22, x9
    ldrb    w10, [x9]
    and     w10, w10, #0x7F
    strb    w10, [x9]
    ldrb    w10, [x9, #0x28]
    and     w10, w10, #0x7F
    strb    w10, [x9, #0x28]

    mov     x0, x22
    mov     x1, x23
    ldr     w2, [sp]
    mov     x3, sp
    blr     x25
    add     sp, sp, #0x10

// ============= TLS CALLBACK PART 1 =============

section PETLSC
    adr     x9, PETLSC2
    movz    w10, #0x201f
    movk    w10, #0xd503, lsl #16   // nop = 0xd503201f
    str     w10, [x9]
    LDSYM32 w9, tls_module_base
    add     x0, x19, x9
    mov     w1, #1
    mov     x2, #0
    bl      PETLSC2

// ============= CLEANUP =============

section PEMAIN20
    ldp     x29, x30, [sp, #0x50]
    ldp     x27, x28, [sp, #0x40]
    ldp     x25, x26, [sp, #0x30]
    ldp     x23, x24, [sp, #0x20]
    ldp     x21, x22, [sp, #0x10]
    ldp     x19, x20, [sp], #0x60

section CLEARSTACK
    sub     x9, sp, #128
0:  str     xzr, [sp, #-8]!
    cmp     sp, x9
    b.ne    0b
    add     sp, sp, #128

section PEMAIN21
reloc_end_jmp:

section PEISDLL9
    ldr     x2, [sp, #0x10]
    ldp     x0, x1, [sp], #0x20
section PEISEFI9
    ldp     x0, x1, [sp], #0x10

section PERETURN
    mov     w0, #1
    ret
section PEDOJUMP
    b       original_entry

// ============= TLS CALLBACK PART 2 =============

section PETLSC2
    ret
    stp     x29, x30, [sp, #-0x30]!
    stp     x0, x1, [sp, #0x10]
    str     x2, [sp, #0x20]
    adr     x25, tls_callbacks_ptr
walk_tlsc:
    ldr     x9, [x25], #8
    cbz     x9, done_tlsc
    ldp     x0, x1, [sp, #0x10]
    ldr     x2, [sp, #0x20]
    blr     x9
    b       walk_tlsc
done_tlsc:
    ldp     x29, x30, [sp], #0x30
    ret

// ============= UPX HEADER =============

section UPX1HEAD
    .byte   85,80,88,33
    .byte   161,216,208,213
    .long   0
    .long   0
    .long   0
    .long   0
    .long   0
    .byte   0
    .byte   0
    .byte   0
    .byte   45
