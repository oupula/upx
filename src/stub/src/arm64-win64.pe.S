/* arm64-win64.pe.S -- loader & decompressor for the w64/pe32+ ARM64 format
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) Markus Franz Xaver Johannes Oberhumer
*  Copyright (C) Laszlo Molnar
*  Copyright (C) John F. Reiser
*  All Rights Reserved.
*
*  UPX and the UCL library are free software; you can redistribute them
*  and/or modify them under the terms of the GNU General Public License as
*  published by the Free Software Foundation; either version 2 of
*  the License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; see the file COPYING.
*  If not, write to the Free Software Foundation, Inc.,
*  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*
*  Markus F.X.J. Oberhumer              Laszlo Molnar
*  <markus@oberhumer.com>               <ml1050@users.sourceforge.net>
*
*  John F. Reiser
*  <jreiser@users.sourceforge.net>
*/

// Windows doesn't support dc/ic cache instructions in user mode
// Must be defined BEFORE including macros.S
#define NO_SYNC_CACHE 1

#include "arch/arm64/v8/macros.S"

// ARM64 relocation macros for symbol handling
// These create placeholder values that will be patched by the UPX linker

// For 32-bit immediate values loaded via LDR literal
// The placeholder is loaded from a nearby literal pool
.macro  LDR_IMM32 reg, sym
        ldr     \reg, 90f
        b       91f
        .balign 4
90:     .4byte  0       // placeholder for \sym
        .reloc  90b, R_AARCH64_ABS32, \sym
91:
.endm

// For 64-bit immediate values
.macro  LDR_IMM64 reg, sym
        ldr     \reg, 90f
        b       91f
        .balign 8
90:     .8byte  0       // placeholder for \sym  
        .reloc  90b, R_AARCH64_ABS64, \sym
91:
.endm

// =============
// ============= ENTRY POINT
// =============

// ARM64 Windows calling convention:
//   x0-x7: arguments, x0: return value
//   x8: indirect result location
//   x9-x15: temporary (caller-saved)
//   x16-x17: intra-procedure-call scratch (IP0/IP1)
//   x18: platform register (TEB on Windows)
//   x19-x28: callee-saved
//   x29: frame pointer (FP)
//   x30: link register (LR)
//   SP must be 16-byte aligned

section START
section PEISDLL0
        // DllMain(hModule=x0, reason=x1, reserved=x2)
        // Save arguments for later restoration
        str     x0, [sp, #-0x30]!
        str     x1, [sp, #0x08]
        str     x2, [sp, #0x10]
section PEISEFI0
        stp     x0, x1, [sp, #-0x10]!

section PEISDLL1
        cmp     w1, #1          // DLL_PROCESS_ATTACH
        b.ne    reloc_end_jmp
section PEMAIN01
        // Save callee-saved registers
        stp     x19, x20, [sp, #-0x60]!
        stp     x21, x22, [sp, #0x10]
        stp     x23, x24, [sp, #0x20]
        // Note: x25 is calculated AFTER this point, so we save x26 only here
        // x25 will be set to image_base and must NOT be restored in PEMAIN20
        str     x26, [sp, #0x38]       // save x26 only (x25 calculated later)
        stp     x27, x28, [sp, #0x40]
        stp     x29, x30, [sp, #0x50]
        // x19 = src (compressed data), x20 = dst (decompression target)
        // x25 = image base (saved for PEIMPORT)
        // Calculate image base: current_VA - current_RVA
        adr     x19, 0f                // x19 = VA of label 0
        ldr     x9, 1f                 // x9 = RVA of label 0 (filled by linker)
        b       2f
        .balign 8
0:                                     // This label's address
1:      .8byte  code_rva               // RVA of label 0
2:      sub     x25, x19, x9           // x25 = image base (VA - RVA) - SAVED
        ldr     x9, 3f
        b       4f
        .balign 8
3:      .8byte  start_of_compressed    // RVA of compressed data
4:      add     x19, x25, x9           // x19 = image_base + RVA = compressed data VA
        ldr     w9, 5f
        b       6f
        .balign 4
5:      .4byte  start_of_uncompressed  // negative offset from compressed to uncompressed
6:      sxtw    x9, w9                 // sign-extend to 64-bit
        add     x20, x19, x9           // x20 = uncompressed data VA

section PEICONS1
        ldr     w10, 1f
        b       2f
1:      .4byte  icon_offset
2:      ldrh    w9, [x20, x10]
        add     w9, w9, #1
        strh    w9, [x20, x10]
section PEICONS2
        ldr     w10, 1f
        ldr     w11, 3f
        b       4f
1:      .4byte  icon_offset
3:      .4byte  icon_delta
4:      ldrh    w9, [x20, x10]
        add     w9, w9, w11
        strh    w9, [x20, x10]
section PETLSHAK
        ldr     x10, 1f
        b       2f
        .balign 8
1:      .8byte  tls_address
2:      add     x9, x20, x10
        ldr     w10, [x9]              // save the TLS index
        stp     x9, x10, [sp, #-0x10]!
        ldr     w11, 3f
        b       4f
        .balign 4
3:      .4byte  tls_value
4:      str     w11, [x9]              // restore compressed data overwritten by TLS index
        b       PEMAIN02               // jump over alignment padding

section PEMAIN02
        mov     x21, x20               // save vaddr for later

// =============
// ============= DECOMPRESSION
// =============

section NRV_HEAD
        // Setup decompression parameters: x0=src, w1=len, x2=dst, x3=&plen_dst
        mov     x0, x19                // x0 = src (compressed data)
        mov     x2, x20                // x2 = dst (decompression target)
        ldr     w1, 1f
        ldr     w9, 3f
        b       5f
1:      .4byte  compressed_len
3:      .4byte  uncompressed_len
5:      sub     sp, sp, #0x10
        str     w9, [sp]
        mov     x3, sp                 // x3 = &plen_dst
        b       NRV2B                  // explicit jump to avoid alignment padding

        // Windows doesn't support dc/ic cache instructions in user mode
#define NO_SYNC_CACHE 1

#define M_NRV2B_LE32    2
#define M_NRV2D_LE32    5
#define M_NRV2E_LE32    8
#define M_CL1B_LE32     11
#define M_LZMA          14

#define xsrc    x0
#define xsrclen w1
#define xdst    x2
#define xdstlen x3
#define methb   w4

#define NO_METHOD_CHECK 1

off     .req w5

// Skip ret in eof_n2b so NRV2B falls through
#define NO_EOF_RET 1

section NRV2B
#include "arch/arm64/v8/nrv2b_d32.S"

// After NRV2B decompression, jump to PEMAIN10 (skip NRV2D/NRV2E/LZMA)
section NRV2B_DONE
        add     sp, sp, #0x10          // undo NRV_HEAD's sub sp, sp, #0x10
        b       PEMAIN10

section NRV2D
#include "arch/arm64/v8/nrv2d_d32.S"

section NRV2D_DONE
        add     sp, sp, #0x10          // undo NRV_HEAD's sub sp, sp, #0x10
        b       PEMAIN10

section NRV2E
#include "arch/arm64/v8/nrv2e_d32.S"

section NRV2E_DONE
        add     sp, sp, #0x10          // undo NRV_HEAD's sub sp, sp, #0x10
        b       PEMAIN10


section LZMA_HEAD
        // Windows doesn't support dc/ic cache instructions in user mode
#ifndef NO_SYNC_CACHE
#define NO_SYNC_CACHE 1
#endif

#include "arch/arm64/v8/lzma_d.S"

section LZMA_TAIL
decompress_done:

// =============
section PEMAIN10
        // NRV2B_DONE already restored sp, just set x19
        mov     x19, x21               // x19 = vaddr (base of uncompressed)
        nop                            // padding to 16 bytes to avoid alignment gaps
        nop
        nop

section PEMAIN10J
        b       PEIMPORT               // jump over alignment padding to PEIMPORT

section PEMAIN10R  
        b       PERELOC1               // jump over alignment padding to PERELOC (no imports)

section PEMAIN10D
        b       PEDEPHAK               // jump over alignment padding to PEDEPHAK (no imports/relocs)

section PEMAIN10M
        b       PEMAIN20               // jump over alignment padding to PEMAIN20 (minimal case)

section PETLSHAK2
        // Restore the TLS index
        ldp     x9, x10, [sp], #0x10
        str     w10, [x9]
        b       PEIMPORT               // jump over alignment padding

// =============
// ============= IMPORTS
// =============

section PEIMPORT
        ldr     x9, 1f
        b       2f
        .balign 8
1:      .8byte  compressed_imports
2:      add     x22, x19, x9
next_dll:
        ldr     w9, [x22]              // offset to DLL name
        cbz     w9, imports_done
        ldr     w10, [x22, #4]         // IAT offset
        add     x0, x9, x19
        ldr     x9, 3f
        b       4f
        .balign 8
3:      .8byte  start_of_imports
4:      add     x0, x0, x9             // x0 = DLL name ptr
        add     x23, x10, x19         // x23 = IAT ptr
        add     x22, x22, #8

        // LoadLibraryA(x0=lpLibFileName)
        ldr     x9, 5f
        b       6f
        .balign 8
5:      .8byte  LoadLibraryA
6:      add     x9, x25, x9            // x9 = image_base + IAT_RVA
        ldr     x9, [x9]               // x9 = actual function pointer
        blr     x9

        mov     x24, x0               // x24 = hModule
next_func:
        ldrb    w9, [x22], #1
        cbz     w9, next_dll
section PEIBYORD
        tbz     w9, #7, byname        // bit7 clear => by name
section PEK32ORD
        tbnz    w9, #5, not_kernel32   // bit5 set => not kernel32 ordinal
        ldr     w9, [x22]
        add     x22, x22, #4
        ldr     x0, [x9, x19]
        ldr     x10, 1f
        b       2f
        .balign 8
1:      .8byte  kernel32_ordinals
2:      add     x0, x0, x10
        b       next_imp
not_kernel32:
section PEIMORD1
        ldrh    w1, [x22]
        add     x22, x22, #2
        b       first_imp

byname:
section PEIMPOR2
        mov     x1, x22               // x1 = function name
        sub     w9, w9, #1
0:      ldrb    w10, [x22], #1
        cbnz    w10, 0b                // skip to null terminator
first_imp:
        mov     x0, x24                // x0 = hModule

        // GetProcAddress(x0=hModule, x1=lpProcName)
        ldr     x9, 1f
        b       2f
        .balign 8
1:      .8byte  GetProcAddress
2:      add     x9, x25, x9            // x9 = image_base + IAT_RVA
        ldr     x9, [x9]               // x9 = actual function pointer
        blr     x9

        cbz     x0, imp_failed
next_imp:
        str     x0, [x23], #8
        b       next_func
imp_failed:
section PEIERDLL
        // DLL import failed - return 0
        ldp     x29, x30, [sp, #0x50]
        ldp     x27, x28, [sp, #0x40]
        ldp     x25, x26, [sp, #0x30]
        ldp     x23, x24, [sp, #0x20]
        ldp     x21, x22, [sp, #0x10]
        ldp     x19, x20, [sp], #0x60
        mov     x0, #0
        ret

section PEIEREXE
        // EXE import failed - ExitProcess
        ldr     x9, 1f
        b       2f
        .balign 8
1:      .8byte  ExitProcess
2:      add     x9, x25, x9            // x9 = image_base + IAT_RVA
        ldr     x9, [x9]               // x9 = actual function pointer
        br      x9
section PEIMDONE
imports_done:


// =============
// ============= RELOCATION
// =============

section PERELOC1
        ldr     x9, 1f
        b       2f
        .balign 8
1:      .8byte  start_of_relocs
2:      add     x22, x19, x9
section PERELOC2
        add     x22, x22, #4
section PERELOC3
        sub     x23, x19, #4          // x23 = base - 4
reloc_main:
        ldrb    w9, [x22], #1
        cbz     w9, reloc_endx
        cmp     w9, #0xEF
        b.hi    reloc_fx
reloc_add:
        add     x23, x23, x9
        ldr     x10, [x23]
        rev     x10, x10               // bswap
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

section RELOC64E
        b       PEDEPHAK               // jump over alignment padding to PEDEPHAK

section RELOC64M
        b       PEMAIN20               // jump over alignment padding to PEMAIN20 (no PEDEPHAK)

// =============
section PEDEPHAK
        ldr     x26, 1f
        b       2f
        .balign 8
1:      .8byte  VirtualProtect
2:      add     x26, x25, x26          // x26 = image_base + IAT_RVA
        ldr     x26, [x26]             // x26 = actual function pointer
        ldr     x9, 3f
        b       4f
        .balign 8
3:      .8byte  vp_base
4:      add     x22, x19, x9
        ldr     w23, 5f
        b       6f
5:      .4byte  vp_size
6:
        // VirtualProtect(lpAddress=x0, dwSize=x1, flNewProtect=x2, lpflOldProtect=x3)
        sub     sp, sp, #0x10
        mov     x0, x22
        mov     x1, x23
        mov     w2, #4                 // PAGE_READWRITE
        mov     x3, sp                 // &oldProtect
        blr     x26

        ldr     w9, 7f
        b       8f
7:      .4byte  swri
8:      add     x9, x22, x9
        ldrb    w10, [x9]
        and     w10, w10, #0x7F        // clear write flag on UPX0
        strb    w10, [x9]
        ldrb    w10, [x9, #0x28]
        and     w10, w10, #0x7F        // clear write flag on UPX1
        strb    w10, [x9, #0x28]

        // Restore original protection
        mov     x0, x22
        mov     x1, x23
        ldr     w2, [sp]              // old protection
        mov     x3, sp
        blr     x26
        add     sp, sp, #0x10

// =============
// ============= TLS callback support part 1
// =============

section PETLSC
        // Overwrite the ret in PETLSC2 with a nop
        adr     x9, PETLSC2
        // Load nop instruction (0xd503201f) using two instructions
        mov     w10, #0x201f
        movk    w10, #0xd503, lsl #16
        str     w10, [x9]

        ldr     x9, 1f
        b       2f
        .balign 8
1:      .8byte  tls_module_base
2:      add     x0, x19, x9            // module base
        mov     w1, #1                 // DLL_PROCESS_ATTACH
        mov     x2, #0                // reserved
        bl      PETLSC2

// ============= Cleanup

section PEMAIN20
        ldp     x29, x30, [sp, #0x50]
        ldp     x27, x28, [sp, #0x40]
        // Note: x25 holds image_base calculated in PEMAIN01, do NOT restore it
        ldr     x26, [sp, #0x38]       // restore x26 only
        ldp     x23, x24, [sp, #0x20]
        ldp     x21, x22, [sp, #0x10]
        ldp     x19, x20, [sp], #0x60
        b       PEDOJUMP               // explicit jump to avoid alignment padding

section CLEARSTACK
        // Clear dirty stack (128 bytes)
        sub     x9, sp, #128
0:      str     xzr, [sp, #-8]!
        cmp     sp, x9
        b.ne    0b
        add     sp, sp, #128

section PEMAIN21
reloc_end_jmp:

section PEISDLL9
        ldr     x2, [sp, #0x10]
        ldr     x1, [sp, #0x08]
        ldr     x0, [sp]
        add     sp, sp, #0x30
section PEISEFI9
        ldp     x0, x1, [sp], #0x10

section PERETURN
        mov     w0, #1
        ret
section PEDOJUMP
        // original_entry is a 32-bit RVA, add image_base (x25)
        ldr     w9, 1f
        b       2f
        .balign 4
1:      .4byte  original_entry
2:      add     x9, x25, x9            // x9 = image_base + original_entry_RVA
        br      x9

// =============
// ============= TLS callback support part 2
// =============

section PETLSC2
        ret                            // gets overwritten with nop by PETLSC
        stp     x29, x30, [sp, #-0x30]!
        stp     x0, x1, [sp, #0x10]
        str     x2, [sp, #0x20]
        ldr     x9, 1f
        b       2f
        .balign 8
1:      .8byte  tls_callbacks_ptr
2:      adr     x19, 1b
        add     x19, x19, x9
walk_tlsc_chain2:
        ldr     x9, [x19], #8
        cbz     x9, done_callbacks
        // Call TLS callback: x0=hModule, x1=reason, x2=reserved (already set)
        ldp     x0, x1, [sp, #0x10]
        ldr     x2, [sp, #0x20]
        blr     x9
        b       walk_tlsc_chain2
done_callbacks:
        ldp     x0, x1, [sp, #0x10]
        ldr     x2, [sp, #0x20]
        ldp     x29, x30, [sp], #0x30
        ret

// =============
// ============= CUT HERE
// =============

#include        "include/header.S"

// vim:set ts=8 sw=8 et:
