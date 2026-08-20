/* lzma_d.S -- arm64 decompressor for LZMA

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   Copyright (C) Laszlo Molnar
   Copyright (C) John F. Reiser
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ezerotven+github@gmail.com>

   John F. Reiser
   <jreiser@users.sourceforge.net>
*/

#include "macros.S"
lr .req x30
fp .req x29

#define section .section
NBPW= 8

  section LZMA_ELF00
//decompress:  // (uchar const *src, size_t lsrc, uchar *dst, u32 &ldst, uint method)
/* Arguments according to calling convention */
src  .req x0
lsrc .req w1
dst  .req x2
ldst .req x3  /* Out: actually a reference: &len_dst */

t0   .req w7
t1   .req w8
t1x  .req x8

        PUSH4(x2,x3, fp,lr)  // MATCH_94  dst,ldst, fp,lr
        mov fp,sp  // we use alloca (inlined and zeroed)

#define LZMA_BASE_SIZE 1846
#define LZMA_LIT_SIZE   768

        ldrb t1,[src,#0]  // first byte, replaces LzmaDecodeProperties()
        mov t0,#2*LZMA_LIT_SIZE
        lsr t1,t1,#3  // lit_context_bits + lit_pos_bits
        lslv t0,t0,t1  // 2*LZMA_LIT_SIZE << (lit_context_bits + lit_pos_bits)
#define W 4  /* even #bits to round up so that 8 bits span all the 1's */
        add t0,t0,#((~(~0<<W) + 2*LZMA_BASE_SIZE)>>W)<<W  // 0 mod 16
        // +16: room for the 4-byte state header (lc/lp/pb + pad) below the
        // probability array and a spare inSizeProcessed slot above it. See
        // the layout comment at "State= 0" below.
        add t0,t0,#16

        mov t1x,sp
        // Stack probe: touch each page of the region we are about to use.
        // On Windows the thread stack grows on demand via a guard page just
        // below sp; writing at a large offset above the final sp (as the
        // decoder does when initializing its probability array) skips the
        // guard and faults. Probing page by page commits the pages first.
        // x9 = final sp target; probe from (sp - t0) upward a page at a time.
        mov x9,sp
        sub x9,x9,t0,uxtw
1:      cmp x9,t1x
        bhs 2f
        ldr wzr,[x9]
        add x9,x9,#0x1000
        b 1b
2:
        mov t1x,sp
        sub sp,sp,t0,uxtw
        mov x4,sp
1:  // clear lzma probability array
        stp xzr,xzr,[x4],#2*NBPW
        cmp x4,t1x
        blo 1b

a0 .req x0  /* &CLzmaDecoderState */
a1 .req x1  /* inp */
a2 .req w2  /* inSize */
a3 .req x3  /* &inSizeProcessed */
a4 .req x4  /* outp */
a5 .req w5  /* outSize */
a6 .req x6  /* &outSizeProcessed */
//The target is:
//LzmaDecode(  // from lzmaSDK/C/7zip/Compress/LZMA_C/LzmaDecode.h
//      a0= &CLzmaDecoderState,
//      a1= inp,  a2= inSize,  a3= &inSizeProcessed,
//      a4= outp, a5= outSize, a6= &outSizeProcessed
//)
        mov a6,ldst  // &outSizeProcessed
        ldr a5,[a6]  // outSize
        mov a4,dst  // outp
        mov a1,src  // inp
        // Decoder memory contract (both DEC10 and DEC20): probability array
        // starts at (vs + 4) and extends 2*count bytes upward. Layout of the
        // alloca'd region (t0 = 2*count + 16, all zeroed):
        //   [newsp+0  .. +3]    state header: lc/lp/pb (+pad)
        //   [newsp+4  .. +2*count+4)  probability array
        //   [oldsp-8  .. -4]    inSizeProcessed slot (8 bytes above the array
        //                        tail + pad; the decoder writes its consumed
        //                        length here, the array never reaches it)
State= 0
        add a0,sp,#State
        add a3,t1x,#-8  // &inSizeProcessed, at the top of the alloca region
        sub w2,lsrc,#2  // inSize

        ldrb t0,[a1],#1  // first byte, replaces LzmaDecodeProperties()
        and  t0,t0,#7  // posBits
        strb t0,[a0,#2]
        ldrb t0,[a1],#1  // second byte, replaces LzmaDecodeProperties()
        lsr  t1,t0,#4  // lit_pos_bits
        strb t1,[a0,#1]
        and  t0,t0,#0xf  // lib_context_bits
        strb t0,[a0,#0]
        bl ClangLzmaDecode  // the call
        mov sp,fp  // undo inlined alloca

#if defined(WINDOWS_BACK) || !defined(DAISY_CHAIN)  //{
eof_lzma:
        mov x5,x0  // save result value
        POP4(x0,x1, fp,lr)  // MATCH_94  x0= orig_dst; x1= plen_dst
        ldr x1,[x1]  // outSizeProcessed

        add x1,x1,x0  // last
        sync_cache  // x0= lo; x1= hi; uses x2-x4

        mov x0,x5  // result value
        ret
#else  //}{
        b eof_lzma
#endif  //}

#undef t0
#undef t1
#undef t1x

#undef lsrc
#undef ldst

    .unreq src
    .unreq lsrc
    .unreq dst
    .unreq ldst
    .unreq t0
    .unreq t1
    .unreq t1x
    .unreq a0
    .unreq a1
    .unreq a2
    .unreq a3
    .unreq a4
    .unreq a5
    .unreq a6

ClangLzmaDecode:  // entry to C-lang LzmaDecode in next section
  section LZMA_DEC20
#include "lzma_d_cf.S"

  section LZMA_DEC10
#if 0  /*{*/
#include "lzma_d_cs.S"
#else  /*}{*/
#define PARAMETER_STYLE 3
#include "lzma_d-arm.S"
#endif  /*}*/

  section LZMA_DEC30
not_lzma:  // fall into daisy chain

// vi:ts=8:et

