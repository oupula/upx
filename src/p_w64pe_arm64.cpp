/* p_w64pe_arm64.cpp --

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   Copyright (C) Laszlo Molnar
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
 */

#include "conf.h"
#include "file.h"
#include "filter.h"
#include "packer.h"
#include "pefile.h"
#include "p_w64pe_arm64.h"
#define WANT_EHDR_ENUM 1
#include "p_elf_enum.h"
#include "linker.h"

static const CLANG_FORMAT_DUMMY_STATEMENT
#include "stub/arm64-win64.pe.h"

/*************************************************************************
//
**************************************************************************/

PackW64PeArm64::PackW64PeArm64(InputFile *f) : super(f) { use_stub_relocs = false; }

Linker *PackW64PeArm64::newLinker() const { return new ElfLinkerArm64LE; }

const int *PackW64PeArm64::getCompressionMethods(int method, int level) const {
    bool small = ih.codesize + ih.datasize <= 256 * 1024;
    return Packer::getDefaultCompressionMethods_le32(method, level, small);
}

const int *PackW64PeArm64::getFilters() const { return nullptr; }

/*************************************************************************
// pack
**************************************************************************/

tribool PackW64PeArm64::canPack() {
    if (!readFileHeader())
        return false;
    checkMachine(ih.cpu);
    if (ih.cpu != IMAGE_FILE_MACHINE_ARM64)
        return false;
    return true;
}

void PackW64PeArm64::buildLoader(const Filter *ft) {
    UNUSED(ft);
    // recompute tlsindex (see pack() below)
    unsigned tmp_tlsindex = tlsindex;
    const unsigned oam1 = ih.objectalign - 1;
    const unsigned newvsize = (ph.u_len + rvamin + ph.overlap_overhead + oam1) & ~oam1;
    if (tlsindex && ((newvsize - ph.c_len - 1024 + oam1) & ~oam1) > tlsindex + 4)
        tmp_tlsindex = 0;

    // prepare loader
    initLoader(EM_ARM64, stub_arm64_win64_pe, sizeof(stub_arm64_win64_pe), 2);
    addLoader("START");
    if (ih.entry && isdll)
        addLoader("PEISDLL0");
    if (isefi)
        addLoader("PEISEFI0");
    addLoader(isdll ? "PEISDLL1" : "", "PEMAIN01",
              icondir_count > 1 ? (icondir_count == 2 ? "PEICONS1" : "PEICONS2") : "",
              tmp_tlsindex ? "PETLSHAK" : "", "PEMAIN02",

              M_IS_LZMA(ph.method) ? "LZMA_HEAD,LZMA_ELF00,LZMA_DEC20,LZMA_TAIL"

              : M_IS_NRV2B(ph.method) ? "NRV_HEAD,NRV2B"
              : M_IS_NRV2D(ph.method) ? "NRV_HEAD,NRV2D"
              : M_IS_NRV2E(ph.method) ? "NRV_HEAD,NRV2E"
                                      : "UNKNOWN_COMPRESSION_METHOD",
              "", "PEMAIN10");
    // Add jump to skip alignment padding between sections
    if (tmp_tlsindex)
        addLoader("PETLSHAK2");
    else if (soimport)
        addLoader("PEMAIN10J");  // jump to PEIMPORT
    else if (sorelocs)
        addLoader("PEMAIN10R");  // jump to PERELOC1
    else
        addLoader("PEMAIN10M");  // jump to PEMAIN20
    // NOTE: no PEFILTER for ARM64 yet (no call/branch filter implemented)
    if (soimport)
        addLoader("PEIMPORT", importbyordinal ? "PEIBYORD" : "", kernel32ordinal ? "PEK32ORD" : "",
                  importbyordinal ? "PEIMORD1" : "", "PEIMPOR2", isdll ? "PEIERDLL" : "PEIEREXE",
                  "PEIMDONE");
    if (sorelocs) {
        addLoader(soimport == 0 || soimport + cimports != crelocs ? "PERELOC1" : "PERELOC2",
                  "PERELOC3", big_relocs ? "REL64BIG" : "", "RELOC64J",
                  "RELOC64M");  // jump over alignment padding to PEMAIN20
    }
    // FIXME: PEDEPHAK causes ACCESS_VIOLATION on ARM64 Windows, temporarily disabled
    // if (use_dep_hack)
    //     addLoader("PEDEPHAK");

    // TLS callback support PART 1
    if (use_tls_callbacks)
        addLoader("PETLSC");

    addLoader("PEMAIN20");
    // FIXME: CLEARSTACK causes DATATYPE_MISALIGNMENT on ARM64 Windows, temporarily disabled
    // if (use_clear_dirty_stack)
    //     addLoader("CLEARSTACK");
    addLoader("PEMAIN21");

    if (ih.entry && isdll)
        addLoader("PEISDLL9");
    if (isefi)
        addLoader("PEISEFI9");
    addLoader(ih.entry || !ilinker ? "PEDOJUMP" : "PERETURN");

    // TLS callback support PART 2
    if (use_tls_callbacks)
        addLoader("PETLSC2");

    addLoader("IDENTSTR,UPX1HEAD");
}

bool PackW64PeArm64::needForceOption() const {
    // return true if we need `--force` to pack this file
    bool r = false;
    r |= (ih.opthdrsize != 0xf0); // optional header size is 0xF0 in PE32+ files
    r |= ((ih.flags & IMAGE_FILE_EXECUTABLE_IMAGE) == 0);
    r |= ((ih.flags & IMAGE_FILE_32BIT_MACHINE) != 0); // 32 bit machine flag may not be set
    r |= (ih.coffmagic != 0x20b);                      // COFF magic is 0x20B in PE32+ files
    r |= (ih.entry == 0 && !isdll);
    r |= (ih.ddirsentries != 16);
    return r;
}

void PackW64PeArm64::defineSymbols(unsigned ncsection, unsigned upxsection, unsigned sizeof_oh,
                                   unsigned ic, unsigned s1addr) {
    const unsigned myimport = ncsection + soresources - rvamin;

    // patch loader
    linker->defineSymbol("original_entry", ih.entry);
    if (use_dep_hack) {
        const unsigned swri = pe_offset + sizeof_oh + sizeof(pe_section_t) - 1;
        const unsigned addr = 0u - rvamin + swri;
        linker->defineSymbol("swri", addr & 0xfff);
        linker->defineSymbol(
            "vp_size", ((addr & 0xfff) + 0x28 >= 0x1000) ? 0x2000 : 0x1000);
        linker->defineSymbol("vp_base", addr & ~0xfff);
        linker->defineSymbol("VirtualProtect", ilinkerGetAddress("kernel32.dll", "VirtualProtect"));
    }
    linker->defineSymbol("start_of_relocs", crelocs);

    if (ilinker) {
        if (!isdll)
            linker->defineSymbol("ExitProcess", ilinkerGetAddress("kernel32.dll", "ExitProcess"));
        linker->defineSymbol("GetProcAddress", ilinkerGetAddress("kernel32.dll", "GetProcAddress"));
        linker->defineSymbol("kernel32_ordinals", myimport);
        linker->defineSymbol("LoadLibraryA", ilinkerGetAddress("kernel32.dll", "LoadLibraryA"));
        linker->defineSymbol("start_of_imports", myimport);
        linker->defineSymbol("compressed_imports", cimports);
    }

    if (M_IS_LZMA(ph.method)) {
        if (linker->findSymbol("lzma_c_len", false)) {
            linker->defineSymbol("lzma_c_len", ph.c_len - 2);
        }
        if (linker->findSymbol("lzma_u_len", false)) {
            linker->defineSymbol("lzma_u_len", ph.u_len);
        }
    }
    if (linker->findSymbol("filter_buffer_start", false))
        linker->defineSymbol("filter_buffer_start", ih.codebase - rvamin);

    linker->defineSymbol("tls_value",
                         (tlsindex + 4 > s1addr) ? get_le32(obuf + tlsindex - s1addr - ic) : 0);
    linker->defineSymbol("tls_address", tlsindex - rvamin);

    linker->defineSymbol("icon_delta", icondir_count - 1);
    linker->defineSymbol("icon_offset", ncsection + icondir_offset - rvamin);

    const unsigned esi0 = s1addr + ic;
    linker->defineSymbol("start_of_uncompressed", 0u - esi0 + rvamin);
    linker->defineSymbol("start_of_compressed", esi0);
    linker->defineSymbol("compressed_len", ph.c_len);
    linker->defineSymbol("uncompressed_len", ph.u_len);
    // code_rva: RVA of the LBASE label in PEMAIN01 for image base calc.
    // The label's offset within the linked loader is layout-dependent
    // (PEISDLL0/PEISDLL1 prefix sections shift it for DLLs), so query the
    // linker instead of hard-coding 0x28 — the old constant was wrong for
    // DLLs (base off by the 24-byte PEISDLL prefix => every image_base+
    // RVA address wrong => LZMA read garbage props => stack smashing).
    linker->defineSymbol("code_rva", upxsection + linker->getSymbolOffset("LBASE"));

    if (use_tls_callbacks) {
        linker->defineSymbol("tls_callbacks_ptr", tlscb_ptr - ih.imagebase);
        linker->defineSymbol("tls_module_base", 0u - rvamin);
    }

    linker->defineSymbol("START", upxsection);

    // NRV_HEAD ends with "bl DECOMPRESS_ENTRY"; the NRV decoders are
    // call-convention functions (PUSH lr / POP lr + ret), so they must be
    // entered with bl. Point DECOMPRESS_ENTRY at the linked decoder's
    // section start; the linker patches the CALL26 relative branch.
    if (M_IS_NRV2B(ph.method))
        linker->defineSymbol("DECOMPRESS_ENTRY", linker->getSymbolOffset("NRV2B"));
    else if (M_IS_NRV2D(ph.method))
        linker->defineSymbol("DECOMPRESS_ENTRY", linker->getSymbolOffset("NRV2D"));
    else if (M_IS_NRV2E(ph.method))
        linker->defineSymbol("DECOMPRESS_ENTRY", linker->getSymbolOffset("NRV2E"));
}

void PackW64PeArm64::setOhHeaderSize(const pe_section_t *osection) {
    // SizeOfHeaders
    oh.headersize =
        ALIGN_UP(pe_offset + usizeof(oh) + usizeof(*osection) * oh.objects, oh.filealign);
}

void PackW64PeArm64::pack(OutputFile *fo) {
    unsigned mask = (1u << IMAGE_SUBSYSTEM_WINDOWS_GUI) | (1u << IMAGE_SUBSYSTEM_WINDOWS_CUI) |
                    (1u << IMAGE_SUBSYSTEM_EFI_APPLICATION) |
                    (1u << IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) |
                    (1u << IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) | (1u << IMAGE_SUBSYSTEM_EFI_ROM);
    super::pack0(fo, mask, 0x0000000140000000ULL);
}

/*************************************************************************
// unpack
**************************************************************************/

tribool PackW64PeArm64EC::canPack() {
    if (!readFileHeader())
        return false;
    checkMachine(ih.cpu);
    if (ih.cpu != IMAGE_FILE_MACHINE_ARM64EC)
        return false;
    throwCantPack("win64/arm64ec is not yet implemented");
    return true;
}

/* vim:set ts=4 sw=4 et: */
