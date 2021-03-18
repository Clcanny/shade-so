// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/08
// Description: https://google.github.io/styleguide/cppguide.html

#include <cstdint>
#include <map>
#include <memory>

#include <LIEF/ELF.hpp>

// #include "spdlog/spdlog.h"
#include "src/elf.h"
#include "src/extend_section.h"
#include "src/handle_global_data_op.h"
#include "src/handle_init_fini_op.h"
#include "src/handle_lazy_symbol_binding.h"
#include "src/handle_strict_symbol_binding.h"
#include "src/merge_section.h"
#include "src/merge_text_section.h"
#include "src/operator.h"
#include "src/patch_rip_insts.h"
#include "src/relocate_jump_slot_entry.h"

int main() {
    // spdlog::set_level(spdlog::level::debug);
    // spdlog::set_pattern("[source %s] [function %!] [line %#] %v");

    std::unique_ptr<LIEF::ELF::Binary> src(
        LIEF::ELF::Parser::parse("libfoo.so"));
    std::unique_ptr<LIEF::ELF::Binary> dst(
        LIEF::ELF::Parser::parse("main.out"));
    std::unique_ptr<LIEF::ELF::Binary> out(
        LIEF::ELF::Parser::parse("main.out"));

    shade_so::SecMallocMgr sec_malloc_mgr(*dst, *src, out.get());
    for (const std::string& sec_name : std::vector<std::string>{
             ".plt.got",
             ".got",
             ".dynsym",
             ".symtab",
             ".rela.dyn",
             ".strtab",
             ".text",
             ".plt",
             ".got.plt",
             ".rela.plt",
             ".dynstr",
             ".rodata",
             // ".init_array",
             ".data"
             // ".init",
             // ".tdata",
             // ".tbss",
         }) {
        // shade_so::ExtendSection(
        //     out.get(), sec_name, src->get_section(sec_name).size())();
        sec_malloc_mgr.get_or_create(sec_name, 0x0);
    }
    for (auto& [_, sec_malloc] : sec_malloc_mgr.get()) {
        sec_malloc.malloc_dependency();
    }
    shade_so::OperatorArgs args(*dst, *src, out.get(), &sec_malloc_mgr);
    shade_so::HandleInitFiniOp handle_init_fini_op(args);
    handle_init_fini_op.extend();

    do {
        // if (!src->has(LIEF::ELF::SEGMENT_TYPES::PT_TLS)) {
        //     break;
        // }
        // const auto& src_seg = src->get(LIEF::ELF::SEGMENT_TYPES::PT_TLS);
        // LIEF::ELF::Segment* out_seg = nullptr;
        // if (out->has(LIEF::ELF::SEGMENT_TYPES::PT_TLS)) {
        //     out_seg = &out->get(LIEF::ELF::SEGMENT_TYPES::PT_TLS);
        // } else {
        //     LIEF::ELF::Segment seg;
        //     seg.type(LIEF::ELF::SEGMENT_TYPES::PT_TLS);
        //     seg.flags(src_seg.flags());
        //     seg.alignment(src_seg.alignment());
        //     out_seg = &out->add_segment<>(seg, 0);
        // }
        // if (src->has_section(".tdata")) {
        //     if (!out->has_section(".tdata")) {
        //         out->add_section
        //     }
        //     shade_so::ExtendSection(
        //         out.get(), ".tdata", src->get_section(".tdata").size())();
        // }
    } while (false);

    shade_so::MergeSection(src.get(), dst.get(), out.get(), ".rodata", 0)();
    // shade_so::MergeSection(
    //     src.get(), dst.get(), out.get(), ".init_array", 0x0)();
    // shade_so::MergeSection(src.get(), dst.get(), out.get(), ".tdata", 0x0)();
    // shade_so::MergeSection(src.get(), dst.get(), out.get(), ".tbss", 0x0)();
    shade_so::MergeSection(src.get(), dst.get(), out.get(), ".got", 0x0)();
    shade_so::HandleLazySymbolBinding(src.get(), dst.get(), out.get())();
    shade_so::MergeTextSection(src.get(), dst.get(), out.get())();
    shade_so::HandleStrictSymbolBinding(src.get(), dst.get(), out.get())();

    // {
    //     for (auto i = 0; i < src->dynamic_relocations().size(); i++) {
    //         const auto& src_reloc = src->dynamic_relocations()[i];
    //         LIEF::ELF::Relocation out_reloc = src_reloc;
    //         if (src_reloc.type() ==
    //                 static_cast<uint32_t>(
    //                     shade_so::RelocType::R_X86_64_DTPMOD64) ||
    //             src_reloc.type() ==
    //                 static_cast<uint32_t>(
    //                     shade_so::RelocType::R_X86_64_DTPOFF64)) {
    //             if (src_reloc.has_symbol()) {
    //                 const auto& src_sym = src_reloc.symbol();
    //                 // TODO(junbin.rjb)
    //                 // 注意是加到 dynamic symbol 里去了还是加到 static symbol
    //                 // 里去了
    //                 if (out->has_symbol(src_sym.name())) {
    //                     out_reloc.symbol(dynamic_cast<LIEF::ELF::Symbol*>(
    //                         &out->get_symbol(src_sym.name())));
    //                 } else {
    //                     auto& out_sym = out->add_dynamic_symbol(src_sym);
    //                     out_reloc.symbol(&out_sym);
    //                 }
    //             }
    //             out_reloc.address(out->get_section(".got").virtual_address()
    //             +
    //                               dst->get_section(".got").size() +
    //                               (src_reloc.address() -
    //                                src->get_section(".got").virtual_address()));
    //             // out->add_dynamic_relocation(out_reloc);
    //         }
    //     }
    // }

    handle_init_fini_op.merge();

    shade_so::HandleGlobalDataOp handle_global_data_op(args);
    handle_global_data_op.merge();

    shade_so::PatchRipInsts(src.get(), dst.get(), out.get())();

    // Set relocation and symbol done.
    // Reset symbol value.
    // TODO(junbin.rjb)
    // Fix LIEF bug.
    out->write("modified-main.out");
    out = LIEF::ELF::Parser::parse("modified-main.out");
    shade_so::RelocateJumpSlotEntry(out.get())();
    out->remove_library("libfoo.so");
    out->add_library("libbar.so");
    out->write("modified-main.out");
}
