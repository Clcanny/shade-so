// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/08
// Description: https://google.github.io/styleguide/cppguide.html

#include <cstdint>
#include <memory>

#include <LIEF/ELF.hpp>

// #include "spdlog/spdlog.h"
#include "src/extend_section.h"
#include "src/handle_lazy_symbol_binding.h"
#include "src/handle_strict_symbol_binding.h"
#include "src/merge_section.h"
#include "src/merge_text_section.h"
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

    for (const std::string& sec_name : std::vector<std::string>{".plt.got",
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
                                                                ".rodata"}) {
        shade_so::ExtendSection(
            out.get(), sec_name, src->get_section(sec_name).size())();
    }

    shade_so::MergeSection(src.get(), dst.get(), out.get(), ".rodata", 0)();
    shade_so::HandleLazySymbolBinding(src.get(), dst.get(), out.get())();
    shade_so::MergeTextSection(src.get(), dst.get(), out.get())();
    shade_so::HandleStrictSymbolBinding(src.get(), dst.get(), out.get())();
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
