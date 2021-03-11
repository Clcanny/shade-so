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

    using shade_so::ExtendSection;
    ExtendSection(out.get(), ".plt.got", src->get_section(".plt.got").size())();
    ExtendSection(out.get(), ".got", src->get_section(".got").size())();
    ExtendSection(out.get(), ".dynsym", src->get_section(".dynsym").size())();
    ExtendSection(out.get(), ".symtab", src->get_section(".symtab").size())();
    ExtendSection(
        out.get(), ".rela.dyn", src->get_section(".rela.dyn").size())();
    ExtendSection(out.get(), ".strtab", src->get_section(".strtab").size())();
    ExtendSection(out.get(), ".symtab", src->get_section(".symtab").size())();
    ExtendSection(out.get(), ".text", src->get_section(".text").size())();

    ExtendSection(out.get(), ".plt", src->get_section(".plt").size())();
    ExtendSection(out.get(), ".got.plt", src->get_section(".got.plt").size())();
    ExtendSection(
        out.get(), ".rela.plt", src->get_section(".rela.plt").size())();
    ExtendSection(out.get(), ".dynsym", src->get_section(".dynsym").size())();
    ExtendSection(out.get(), ".dynstr", src->get_section(".dynstr").size())();
    // out->write("modified-main.out");

    // out = LIEF::ELF::Parser::parse("modified-main.out");
    shade_so::HandleLazySymbolBinding(src.get(), dst.get(), out.get())();
    shade_so::MergeTextSection(src.get(), dst.get(), out.get())();
    shade_so::HandleStrictSymbolBinding(src.get(), dst.get(), out.get())();
    shade_so::PatchRipInsts(src.get(), dst.get(), out.get())();
    out->write("modified-main.out");

    // Set relocation and symbol done.
    out = LIEF::ELF::Parser::parse("modified-main.out");
    shade_so::RelocateJumpSlotEntry(out.get())();
    out->remove_library("libfoo.so");
    out->add_library("libbar.so");
    out->write("modified-main.out");
}
