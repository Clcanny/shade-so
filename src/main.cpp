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
#include "src/handle_lazy_symbol_binding.h"
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

    shade_so::HandleLazySymbolBinding(src.get(), dst.get(), out.get())();
    shade_so::MergeTextSection(src.get(), dst.get(), out.get())();
    shade_so::PatchRipInsts(src.get(), dst.get(), out.get())();
    out->write("modified-main.out");

    // Set relocation and symbol done.
    out = LIEF::ELF::Parser::parse("modified-main.out");
    shade_so::RelocateJumpSlotEntry(out.get())();
    out->remove_library("libfoo.so");
    out->write("modified-main.out");
}
