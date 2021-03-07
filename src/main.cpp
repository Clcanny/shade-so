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
#include "src/merge_section.h"
#include "src/patch_rip_insts.h"

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
    uint8_t nop_code = 0x90;
    uint64_t va =
        shade_so::MergeSection(src.get(), out.get(), ".text", nop_code)();
    shade_so::PatchRipInsts(dst.get(), out.get())();

    out->write("modified-main.out");
}
