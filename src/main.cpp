// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/08
// Description: https://google.github.io/styleguide/cppguide.html

#include <memory>

#include <LIEF/ELF.hpp>

#include "spdlog/spdlog.h"
#include "src/handle_lazy_symbol_binding.h"

int main() {
    spdlog::set_level(spdlog::level::debug);

    std::unique_ptr<LIEF::ELF::Binary> src(
        LIEF::ELF::Parser::parse("libfoo.so"));
    std::unique_ptr<LIEF::ELF::Binary> dst(
        LIEF::ELF::Parser::parse("main.out"));
    std::unique_ptr<LIEF::ELF::Binary> out(
        LIEF::ELF::Parser::parse("main.out"));

    shade_so::HandleLazySymbolBinding(src.get(), dst.get(), out.get())();
}
