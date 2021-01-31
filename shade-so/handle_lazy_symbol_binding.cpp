// Copyright (c) @ 2020 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2020/10/13
// Description

#include "handle_lazy_symbol_binding.h"

#include <algorithm>
#include <cassert>
#include <numeric>
#include <ranges>

namespace LIEF {
namespace ELF {

HandleLazySymbolBinding::HandleLazySymbolBinding(Binary* src,
                                                 Binary* dst,
                                                 Binary* out)
    : src_(src), dst_(dst), out_(out) {
    assert(src_);
    assert(dst_);
    assert(out_);
}

uint64_t HandleLazySymbolBinding::check() const {
    const Section& plt = src_->get_section(".plt");
    assert(plt.entry_size() != 0);
    uint64_t plt_entries_num = plt.size() / plt.entry_size();
    assert(plt_entries_num >= 1);
    plt_entries_num -= 1;

    const Section& got_plt = src_->get_section(".got.plt");
    assert(got_plt.entry_size() != 0);
    uint64_t got_plt_entries_num = got_plt.size() / got_plt.entry_size();
    assert(got_plt_entries_num >= 3);
    got_plt_entries_num -= 3;
    assert(got_plt_entries_num == plt_entries_num);

    const Section& rela_plt = src_->get_section(".rela.plt");
    assert(rela_plt.entry_size() != 0);
    uint64_t rela_plt_num = rela_plt.size() / rela_plt.entry_size();
    assert(rela_plt_num == plt_entries_num);

    uint64_t undef_dynsym_entries_num = std::count_if(
        std::begin(src_->dynamic_symbols()),
        std::end(src_->dynamic_symbols()),
        [](const Symbol& sym) {
            return sym.shndx() ==
                   static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF);
        });
    assert(undef_dynsym_entries_num == plt_entries_num);

    return plt_entries_num;
}

void HandleLazySymbolBinding::extend(uint64_t entries_num) {
    const Section& plt = out_->get_section(".plt");
    out_->extend(plt, plt.entry_size() * entries_num);

    const Section& got_plt = out_->get_section(".plt.got");
    out_->extend(got_plt, got_plt.entry_size() * entries_num);

    const Section& rela_plt = out_->get_section(".rela.plt");
    out_->extend(rela_plt, rela_plt.entry_size() * entries_num);

    const Section& dynsym = out_->get_section(".dynsym");
    out_->extend(dynsym, dynsym.entry_size() * entries_num);

    // No need to handle .dynstr, LIEF will handle it.
    src_->dynamic_symbols() | std::views::filter([](const Symbol& sym) {
        return sym.shndx() ==
               static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF);
    }) | std::views::transform([](const Symbol& sym) {
        return sym.name().size() + 1;
    });
}

void HandleLazySymbolBinding::add_plt(uint64_t src_id) {
    Section& plt = src_->get_section(".plt");
    // The first entry of .plt section is a stub.
    // uint64_t begin = (src_id + 1) * plt.entry_size();
    // uint64_t end = (src_id + 2) * plt.entry_size();
    // uint64_t offset = begin;
    // uint64_t instrCnt = 0;
    // while (offset < end) {
    //     ZydisDecodedInstruction instr;
    //     assert(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
    //         &decoder_, plt.content() + i, end - i, &instr)));
    //     offset += instr.length;
    // }
    // assert(offset == end);
}

}  // namespace ELF
}  // namespace LIEF
