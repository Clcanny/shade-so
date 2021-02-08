// Copyright (c) @ 2020 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2020/10/13
// Description

#include "src/handle_lazy_symbol_binding.h"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <numeric>
#include <vector>

// #include "spdlog/sinks/file_sinks.h"
// #include "spdlog/spdlog.h"
#include "src/const.h"
#include "src/extend_section.h"

namespace shade_so {
namespace {

// static auto kLogger = spdlog::rotating_logger_mt(
//     "HandleLazySymbolBinding", "logs/shade_so.LOG", 5 * 1024 * 1024, 3);

}  // namespace

HandleLazySymbolBinding::HandleLazySymbolBinding(Binary* src,
                                                 Binary* dst,
                                                 Binary* out)
    : src_(src), dst_(dst), out_(out) {
    assert(src_);
    assert(dst_);
    assert(out_);

    ZydisDecoderInit(
        &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
}

uint64_t HandleLazySymbolBinding::operator()() {
    const Section& plt = src_->get_section(".plt");
    uint64_t plt_entries_num = plt.size() / plt.entry_size();
    assert(plt_entries_num >= 1);
    plt_entries_num -= 1;

    const Section& got_plt = src_->get_section(".got.plt");
    uint64_t got_plt_entries_num = got_plt.size() / got_plt.entry_size();
    assert(got_plt_entries_num >= 3);
    got_plt_entries_num -= 3;
    assert(got_plt_entries_num == plt_entries_num);

    const Section& rela_plt = src_->get_section(".rela.plt");
    uint64_t rela_plt_num = rela_plt.size() / rela_plt.entry_size();
    assert(rela_plt_num == plt_entries_num);

    uint64_t undef_dynsym_entries_num = std::count_if(
        std::begin(src_->dynamic_symbols()),
        std::end(src_->dynamic_symbols()),
        [](const Symbol& sym) {
            return sym.shndx() ==
                   static_cast<uint16_t>(
                       LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF);
        });
    // assert(undef_dynsym_entries_num == plt_entries_num);

    add_plt(0);
    return plt_entries_num;
}

void HandleLazySymbolBinding::extend(uint64_t entries_num) {
    const Section& plt = out_->get_section(".plt");
    ExtendSection()(out_, ".plt.got", plt.entry_size() * entries_num);

    const Section& got_plt = out_->get_section(".plt.got");
    ExtendSection()(out_, ".plt.got", got_plt.entry_size() * entries_num);

    const Section& rela_plt = out_->get_section(".rela.plt");
    ExtendSection()(out_, ".rela.plt", rela_plt.entry_size() * entries_num);

    const Section& dynsym = out_->get_section(".dynsym");
    ExtendSection()(out_, ".dynsym", dynsym.entry_size() * entries_num);

    // I use a very loose upper bound here.
    ExtendSection()(out_, ".dynstr", src_->get_section(".dynstr").size());
}

void HandleLazySymbolBinding::add_plt(uint64_t src_id) {
    LIEF::ELF::Section& plt = src_->get_section(section_names::kPlt);
    std::vector<uint8_t> content = plt.content();
    uint8_t* data = content.data();
    auto size = plt.entry_size();

    // The first entry of .plt section is a stub.
    decltype(size) offset = 0;
    for (int i = 0; i < 3; i++) {
        ZydisDecodedInstruction instr;
        assert(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
            &decoder_, data + offset, plt.entry_size() - offset, &instr)));
        offset += instr.length;

        if (i == 0) {
            assert(instr.mnemonic == ZYDIS_MNEMONIC_PUSH);
            // kLogger->info("The 1st instruction of plt stub is push.");
            std::cout << "here" << std::endl;
        }
        instr.operand_count;
    }

    uint64_t begin = (src_id + 1) * plt.entry_size();
    uint64_t end = (src_id + 2) * plt.entry_size();
    // uint64_t offset = begin;
    offset = begin;
    uint64_t instrCnt = 0;
    while (offset < end) {
        ZydisDecodedInstruction instr;
        assert(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
            &decoder_, content.data() + offset, end - offset, &instr)));
        offset += instr.length;
    }
    assert(offset == end);
}

}  // namespace shade_so
