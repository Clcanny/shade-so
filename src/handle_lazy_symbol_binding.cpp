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
#include "src/elf.h"
#include "src/extend_section.h"

namespace shade_so {
namespace {

// static auto kLogger = spdlog::rotating_logger_mt(
//     "HandleLazyBindingSymOp", "logs/shade_so.LOG", 5 * 1024 * 1024, 3);

}  // namespace

HandleLazyBindingSymOp::HandleLazyBindingSymOp(OperatorArgs args)
    : args_(args) {
    ZydisDecoderInit(
        &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
}

void HandleLazyBindingSymOp::extend() {
    args_.sec_malloc_mgr_->get_or_create(".plt").malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(".got.plt").malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(".rela.plt").malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(".dynsym").malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(".dynstr").malloc_dependency();
}

void HandleLazyBindingSymOp::merge() {
    auto src_ = &args_.dependency_;
    auto dst_ = &args_.artifact_;
    auto out_ = args_.fat_;

    const auto& plt = src_->get_section(".plt");
    uint64_t plt_entries_num = plt.size() / plt.entry_size();
    assert(plt_entries_num >= 1);
    plt_entries_num -= 1;

    const auto& got_plt = src_->get_section(".got.plt");
    uint64_t got_plt_entries_num = got_plt.size() / got_plt.entry_size();
    assert(got_plt_entries_num >= 3);
    got_plt_entries_num -= 3;
    assert(got_plt_entries_num == plt_entries_num);

    const auto& rela_plt = src_->get_section(".rela.plt");
    uint64_t rela_plt_num = rela_plt.size() / rela_plt.entry_size();
    assert(rela_plt_num == plt_entries_num);

    uint64_t undef_dynsym_entries_num = std::count_if(
        std::begin(src_->dynamic_symbols()),
        std::end(src_->dynamic_symbols()),
        [](const LIEF::ELF::Symbol& sym) {
            return sym.shndx() ==
                   static_cast<uint16_t>(
                       LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF);
        });
    // assert(undef_dynsym_entries_num == plt_entries_num);

    extend(plt_entries_num);

    const auto& plt_got = out_->get_section(".plt.got");
    fill(plt_entries_num);
    // return plt_entries_num;
}

void HandleLazyBindingSymOp::extend(uint64_t entries_num) {
    namespace names = sec_names;

    // const auto& plt = out_->get_section(".plt");

    // const auto& got_plt = out_->get_section(names::kGotPlt);

    // const auto& rela_plt = out_->get_section(".rela.plt");

    // const auto& dynsym = out_->get_section(".dynsym");

    // I use a very loose upper bound here.
}

template <int N>
void HandleLazyBindingSymOp::handle_plt_entry_inst(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(false);
}

template <>
void HandleLazyBindingSymOp::handle_plt_entry_inst<0>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    auto src_ = &args_.dependency_;
    auto dst_ = &args_.artifact_;
    auto out_ = args_.fat_;

    assert(inst.mnemonic == ZYDIS_MNEMONIC_JMP);
    const ZydisDecodedOperand& operand = get_exact_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
           operand.mem.base == ZYDIS_REGISTER_RIP &&
           operand.mem.disp.has_displacement);

    const auto& out_plt_sec = out_->get_section(sec_names::kPlt);
    const auto& dst_got_plt_sec = dst_->get_section(sec_names::kGotPlt);
    const auto& out_got_plt_sec = out_->get_section(sec_names::kGotPlt);
    uint64_t cur_va = out_plt_sec.virtual_address() + offset;
    uint64_t rip = cur_va + inst.length;
    uint64_t addend = out_got_plt_sec.virtual_address() +
                      dst_got_plt_sec.size() +
                      entry_id * out_got_plt_sec.entry_size() - rip;
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.disp.size / 8; i++) {
        bytes_to_be_patched.emplace_back((addend >> (8 * i)) & 0xFF);
    }
    assert(cur_va + inst.raw.disp.offset + bytes_to_be_patched.size() <=
           out_plt_sec.virtual_address() + out_plt_sec.size());
    out_->patch_address(cur_va + inst.raw.disp.offset, bytes_to_be_patched);

    bytes_to_be_patched.clear();
    auto got_plt_es = out_got_plt_sec.entry_size();
    for (auto i = 0; i < got_plt_es; i++) {
        bytes_to_be_patched.emplace_back(((cur_va + inst.length) >> (8 * i)) &
                                         0xFF);
    }
    assert(out_got_plt_sec.virtual_address() + dst_got_plt_sec.size() +
               entry_id * got_plt_es + bytes_to_be_patched.size() <=
           out_got_plt_sec.virtual_address() + out_got_plt_sec.size());
    out_->patch_address(out_got_plt_sec.virtual_address() +
                            dst_got_plt_sec.size() + entry_id * got_plt_es,
                        bytes_to_be_patched);
}

template <>
void HandleLazyBindingSymOp::handle_plt_entry_inst<1>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    auto src_ = &args_.dependency_;
    auto dst_ = &args_.artifact_;
    auto out_ = args_.fat_;

    assert(inst.mnemonic == ZYDIS_MNEMONIC_PUSH);
    const ZydisDecodedOperand& operand = get_exact_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
           operand.imm.is_signed == ZYAN_TRUE &&
           operand.imm.is_relative == ZYAN_FALSE);

    const auto& out_plt_sec = out_->get_section(sec_names::kPlt);
    const auto& out_got_plt_sec = out_->get_section(sec_names::kGotPlt);
    const auto& out_rela_plt_sec = out_->get_section(sec_names::kRelaPlt);
    assert(entry_id < src_->pltgot_relocations().size());
    const auto& src_reloc = src_->pltgot_relocations()[entry_id];
    LIEF::ELF::Relocation out_reloc = src_reloc;
    if (src_reloc.has_symbol()) {
        const auto& src_sym = src_reloc.symbol();
        // Symbol& out_sym = out_->add_dynamic_symbol(
        //     src_sym,
        //     src_sym.has_version() ? const_cast<LIEF::ELF::SymbolVersion*>(
        //                                 &src_sym.symbol_version())
        //                           : nullptr);
        LIEF::ELF::Symbol& out_sym = out_->add_dynamic_symbol(src_sym);
        out_reloc.symbol(&out_sym);
    }
    out_reloc.address(out_got_plt_sec.virtual_address() +
                      (dst_->pltgot_relocations().size() + 3 + entry_id) *
                          out_got_plt_sec.entry_size());
    out_->add_pltgot_relocation(out_reloc);

    auto out_rela_id = out_->pltgot_relocations().size() - 1;
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.imm[0].size / 8; i++) {
        bytes_to_be_patched.emplace_back((out_rela_id >> (8 * i)) & 0xFF);
    }
    assert(out_plt_sec.virtual_address() + offset + inst.raw.imm[0].offset +
               bytes_to_be_patched.size() <=
           out_plt_sec.virtual_address() + out_plt_sec.size());
    out_->patch_address(out_plt_sec.virtual_address() + offset +
                            inst.raw.imm[0].offset,
                        bytes_to_be_patched);
}

template <>
void HandleLazyBindingSymOp::handle_plt_entry_inst<2>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    auto src_ = &args_.dependency_;
    auto dst_ = &args_.artifact_;
    auto out_ = args_.fat_;

    assert(inst.mnemonic == ZYDIS_MNEMONIC_JMP);
    const ZydisDecodedOperand& operand = get_exact_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
           operand.imm.is_signed == 1 && operand.imm.is_relative == 1);

    uint64_t out_plt_va = out_->get_section(sec_names::kPlt).virtual_address();
    int64_t value = -1 * (offset + inst.length);
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.imm[0].size / 8; i++) {
        bytes_to_be_patched.emplace_back((value >> (8 * i)) & 0xFF);
    }
    assert(out_plt_va + offset + inst.raw.imm[0].offset +
               bytes_to_be_patched.size() <=
           out_plt_va + out_->get_section(sec_names::kPlt).size());
    out_->patch_address(out_plt_va + offset + inst.raw.imm[0].offset,
                        bytes_to_be_patched);
}

void HandleLazyBindingSymOp::fill(uint64_t entries_num) {
    auto src_ = &args_.dependency_;
    auto dst_ = &args_.artifact_;
    auto out_ = args_.fat_;

    const auto& src_plt = src_->get_section(sec_names::kPlt);
    std::vector<uint8_t> src_plt_content = src_plt.content();
    const auto& dst_plt = dst_->get_section(sec_names::kPlt);
    const auto& out_plt = out_->get_section(sec_names::kPlt);
    auto plt_entry_size = src_plt.entry_size();
    assert(plt_entry_size == dst_plt.entry_size());
    assert(plt_entry_size == out_plt.entry_size());
    // The first entry of .plt section is a stub.
    out_->patch_address(
        out_plt.virtual_address() + dst_plt.size(),
        std::vector<uint8_t>(src_plt_content.begin() + 1 * plt_entry_size,
                             src_plt_content.end()));
    std::vector<uint8_t> out_plt_content = out_plt.content();

    assert(src_plt.size() == (1 + entries_num) * plt_entry_size);
    for (int entry = 0; entry < entries_num; entry++) {
        uint64_t begin = dst_plt.size() + entry * plt_entry_size;
        uint64_t end = begin + plt_entry_size;
        uint64_t offset = begin;
        for (int inst_id = 0; inst_id < 3; inst_id++) {
            ZydisDecodedInstruction inst;
            assert(ZYAN_SUCCESS(
                ZydisDecoderDecodeBuffer(&decoder_,
                                         out_plt_content.data() + offset,
                                         end - offset,
                                         &inst)));
            switch (inst_id) {
            case 0:
                handle_plt_entry_inst<0>(entry, offset, inst);
                break;
            case 1:
                handle_plt_entry_inst<1>(entry, offset, inst);
                break;
            case 2:
                handle_plt_entry_inst<2>(entry, offset, inst);
                break;
                // default:
                //     assert(false);
            }
            offset += inst.length;
        }
        assert(offset == end);
    }
}

ZydisDecodedOperand HandleLazyBindingSymOp::get_exact_one_visible_operand(
    const ZydisDecodedInstruction& inst) {
    auto begin = inst.operands;
    auto end = inst.operands + inst.operand_count;
    auto visible = [](const ZydisDecodedOperand& operand) {
        return operand.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
    };
    assert(std::count_if(begin, end, visible) == 1);
    return *std::find_if(begin, end, visible);
}

}  // namespace shade_so
