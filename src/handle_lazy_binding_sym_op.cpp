// Copyright (c) @ 2020 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2020/10/13
// Description

#include "src/handle_lazy_binding_sym_op.h"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <numeric>
#include <vector>

#include "src/const.h"
#include "src/elf.h"

namespace shade_so {

HandleLazyBindingSymOp::HandleLazyBindingSymOp(OperatorArgs args)
    : args_(args) {
    ZydisDecoderInit(
        &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
}

void HandleLazyBindingSymOp::extend() {
    args_.sec_malloc_mgr_->get_or_create(sec_names::kPlt).malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(sec_names::kGotPlt)
        .malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(sec_names::kRelaPlt)
        .malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(sec_names::kDynsym)
        .malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(sec_names::kDynstr)
        .malloc_dependency();
}

void HandleLazyBindingSymOp::merge() {
    const auto& plt = args_.dependency_.get_section(sec_names::kPlt);
    uint64_t plt_entries_num = plt.size() / plt.entry_size();
    assert(plt_entries_num >= 1);
    plt_entries_num -= 1;

    const auto& got_plt = args_.dependency_.get_section(sec_names::kGotPlt);
    uint64_t got_plt_entries_num = got_plt.size() / got_plt.entry_size();
    assert(got_plt_entries_num >= 3);
    got_plt_entries_num -= 3;
    assert(got_plt_entries_num == plt_entries_num);

    const auto& rela_plt = args_.dependency_.get_section(sec_names::kRelaPlt);
    uint64_t rela_plt_num = rela_plt.size() / rela_plt.entry_size();
    assert(rela_plt_num == plt_entries_num);

    uint64_t undef_dynsym_entries_num = std::count_if(
        std::begin(args_.dependency_.dynamic_symbols()),
        std::end(args_.dependency_.dynamic_symbols()),
        [](const LIEF::ELF::Symbol& sym) {
            return sym.shndx() ==
                   static_cast<uint16_t>(
                       LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF);
        });
    // assert(undef_dynsym_entries_num == plt_entries_num);

    fill(plt_entries_num);
}

template <int N>
void HandleLazyBindingSymOp::handle_plt_entry_inst(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(false);
}

template <>
void HandleLazyBindingSymOp::handle_plt_entry_inst<0>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(inst.mnemonic == ZYDIS_MNEMONIC_JMP);
    const ZydisDecodedOperand& operand = get_exact_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
           operand.mem.base == ZYDIS_REGISTER_RIP &&
           operand.mem.disp.has_displacement);

    const auto& fat_plt_sec = args_.fat_->get_section(sec_names::kPlt);
    const auto& artifact_got_plt_sec =
        args_.artifact_.get_section(sec_names::kGotPlt);
    assert(artifact_got_plt_sec.size() ==
           args_.sec_malloc_mgr_->get(sec_names::kGotPlt)
               .exact_one_block_offset());
    const auto& fat_got_plt_sec = args_.fat_->get_section(sec_names::kGotPlt);
    uint64_t cur_va = fat_plt_sec.virtual_address() + offset;
    uint64_t rip = cur_va + inst.length;
    uint64_t addend = fat_got_plt_sec.virtual_address() +
                      artifact_got_plt_sec.size() +
                      entry_id * fat_got_plt_sec.entry_size() - rip;
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.disp.size / 8; i++) {
        bytes_to_be_patched.emplace_back((addend >> (8 * i)) & 0xFF);
    }
    assert(cur_va + inst.raw.disp.offset + bytes_to_be_patched.size() <=
           fat_plt_sec.virtual_address() + fat_plt_sec.size());
    args_.fat_->patch_address(cur_va + inst.raw.disp.offset,
                              bytes_to_be_patched);

    bytes_to_be_patched.clear();
    auto got_plt_es = fat_got_plt_sec.entry_size();
    for (auto i = 0; i < got_plt_es; i++) {
        bytes_to_be_patched.emplace_back(((cur_va + inst.length) >> (8 * i)) &
                                         0xFF);
    }
    assert(fat_got_plt_sec.virtual_address() + artifact_got_plt_sec.size() +
               entry_id * got_plt_es + bytes_to_be_patched.size() <=
           fat_got_plt_sec.virtual_address() + fat_got_plt_sec.size());
    args_.fat_->patch_address(fat_got_plt_sec.virtual_address() +
                                  artifact_got_plt_sec.size() +
                                  entry_id * got_plt_es,
                              bytes_to_be_patched);
}

template <>
void HandleLazyBindingSymOp::handle_plt_entry_inst<1>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(inst.mnemonic == ZYDIS_MNEMONIC_PUSH);
    const ZydisDecodedOperand& operand = get_exact_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
           operand.imm.is_signed == ZYAN_TRUE &&
           operand.imm.is_relative == ZYAN_FALSE);

    const auto& fat_plt_sec = args_.fat_->get_section(sec_names::kPlt);
    const auto& fat_got_plt_sec = args_.fat_->get_section(sec_names::kGotPlt);
    const auto& fat_rela_plt_sec = args_.fat_->get_section(sec_names::kRelaPlt);
    assert(entry_id < args_.dependency_.pltgot_relocations().size());
    const auto& dep_reloc = args_.dependency_.pltgot_relocations()[entry_id];
    LIEF::ELF::Relocation fat_reloc = dep_reloc;
    if (dep_reloc.has_symbol()) {
        auto fat_sym = create_fat_sym(args_, dep_reloc.symbol());
        fat_reloc.symbol(&get_or_insert_fat_sym(args_, *fat_sym, true));
    }
    fat_reloc.address(
        fat_got_plt_sec.virtual_address() +
        (args_.artifact_.pltgot_relocations().size() + 3 + entry_id) *
            fat_got_plt_sec.entry_size());
    args_.fat_->add_pltgot_relocation(fat_reloc);

    auto fat_rela_id = args_.fat_->pltgot_relocations().size() - 1;
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.imm[0].size / 8; i++) {
        bytes_to_be_patched.emplace_back((fat_rela_id >> (8 * i)) & 0xFF);
    }
    assert(fat_plt_sec.virtual_address() + offset + inst.raw.imm[0].offset +
               bytes_to_be_patched.size() <=
           fat_plt_sec.virtual_address() + fat_plt_sec.size());
    args_.fat_->patch_address(fat_plt_sec.virtual_address() + offset +
                                  inst.raw.imm[0].offset,
                              bytes_to_be_patched);
}

template <>
void HandleLazyBindingSymOp::handle_plt_entry_inst<2>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(inst.mnemonic == ZYDIS_MNEMONIC_JMP);
    const ZydisDecodedOperand& operand = get_exact_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
           operand.imm.is_signed == 1 && operand.imm.is_relative == 1);

    uint64_t fat_plt_va =
        args_.fat_->get_section(sec_names::kPlt).virtual_address();
    int64_t value = -1 * (offset + inst.length);
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.imm[0].size / 8; i++) {
        bytes_to_be_patched.emplace_back((value >> (8 * i)) & 0xFF);
    }
    assert(fat_plt_va + offset + inst.raw.imm[0].offset +
               bytes_to_be_patched.size() <=
           fat_plt_va + args_.fat_->get_section(sec_names::kPlt).size());
    args_.fat_->patch_address(fat_plt_va + offset + inst.raw.imm[0].offset,
                              bytes_to_be_patched);
}

void HandleLazyBindingSymOp::fill(uint64_t entries_num) {
    const auto& dep_plt_sec = args_.dependency_.get_section(sec_names::kPlt);
    std::vector<uint8_t> dep_plt_content = dep_plt_sec.content();
    const auto& artifact_plt_sec = args_.artifact_.get_section(sec_names::kPlt);
    const auto& fat_plt_sec = args_.fat_->get_section(sec_names::kPlt);
    auto plt_entry_size = dep_plt_sec.entry_size();
    assert(plt_entry_size == artifact_plt_sec.entry_size());
    assert(plt_entry_size == fat_plt_sec.entry_size());
    // The first entry of .plt section is a stub.
    assert(
        artifact_plt_sec.size() ==
        args_.sec_malloc_mgr_->get(sec_names::kPlt).exact_one_block_offset());
    args_.fat_->patch_address(
        fat_plt_sec.virtual_address() + artifact_plt_sec.size(),
        std::vector<uint8_t>(dep_plt_content.begin() + 1 * plt_entry_size,
                             dep_plt_content.end()));
    std::vector<uint8_t> fat_plt_content = fat_plt_sec.content();

    assert(dep_plt_sec.size() == (1 + entries_num) * plt_entry_size);
    for (int entry = 0; entry < entries_num; entry++) {
        uint64_t begin = artifact_plt_sec.size() + entry * plt_entry_size;
        uint64_t end = begin + plt_entry_size;
        uint64_t offset = begin;
        for (int inst_id = 0; inst_id < 3; inst_id++) {
            ZydisDecodedInstruction inst;
            assert(ZYAN_SUCCESS(
                ZydisDecoderDecodeBuffer(&decoder_,
                                         fat_plt_content.data() + offset,
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
            default:
                assert(false);
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
