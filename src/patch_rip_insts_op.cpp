// Copyright (c) @ 2021 junbin.rjb.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#include "src/patch_rip_insts_op.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <functional>

#include "src/const.h"

namespace shade_so {

PatchRipInstsOp::PatchRipInstsOp(OperatorArgs args)
    : args_(args), libc_csu_init_sa_(0), libc_csu_init_sz_(0) {
    ZydisDecoderInit(
        &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);

    if (args_.fat_->has_static_symbol(func_names::kLibcCsuInit)) {
        const auto& libc_csu_init_sym =
            args_.fat_->get_static_symbol(func_names::kLibcCsuInit);
        libc_csu_init_sa_ = libc_csu_init_sym.value();
        libc_csu_init_sz_ = libc_csu_init_sym.size();
    } else {
        // TODO(junbin.rjb)
        // Log warning.
    }
}

void PatchRipInstsOp::patch() {
    for (const std::string& sec_name :
         std::array<std::string, 4>{sec_names::kInit,
                                    sec_names::kText,
                                    sec_names::kPlt,
                                    sec_names::kPltGot}) {
        patch(sec_name);
    }
}

void PatchRipInstsOp::patch(const std::string& sec_name) {
    patch(
        sec_name,
        [](const ZydisDecodedOperand& operand) {
            if (operand.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT &&
                operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operand.mem.base == ZYDIS_REGISTER_RIP) {
                assert(operand.mem.disp.has_displacement);
                return true;
            }
            return false;
        },
        [](const ZydisDecodedInstruction& inst,
           const ZydisDecodedOperand& operand,
           int operand_id) {
            const auto operand_offset = inst.raw.disp.offset;
            const auto operand_size = inst.raw.disp.size / 8;
            assert(operand_id == 0);
            return RipOperand{.offset = inst.raw.disp.offset,
                              .size = inst.raw.disp.size / 8,
                              .arg = operand.mem.disp.value};
        });
    patch(
        sec_name,
        [](const ZydisDecodedOperand& operand) {
            return operand.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT &&
                   operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                   operand.imm.is_relative == ZYAN_TRUE;
        },
        [](const ZydisDecodedInstruction& inst,
           const ZydisDecodedOperand& operand,
           int operand_id) {
            assert(operand_id < 2);
            assert(inst.raw.imm[operand_id].size % 8 == 0);
            return RipOperand{.offset = inst.raw.imm[operand_id].offset,
                              .size = inst.raw.imm[operand_id].size / 8,
                              .arg = operand.imm.value.s};
        });
}

void PatchRipInstsOp::patch(
    const std::string& sec_name,
    const std::function<bool(const ZydisDecodedOperand&)>& need_to_patch,
    const std::function<RipOperand(const ZydisDecodedInstruction&,
                                   const ZydisDecodedOperand&,
                                   int)>& extract) {
    const auto& dep_sec = args_.dependency_.get_section(sec_name);
    const auto& artifact_sec = args_.artifact_.get_section(sec_name);
    const auto& fat_sec = args_.fat_->get_section(sec_name);
    std::vector<uint8_t> fat_content = fat_sec.content();
    assert(fat_content.size() >= artifact_sec.size());

    uint64_t offset = 0;
    while (offset < fat_content.size()) {
        ZydisDecodedInstruction inst;
        assert(
            ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder_,
                                                  fat_content.data() + offset,
                                                  fat_content.size() - offset,
                                                  &inst)));
        // (begin, end)
        auto begin = &inst.operands[0] - 1;
        auto end = &inst.operands[0] + inst.operand_count;
        for (int operand_id = 0;
             (begin = std::find_if(begin + 1, end, need_to_patch)) != end;
             operand_id++) {
            assert(operand_id < 2);
            const ZydisDecodedOperand& operand = *begin;
            RipOperand rip_operand = extract(inst, operand, operand_id);
            uint64_t rip_arg = get_rip_arg(sec_name, offset, rip_operand);
            uint64_t new_rip_arg = cal_new_rip_arg(offset < artifact_sec.size(),
                                                   sec_name,
                                                   inst,
                                                   operand,
                                                   offset,
                                                   rip_arg);

            std::vector<uint8_t> bytes_to_be_patched;
            for (std::size_t i = 0; i < rip_operand.size; i++) {
                bytes_to_be_patched.emplace_back((new_rip_arg >> (8 * i)) &
                                                 0xFF);
            }
            uint64_t fat_cur_va = fat_sec.virtual_address() + offset;
            uint64_t fat_rip = fat_cur_va + inst.length;
            args_.fat_->patch_address(fat_cur_va + rip_operand.offset,
                                      bytes_to_be_patched);

            ZydisDecodedInstruction new_inst;
            assert(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
                &decoder_,
                args_.fat_->get_section(sec_name).content().data() + offset,
                inst.length,
                &new_inst)));
            uint64_t new_fat_jump_to = 0;
            assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                &new_inst,
                &new_inst.operands[0] + (begin - &inst.operands[0]),
                fat_cur_va,
                &new_fat_jump_to)));
            assert(new_fat_jump_to - fat_rip == new_rip_arg);
        }
        offset += inst.length;
    }
    assert(offset == fat_content.size());
}

uint64_t PatchRipInstsOp::get_rip_arg(const std::string& sec_name,
                                      uint64_t inst_off,
                                      RipOperand rip_operand) const {
    std::vector<uint8_t> fat_content =
        args_.fat_->get_section(sec_name).content();
    uint64_t rip_arg = 0;
    for (decltype(rip_operand.size) i = 0; i < rip_operand.size; i++) {
        auto t = fat_content[inst_off + rip_operand.offset + i] * 1L;
        rip_arg |= t << (8 * i);
    }
    switch (rip_operand.size) {
    case 1:
        rip_arg = static_cast<int8_t>(rip_arg);
        break;
    case 2:
        rip_arg = static_cast<int16_t>(rip_arg);
        break;
    case 4:
        rip_arg = static_cast<int32_t>(rip_arg);
        break;
    case 8:
        break;
    default:
        assert(false);
    }
    assert(rip_arg == rip_operand.arg);
    return rip_arg;
}

template <>
uint64_t PatchRipInstsOp::cal_new_rip_arg_internal<true>(
    const std::string& sec_name,
    const ZydisDecodedInstruction& inst,
    const ZydisDecodedOperand& operand,
    uint64_t inst_off,
    uint64_t artifact_rip_arg) const {
    const auto& artifact_sec = args_.artifact_.get_section(sec_name);
    const auto& fat_sec = args_.fat_->get_section(sec_name);

    uint64_t artifact_cur_va = artifact_sec.virtual_address() + inst_off;
    uint64_t artifact_rip = artifact_cur_va + inst.length;
    uint64_t artifact_jump_to = 0;
    assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
        &inst, &operand, artifact_cur_va, &artifact_jump_to)));
    assert(artifact_jump_to == artifact_rip + artifact_rip_arg);

    const LIEF::ELF::Section* artifact_to_sec =
        sec_from_va(args_.artifact_, artifact_jump_to);
    const auto& fat_to_sec = args_.fat_->get_section(artifact_to_sec->name());

    uint64_t fat_cur_va = fat_sec.virtual_address() + inst_off;
    uint64_t fat_rip = fat_cur_va + inst.length;
    uint64_t fat_rip_arg = 0;
    // Hack for __libc_csu_init.
    const auto& artifact_init_array_sec =
        args_.artifact_.get_section(sec_names::kInitArray);
    if (artifact_jump_to == artifact_init_array_sec.virtual_address() +
                                artifact_init_array_sec.size() &&
        (artifact_cur_va >= libc_csu_init_sa_ &&
         artifact_cur_va < libc_csu_init_sa_ + libc_csu_init_sz_)) {
        fat_rip_arg =
            args_.fat_->get_section(sec_names::kInitArray).virtual_address() +
            args_.fat_->get(LIEF::ELF::DYNAMIC_TAGS::DT_INIT_ARRAY)
                    .as<LIEF::ELF::DynamicEntryArray>()
                    ->size() *
                args_.fat_->get_section(sec_names::kInitArray).entry_size() -
            fat_rip;
        std::cout << "here" << std::endl;
    } else {
        fat_rip_arg = fat_to_sec.virtual_address() +
                      (artifact_jump_to - artifact_to_sec->virtual_address()) -
                      fat_rip;
    }
    return fat_rip_arg;
}

template <>
uint64_t PatchRipInstsOp::cal_new_rip_arg_internal<false>(
    const std::string& sec_name,
    const ZydisDecodedInstruction& inst,
    const ZydisDecodedOperand& operand,
    uint64_t inst_off,
    uint64_t dep_rip_arg) const {
    if (sec_name == sec_names::kPlt) {
        return dep_rip_arg;
    }
    const auto& dep_sec = args_.dependency_.get_section(sec_name);
    const auto& fat_sec = args_.fat_->get_section(sec_name);

    uint64_t dep_cur_va =
        dep_sec.virtual_address() +
        (inst_off -
         args_.sec_malloc_mgr_->get(dep_sec.name()).exact_one_block_offset());
    uint64_t dep_rip = dep_cur_va + inst.length;
    uint64_t dep_jump_to = 0;
    assert(ZYAN_SUCCESS(
        ZydisCalcAbsoluteAddress(&inst, &operand, dep_cur_va, &dep_jump_to)));
    assert(dep_jump_to == dep_rip + dep_rip_arg);

    const LIEF::ELF::Section* dep_to_sec =
        sec_from_va(args_.dependency_, dep_jump_to);
    const auto& fat_to_sec = args_.fat_->get_section(dep_to_sec->name());
    uint64_t fat_cur_va = fat_sec.virtual_address() + inst_off;
    uint64_t fat_rip = fat_cur_va + inst.length;
    uint64_t fat_rip_arg =
        fat_to_sec.virtual_address() +
        args_.sec_malloc_mgr_->get(fat_to_sec.name()).exact_one_block_offset() +
        (dep_jump_to - dep_to_sec->virtual_address()) - fat_rip;
    if (dep_to_sec->name() == sec_names::kPlt) {
        assert(fat_to_sec.entry_size() == dep_to_sec->entry_size());
        fat_rip_arg -= 1 * dep_to_sec->entry_size();
    }
    return fat_rip_arg;
}

uint64_t PatchRipInstsOp::cal_new_rip_arg(bool from_artifact,
                                          const std::string& sec_name,
                                          const ZydisDecodedInstruction& inst,
                                          const ZydisDecodedOperand& operand,
                                          uint64_t inst_off,
                                          uint64_t artifact_rip_arg) const {
    if (from_artifact) {
        return cal_new_rip_arg_internal<true>(
            sec_name, inst, operand, inst_off, artifact_rip_arg);
    } else {
        return cal_new_rip_arg_internal<false>(
            sec_name, inst, operand, inst_off, artifact_rip_arg);
    }
}

const LIEF::ELF::Section* PatchRipInstsOp::sec_from_va(
    const LIEF::ELF::Binary& bin, uint64_t va) const {
    const LIEF::ELF::Section* sec = nullptr;
    if (bin.has_section_with_va(va)) {
        sec = &bin.section_from_virtual_address(va);
    } else if (bin.has_section(sec_names::kData)) {
        // __TMC_END__
        const auto& data_sec = bin.get_section(sec_names::kData);
        auto tmc_end = data_sec.virtual_address() + data_sec.size();
        if (va == tmc_end) {
            sec = &data_sec;
        } else {
            assert(false);
        }
    } else {
        assert(false);
    }
    return sec;
}

}  // namespace shade_so
