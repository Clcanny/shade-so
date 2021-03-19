// Copyright (c) @ 2021 junbin.rjb.
// Copyright (c) @ 2021 junbin.rjb.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#include "src/patch_rip_insts.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <functional>

// #include "spdlog/spdlog.h"

namespace shade_so {
namespace {

// static auto kLogger = spdlog::rotating_logger_mt(
//     "PatchRipInstsOp", "logs/shade_so.LOG", 5 * 1024 * 1024, 3);

}  // namespace

PatchRipInstsOp::PatchRipInstsOp(OperatorArgs args)
    : src_(const_cast<LIEF::ELF::Binary*>(&args.dependency_)),
      dst_(const_cast<LIEF::ELF::Binary*>(&args.artifact_)), out_(args.fat_) {
    assert(src_ != nullptr);
    assert(dst_ != nullptr);
    assert(out_ != nullptr);
    ZydisDecoderInit(
        &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
}

void PatchRipInstsOp::patch() {
    for (const std::string& sec_name :
         std::array<std::string, 4>{".init", ".text", ".plt", ".plt.got"}) {
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
            return BriefValue{.offset = inst.raw.disp.offset,
                              .size = inst.raw.disp.size / 8,
                              .value = operand.mem.disp.value};
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
            return BriefValue{.offset = inst.raw.imm[operand_id].offset,
                              .size = inst.raw.imm[operand_id].size / 8,
                              .value = operand.imm.value.s};
        });
}

void PatchRipInstsOp::patch(
    const std::string& sec_name,
    const std::function<bool(const ZydisDecodedOperand&)>& need_to_patch,
    const std::function<BriefValue(const ZydisDecodedInstruction&,
                                   const ZydisDecodedOperand&,
                                   int)>& extract) {
    const Section& src_sec = src_->get_section(sec_name);
    const Section& dst_sec = dst_->get_section(sec_name);
    const Section& out_sec = out_->get_section(sec_name);
    std::vector<uint8_t> out_content = out_sec.content();
    assert(out_content.size() >= dst_sec.size());
    // std::vector<uint8_t> dst_content = dst_sec.content();
    // assert(std::memcmp(dst_content.data(),
    //                    out_content.data(),
    //                    dst_content.size()) == 0);

    uint64_t offset = 0;
    while (offset < out_content.size()) {
        ZydisDecodedInstruction inst;
        assert(
            ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder_,
                                                  out_content.data() + offset,
                                                  out_content.size() - offset,
                                                  &inst)));
        // (begin, end)
        auto begin = &inst.operands[0] - 1;
        auto end = &inst.operands[0] + inst.operand_count;
        for (int operand_id = 0;
             (begin = std::find_if(begin + 1, end, need_to_patch)) != end;
             operand_id++) {
            assert(operand_id < 2);
            const ZydisDecodedOperand& operand = *begin;

            BriefValue bv = extract(inst, operand, operand_id);
            int64_t value = 0;
            for (decltype(bv.size) i = 0; i < bv.size; i++) {
                auto t = out_content[offset + bv.offset + i] * 1L;
                value |= t << (8 * i);
            }
            switch (bv.size) {
            case 1:
                value = static_cast<int8_t>(value);
                break;
            case 2:
                value = static_cast<int16_t>(value);
                break;
            case 4:
                value = static_cast<int32_t>(value);
                break;
            case 8:
                break;
            default:
                assert(false);
            }
            assert(value == bv.value);

            bool from_dst = offset < dst_sec.size();
            const LIEF::ELF::Section& in_sec = from_dst ? dst_sec : src_sec;
            LIEF::ELF::Binary* in_bin = from_dst ? dst_ : src_;

            uint64_t in_cur_va = in_sec.virtual_address() + offset -
                                 (from_dst ? 0 : dst_sec.size());
            uint64_t in_rip = in_cur_va + inst.length;
            uint64_t in_jump_to = 0;
            assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                &inst, &operand, in_cur_va, &in_jump_to)));
            assert(in_jump_to == in_rip + value);

            // __TMC_END__
            if (!in_bin->has_section_with_va(in_jump_to)) {
                continue;
            }
            assert(in_bin->has_section_with_va(in_jump_to));
            const Section& in_to_sec = in_bin->get_section_with_va(in_jump_to);
            const Section& dst_to_sec = dst_->get_section(in_to_sec.name());
            const Section& out_to_sec = out_->get_section(in_to_sec.name());
            uint64_t out_cur_va = out_sec.virtual_address() + offset;
            uint64_t out_rip = out_cur_va + inst.length;
            int64_t new_value = out_to_sec.virtual_address() +
                                (from_dst ? 0 : dst_to_sec.size()) +
                                (in_jump_to - in_to_sec.virtual_address()) -
                                out_rip;
            if (!from_dst && sec_name == ".plt") {
                continue;
            }
            if (!from_dst) {
                if (in_to_sec.name() == ".plt") {
                    new_value -= 1 * in_to_sec.entry_size();
                }
            }

            std::vector<uint8_t> bytes_to_be_patched;
            for (std::size_t i = 0; i < bv.size; i++) {
                bytes_to_be_patched.emplace_back((new_value >> (8 * i)) & 0xFF);
            }
            out_->patch_address(out_cur_va + bv.offset, bytes_to_be_patched);

            ZydisDecodedInstruction new_inst;
            assert(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
                &decoder_,
                out_->get_section(sec_name).content().data() + offset,
                inst.length,
                &new_inst)));
            uint64_t new_out_jump_to = 0;
            assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                &new_inst,
                &new_inst.operands[0] + (begin - &inst.operands[0]),
                out_cur_va,
                &new_out_jump_to)));
            assert(new_out_jump_to - out_to_sec.virtual_address() -
                       (from_dst ? 0 : dst_to_sec.size()) ==
                   in_jump_to - in_to_sec.virtual_address() -
                       ((!from_dst && in_to_sec.name() == ".plt")
                            ? in_to_sec.entry_size()
                            : 0));
            // kLogger->info(
            //     "Instruction at 0x{:x} changes from '{:s}' to '{:s}'.",
            //     "Instruction at 0x{:x} changes from '{:s}' to '{:s}'.",
            //     origin_buf,
            //     new_buf);
        }
        offset += inst.length;
    }
    assert(offset == out_content.size());
}

}  // namespace shade_so
