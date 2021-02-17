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

// #include "spdlog/spdlog.h"

namespace shade_so {
namespace {

// static auto kLogger = spdlog::rotating_logger_mt(
//     "PatchRipInsts", "logs/shade_so.LOG", 5 * 1024 * 1024, 3);

}  // namespace

PatchRipInsts::PatchRipInsts(Binary* dst, Binary* out) : dst_(dst), out_(out) {
    assert(dst_ != nullptr);
    assert(out_ != nullptr);
    ZydisDecoderInit(
        &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
}

void PatchRipInsts::operator()() {
    for (const std::string& sec_name :
         std::array<std::string, 4>{".init", ".text", ".plt", ".plt.got"}) {
        patch(sec_name);
    }
}

void PatchRipInsts::patch(const std::string& sec_name) {
    const Section& dst_sec = dst_->get_section(sec_name);
    std::vector<uint8_t> dst_content = dst_sec.content();
    const Section& out_sec = out_->get_section(sec_name);
    std::vector<uint8_t> out_content = out_sec.content();
    assert(out_content.size() >= dst_content.size());
    std::memcmp(dst_content.data(), out_content.data(), dst_content.size());

    uint64_t offset = 0;
    while (offset < dst_content.size()) {
        ZydisDecodedInstruction inst;
        assert(
            ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder_,
                                                  out_content.data() + offset,
                                                  out_content.size() - offset,
                                                  &inst)));

        // (begin, end)
        auto begin = &inst.operands[0] - 1;
        auto end = &inst.operands[0] + inst.operand_count;
        for (int imm_operand_id = 0;
             (begin = std::find_if(
                  begin + 1,
                  end,
                  [](const ZydisDecodedOperand& operand) {
                      return operand.visibility ==
                                 ZYDIS_OPERAND_VISIBILITY_EXPLICIT &&
                             operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                             operand.imm.is_relative == ZYAN_TRUE;
                  })) != end;
             imm_operand_id++) {
            assert(imm_operand_id < 2);
            const ZydisDecodedOperand& operand = *begin;
            // TODO(junbin.rjb)
            // type = ZYDIS_OPERAND_TYPE_MEMORY
            if (operand.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT &&
                operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operand.imm.is_relative == ZYAN_TRUE) {
                uint64_t dst_rip =
                    dst_sec.virtual_address() + offset + inst.length;
                uint64_t dst_jump_to = 0;
                assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                    &inst, &operand, dst_rip - inst.length, &dst_jump_to)));
                // I assume index of imm is zero.
                const auto operand_offset = inst.raw.imm[imm_operand_id].offset;
                const auto operand_size = inst.raw.imm[imm_operand_id].size / 8;
                // Ignore is_signed.
                int32_t imm = 0;
                for (auto i = 0; i < operand_size; i++) {
                    auto t = out_content[offset + operand_offset + i] * 1L;
                    imm |= t << (8 * i);
                }
                if (imm != operand.imm.value.s) {
                    std::cout << "error" << std::endl;
                    continue;
                }
                assert(imm == operand.imm.value.s);

                assert(dst_->has_section_with_va(dst_jump_to));
                const Section& dst_to_sec =
                    dst_->get_section_with_va(dst_jump_to);
                const Section& out_to_sec =
                    out_->get_section(dst_to_sec.name());
                uint64_t out_cur_va = out_sec.virtual_address() + offset;
                uint64_t out_rip = out_cur_va + inst.length;
                int32_t new_imm = out_to_sec.virtual_address() +
                                  (dst_jump_to - dst_to_sec.virtual_address()) -
                                  out_rip;

                std::vector<uint8_t> bytes_to_be_patched;
                for (std::size_t i = 0; i < operand_size; i++) {
                    bytes_to_be_patched.emplace_back((new_imm >> (8 * i)) &
                                                     0xFF);
                }
                out_->patch_address(out_cur_va + operand_offset,
                                    bytes_to_be_patched);

                ZydisDecodedInstruction new_inst;
                assert(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
                    &decoder_,
                    out_->get_section(sec_name).content().data() + offset,
                    inst.length,
                    &new_inst)));
                uint64_t new_out_jump_to = 0;
                assert(
                    ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&new_inst,
                                                          &new_inst.operands[0],
                                                          out_cur_va,
                                                          &new_out_jump_to)));
                assert(new_out_jump_to - out_to_sec.virtual_address() ==
                       dst_jump_to - dst_to_sec.virtual_address());
                std::cout << "here" << std::endl;
            }
        }

        begin = &inst.operands[0] - 1;
        end = &inst.operands[0] + inst.operand_count;
        while ((begin = std::find_if(
                    begin + 1, end, [](const ZydisDecodedOperand& operand) {
                        return operand.mem.type != ZYDIS_MEMOP_TYPE_INVALID &&
                               operand.mem.base == ZYDIS_REGISTER_RIP;
                    })) != end) {
            const ZydisDecodedOperand& operand = *begin;
            if (!operand.mem.disp.has_displacement) {
                // TODO(junbin.rjb)
                // kLogger->warning();
                continue;
            }
            const auto operand_offset = inst.raw.disp.offset;
            const auto operand_size = inst.raw.disp.size / 8;
            uint64_t disp = 0;
            for (auto i = 0; i < operand_size; i++) {
                auto t = out_content[offset + operand_offset + i] * 1L;
                disp |= t << (8 * i);
            }
            assert(disp == operand.mem.disp.value);
            // offset has already been add inst.length.
            uint64_t dst_rip = dst_sec.virtual_address() + offset + inst.length;
            // Note: I assume operator is addition.
            uint64_t dst_jump_to = 0;
            assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                &inst, &operand, dst_rip - inst.length, &dst_jump_to)));
            assert(dst_jump_to == dst_rip + disp);

            assert(dst_->has_section_with_va(dst_jump_to));
            const Section& dst_to_sec = dst_->get_section_with_va(dst_jump_to);
            const Section& out_to_sec = out_->get_section(dst_to_sec.name());
            uint64_t out_cur_va = out_sec.virtual_address() + offset;
            uint64_t out_rip = out_cur_va + inst.length;
            uint64_t new_disp = out_to_sec.virtual_address() +
                                (dst_jump_to - dst_to_sec.virtual_address()) -
                                out_rip;
            // kLogger->info("Rip addend at 0x{:x} changes from 0x{:x} to
            // 0x{:x}.",
            //               out_cur_va,
            //               disp,
            //               new_disp);
            std::vector<uint8_t> bytes_to_be_patched;
            for (std::size_t i = 0; i < operand_size; i++) {
                bytes_to_be_patched.emplace_back((new_disp >> (8 * i)) & 0xFF);
            }
            out_->patch_address(out_cur_va + operand_offset,
                                bytes_to_be_patched);

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
            assert(new_out_jump_to - out_to_sec.virtual_address() ==
                   dst_jump_to - dst_to_sec.virtual_address());

            char origin_buf[256];
            ZydisFormatterFormatInstruction(
                &formatter_, &inst, origin_buf, sizeof(origin_buf), out_cur_va);
            char new_buf[256];
            ZydisFormatterFormatInstruction(
                &formatter_, &new_inst, new_buf, sizeof(new_buf), out_cur_va);
            // kLogger->info(
            //     "Instruction at 0x{:x} changes from '{:s}' to '{:s}'.",
            //     "Instruction at 0x{:x} changes from '{:s}' to '{:s}'.",
            //     origin_buf,
            //     new_buf);
        }

        offset += inst.length;
    }
    assert(offset == dst_content.size());
}

}  // namespace shade_so
