// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
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

namespace shade_so {

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

        // [begin, end)
        auto begin = &inst.operands[0] - 1;
        auto end = &inst.operands[0] + inst.operand_count;
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
            // TODO(junbin.rjb)
            // Add or lea?
            uint64_t dst_jump_to = dst_rip + disp;
            uint64_t ra = 0;
            ZydisCalcAbsoluteAddress(&inst, &operand, dst_rip - inst.length, &ra);
            assert(ra == dst_rip + disp);
            std::cout << "here" << std::endl;

            // assert(dst_->has_section_with_va(dst_jump_to));
            // const Section& dst_to_sec = dst_->get_section_with_va(jump_to);
            // const Section& out_to_sec = dst_->get_section(dst_to_sec.name());
            // int64_t addend =
            //     out_to_sec.virtual_address() - dst_to_sec.virtual_address();
            // assert(addend >= 0);
            // disp += out_to_sec.virtual_address() -
            // dst_to_sec.virtual_address();
            // // TODO(junbin.rjb)
            // // ZydisCalcAbsoluteAddress
            // std::vector<uint8_t> bytes_to_be_patched;
            // for (std::size_t i = 0; i < operand_size; i++) {
            //     bytes_to_be_patched.emplace_back((disp >> (8 * i)) & 0xFF);
            // }
            // out_->patch_address(cur_va_ + operand_offset,
            // bytes_to_be_patched);

            // TODO(junbin.rjb)
            // Assert code of out is same as dst.
        }
        offset += inst.length;
    }
    assert(offset == dst_content.size());
}

}  // namespace shade_so
