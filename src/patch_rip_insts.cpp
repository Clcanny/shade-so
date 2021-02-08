// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#include "src/patch_rip_insts.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cassert>
#include <cstddef>

namespace shade_so {

PatchRipInsts::PatchRipInsts(Binary* bin,
                             const std::string& target_section,
                             uint64_t extend_after,
                             uint64_t extend_size)
    : bin_(bin), sec_va_(0), cur_va_(0),  //
      extend_after_(extend_after), extend_size_(extend_size) {
    assert(bin_ != nullptr);
    const Section& sec = bin_->get_section(target_section);
    sec_va_ = sec.virtual_address();
    assert(sec_va_ != 0);
    cur_va_ = sec_va_;
    content_ = sec.content();

    ZydisDecoderInit(
        &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
}

void PatchRipInsts::operator()() {
    ZydisDecodedInstruction inst;
    for (; cur_va_ < sec_va_ + content_.size() &&
           ZYAN_SUCCESS(
               ZydisDecoderDecodeBuffer(&decoder_,
                                        content_.data() + (cur_va_ - sec_va_),
                                        content_.size() - (cur_va_ - sec_va_),
                                        &inst));
         cur_va_ += inst.length) {
        patch_memory_type_operand(inst);
    }
    assert(cur_va_ == sec_va_ + content_.size());
}

bool PatchRipInsts::patch_memory_type_operand(
    const ZydisDecodedInstruction& inst) {
    auto begin = &inst.operands[0];
    auto end = &inst.operands[0] + inst.operand_count;
    auto is_mem_type_operand = [](const ZydisDecodedOperand& operand) {
        return operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
               operand.mem.base == ZYDIS_REGISTER_RIP &&
               operand.mem.disp.has_displacement;
    };

    int cnt = std::count_if(begin, end, is_mem_type_operand);
    assert(cnt <= 1);
    if (cnt == 0) {
        char buf[256];
        ZydisFormatterFormatInstruction(
            &formatter_, &inst, buf, sizeof(buf), cur_va_);
        // TODO(junbin.rjb)
        // Use gabime/spdlog.
        std::cout << "Can't patch rip addrs: " << buf << std::endl;
        return false;
    }

    const ZydisDecodedOperand* p =
        std::find_if(begin, end, is_mem_type_operand);
    assert(p < end);
    const ZydisDecodedOperand& operand = *p;
    uint64_t disp = 0;
    const std::size_t operand_offset = inst.raw.disp.offset,
                      operand_size = inst.raw.disp.size / 8;
    for (std::size_t i = 0; i < operand_size; i++) {
        disp |= (content_.data()[cur_va_ + operand_offset + i] * 1L) << (8 * i);
    }
    assert(disp == operand.mem.disp.value);

    disp += get_addend(inst, disp);
    std::vector<uint8_t> bytes_to_be_patched;
    for (std::size_t i = 0; i < operand_size; i++) {
        bytes_to_be_patched.emplace_back((disp >> (8 * i)) & 0xFF);
    }
    bin_->patch_address(cur_va_ + operand_offset, bytes_to_be_patched);
    return true;
}

int64_t PatchRipInsts::get_addend(const ZydisDecodedInstruction& inst,
                                  uint64_t disp) {
    uint64_t rip = cur_va_ + inst.length;
    int64_t direction = (rip + disp >= extend_after_ ? 1 : -1) +
                        (cur_va_ >= extend_after_ ? -1 : 1);
    if (direction > 0) {
        return extend_size_;
    } else if (direction == 0) {
        return 0;
    } else {
        return -1 * extend_size_;
    }
}

}  // namespace shade_so
