// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SRC_PATCH_RIP_INSTS_H_
#define SRC_PATCH_RIP_INSTS_H_

#include <Zydis/Zydis.h>

#include <cstdint>
#include <string>
#include <vector>

#include <LIEF/ELF.hpp>

namespace shade_so {

class PatchRipInsts {
    using Binary = LIEF::ELF::Binary;
    using Section = LIEF::ELF::Section;
    using Symbol = LIEF::ELF::Symbol;

    struct BriefValue {
        uint64_t offset;
        uint64_t size;
        // Use int64_t to represent value of type int32_t, uint32_t, int64_t,
        // uint64_t. I don't think overflow will happen in conversion from
        // uint64_t to int64_t.
        int64_t value;
    };

 public:
    PatchRipInsts(Binary* dst, Binary* out);
    void operator()();

 private:
    void patch(const std::string& sec_name);
    void
    patch(const std::string& sec_name,
          const std::function<bool(const ZydisDecodedOperand&)>& need_to_patch,
          const std::function<BriefValue(const ZydisDecodedInstruction&, int)>&
              extract);

 private:
    Binary* dst_;
    Binary* out_;
    ZydisDecoder decoder_;
    ZydisFormatter formatter_;
};

}  // namespace shade_so

#endif  // SRC_PATCH_RIP_INSTS_H_
