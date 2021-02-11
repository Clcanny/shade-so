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

 public:
    PatchRipInsts(Binary* dst, Binary* out);
    void operator()();

 private:
    void patch(const std::string& target_sec_name);

 private:
    Binary* dst_;
    Binary* out_;
    ZydisDecoder decoder_;
    ZydisFormatter formatter_;
};

}  // namespace shade_so

#endif  // SRC_PATCH_RIP_INSTS_H_
