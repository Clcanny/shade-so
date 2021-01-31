// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SRC_PATCH_RIP_INSTS_H_
#define SRC_PATCH_RIP_INSTS_H_

#include <cstdint>
#include <string>
#include <vector>

#include <LIEF/ELF.hpp>

namespace LIEF {
namespace ELF {

class PatchRipInsts {
 public:
    PatchRipInsts(Binary* bin,
                  const std::string& target_section,
                  uint64_t extend_after,
                  extend_size);
    void operator()();

 private:
    Binary* bin_;
    uint64_t sec_va_;
    uint64_t cur_va_;
    std::vector<uint8_t> content_;
    uint64_t extend_after_;
    uint64_t extend_size_;

    ZydisDecoder decoder_;
    ZydisFormatter formatter_;
};

}  // namespace ELF
}  // namespace LIEF

#endif  // SRC_PATCH_RIP_INSTS_H_
