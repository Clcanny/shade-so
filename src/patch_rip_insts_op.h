// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SRC_PATCH_RIP_INSTS_OP_H_
#define SRC_PATCH_RIP_INSTS_OP_H_

#include <Zydis/Zydis.h>

#include <cstdint>
#include <string>
#include <vector>

#include <LIEF/ELF.hpp>

#include "src/operator.h"

namespace shade_so {

struct RipOperand {
    uint64_t offset;
    uint64_t size;
    // Use int64_t to represent value of type int32_t, uint32_t, int64_t,
    // uint64_t. I don't think overflow will happen in conversion from
    // uint64_t to int64_t.
    int64_t arg;
};

class PatchRipInstsOp : public Operator {
 public:
    explicit PatchRipInstsOp(OperatorArgs args);
    void patch() override;

 private:
    void patch(const std::string& sec_name);
    void patch(
        const std::string& sec_name,
        const std::function<bool(const ZydisDecodedOperand&)>& need_to_patch,
        const std::function<RipOperand(const ZydisDecodedInstruction&,
                                       const ZydisDecodedOperand&,
                                       int)>& extract);

    uint64_t get_rip_arg(const std::string& sec_name,
                         uint64_t inst_off,
                         RipOperand operand) const;

    uint64_t cal_new_rip_arg(bool from_artifact,
                             const std::string& sec_name,
                             const ZydisDecodedInstruction& inst,
                             const ZydisDecodedOperand& operand,
                             uint64_t inst_off,
                             uint64_t artifact_rip_arg) const;
    template <bool from_artifact>
    uint64_t cal_new_rip_arg_internal(const std::string& sec_name,
                                      const ZydisDecodedInstruction& inst,
                                      const ZydisDecodedOperand& operand,
                                      uint64_t inst_off,
                                      uint64_t artifact_rip_arg) const;
    const LIEF::ELF::Section* sec_from_va(const LIEF::ELF::Binary& bin,
                                          uint64_t va) const;

 private:
    OperatorArgs args_;
    ZydisDecoder decoder_;
    ZydisFormatter formatter_;

    int64_t libc_csu_init_sa_;
    int64_t libc_csu_init_sz_;
};

}  // namespace shade_so

#endif  // SRC_PATCH_RIP_INSTS_OP_H_
