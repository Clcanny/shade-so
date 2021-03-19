// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SRC_HANDLE_LAZY_SYMBOL_BINDING_H_
#define SRC_HANDLE_LAZY_SYMBOL_BINDING_H_

#include <Zydis/Zydis.h>

#include <cstdint>

#include <LIEF/ELF.hpp>

#include "src/operator.h"

namespace shade_so {

class HandleLazyBindingSymOp : public Operator {
 public:
    explicit HandleLazyBindingSymOp(OperatorArgs args);
    void merge() override;

 private:
    uint64_t check() const;
    void extend(uint64_t src_id);

    void fill(uint64_t entries_num);
    template <int N>
    void handle_plt_entry_inst(int entry_id,
                               uint64_t offset,
                               const ZydisDecodedInstruction& inst);
    ZydisDecodedOperand get_exact_one_visible_operand(
        const ZydisDecodedInstruction& inst);

 private:
    OperatorArgs args_;
    ZydisDecoder decoder_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_LAZY_SYMBOL_BINDING_H_
