// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/11
// Description

#ifndef SRC_HANDLE_STRICT_SYMBOL_BINDING_H_
#define SRC_HANDLE_STRICT_SYMBOL_BINDING_H_

#include <cstdint>

#include <LIEF/ELF.hpp>

#include "src/operator.h"

namespace shade_so {

class HandleStrictBindingSymOp : public Operator {
 public:
    explicit HandleStrictBindingSymOp(OperatorArgs args);
    void extend() override;
    void merge() override;

 private:
    OperatorArgs args_;
    int64_t plt_got_off_;
    int64_t got_off_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_STRICT_SYMBOL_BINDING_H_
