// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/17
// Description

#ifndef SRC_HANDLE_INIT_FINI_OP_H_
#define SRC_HANDLE_INIT_FINI_OP_H_

#include <cstdint>

#include <LIEF/ELF.hpp>

#include "src/operator.h"

namespace shade_so {

class HandleInitFiniOp : public Operator {
 public:
    explicit HandleInitFiniOp(OperatorArgs args);
    void extend() override;
    void merge() override;

 private:
    void merge_init_array();

 private:
    OperatorArgs args_;
    int64_t init_off_;
    int64_t init_array_off_;
    int64_t fini_off_;
    int64_t fini_array_off_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_INIT_FINI_OP_H_
