// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/18
// Description

#ifndef SRC_HANDLE_GLOBAL_DATA_OP_H_
#define SRC_HANDLE_GLOBAL_DATA_OP_H_

#include <cstdint>

#include "src/operator.h"

namespace shade_so {

class HandleGlobalDataOp : public Operator {
 public:
    explicit HandleGlobalDataOp(OperatorArgs args);
    void extend() override;
    void merge() override;

 private:
    void merge_relative_relocs();

 private:
    OperatorArgs args_;
    // TODO(junbin.rjb)
    // bss_off_?
    int64_t data_off_;
    int64_t rodata_off_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_GLOBAL_DATA_OP_H_
