// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/08
// Description

#ifndef SRC_MERGE_TEXT_SECTION_H_
#define SRC_MERGE_TEXT_SECTION_H_

#include <cstdint>

#include <LIEF/ELF.hpp>

#include "src/operator.h"

namespace shade_so {

class HandleCodeOp : public Operator {
 public:
    explicit HandleCodeOp(OperatorArgs args);
    void extend() override;
    void merge() override;

 private:
    int64_t text_off_;
    OperatorArgs args_;
};

};  // namespace shade_so

#endif  // SRC_MERGE_TEXT_SECTION_H_
