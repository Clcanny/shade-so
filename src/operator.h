// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/17
// Description

#ifndef SRC_OPERATOR_H_
#define SRC_OPERATOR_H_

#include <LIEF/ELF.hpp>

#include "src/extend_section.h"

namespace shade_so {

class OperatorArgs {
 public:
    OperatorArgs(const LIEF::ELF::Binary& artifact,
                 const LIEF::ELF::Binary& dependency,
                 LIEF::ELF::Binary* fat,
                 SecMallocMgr* sec_malloc_mgr);

 public:
    const LIEF::ELF::Binary& artifact_;
    const LIEF::ELF::Binary& dependency_;
    LIEF::ELF::Binary* fat_;
    SecMallocMgr* sec_malloc_mgr_;
};

class Operator {
 public:
    explicit Operator(OperatorArgs args);
    virtual void extend();
    virtual void merge();
    virtual void patch();

 protected:
    OperatorArgs args_;
};

}  // namespace shade_so

#endif  // SRC_OPERATOR_H_
