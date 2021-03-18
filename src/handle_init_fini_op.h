// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/17
// Description

#ifndef SRC_HANDLE_INIT_FINI_OP_H_
#define SRC_HANDLE_INIT_FINI_OP_H_

#include <map>
#include <string>

#include <LIEF/ELF.hpp>

#include "src/extend_section.h"
#include "src/operator.h"

namespace shade_so {

class HandleInitFiniOp : public Operator {
 public:
    HandleInitFiniOp(const LIEF::ELF::Binary& dependency,
                     LIEF::ELF::Binary* fat,
                     std::map<std::string, SecMallocMgr>* sec_malloc_mgrs);
    void extend() override;

 private:
    std::map<std::string, SecMallocMgr> sec_malloc_mgrs_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_INIT_FINI_OP_H_
