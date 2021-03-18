// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/17
// Description

#include "src/operator.h"

namespace shade_so {

OperatorArgs::OperatorArgs(const LIEF::ELF::Binary& artifact,
                           const LIEF::ELF::Binary& dependency,
                           LIEF::ELF::Binary* fat,
                           SecMallocMgr* sec_malloc_mgr)
    : artifact_(artifact), dependency_(dependency), fat_(fat),
      sec_malloc_mgr_(sec_malloc_mgr) {
    assert(fat_);
    assert(sec_malloc_mgr_);
}

Operator::Operator(OperatorArgs args) : args_(args) {
}

void Operator::extend() {
}

void Operator::merge() {
}

void Operator::patch() {
}

}  // namespace shade_so
