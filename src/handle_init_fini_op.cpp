// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/18
// Description

#include "src/handle_init_fini_op.h"

#include <cassert>
#include <array>

namespace shade_so {

HandleInitFiniOp::HandleInitFiniOp(
    const LIEF::ELF::Binary& dependency,
    LIEF::ELF::Binary* fat,
    std::map<std::string, SecMallocMgr>* sec_malloc_mgrs)
    : dependency_(dependency), fat_(fat), sec_malloc_mgrs_(sec_malloc_mgrs) {
    assert(fat_ != nullptr);
    assert(sec_malloc_mgrs_ != nullptr);
}

void HandleInitFiniOp::extend() {
    auto []sec_malloc_mgrs->emplace(".init", SecMallocMgr(".init"));
}

}  // namespace shade_so
