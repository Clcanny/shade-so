// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/18
// Description

#include "src/handle_init_fini_op.h"

#include <array>
#include <cassert>

namespace shade_so {

HandleInitFiniOp::HandleInitFiniOp(OperatorArgs args)
    : args_(args), init_off_(0), init_array_off_(0), fini_off_(0),
      fini_array_off_(0) {
}

void HandleInitFiniOp::extend() {
    init_off_ =
        args_.sec_malloc_mgr_->get_or_create(".init", 1).malloc_dependency();
    init_array_off_ = args_.sec_malloc_mgr_->get_or_create(".init_array", 1)
                          .malloc_dependency(1, MallocUnit::kEntry);
    fini_off_ =
        args_.sec_malloc_mgr_->get_or_create(".fini", 1).malloc_dependency();
    fini_array_off_ = args_.sec_malloc_mgr_->get_or_create(".fini_array", 1)
                          .malloc_dependency(1, MallocUnit::kEntry);
}

void HandleInitFiniOp::merge() {
    merge_section(args_.dependency_, args_.fat_, ".init", init_off_);
    merge_section(args_.dependency_, args_.fat_, ".fini", fini_off_);
}

}  // namespace shade_so
