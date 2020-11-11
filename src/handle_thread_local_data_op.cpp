// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/21
// Description

#include "src/handle_thread_local_data_op.h"

#include "src/const.h"

namespace shade_so {

HandleThreadLocalDataOp::HandleThreadLocalDataOp(OperatorArgs args)
    : args_(args), tbss_off_(0), tdata_off_(0) {
}

void HandleThreadLocalDataOp::extend() {
    // tbss_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kTbss)
    //                 .malloc_dependency();
    // tdata_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kTdata)
    //                  .malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(sec_names::kTbss);
    args_.sec_malloc_mgr_->get_or_create(sec_names::kTdata);
}

void HandleThreadLocalDataOp::merge() {
}

}  // namespace shade_so
