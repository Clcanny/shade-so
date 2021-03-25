// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/21
// Description

#ifndef SRC_HANDLE_THREAD_LOCAL_DATA_OP_H_
#define SRC_HANDLE_THREAD_LOCAL_DATA_OP_H_

#include <cstdint>

#include "src/operator.h"

namespace shade_so {

class HandleThreadLocalDataOp : public Operator {
 public:
    explicit HandleThreadLocalDataOp(OperatorArgs args);
    void extend() override;
    void merge() override;

 private:
    void merge_reloc(const LIEF::ELF::Segment& dep_tls_seg,
                     const LIEF::ELF::Segment& fat_tls_seg);

 private:
    OperatorArgs args_;
    int64_t tdata_off_;
    int64_t tbss_off_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_THREAD_LOCAL_DATA_OP_H_
