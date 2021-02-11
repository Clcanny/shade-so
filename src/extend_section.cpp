// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#include "src/extend_section.h"

#include <array>
#include <cassert>

#include "src/patch_rip_insts.h"

namespace shade_so {

ExtendSection::ExtendSection(Binary* bin,
                             const std::string& name,
                             uint64_t size)
    : bin_(bin), section_(bin_->get_section(name)), size_(size) {
    assert(bin_ != nullptr);
    assert(size_ > 0);
}

uint64_t ExtendSection::operator()() {
    ceil_size();
    bin_->extend(section_, size_);
    return size_;
}

void ExtendSection::ceil_size() {
    uint64_t align = section_.alignment();
    uint64_t va = section_.virtual_address();
    uint64_t sz = section_.size();
    assert(va % align == 0);
    assert(sz % align == 0);
    // Ensure section align after extending.
    if (size_ % align != 0) {
        size_ = (size_ / align + 1) * align;
    }
}

}  // namespace shade_so
