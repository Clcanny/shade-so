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

uint64_t ExtendSection::operator()(Binary* bin,
                                   const std::string& name,
                                   uint64_t size) {
    assert(bin && size);
    const Section& section = bin_->get_section(name_);
    size = ceil_size(section, size);
    bin->extend(section, size);

    uint64_t va = section.virtual_address();
    if (va != 0) {
        patch_rip_addrs(bin, va + section.size(), size);
    }
    return size_;
}

uint64_t ExtendSection::ceil_size(const Section& section, uint64_t size) {
    uint64_t align = section.alignment();
    uint64_t va = section.virtual_address();
    uint64_t sz = section.size();
    assert(va % align == 0);
    assert(sz % align == 0);
    // Ensure section align after extending.
    if (size % align == 0) {
        return size;
    } else {
        return (size / align + 1) * align;
    }
}

void ExtendSection::patch_rip_addrs(Binary* bin,
                                    uint64_t insert_at,
                                    uint64_t size) {
    for (const std::string& name :
         std::array<std::string, 4>{".init", ".text", ".plt", ".plt.got"}) {
        PatchRipInsts(bin, name, insert_at, size)();
    }
}

}  // namespace shade_so
