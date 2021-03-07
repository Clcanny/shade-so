// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/07
// Description

#include "src/merge_section.h"

#include <cstring>
#include <vector>

#include "src/extend_section.h"

namespace shade_so {

MergeSection::MergeSection(Binary* src,
                           Binary* out,
                           const std::string& section_name,
                           uint8_t empty_value)
    : src_(src), out_(out), section_name_(section_name),
      empty_value_(empty_value) {
}

uint64_t MergeSection::operator()() {
    const Section& src_sec = src_->get_section(section_name_);
    Section& out_sec = out_->get_section(section_name_);
    assert(src_sec.alignment() == out_sec.alignment());
    uint64_t dst_origin_va = out_sec.virtual_address();
    uint64_t dst_origin_off = out_sec.offset();
    uint64_t dst_origin_sz = out_sec.size();
    // assert(src_sec.information() == out_sec.information());

    // Extend.
    const std::vector<uint8_t>& src_content = src_sec.content();
    uint64_t extend_sz =
        ExtendSection(out_, section_name_, src_content.size())();
    assert(extend_sz >= src_content.size());

    // Fill out_sec hole with src_sec.
    std::vector<uint8_t> out_content = out_sec.content();
    std::memset(out_content.data() + (out_content.size() - extend_sz),
                empty_value_,
                extend_sz);
    std::memcpy(out_content.data() + (out_content.size() - extend_sz),
                src_content.data(),
                src_content.size());
    out_sec.content(out_content);

    return out_sec.virtual_address() + (out_content.size() - extend_sz);
}

}  // namespace shade_so
