// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/07
// Description

#include "src/merge_section.h"

#include <cstring>
#include <vector>

namespace shade_so {

MergeSection::MergeSection(Binary* src,
                           Binary* dst,
                           Binary* out,
                           const std::string& section_name,
                           uint8_t empty_value)
    : src_(src), dst_(dst), out_(out), section_name_(section_name),
      empty_value_(empty_value) {
}

void MergeSection::operator()() {
    const Section& src_sec = src_->get_section(section_name_);
    const Section& dst_sec = dst_->get_section(section_name_);
    Section& out_sec = out_->get_section(section_name_);
    uint64_t dst_origin_va = dst_sec.virtual_address();
    uint64_t dst_origin_off = dst_sec.offset();
    uint64_t dst_origin_sz = dst_sec.size();

    // Fill out_sec hole with src_sec.
    const std::vector<uint8_t>& src_content = src_sec.content();
    std::vector<uint8_t> out_content = out_sec.content();
    assert(out_content.size() >= dst_origin_sz + src_content.size());
    std::memset(out_content.data() + dst_origin_sz,
                empty_value_,
                out_content.size() - dst_origin_sz);
    std::memcpy(out_content.data() + dst_origin_sz,
                src_content.data(),
                src_content.size());
    out_sec.content(out_content);
}

}  // namespace shade_so
