// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/17
// Description

#include "src/operator.h"

#include <vector>

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

void Operator::extend() {
}

void Operator::merge() {
}

void Operator::patch() {
}

void Operator::merge_section(const LIEF::ELF::Binary& dependency,
                             LIEF::ELF::Binary* fat,
                             const std::string& name,
                             int64_t offset) {
    const auto& dep_sec = dependency.get_section(name);
    auto& fat_sec = fat->get_section(name);
    // Fill fat_sec hole with dep_sec.
    const std::vector<uint8_t>& dep_content = dep_sec.content();
    std::vector<uint8_t> fat_content = fat_sec.content();
    assert(fat_content.size() >= offset + dep_content.size());
    std::memcpy(
        fat_content.data() + offset, dep_content.data(), dep_content.size());
    fat_sec.content(fat_content);
}

}  // namespace shade_so
