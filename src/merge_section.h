// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/07
// Description

#ifndef SRC_MERGE_SECTION_H_
#define SRC_MERGE_SECTION_H_

#include <cstdint>
#include <string>

#include <LIEF/ELF.hpp>

namespace shade_so {

class MergeSection {
    using Binary = LIEF::ELF::Binary;
    using Section = LIEF::ELF::Section;

 public:
    MergeSection(Binary* src,
                 Binary* dst,
                 Binary* out,
                 const std::string& section_name,
                 uint8_t empty_value);
    void operator()();

 private:
    Binary* src_;
    Binary* dst_;
    Binary* out_;
    std::string section_name_;
    uint8_t empty_value_;
};

}  // namespace shade_so

#endif  // SRC_MERGE_SECTION_H_
