// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SRC_EXTEND_SECTION_H_
#define SRC_EXTEND_SECTION_H_

#include <string>

#include <LIEF/ELF.hpp>

namespace shade_so {

class ExtendSection {
    using Binary = LIEF::ELF::Binary;
    using Section = LIEF::ELF::Section;

 public:
    uint64_t operator()(Binary* bin, const std::string& name, uint64_t size);

 private:
    uint64_t ceil_size(const Section& section, uint64_t size);
    void patch_rip_addrs(Binary* bin, uint64_t insert_at, uint64_t size);

 private:
    // Binary* bin_;
    // std::string name_;
    // uint64_t size_;
};

}  // namespace shade_so

#endif  // SRC_EXTEND_SECTION_H_
