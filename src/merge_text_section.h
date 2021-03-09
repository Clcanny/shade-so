// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/08
// Description

#ifndef SRC_MERGE_TEXT_SECTION_H_
#define SRC_MERGE_TEXT_SECTION_H_

#include <LIEF/ELF.hpp>

namespace shade_so {

class MergeTextSection {
 public:
    MergeTextSection(LIEF::ELF::Binary* src,
                     LIEF::ELF::Binary* dst,
                     LIEF::ELF::Binary* out);
    void operator()();

 private:
    LIEF::ELF::Binary* src_;
    LIEF::ELF::Binary* dst_;
    LIEF::ELF::Binary* out_;
};

};  // namespace shade_so

#endif  // SRC_MERGE_TEXT_SECTION_H_
