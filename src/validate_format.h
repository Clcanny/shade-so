// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/07
// Description

#ifndef SRC_VALIDATE_FORMAT_H_
#define SRC_VALIDATE_FORMAT_H_

#include <array>
#include <cstdint>
#include <tuple>

#include <LIEF/ELF.hpp>

namespace shade_so {

class ValidateFormat {
 public:
    explicit ValidateFormat(LIEF::ELF::Binary* bin);
    bool operator()() const;

 private:
    LIEF::ELF::Binary* bin_;
    std::array<std::tuple<const char*, uint64_t>, 3> expected_sections_;
    std::array<const char*, 1> not_expected_sections;
};

}  // namespace shade_so

#endif  // SRC_VALIDATE_FORMAT_H_
