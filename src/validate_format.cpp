// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/07
// Description

#include "src/validate_format.h"

#include "src/const.h"

namespace shade_so {

ValidateFormat::ValidateFormat(LIEF::ELF::Binary* bin)
    : bin_(bin),
      expected_sections_({std::make_tuple(sec_names::kPlt, 0x10),
                          std::make_tuple(sec_names::kGotPlt, 0x8),
                          std::make_tuple(sec_names::kRelaPlt, 0x18)}),
      not_expected_sections({sec_names::kRelPlt}) {
}

bool ValidateFormat::operator()() const {
    for (auto [name, entry_size] : expected_sections_) {
        if (bin_->has_section(name) &&
            bin_->get_section(name).entry_size() != entry_size) {
            return false;
        }
    }
    return true;
}

}  // namespace shade_so
