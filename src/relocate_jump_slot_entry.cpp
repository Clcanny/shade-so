// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/07
// Description

#include "src/relocate_jump_slot_entry.h"

#include <cstdint>
#include <string>
#include <vector>

namespace shade_so {

RelocateJumpSlotEntry::RelocateJumpSlotEntry(LIEF::ELF::Binary* out)
    : out_(out) {
}

void RelocateJumpSlotEntry::operator()() {
    for (auto i = 0; i < out_->pltgot_relocations().size(); i++) {
        const LIEF::ELF::Relocation& reloc = out_->pltgot_relocations()[i];
        if (!reloc.has_symbol()) {
            continue;
        }
        const std::string& name = reloc.symbol().name();
        if (!out_->has_static_symbol(name)) {
            continue;
        }
        const LIEF::ELF::Symbol& sym = out_->get_static_symbol(name);
        std::vector<uint8_t> bytes_to_be_patched;
        for (auto i = 0; i < 8; i++) {
            bytes_to_be_patched.emplace_back((sym.value() >> (8 * i)) & 0xFF);
        }
        std::cout << std::hex << reloc.address() << std::endl;
        out_->patch_address(reloc.address(), bytes_to_be_patched);
    }
}

}  // namespace shade_so
