// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/07
// Description

#include "src/relocate_jump_slot_entry.h"

#include <cstdint>

namespace shade_so {

RelocateJumpSlotEntry::RelocateJumpSlotEntry(LIEF::ELF::Binary* src,
                                             LIEF::ELF::Binary* dst,
                                             LIEF::ELF::Binary* out)
    : src_(src), dst_(dst), out_(out) {
}

void RelocateJumpSlotEntry::operator()() {
    for (auto i = 0; i < out_->pltgot_relocations().size(); i++) {
        const LIEF::ELF::Relocation& out_reloc = out_->pltgot_relocations()[i];
        if (!out_reloc.has_symbol()) {
            continue;
        }
        const LIEF::ELF::Symbol& src_sym =
            src_->get_dynamic_symbol(reloc.symbol().name());
        const LIEF::ELF::Section& src_sec =
            src_->section_from_virtual_address(src_sym.value());
        const LIEF::ELF::Section& dst_sec = dst_->get_section(src_sec.name());
        const LIEF::ELF::Section& out_sec = out_->get_section(src_sec.name());
        // out_sec doesn't contain dst_sec.
        if (!(out_sec.size() >= src_sec.size() + dst_sec.size())) {
            continue;
        }
        uint64_t out_sym_va =
    }
}

}  // namespace shade_so
