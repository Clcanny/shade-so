// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/18
// Description

#include "src/handle_global_data_op.h"

#include <algorithm>
#include <cassert>

#include <LIEF/ELF.hpp>

#include "src/elf.h"

namespace shade_so {

HandleGlobalDataOp::HandleGlobalDataOp(OperatorArgs args) : args_(args) {
}

void HandleGlobalDataOp::extend() {
    auto dyn_relocs = args_.dependency_.dynamic_relocations();
    auto n = std::count_if(
        dyn_relocs.begin(),
        dyn_relocs.end(),
        [](const LIEF::ELF::Relocation& reloc) {
            return reloc.type() == static_cast<uint32_t>(
                                       shade_so::RelocType::R_X86_64_RELATIVE);
        });
    args_.sec_malloc_mgr_->get_or_create(".rela.plt", 0, false, 2)
        .malloc(n, MallocUnit::kEntry);
}

void HandleGlobalDataOp::merge() {
    merge_relative_relocs();
}

void HandleGlobalDataOp::merge_relative_relocs() {
    for (const auto& dep_reloc : args_.dependency_.dynamic_relocations()) {
        if (dep_reloc.type() !=
            static_cast<uint32_t>(shade_so::RelocType::R_X86_64_RELATIVE)) {
            continue;
        }
        // assert(!dep_reloc.has_symbol());

        const LIEF::ELF::Section& dep_sec =
            args_.dependency_.section_from_virtual_address(dep_reloc.address());
        const LIEF::ELF::Section& fat_sec =
            args_.fat_->get_section(dep_sec.name());
        const LIEF::ELF::Section& dep_to_sec =
            args_.dependency_.section_from_virtual_address(dep_reloc.addend());
        const LIEF::ELF::Section& fat_to_sec =
            args_.fat_->get_section(dep_to_sec.name());

        LIEF::ELF::Relocation fat_reloc(
            fat_sec.virtual_address() +
                args_.sec_malloc_mgr_->get(fat_sec.name())
                    .exact_one_block_offset() +
                (dep_reloc.address() - dep_sec.virtual_address()),
            dep_reloc.type(),
            fat_to_sec.virtual_address() +
                args_.sec_malloc_mgr_->get(fat_to_sec.name())
                    .exact_one_block_offset() +
                (dep_reloc.addend() - dep_to_sec.virtual_address()),
            dep_reloc.is_rela());
        fat_reloc.info(dep_reloc.info());
        if (dep_reloc.has_section()) {
            fat_reloc.section(
                &args_.fat_->get_section(dep_reloc.section().name()));
        }
        args_.fat_->add_dynamic_relocation(fat_reloc);
    }
}

}  // namespace shade_so
