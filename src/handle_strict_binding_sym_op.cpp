// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/11
// Description

#include "src/handle_strict_binding_sym_op.h"

#include <algorithm>
#include <cstdint>
#include <string>

#include "src/const.h"
#include "src/elf.h"

namespace shade_so {

HandleStrictBindingSymOp::HandleStrictBindingSymOp(OperatorArgs args)
    : args_(args), plt_got_off_(0), got_off_(0) {
}

void HandleStrictBindingSymOp::extend() {
    plt_got_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kPltGot)
                       .malloc_dependency();
    got_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kGot)
                   .malloc_dependency();
}

void HandleStrictBindingSymOp::merge() {
    merge_section(
        args_.dependency_, args_.fat_, sec_names::kPltGot, plt_got_off_);
    merge_section(args_.dependency_, args_.fat_, sec_names::kGot, got_off_);

    for (auto i = 0; i < args_.dependency_.relocations().size(); i++) {
        const LIEF::ELF::Relocation& dep_reloc =
            args_.dependency_.relocations()[i];
        if (dep_reloc.type() !=
            static_cast<uint32_t>(RelocType::R_X86_64_GLOB_DAT)) {
            continue;
        }
        const LIEF::ELF::Section& dep_sec =
            args_.dependency_.section_from_virtual_address(dep_reloc.address());
        const LIEF::ELF::Section& fat_sec =
            args_.fat_->get_section(dep_sec.name());
        auto fat_sec_id =
            std::find_if(args_.fat_->sections().begin(),
                         args_.fat_->sections().end(),
                         [&fat_sec](const LIEF::ELF::Section& sec) {
                             return sec == fat_sec;
                         }) -
            args_.fat_->sections().begin();

        const LIEF::ELF::Symbol& dep_sym = dep_reloc.symbol();
        uint64_t value = 0;
        if (args_.dependency_.has_section_with_va(dep_sym.value())) {
            const auto& dep_to_sec =
                args_.dependency_.section_from_virtual_address(dep_sym.value());
            const std::string& name = dep_to_sec.name();
            value = args_.fat_->get_section(name).virtual_address() +
                    args_.sec_malloc_mgr_->get(name).exact_one_block_offset() +
                    (dep_sym.value() - dep_to_sec.virtual_address());
        }
        auto fat_sym = create_fat_sym(args_, dep_sym);
        fat_sym->value(value);
        get_or_insert_fat_sym(args_, *fat_sym, false);
        LIEF::ELF::Symbol& sym = get_or_insert_fat_sym(args_, *fat_sym, true);

        LIEF::ELF::Relocation fat_reloc(
            fat_sec.virtual_address() +
                args_.sec_malloc_mgr_->get(fat_sec.name())
                    .exact_one_block_offset() +
                (dep_reloc.address() - dep_sec.virtual_address()),
            dep_reloc.type(),
            dep_reloc.addend(),
            dep_reloc.is_rela());
        fat_reloc.symbol(&sym);
        args_.fat_->add_dynamic_relocation(fat_reloc);
    }
}

}  // namespace shade_so
