// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/11
// Description

#include "src/handle_strict_symbol_binding.h"

#include <algorithm>
#include <cstdint>
#include <string>

#include "src/elf.h"
#include "src/extend_section.h"
#include "src/merge_section.h"

namespace shade_so {

HandleStrictBindingSymOp::HandleStrictBindingSymOp(OperatorArgs args)
    : args_(args) {
}

void HandleStrictBindingSymOp::extend() {
    args_.sec_malloc_mgr_->get_or_create(".plt.got", 0x0).malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(".got", 0x0).malloc_dependency();
}

void HandleStrictBindingSymOp::merge() {
    auto src_ = &args_.dependency_;
    auto dst_ = &args_.artifact_;
    auto out_ = args_.fat_;

    merge_section(*src_,
                  out_,
                  ".plt.got",
                  args_.sec_malloc_mgr_->get(".plt.got").latest_block_offset());
    merge_section(*src_,
                  out_,
                  ".got",
                  args_.sec_malloc_mgr_->get(".got").latest_block_offset());

    for (auto i = 0; i < src_->relocations().size(); i++) {
        const LIEF::ELF::Relocation& src_reloc = src_->relocations()[i];
        // TODO(junbin.rjb)
        // Split.
        if (src_reloc.type() ==
            static_cast<uint32_t>(RelocType::R_X86_64_GLOB_DAT)) {
            const LIEF::ELF::Section& src_sec =
                src_->section_from_virtual_address(src_reloc.address());
            const LIEF::ELF::Section& dst_sec =
                dst_->get_section(src_sec.name());
            const LIEF::ELF::Section& out_sec =
                out_->get_section(src_sec.name());
            auto out_sec_id =
                std::find_if(out_->sections().begin(),
                             out_->sections().end(),
                             [&out_sec](const LIEF::ELF::Section& sec) {
                                 return sec == out_sec;
                             }) -
                out_->sections().begin();

            const LIEF::ELF::Symbol& src_sym = src_reloc.symbol();
            uint64_t value = 0;
            if (src_->has_section_with_va(src_sym.value())) {
                const auto& src_to_sec =
                    src_->section_from_virtual_address(src_sym.value());
                const std::string& name = src_to_sec.name();
                value = out_->get_section(name).virtual_address() +
                        dst_->get_section(name).size() +
                        (src_sym.value() - src_to_sec.virtual_address());
            }
            // if (src_reloc.type() ==
            // static_cast<uint32_t>(RelocType::R_X86_64_RELATIVE)) {
            //     value = 0x8b01 + (0x8b01 - 0x8001);
            // }
            LIEF::ELF::Symbol out_sym(src_sym.name(),
                                      src_sym.type(),
                                      src_sym.binding(),
                                      src_sym.other(),
                                      // out_sec_id,
                                      src_sym.section_idx() == 0 ? 0
                                                                 : out_sec_id,
                                      value,
                                      src_sym.size());
            out_->add_static_symbol(out_sym);
            LIEF::ELF::Symbol& sym = out_->add_dynamic_symbol(out_sym, nullptr);

            LIEF::ELF::Relocation out_reloc(
                out_sec.virtual_address() + dst_sec.size() +
                    (src_reloc.address() - src_sec.virtual_address()),
                src_reloc.type(),
                src_reloc.addend(),
                src_reloc.is_rela());
            out_reloc.symbol(&sym);
            out_->add_dynamic_relocation(out_reloc);
        }
    }
}

}  // namespace shade_so
