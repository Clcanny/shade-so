// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/11
// Description

#include "src/handle_strict_symbol_binding.h"

#include <algorithm>
#include <cstdint>

#include "src/elf.h"
#include "src/extend_section.h"
#include "src/merge_section.h"

namespace shade_so {

HandleStrictSymbolBinding::HandleStrictSymbolBinding(LIEF::ELF::Binary* src,
                                                     LIEF::ELF::Binary* dst,
                                                     LIEF::ELF::Binary* out)
    : src_(src), dst_(dst), out_(out) {
}

void HandleStrictSymbolBinding::operator()() {
    ExtendSection(out_, ".plt.got", src_->get_section(".plt.got").size())();
    MergeSection(src_, out_, ".plt.got", 0x90)();
    ExtendSection(out_, ".got", src_->get_section(".got").size())();
    MergeSection(src_, out_, ".got", 0x0)();
    ExtendSection(out_, ".dynsym", src_->get_section(".dynsym").size())();
    ExtendSection(out_, ".symtab", src_->get_section(".symtab").size())();
    ExtendSection(out_, ".rela.dyn", src_->get_section(".rela.dyn").size())();

    for (auto i = 0; i < src_->relocations().size(); i++) {
        const LIEF::ELF::Relocation& src_reloc = src_->relocations()[i];
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
            LIEF::ELF::Symbol out_sym(src_sym.name(),
                                      src_sym.type(),
                                      src_sym.binding(),
                                      src_sym.other(),
                                      // out_sec_id,
                                      src_sym.section_idx() == 0 ? 0
                                                                 : out_sec_id,
                                      src_sym.value(),
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
