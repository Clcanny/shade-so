// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/08
// Description

#include "src/merge_text_section.h"

#include <algorithm>
#include <set>
#include <string>

#include "src/extend_section.h"
#include "src/merge_section.h"

namespace shade_so {

MergeTextSection::MergeTextSection(LIEF::ELF::Binary* src,
                                   LIEF::ELF::Binary* dst,
                                   LIEF::ELF::Binary* out)
    : src_(src), dst_(dst), out_(out) {
}

void MergeTextSection::operator()() {
    // I use a very loose value.
    ExtendSection(out_, ".strtab", src_->get_section(".strtab").size());
    ExtendSection(out_, ".symtab", src_->get_section(".symtab").size());

    uint8_t nop_code = 0x90;
    MergeSection(src_, out_, ".text", nop_code)();
    const LIEF::ELF::Section& src_text_sec = src_->text_section();
    const LIEF::ELF::Section& dst_text_sec = dst_->text_section();
    const LIEF::ELF::Section& out_text_sec = out_->text_section();
    auto out_text_id =
        std::find_if(out_->sections().begin(),
                     out_->sections().end(),
                     [&out_text_sec](const LIEF::ELF::Section& sec) {
                         return sec == out_text_sec;
                     }) -
        out_->sections().begin();
    std::set<std::string> addedSyms;
    for (auto i = 0; i < src_->symbols().size(); i++) {
        const LIEF::ELF::Symbol& src_sym = src_->symbols()[i];
        if (!src_sym.is_function() || src_sym.is_imported()) {
            continue;
        }
        if (!(src_sym.value() >= src_text_sec.virtual_address() &&
              src_sym.value() <
                  src_text_sec.virtual_address() + src_text_sec.size())) {
            continue;
        }
        const std::string& name = src_sym.name();
        if (addedSyms.find(name) != addedSyms.end()) {
            continue;
        }
        addedSyms.insert(name);
        if (name != "_Z41__static_initialization_and_destruction_0ii") {
            // if (name != "_Z3foov" && name !=
            // "_Z41__static_initialization_and_destruction_0ii") { if (name !=
            // "_Z3foov") {
            continue;
        }
        LIEF::ELF::Symbol out_sym(
            name,
            LIEF::ELF::ELF_SYMBOL_TYPES::STT_FUNC,
            LIEF::ELF::SYMBOL_BINDINGS::STB_LOCAL,
            // src_sym.other(),
            0,
            out_text_id,
            src_sym.value() - src_text_sec.virtual_address() +
                (out_text_sec.virtual_address() + dst_text_sec.size()),
            src_sym.size());
        out_->add_static_symbol(out_sym);
    }
}

}  // namespace shade_so
