// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/08
// Description

#include "src/handle_code_op.h"

#include <algorithm>
#include <set>
#include <string>

namespace shade_so {

HandleCodeOp::HandleCodeOp(OperatorArgs args) : args_(args) {
}

void HandleCodeOp::extend() {
    uint8_t nop_code = 0x90;
    text_off_ =
        args_.sec_malloc_mgr_->get_or_create(".text").malloc_dependency();
}

void HandleCodeOp::merge() {
    auto src_ = const_cast<LIEF::ELF::Binary*>(&args_.dependency_);
    auto dst_ = const_cast<LIEF::ELF::Binary*>(&args_.artifact_);
    auto out_ = args_.fat_;

    merge_section(*src_, out_, ".text", text_off_);
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
