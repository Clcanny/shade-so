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

#include "src/const.h"

namespace shade_so {

HandleCodeOp::HandleCodeOp(OperatorArgs args) : args_(args) {
}

void HandleCodeOp::extend() {
    text_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kText)
                    .malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(sec_names::kSymtab)
        .malloc_dependency();
    args_.sec_malloc_mgr_->get_or_create(sec_names::kStrtab)
        .malloc_dependency();
}

void HandleCodeOp::merge() {
    merge_section(args_.dependency_, args_.fat_, sec_names::kText, text_off_);
    const LIEF::ELF::Section& dep_text_sec =
        args_.dependency_.get_section(sec_names::kText);
    const LIEF::ELF::Section& fat_text_sec =
        args_.fat_->get_section(sec_names::kText);
    auto fat_text_id =
        std::find_if(args_.fat_->sections().begin(),
                     args_.fat_->sections().end(),
                     [&fat_text_sec](const LIEF::ELF::Section& sec) {
                         return sec == fat_text_sec;
                     }) -
        args_.fat_->sections().begin();
    std::set<std::string> addedSyms;
    for (auto i = 0; i < args_.dependency_.symbols().size(); i++) {
        const LIEF::ELF::Symbol& dep_sym = args_.dependency_.symbols()[i];
        if (!dep_sym.is_function() || dep_sym.is_imported()) {
            continue;
        }
        if (!(dep_sym.value() >= dep_text_sec.virtual_address() &&
              dep_sym.value() <
                  dep_text_sec.virtual_address() + dep_text_sec.size())) {
            continue;
        }
        const std::string& name = dep_sym.name();
        if (addedSyms.find(name) != addedSyms.end()) {
            continue;
        }
        addedSyms.insert(name);
        LIEF::ELF::Symbol fat_sym(
            name,
            LIEF::ELF::ELF_SYMBOL_TYPES::STT_FUNC,
            LIEF::ELF::SYMBOL_BINDINGS::STB_LOCAL,
            // dep_sym.other(),
            0,
            fat_text_id,
            fat_text_sec.virtual_address() + text_off_ +
                (dep_sym.value() - dep_text_sec.virtual_address()),
            dep_sym.size());
        args_.fat_->add_static_symbol(fat_sym);
    }
}

}  // namespace shade_so
