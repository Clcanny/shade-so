// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/17
// Description

#include "src/operator.h"

#include <algorithm>
#include <iterator>
#include <vector>

namespace shade_so {

OperatorArgs::OperatorArgs(const LIEF::ELF::Binary& artifact,
                           const LIEF::ELF::Binary& dependency,
                           LIEF::ELF::Binary* fat,
                           SecMallocMgr* sec_malloc_mgr)
    : artifact_(artifact), dependency_(dependency), fat_(fat),
      sec_malloc_mgr_(sec_malloc_mgr) {
    assert(fat_);
    assert(sec_malloc_mgr_);
}

void Operator::extend() {
}

void Operator::merge() {
}

void Operator::patch() {
}

void Operator::merge_section(const LIEF::ELF::Binary& dependency,
                             LIEF::ELF::Binary* fat,
                             const std::string& name,
                             int64_t offset) {
    const auto& dep_sec = dependency.get_section(name);
    auto& fat_sec = fat->get_section(name);
    // Fill fat_sec hole with dep_sec.
    const std::vector<uint8_t>& dep_content = dep_sec.content();
    std::vector<uint8_t> fat_content = fat_sec.content();
    assert(fat_content.size() >= offset + dep_content.size());
    std::memcpy(
        fat_content.data() + offset, dep_content.data(), dep_content.size());
    fat_sec.content(fat_content);
}

std::unique_ptr<LIEF::ELF::Symbol> Operator::create_fat_sym(
    OperatorArgs args, const LIEF::ELF::Symbol& dep_sym) {
    uint16_t dep_sec_id = dep_sym.section_idx();
    uint16_t fat_sec_id = 0;
    if (dep_sec_id != 0) {
        const auto& dep_sec_name =
            args.dependency_.sections()[dep_sec_id].name();
        auto begin = std::begin(args.fat_->sections());
        auto end = std::end(args.fat_->sections());
        auto it = std::find_if(
            begin, end, [&dep_sec_name](const LIEF::ELF::Section& sec) {
                return sec.name() == dep_sec_name;
            });
        assert(it != end);
        fat_sec_id = it - begin;
    }
    auto fat_sym = new LIEF::ELF::Symbol(dep_sym.name(),
                                         dep_sym.type(),
                                         dep_sym.binding(),
                                         dep_sym.other(),
                                         fat_sec_id,
                                         // Leave value to caller.
                                         dep_sym.value(),
                                         dep_sym.size());
    fat_sym->information(dep_sym.information());
    return std::unique_ptr<LIEF::ELF::Symbol>(fat_sym);
}

LIEF::ELF::Symbol& Operator::get_or_insert_fat_sym(
    OperatorArgs args, const LIEF::ELF::Symbol& fat_sym, bool is_dyn_sym) {
    if (is_dyn_sym) {
        auto begin = std::begin(args.fat_->dynamic_symbols());
        auto end = std::end(args.fat_->dynamic_symbols());
        auto it =
            std::find_if(begin, end, [&fat_sym](const LIEF::ELF::Symbol& sym) {
                return sym.name() == fat_sym.name() &&
                       sym.is_imported() == fat_sym.is_imported();
            });
        if (it != end) {
            return *it;
        }
        return args.fat_->add_dynamic_symbol(fat_sym);
    } else {
        auto begin = std::begin(args.fat_->static_symbols());
        auto end = std::end(args.fat_->static_symbols());
        auto it =
            std::find_if(begin, end, [&fat_sym](const LIEF::ELF::Symbol& sym) {
                return sym.name() == fat_sym.name() &&
                       sym.is_imported() == fat_sym.is_imported();
            });
        if (it != end) {
            return *it;
        }
        return args.fat_->add_static_symbol(fat_sym);
    }
}

}  // namespace shade_so
