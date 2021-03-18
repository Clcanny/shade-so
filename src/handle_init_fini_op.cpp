// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/18
// Description

#include "src/handle_init_fini_op.h"

#include <array>
#include <cassert>

#include "src/const.h"

namespace shade_so {

HandleInitFiniOp::HandleInitFiniOp(OperatorArgs args)
    : args_(args), init_off_(0), init_array_off_(0), fini_off_(0),
      fini_array_off_(0) {
}

void HandleInitFiniOp::extend() {
    init_off_ =
        args_.sec_malloc_mgr_->get_or_create(".init", 1).malloc_dependency();
    init_array_off_ = args_.sec_malloc_mgr_->get_or_create(".init_array", 1)
                          .malloc_dependency(1, MallocUnit::kEntry);
    fini_off_ =
        args_.sec_malloc_mgr_->get_or_create(".fini", 1).malloc_dependency();
    fini_array_off_ = args_.sec_malloc_mgr_->get_or_create(".fini_array", 1)
                          .malloc_dependency(1, MallocUnit::kEntry);
}

void HandleInitFiniOp::merge() {
    merge_section(args_.dependency_, args_.fat_, ".init", init_off_);
    merge_section(args_.dependency_, args_.fat_, ".fini", fini_off_);
    merge_init_array();
}

void HandleInitFiniOp::merge_init_array() {
    LIEF::ELF::DynamicEntryArray* fat_init_arr =
        args_.fat_->get(LIEF::ELF::DYNAMIC_TAGS::DT_INIT_ARRAY)
            .as<LIEF::ELF::DynamicEntryArray>();
    const LIEF::ELF::DynamicEntryArray* dep_init_arr =
        const_cast<LIEF::ELF::Binary*>(&args_.dependency_)
            ->get(LIEF::ELF::DYNAMIC_TAGS::DT_INIT_ARRAY)
            .as<LIEF::ELF::DynamicEntryArray>();

    const auto& fat_init_sec = args_.fat_->get_section(sec_names::kInit);
    fat_init_arr->append(
        fat_init_sec.virtual_address() +
        args_.sec_malloc_mgr_->get(sec_names::kInit).exact_one_block_offset());

    for (uint64_t dep_init_func : dep_init_arr->array()) {
        const auto& dep_to_sec =
            args_.dependency_.section_from_virtual_address(dep_init_func);
        const auto& fat_to_sec = args_.fat_->get_section(dep_to_sec.name());
        int64_t fat_init_func = fat_to_sec.virtual_address() +
                                args_.sec_malloc_mgr_->get(fat_to_sec.name())
                                    .exact_one_block_offset() +
                                (dep_init_func - dep_to_sec.virtual_address());
        fat_init_arr->append(fat_init_func);
    }
}

}  // namespace shade_so
