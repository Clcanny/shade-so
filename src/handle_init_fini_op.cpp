// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/18
// Description

#include "src/handle_init_fini_op.h"

#include <array>
#include <cassert>

#include <LIEF/ELF.hpp>

#include "src/const.h"
#include "src/elf.h"

namespace shade_so {

HandleInitFiniOp::HandleInitFiniOp(OperatorArgs args)
    : args_(args), init_off_(0), init_array_off_(0), fini_off_(0),
      fini_array_off_(0) {
}

void HandleInitFiniOp::extend() {
    init_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kInit)
                    .malloc_dependency();
    init_array_off_ =
        args_.sec_malloc_mgr_->get_or_create(sec_names::kInitArray)
            .malloc_dependency();
    fini_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kFini)
                    .malloc_dependency();
    fini_array_off_ =
        args_.sec_malloc_mgr_->get_or_create(sec_names::kFiniArray)
            .malloc_dependency(1, MallocUnit::kEntry);
}

void HandleInitFiniOp::merge() {
    merge_section(args_.dependency_, args_.fat_, sec_names::kInit, init_off_);
    merge_section(args_.dependency_, args_.fat_, sec_names::kFini, fini_off_);
    merge_init_array();
}

void HandleInitFiniOp::merge_init_array() {
    const LIEF::ELF::DynamicEntryArray* artifact_init_arr =
        const_cast<LIEF::ELF::Binary*>(&args_.artifact_)
            ->get(LIEF::ELF::DYNAMIC_TAGS::DT_INIT_ARRAY)
            .as<LIEF::ELF::DynamicEntryArray>();
    const LIEF::ELF::DynamicEntryArray* dep_init_arr =
        const_cast<LIEF::ELF::Binary*>(&args_.dependency_)
            ->get(LIEF::ELF::DYNAMIC_TAGS::DT_INIT_ARRAY)
            .as<LIEF::ELF::DynamicEntryArray>();
    LIEF::ELF::DynamicEntryArray* fat_init_arr =
        args_.fat_->get(LIEF::ELF::DYNAMIC_TAGS::DT_INIT_ARRAY)
            .as<LIEF::ELF::DynamicEntryArray>();

    assert(fat_init_arr->size() == artifact_init_arr->size());
    fat_init_arr->array().clear();

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

    for (uint64_t artifact_init_func : artifact_init_arr->array()) {
        const auto& artifact_to_sec =
            args_.artifact_.section_from_virtual_address(artifact_init_func);
        const auto& fat_to_sec =
            args_.fat_->get_section(artifact_to_sec.name());
        int64_t fat_init_func =
            fat_to_sec.virtual_address() +
            (artifact_init_func - artifact_to_sec.virtual_address());
        fat_init_arr->append(fat_init_func);
    }

    const auto& fat_init_array_sec =
        args_.fat_->get_section(sec_names::kInitArray);
    for (auto i = 0; i < fat_init_arr->size(); i++) {
        args_.fat_->add_dynamic_relocation(
            LIEF::ELF::Relocation(fat_init_array_sec.virtual_address() +
                                      i * fat_init_array_sec.entry_size(),
                                  RelocType::R_X86_64_RELATIVE,
                                  fat_init_arr->array()[i],
                                  true));
    }
}

}  // namespace shade_so
