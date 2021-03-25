// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/21
// Description

#include "src/handle_thread_local_data_op.h"

#include <LIEF/ELF.hpp>

#include "src/const.h"
#include "src/elf.h"

namespace shade_so {

HandleThreadLocalDataOp::HandleThreadLocalDataOp(OperatorArgs args)
    : args_(args), tbss_off_(0), tdata_off_(0) {
}

void HandleThreadLocalDataOp::extend() {
    tdata_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kTdata)
                     .malloc_dependency();
    tbss_off_ = args_.sec_malloc_mgr_->get_or_create(sec_names::kTbss)
                    .malloc_dependency();
}

void HandleThreadLocalDataOp::merge() {
    merge_section(args_.dependency_, args_.fat_, sec_names::kTdata, tdata_off_);

    const auto& dep_tls_seg =
        args_.dependency_.get(LIEF::ELF::SEGMENT_TYPES::PT_TLS);
    const auto& dep_tdata_sec =
        args_.dependency_.get_section(sec_names::kTdata);
    assert(dep_tls_seg.has(dep_tdata_sec));
    assert(dep_tls_seg.virtual_address() == dep_tdata_sec.virtual_address());
    const auto& dep_tbss_sec = args_.dependency_.get_section(sec_names::kTbss);
    assert(dep_tls_seg.has(dep_tbss_sec));
    assert(dep_tls_seg.virtual_address() + dep_tls_seg.virtual_size() >=
           dep_tbss_sec.virtual_address() + dep_tbss_sec.size());
    assert(dep_tdata_sec.virtual_address() + dep_tdata_sec.size() <=
           dep_tbss_sec.virtual_address());

    merge_reloc(dep_tls_seg, args_.fat_->get(LIEF::ELF::SEGMENT_TYPES::PT_TLS));
}

void HandleThreadLocalDataOp::merge_reloc(
    const LIEF::ELF::Segment& dep_tls_seg,
    const LIEF::ELF::Segment& fat_tls_seg) {
    for (auto i = 0; i < args_.dependency_.dynamic_relocations().size(); i++) {
        const auto& dep_reloc = args_.dependency_.dynamic_relocations()[i];
        if (dep_reloc.type() !=
                static_cast<uint32_t>(RelocType::R_X86_64_DTPMOD64) &&
            dep_reloc.type() !=
                static_cast<uint32_t>(RelocType::R_X86_64_DTPOFF64)) {
            continue;
        }

        const auto& dep_got_sec =
            args_.dependency_.get_section(sec_names::kGot);
        assert(dep_reloc.address() >= dep_got_sec.virtual_address() &&
               dep_reloc.address() <
                   dep_got_sec.virtual_address() + dep_got_sec.size());
        const auto& fat_got_sec = args_.fat_->get_section(sec_names::kGot);
        LIEF::ELF::Relocation fat_reloc(
            fat_got_sec.virtual_address() +
                args_.sec_malloc_mgr_->get(sec_names::kGot)
                    .exact_one_block_offset() +
                (dep_reloc.address() - dep_got_sec.virtual_address()),
            dep_reloc.type(),
            dep_reloc.addend(),
            dep_reloc.is_rela());

        assert(dep_reloc.has_symbol());
        const auto& dep_sym = dep_reloc.symbol();
        auto fat_sym = create_fat_sym(args_, dep_sym);

        {
            // TODO(junbin.rjb)
            int64_t dep_va = dep_tls_seg.virtual_address() + dep_sym.value();
            const auto& dep_sec =
                args_.dependency_.section_from_virtual_address(dep_va);
            const auto& fat_sec = args_.fat_->get_section(dep_sec.name());
            int64_t fat_va = fat_sec.virtual_address() +
                             args_.sec_malloc_mgr_->get(fat_sec.name())
                                 .exact_one_block_offset() +
                             (dep_va - dep_sec.virtual_address());
            fat_sym->value(fat_va - fat_tls_seg.virtual_address());
        }

        fat_reloc.symbol(&get_or_insert_fat_sym(args_, *fat_sym, true));
        args_.fat_->add_dynamic_relocation(fat_reloc);
    }
}

}  // namespace shade_so
