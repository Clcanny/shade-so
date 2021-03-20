// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/08
// Description: https://google.github.io/styleguide/cppguide.html

#include <cstdint>
#include <map>
#include <memory>

#include <LIEF/ELF.hpp>

#include "src/elf.h"
#include "src/extend_section.h"
#include "src/handle_global_data_op.h"
#include "src/handle_init_fini_op.h"
#include "src/handle_lazy_symbol_binding.h"
#include "src/handle_strict_symbol_binding.h"
#include "src/merge_text_section.h"
#include "src/operator.h"
#include "src/patch_rip_insts.h"
#include "src/relocate_jump_slot_entry.h"

int main() {
    std::unique_ptr<LIEF::ELF::Binary> src(
        LIEF::ELF::Parser::parse("libfoo.so"));
    std::unique_ptr<LIEF::ELF::Binary> dst(
        LIEF::ELF::Parser::parse("main.out"));
    std::unique_ptr<LIEF::ELF::Binary> out(
        LIEF::ELF::Parser::parse("main.out"));

    shade_so::SecMallocMgr sec_malloc_mgr(*dst, *src, out.get());
    for (const std::string& sec_name :
         std::vector<std::string>{".symtab", ".rela.dyn", ".strtab"}) {
        sec_malloc_mgr.get_or_create(sec_name);
    }
    for (auto& [_, sec_malloc] : sec_malloc_mgr.get()) {
        sec_malloc.malloc_dependency();
    }
    shade_so::OperatorArgs args(*dst, *src, out.get(), &sec_malloc_mgr);
    shade_so::HandleInitFiniOp handle_init_fini_op(args);
    handle_init_fini_op.extend();
    shade_so::HandleGlobalDataOp handle_global_data_op(args);
    handle_global_data_op.extend();
    shade_so::HandleLazyBindingSymOp handle_lazy_binding_sym_op(args);
    handle_lazy_binding_sym_op.extend();
    shade_so::HandleStrictBindingSymOp handle_strict_binding_sym_op(args);
    handle_strict_binding_sym_op.extend();
    shade_so::HandleCodeOp handle_code_op(args);
    handle_code_op.extend();

    handle_lazy_binding_sym_op.merge();
    handle_code_op.merge();
    handle_strict_binding_sym_op.merge();
    handle_init_fini_op.merge();
    handle_global_data_op.merge();

    shade_so::PatchRipInstsOp patch_rip_insts_op(args);
    patch_rip_insts_op.patch();

    // Set relocation and symbol done.
    // Reset symbol value.
    // TODO(junbin.rjb)
    // Fix LIEF bug.
    out->write("modified-main.out");
    out = LIEF::ELF::Parser::parse("modified-main.out");
    shade_so::RelocateJumpSlotEntry(out.get())();
    out->remove_library("libfoo.so");
    out->add_library("libbar.so");
    out->write("modified-main.out");
}
