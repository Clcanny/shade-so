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
#include "src/handle_code_op.h"
#include "src/handle_global_data_op.h"
#include "src/handle_init_fini_op.h"
#include "src/handle_lazy_binding_sym_op.h"
#include "src/handle_strict_binding_sym_op.h"
#include "src/handle_thread_local_data_op.h"
#include "src/operator.h"
#include "src/patch_rip_insts.h"
#include "src/relocate_jump_slot_entry.h"
#include "src/sec_malloc_mgr.h"

int main() {
    std::unique_ptr<LIEF::ELF::Binary> src(
        LIEF::ELF::Parser::parse("libfoo.so"));
    std::unique_ptr<LIEF::ELF::Binary> dst(
        LIEF::ELF::Parser::parse("main.out"));
    std::unique_ptr<LIEF::ELF::Binary> out(
        LIEF::ELF::Parser::parse("main.out"));

    shade_so::SecMallocMgr sec_malloc_mgr(*dst, *src, out.get());
    shade_so::OperatorArgs args(*dst, *src, out.get(), &sec_malloc_mgr);
    std::vector<std::unique_ptr<shade_so::Operator>> ops;
    ops.emplace_back(new shade_so::HandleInitFiniOp(args));
    ops.emplace_back(new shade_so::HandleCodeOp(args));
    ops.emplace_back(new shade_so::HandleGlobalDataOp(args));
    ops.emplace_back(new shade_so::HandleThreadLocalDataOp(args));
    ops.emplace_back(new shade_so::HandleLazyBindingSymOp(args));
    ops.emplace_back(new shade_so::HandleStrictBindingSymOp(args));
    ops.emplace_back(new shade_so::PatchRipInstsOp(args));
    for (const auto& op : ops) {
        op->extend();
    }
    for (const auto& op : ops) {
        op->merge();
    }
    for (const auto& op : ops) {
        op->patch();
    }

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
