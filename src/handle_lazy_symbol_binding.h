// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SRC_HANDLE_LAZY_SYMBOL_BINDING_H_
#define SRC_HANDLE_LAZY_SYMBOL_BINDING_H_

#include <Zydis/Zydis.h>

#include <cstdint>

#include <LIEF/ELF.hpp>

namespace shade_so {

class HandleLazySymbolBinding {
    using Binary = LIEF::ELF::Binary;
    using Section = LIEF::ELF::Section;
    using Symbol = LIEF::ELF::Symbol;
    using Relocation = LIEF::ELF::Relocation;

 public:
    HandleLazySymbolBinding(Binary* src, Binary* dst, Binary* out);
    uint64_t operator()();

 private:
    uint64_t check() const;
    void extend(uint64_t src_id);

    void fill(uint64_t entries_num);
    template <int N>
    void handle_plt_entry_inst(int entry_id,
                               uint64_t offset,
                               const ZydisDecodedInstruction& inst);
    ZydisDecodedOperand get_exactly_one_visible_operand(
        const ZydisDecodedInstruction& inst);

 private:
    Binary* src_;
    Binary* dst_;
    Binary* out_;
    ZydisDecoder decoder_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_LAZY_SYMBOL_BINDING_H_
