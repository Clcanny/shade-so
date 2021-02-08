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

 public:
    HandleLazySymbolBinding(Binary* src, Binary* dst, Binary* output);

    uint64_t operator()();

 private:
    uint64_t check() const;
    void extend(uint64_t src_id);
    void add_plt(uint64_t src_id);
    void add_got_plt(uint64_t src_id);
    void add_rela_plt(uint64_t src_id);
    void add_undef_dynsym(uint64_t src_id);
    void add_dynstr(uint64_t src_id);

 private:
    Binary* src_;
    Binary* dst_;
    Binary* out_;
    ZydisDecoder decoder_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_LAZY_SYMBOL_BINDING_H_
