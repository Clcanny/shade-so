// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SHADE_SO_HANDLE_LAZY_SYMBOL_BINDING_H_
#define SHADE_SO_HANDLE_LAZY_SYMBOL_BINDING_H_

#include <cstdint>

#include <LIEF/ELF.hpp>

namespace LIEF {
namespace ELF {

class HandleLazySymbolBinding {
 public:
    HandleLazySymbolBinding(Binary* src, Binary* dst, Binary* output);

    void operator()();

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
};

}  // namespace ELF
}  // namespace LIEF

#endif  // SHADE_SO_HANDLE_LAZY_SYMBOL_BINDING_H_
