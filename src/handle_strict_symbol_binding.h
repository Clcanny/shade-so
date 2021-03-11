// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/03/11
// Description

#ifndef SRC_HANDLE_STRICT_SYMBOL_BINDING_H_
#define SRC_HANDLE_STRICT_SYMBOL_BINDING_H_

#include <LIEF/ELF.hpp>

namespace shade_so {

class HandleStrictSymbolBinding {
 public:
    HandleStrictSymbolBinding(LIEF::ELF::Binary* src,
                              LIEF::ELF::Binary* dst,
                              LIEF::ELF::Binary* out);
    void operator()();

 private:
    LIEF::ELF::Binary* src_;
    LIEF::ELF::Binary* dst_;
    LIEF::ELF::Binary* out_;
};

}  // namespace shade_so

#endif  // SRC_HANDLE_STRICT_SYMBOL_BINDING_H_
