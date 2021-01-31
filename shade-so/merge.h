// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#include <LIEF/ELF.hpp>

namespace LIEF {
namespace ELF {

class HandleLazySymbolBinding {
 public:
    HandleLazySymbolBinding(Binary* src, Binary* dst, Binary* output);

    void operator()();

 private:
    uint64_t check() const;
    void extend(uint64_t entries_num);
    void add_plt(int32_t origin_id);
    void add_got_plt(int32_t origin_id);
    void add_rela_plt(int32_t origin_id);
    void add_undef_dynsym(int32_t origin_id);
    void add_dynstr(int32_t origin_id);

 private:
    Binary* src_;
    Binary* dst_;
    Binary* out_;
};

}  // namespace ELF
}  // namespace LIEF
