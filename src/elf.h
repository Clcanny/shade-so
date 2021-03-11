// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/11
// Description: This file is a brief version of /usr/include/linux/elf.h.

#ifndef SRC_ELF_H_
#define SRC_ELF_H_

#include <cstdint>

namespace shade_so {

using Elf64_Addr = uint64_t;
using Elf64_Half = uint16_t;
using Elf64_SHalf = int16_t;
using Elf64_Off = uint64_t;
using Elf64_Sword = int32_t;
using Elf64_Word = uint32_t;
using Elf64_Xword = uint64_t;
using Elf64_Sxword = int64_t;

struct Elf64_Rela {
    Elf64_Addr r_offset;    // Location at which to apply the action.
    Elf64_Xword r_info;     // index and type of relocation.
    Elf64_Sxword r_addend;  // Constant addend used to compute value.
};

enum class RelocType { R_X86_64_GLOB_DAT = 6 };

}  // namespace shade_so

#endif  // SRC_ELF_H_
