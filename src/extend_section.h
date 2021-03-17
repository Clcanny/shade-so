// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SRC_EXTEND_SECTION_H_
#define SRC_EXTEND_SECTION_H_

#include <cstdint>
#include <map>
#include <string>

#include <LIEF/ELF.hpp>

namespace shade_so {

class ExtendSection {
    using Binary = LIEF::ELF::Binary;
    using Section = LIEF::ELF::Section;

 public:
    ExtendSection(Binary* bin, const std::string& name, uint64_t size);
    uint64_t operator()();

 private:
    void ceil_size();

 private:
    Binary* bin_;
    const Section& section_;
    uint64_t size_;
};

class SecMallocMgr {
 public:
    SecMallocMgr(const LIEF::ELF::Binary& artifact,
                 const LIEF::ELF::Binary& dependency,
                 LIEF::ELF::Binary* fat,
                 const std::string& name,
                 int max_alloc_times = 1);
    int64_t malloc(int64_t size);
    int64_t malloc_artifact();
    int64_t latest_block_sa() const;

 private:
    const LIEF::ELF::Binary& artifact_;
    const LIEF::ELF::Binary& dependency_;

    LIEF::ELF::Binary* const fat_;
    LIEF::ELF::Section* sec_;
    std::string name_;
    int64_t sec_align_;
    int64_t elf_align_;

    // Start address to size.
    std::map<int64_t, int64_t> blocks_;
    int max_alloc_times_;

    int64_t size_;
    int64_t capacity_;
};

}  // namespace shade_so

#endif  // SRC_EXTEND_SECTION_H_
