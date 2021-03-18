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

enum class MallocUnit { kByte, kEntry };

class SecMalloc {
 public:
    SecMalloc(const LIEF::ELF::Binary& artifact,
              const LIEF::ELF::Binary& dependency,
              LIEF::ELF::Binary* fat,
              const std::string& name,
              bool consider_alignment,
              int max_malloc_times);
    int64_t malloc(int64_t size);
    int64_t malloc_dependency(int64_t addition = 0,
                              MallocUnit unit = MallocUnit::kByte);
    int64_t latest_block_offset() const;
    int64_t exact_one_block_offset() const;

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
    int max_malloc_times_;

    int64_t size_;
    int64_t capacity_;
};

class SecMallocMgr {
 public:
    SecMallocMgr(const LIEF::ELF::Binary& artifact,
                 const LIEF::ELF::Binary& dependency,
                 LIEF::ELF::Binary* fat);
    std::map<std::string, SecMalloc>& get();
    SecMalloc& get(const std::string& name);
    SecMalloc& get_or_create(const std::string& name,
                             bool consider_alignment = false,
                             int max_malloc_times = 1);

 private:
    const LIEF::ELF::Binary& artifact_;
    const LIEF::ELF::Binary& dependency_;
    LIEF::ELF::Binary* fat_;
    std::map<std::string, SecMalloc> sec_mallocs_;
};

}  // namespace shade_so

#endif  // SRC_EXTEND_SECTION_H_
