// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#ifndef SRC_SEC_MALLOC_MGR_H_
#define SRC_SEC_MALLOC_MGR_H_

#include <cstdint>
#include <map>
#include <string>

#include <LIEF/ELF.hpp>

namespace shade_so {

enum class MallocUnit { kByte, kEntry };

class SecMalloc {
 public:
    SecMalloc(const LIEF::ELF::Binary& artifact,
              const LIEF::ELF::Binary& dependency,
              LIEF::ELF::Binary* fat,
              const std::string& name,
              bool need_align,
              bool allow_hole,
              uint8_t empty_val,
              int max_times);
    SecMalloc(const SecMalloc& other) = delete;
    SecMalloc(SecMalloc&& other) = delete;
    SecMalloc& operator=(const SecMalloc& other) = delete;
    SecMalloc& operator=(SecMalloc&& other) = delete;

    int64_t malloc(int64_t size, MallocUnit unit = MallocUnit::kByte);
    int64_t malloc_dependency(int64_t addition = 0,
                              MallocUnit unit = MallocUnit::kByte);
    int64_t exact_one_block_offset() const;
    void close() const;

 private:
    int64_t ceil(int64_t size, int64_t align) const;

 private:
    const LIEF::ELF::Binary& artifact_;
    const LIEF::ELF::Binary& dependency_;

    LIEF::ELF::Binary* const fat_;
    LIEF::ELF::Section* sec_;
    std::string name_;

    int64_t sec_align_;
    int64_t elf_align_;
    bool allow_hole_;
    uint8_t empty_val_;

    // Start address to size.
    std::map<int64_t, int64_t> blocks_;
    int max_times_;

    int64_t size_;
    int64_t capacity_;
};

struct SecMallocCfg {
    bool is_table;
    bool is_code;
    bool multi_malloc;
};

class SecMallocMgr {
 public:
    SecMallocMgr(const LIEF::ELF::Binary& artifact,
                 const LIEF::ELF::Binary& dependency,
                 LIEF::ELF::Binary* fat);
    std::map<std::string, SecMalloc>& get();
    SecMalloc& get(const std::string& name);
    SecMalloc& get_or_create(const std::string& name);

 private:
    static const std::map<std::string, SecMallocCfg> sec_malloc_cfgs_;
    const LIEF::ELF::Binary& artifact_;
    const LIEF::ELF::Binary& dependency_;
    LIEF::ELF::Binary* fat_;
    std::map<std::string, SecMalloc> sec_mallocs_;
};

}  // namespace shade_so

#endif  // SRC_SEC_MALLOC_MGR_H_
