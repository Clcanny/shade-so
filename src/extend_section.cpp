// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#include "src/extend_section.h"

#include <array>
#include <cassert>
#include <cmath>
#include <numeric>

namespace shade_so {

ExtendSection::ExtendSection(Binary* bin,
                             const std::string& name,
                             uint64_t size)
    : bin_(bin), section_(bin_->get_section(name)), size_(size) {
    assert(bin_ != nullptr);
    assert(size_ > 0);
}

uint64_t ExtendSection::operator()() {
    ceil_size();
    bin_->extend(section_, size_);
    return size_;
}

void ExtendSection::ceil_size() {
    uint64_t align = section_.alignment();
    uint64_t va = section_.virtual_address();
    uint64_t sz = section_.size();
    // assert(va % align == 0);
    // assert(sz % align == 0);
    if (size_ % align != 0) {
        size_ = (size_ / align + 1) * align;
    }
}

SecMalloc::SecMalloc(const LIEF::ELF::Binary& artifact,
                     const LIEF::ELF::Binary& dependency,
                     LIEF::ELF::Binary* fat,
                     const std::string& name,
                     bool consider_alignment,
                     int max_malloc_times)
    : artifact_(artifact), dependency_(dependency),          //
      fat_(fat), name_(name), sec_align_(1), elf_align_(1),  //
      max_malloc_times_(max_malloc_times), size_(0), capacity_(0) {
    assert(fat_ != nullptr);
    if (fat->has_section(name_)) {
        sec_ = &fat_->get_section(name_);
    } else {
    }
    assert(sec_ != nullptr);

    if (consider_alignment) {
        for (const auto& bin : std::array<const LIEF::ELF::Binary*, 3>{
                 &artifact_, &dependency_, fat_}) {
            sec_align_ = std::lcm(sec_align_,
                                  bin->has_section(name_)
                                      ? bin->get_section(name_).alignment()
                                      : 1);
            for (const auto& sec : bin->sections()) {
                elf_align_ = std::lcm(elf_align_, sec.alignment());
            }
        }
    }

    size_ = sec_->size();
    capacity_ = size_;
}

int64_t SecMalloc::malloc(int64_t size) {
    assert(blocks_.size() < max_malloc_times_);
    size = std::ceil(size * 1.0 / sec_align_) * sec_align_;
    assert(size_ <= capacity_);
    size_ = std::ceil(size_ * 1.0 / sec_align_) * sec_align_;
    if (size_ + size > capacity_) {
        auto extend_size =
            std::ceil((size_ + size) * 1.0 / elf_align_) * elf_align_ -
            capacity_;
        fat_->extend(*sec_, extend_size);
        capacity_ = size_ + extend_size;
        assert(capacity_ == sec_->size());
        assert(size_ + size <= capacity_);
    }
    auto start = size_;
    size_ += size;
    assert(blocks_.emplace(start, size).second);
    return start;
}

int64_t SecMalloc::malloc_dependency(int64_t addition, MallocUnit unit) {
    const auto& sec = dependency_.get_section(name_);
    switch (unit) {
    case MallocUnit::kByte:
        break;
    case MallocUnit::kEntry:
        assert(sec.entry_size() > 0);
        addition *= sec.entry_size();
        break;
    default:
        assert(false);
    }
    return malloc(sec.size() + addition);
}

int64_t SecMalloc::latest_block_offset() const {
    assert(blocks_.rbegin() != blocks_.rend());
    return blocks_.rbegin()->first;
}

SecMallocMgr::SecMallocMgr(const LIEF::ELF::Binary& artifact,
                           const LIEF::ELF::Binary& dependency,
                           LIEF::ELF::Binary* fat)
    : artifact_(artifact), dependency_(dependency), fat_(fat) {
    assert(fat_);
}

SecMalloc& SecMallocMgr::get_or_create(const std::string& name,
                                       int max_malloc_times) {
    auto it = sec_mallocs_.find(name);
    if (it != sec_mallocs_.end()) {
        return it->second;
    }
    it = sec_mallocs_
             .emplace(name,
                      SecMalloc(
                          artifact_, dependency_, fat_, name, max_malloc_times))
             .first;
    return it->second;
}

}  // namespace shade_so
