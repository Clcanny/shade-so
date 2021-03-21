// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/01/31
// Description

#include "src/sec_malloc_mgr.h"

#include <array>
#include <cassert>
#include <cstring>
#include <numeric>
#include <tuple>
#include <utility>
#include <vector>

#include "src/const.h"

namespace shade_so {

SecMalloc::SecMalloc(const LIEF::ELF::Binary& artifact,
                     const LIEF::ELF::Binary& dependency,
                     LIEF::ELF::Binary* fat,
                     const std::string& name,
                     bool need_align,
                     bool allow_hole,
                     uint8_t empty_val,
                     int max_times)
    : artifact_(artifact), dependency_(dependency), fat_(fat), name_(name),
      sec_align_(1), elf_align_(1), allow_hole_(allow_hole),
      empty_val_(empty_val), max_times_(max_times), size_(0), capacity_(0) {
    assert(fat_ != nullptr);
    if (fat->has_section(name_)) {
        sec_ = &fat_->get_section(name_);
    } else {
        assert(false);
    }
    assert(sec_ != nullptr);

    if (need_align) {
        for (const auto& bin : std::array<const LIEF::ELF::Binary*, 3>{
                 &artifact_, &dependency_, fat_}) {
            auto align = bin->has_section(name_)
                             ? bin->get_section(name_).alignment()
                             : 1;
            sec_align_ = std::lcm(sec_align_, align > 0 ? align : 1);
            for (const auto& sec : bin->sections()) {
                elf_align_ = std::lcm(
                    elf_align_, sec.alignment() > 0 ? sec.alignment() : 1);
            }
        }
    }

    size_ = sec_->size();
    capacity_ = size_;
}

int64_t SecMalloc::malloc(int64_t size, MallocUnit unit) {
    switch (unit) {
    case MallocUnit::kByte:
        break;
    case MallocUnit::kEntry:
        assert(sec_->entry_size() > 0);
        assert(dependency_.get_section(name_).entry_size() ==
               sec_->entry_size());
        size *= sec_->entry_size();
        break;
    default:
        assert(false);
    }

    assert(blocks_.size() < max_times_);
    size = ceil(size, sec_align_);
    assert(size_ <= capacity_);
    if (blocks_.empty()) {
        size_ = ceil(size_, sec_align_);
    }
    assert(size_ % sec_align_ == 0);
    if (size_ + size > capacity_) {
        int64_t exp_cap = ceil(size_ + size, elf_align_);
        assert(exp_cap - capacity_ > 0);
        fat_->extend(*sec_, exp_cap - capacity_);
        capacity_ = exp_cap;
        assert(capacity_ == sec_->size());
        std::vector<uint8_t> content = sec_->content();
        assert(content.size() == capacity_);
        std::memset(content.data() + size_, empty_val_, capacity_ - size_);
        sec_->content(content);
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
        assert(sec.entry_size() == fat_->get_section(name_).entry_size());
        addition *= sec.entry_size();
        break;
    default:
        assert(false);
    }
    return malloc(sec.size() + addition, MallocUnit::kByte);
}

int64_t SecMalloc::exact_one_block_offset() const {
    assert(max_times_ == 1);
    // TODO(junbin.rjb)
    // assert(blocks_.size() == 1);
    return blocks_.begin()->first;
}

void SecMalloc::close() const {
    if (!allow_hole_) {
        int64_t off = 0;
        for (auto it = blocks_.begin(); it != blocks_.end(); it++) {
            assert(off = it->first);
            off += it->second;
        }
        assert(off == size_);
    }
    assert(blocks_.size() <= max_times_);
}

int64_t SecMalloc::ceil(int64_t size, int64_t align) const {
    if (size % align == 0) {
        return size;
    }
    return (size / align + 1) * align;
}

const std::map<std::string, SecMallocCfg> SecMallocMgr::sec_malloc_cfgs_ = {
    {sec_names::kBss, SecMallocCfg{false, false, false}},
    {sec_names::kRodata, SecMallocCfg{false, false, false}},
    {sec_names::kData, SecMallocCfg{false, false, false}},
    {sec_names::kRelaPlt, SecMallocCfg{true, false, false}},
    {sec_names::kInit, SecMallocCfg{false, true, false}},
    {sec_names::kInitArray, SecMallocCfg{true, false, false}},
    {sec_names::kFini, SecMallocCfg{false, true, false}},
    {sec_names::kFiniArray, SecMallocCfg{true, false, false}},
    {sec_names::kSymtab, SecMallocCfg{true, false, false}},
    {sec_names::kRelaDyn, SecMallocCfg{true, false, false}},
    {sec_names::kStrtab, SecMallocCfg{false, false, false}},
    {sec_names::kPltGot, SecMallocCfg{true, true, false}},
    {sec_names::kGot, SecMallocCfg{true, false, false}},
    {sec_names::kText, SecMallocCfg{false, true, false}},
    {sec_names::kPlt, SecMallocCfg{true, true, false}},
    {sec_names::kGotPlt, SecMallocCfg{true, false, false}},
    {sec_names::kRelaPlt, SecMallocCfg{true, false, false}},
    {sec_names::kDynsym, SecMallocCfg{true, false, false}},
    {sec_names::kDynstr, SecMallocCfg{false, false, false}},
    {sec_names::kTbss, SecMallocCfg{false, false, false}},
    {sec_names::kTdata, SecMallocCfg{false, false, false}}};

SecMallocMgr::SecMallocMgr(const LIEF::ELF::Binary& artifact,
                           const LIEF::ELF::Binary& dependency,
                           LIEF::ELF::Binary* fat)
    : artifact_(artifact), dependency_(dependency), fat_(fat) {
    assert(fat_);
}

std::map<std::string, SecMalloc>& SecMallocMgr::get() {
    return sec_mallocs_;
}

SecMalloc& SecMallocMgr::get(const std::string& name) {
    auto it = sec_mallocs_.find(name);
    assert(it != sec_mallocs_.end());
    return it->second;
}

SecMalloc& SecMallocMgr::get_or_create(const std::string& name) {
    auto it_malloc = sec_mallocs_.find(name);
    if (it_malloc != sec_mallocs_.end()) {
        return it_malloc->second;
    }

    auto it_cfg = sec_malloc_cfgs_.find(name);
    assert(it_cfg != sec_malloc_cfgs_.end());
    auto cfg = it_cfg->second;
    it_malloc = sec_mallocs_
                    .emplace(std::piecewise_construct,
                             std::forward_as_tuple(name),
                             std::forward_as_tuple(
                                 artifact_,
                                 dependency_,
                                 fat_,
                                 name,
                                 false,                       // need_align
                                 !cfg.is_table,               // allow_hole
                                 cfg.is_code ? 0x90 : 0x0,    // empty_val
                                 cfg.multi_malloc ? 10 : 1))  // max_times
                    .first;
    return it_malloc->second;
}

}  // namespace shade_so
