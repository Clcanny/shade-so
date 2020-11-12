// Copyright (c) @ 2020 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2020/10/13
// Description

#include <LIEF/ELF.hpp>
#include <Zydis/Zydis.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace LIEF {
namespace ELF {

struct SectionMoveInfo {
    bool is_moved_;

    uint32_t original_index_;
    // Note: Section doesn't have virtual size property. If virtual address
    // isn't zero, then the whole section will be loaded to memory; otherwise,
    // it won't be loaded.
    uint64_t original_virtual_address_;
    uint64_t original_offset_;

    uint32_t new_index_;
    uint64_t new_virtual_address_;
    uint64_t new_offset_;
};

class RipRegisterPatcher {
 public:
    RipRegisterPatcher(Binary* binary,
                       const std::string& section_name,
                       uint64_t barrier,
                       uint64_t added)
        : binary_(binary), section_(binary_->get_section(section_name)),
          section_virtual_address_(section_.virtual_address()),
          content_(section_.content()), data_(content_.data()),
          content_size_(content_.size()), current_instruction_offset_(0),
          barrier_(barrier), added_(added) {
        ZydisDecoderInit(
            &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    }

    void patch() {
        ZydisDecodedInstruction instruction;
        for (; current_instruction_offset_ < content_size_ &&
               ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
                   &decoder_,
                   data_ + current_instruction_offset_,
                   content_size_ - current_instruction_offset_,
                   &instruction));
             current_instruction_offset_ += instruction.length) {
            for (std::size_t i = 0; i < instruction.operand_count; i++) {
                if (operand_contains_rip_register(instruction.operands[i])) {
                    patch_operand(instruction);
                    break;
                }
            }
        }
        assert(current_instruction_offset_ == content_size_);
    }

 private:
    bool operand_contains_rip_register(const ZydisDecodedOperand& operand) {
        if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operand.reg.value == ZYDIS_REGISTER_RIP) {
            return true;
        }
        if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operand.mem.base == ZYDIS_REGISTER_RIP) {
            return true;
        }
        return false;
    }

    void patch_operand(const ZydisDecodedInstruction& instruction) {
        patch_memory_type_operand(instruction);
    }

    void patch_memory_type_operand(const ZydisDecodedInstruction& instruction) {
        std::size_t i = 0;
        for (; i < instruction.operand_count; i++) {
            const ZydisDecodedOperand& operand = instruction.operands[i];
            if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operand.mem.base == ZYDIS_REGISTER_RIP &&
                operand.mem.disp.has_displacement) {
                uint64_t rip = section_virtual_address_ +
                               current_instruction_offset_ + instruction.length;
                if (!(rip + operand.mem.disp.value >= barrier_)) {
                    break;
                }
                uint64_t n = 0;
                const std::size_t operand_offset = instruction.raw.disp.offset,
                                  operand_size = instruction.raw.disp.size / 8;
                for (std::size_t i = 0; i < operand_size; i++) {
                    n |= (data_[current_instruction_offset_ + operand_offset +
                                i] *
                          1L)
                         << (8 * i);
                }
                assert(n == operand.mem.disp.value);
                n += added_;
                std::vector<uint8_t> bytes_to_be_patched;
                for (std::size_t i = 0; i < operand_size; i++) {
                    bytes_to_be_patched.emplace_back((n >> (8 * i)) & 0xFF);
                }
                binary_->patch_address(section_virtual_address_ +
                                           current_instruction_offset_ +
                                           operand_offset,
                                       bytes_to_be_patched);
                break;
            } else if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       operand.reg.value == ZYDIS_REGISTER_RIP) {
                // TODO(junbin.rjb)
                // Do something. Call.
                break;
            }
        }
        assert(i < instruction.operand_count);
        for (std::size_t j = i + 1; j < instruction.operand_count; j++) {
            const ZydisDecodedOperand& operand = instruction.operands[j];
            assert(!(operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                     operand.mem.base == ZYDIS_REGISTER_RIP &&
                     operand.mem.disp.has_displacement));
            // assert(!(operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            //          operand.reg.value == ZYDIS_REGISTER_RIP));
        }
    }

 private:
    Binary* binary_;
    const Section& section_;
    uint64_t section_virtual_address_;
    std::vector<uint8_t> content_;
    uint8_t* data_;
    std::size_t content_size_;
    uint64_t current_instruction_offset_;
    uint64_t barrier_;
    uint64_t added_;
    ZydisDecoder decoder_;
};

class SectionExtender {
 public:
    SectionExtender(Binary* binary,
                    const std::string& name,
                    uint64_t extend_size)
        : binary_(binary), section_name_(name),
          section_(binary_->get_section(section_name_)),
          section_virtual_address_(section_.virtual_address()),
          section_original_virtual_size_(section_.size()),
          extend_size_(extend_size) {
        uint64_t alignment = section_.alignment();
        assert(extend_size_ != 0);
        // Ensure section alignment after extending.
        if (extend_size_ % alignment != 0) {
            extend_size_ = (extend_size_ / alignment + 1) * alignment;
        }
        assert(section_virtual_address_ % alignment == 0);
        // assert(section_original_virtual_size_ == section_.physical_size());
        // assert(section_original_virtual_size_ % alignment == 0);
    }

    uint64_t extend() {
        // Call method of LIEF.
        binary_->extend(section_, extend_size_);
        if (section_name_ == ".text") {
            // Fill with nop.
            LIEF::ELF::Section& section = binary_->get_section(section_name_);
            std::vector<uint8_t> content = section.content();
            std::memset(content.data() + (content.size() - extend_size_),
                        0x90,
                        extend_size_);
            section.content(content);
        }
        if (section_virtual_address_ != 0) {
            for (const std::string& section_name : std::vector<std::string>{
                     ".init", ".text", ".plt", ".plt.got"}) {
                RipRegisterPatcher(binary_,
                                   section_name,
                                   section_virtual_address_ +
                                       section_original_virtual_size_,
                                   extend_size_)
                    .patch();
            }
        }
        return extend_size_;
    }

 private:
    Binary* binary_;
    const std::string& section_name_;
    const Section& section_;
    uint64_t section_virtual_address_;
    uint64_t section_original_virtual_size_;
    uint64_t extend_size_;
};

class SectionMerger {
 public:
    SectionMerger(const std::string& src_file, const std::string& dst_file)
        : src_binary_(Parser::parse(src_file)),
          dst_binary_(Parser::parse(dst_file)) {
        assert(src_binary_);
        assert(dst_binary_);
        init_src_section_move_infos();
    }

    void merge(const std::string& section_name) {
        const Section& src_binary_section =
            src_binary_->get_section(section_name);
        const std::vector<uint8_t>& src_binary_section_content =
            src_binary_section.content();
        uint64_t extend_size =
            SectionExtender(dst_binary_.get(),
                            section_name,
                            src_binary_section_content.size())
                .extend();
        assert(extend_size == src_binary_section_content.size());
        // Fill dst_binary_section hole with src_binary_section.
        Section& dst_binary_section = dst_binary_->get_section(section_name);
        uint64_t dst_original_virtual_address =
            dst_binary_section.virtual_address();
        uint64_t dst_original_offset = dst_binary_section.offset();
        uint64_t dst_original_size = dst_binary_section.size();
        std::vector<uint8_t> dst_binary_section_content =
            dst_binary_section.content();
        dst_binary_section_content.insert(dst_binary_section_content.end(),
                                          src_binary_section_content.begin(),
                                          src_binary_section_content.end());
        dst_binary_section.content(dst_binary_section_content);
        // Set src section move info.
        auto it_src = src_section_move_infos_.find(section_name);
        assert(!it_src->second.is_moved_);
        it_src->second.is_moved_ = true;
        if (dst_original_virtual_address = 0) {
            it_src->second.new_virtual_address_ = 0;
        } else {
            it_src->second.new_virtual_address_ =
                dst_original_virtual_address + dst_original_size;
        }
        it_src->second.new_offset_ = dst_original_offset + dst_original_size;
        if (it_src->second.new_virtual_address_ != 0) {
            for (auto it = src_section_move_infos_.begin();
                 it != src_section_move_infos_.end();
                 it++) {
                if (it != it_src && it->second.is_moved_ &&
                    it->second.new_virtual_address_ >
                        it_src->second.new_virtual_address_) {
                    it->second.new_virtual_address_ += extend_size;
                }
            }
        }
    }

 private:
    void init_src_section_move_infos() {
        for (auto it = src_binary_->sections().begin();
             it != src_binary_->sections().end();
             it++) {
            const Section& section = *it;
            SectionMoveInfo info;
            info.is_moved_ = false;
            info.original_index_ = section.name_idx();
            info.original_virtual_address_ = section.virtual_address();
            info.original_offset_ = section.offset();
            info.new_index_ = info.original_index_;
            info.new_virtual_address_ = info.original_virtual_address_;
            info.new_offset_ = info.original_offset_;
            assert(
                src_section_move_infos_.emplace(section.name(), info).second);
        }
    }

 private:
    std::unique_ptr<Binary> src_binary_;
    std::unique_ptr<Binary> dst_binary_;
    std::map<std::string, SectionMoveInfo> src_section_move_infos_;
};

}  // namespace ELF
}  // namespace LIEF

int main() {
    std::unique_ptr<LIEF::ELF::Binary> exec{LIEF::ELF::Parser::parse("main")};
    std::unique_ptr<LIEF::ELF::Binary> libfoo{
        LIEF::ELF::Parser::parse("libfoo.so")};

    const LIEF::ELF::Section& libfoo_text_section =
        libfoo->get_section(".text");
    std::vector<uint8_t> libfoo_text_section_content =
        libfoo_text_section.content();
    uint64_t extend_size =
        LIEF::ELF::SectionExtender(
            exec.get(), ".text", libfoo_text_section_content.size())
            .extend();
    assert(extend_size >= libfoo_text_section_content.size());
    LIEF::ELF::Section& exec_text_section = exec->get_section(".text");
    std::vector<uint8_t> exec_text_section_content =
        exec_text_section.content();
    std::memcpy(exec_text_section_content.data() +
                    (exec_text_section_content.size() - extend_size),
                libfoo_text_section_content.data(),
                libfoo_text_section_content.size());
    exec_text_section.content(exec_text_section_content);

    exec->patch_pltgot("_Z3foov",
                       exec_text_section.virtual_address() +
                           exec_text_section_content.size() - extend_size);

    // const char* symtab_name = ".symtab";
    // const LIEF::ELF::Section& libfoo_symtab_section =
    //     libfoo->get_section(symtab_name);
    // std::vector<uint8_t> libfoo_symtab_section_content =
    //     libfoo_symtab_section.content();
    // extend_size =
    //     LIEF::ELF::SectionExtender(
    //         exec.get(), symtab_name, libfoo_symtab_section_content.size())
    //         .extend();
    // assert(extend_size >= libfoo_symtab_section_content.size());
    // LIEF::ELF::Section& exec_symtab_section = exec->get_section(symtab_name);
    // std::vector<uint8_t> exec_symtab_section_content =
    //     exec_symtab_section.content();
    // std::memcpy(exec_symtab_section_content.data() +
    //                 (exec_symtab_section_content.size() - extend_size),
    //             libfoo_symtab_section_content.data(),
    //             libfoo_symtab_section_content.size());
    // exec_symtab_section.content(exec_symtab_section_content);

    LIEF::ELF::SectionMerger section_merger("main", "libfoo.so");
    section_merger.merge(".text");

    // Dynamic symbols.
    // for (auto it = libfoo->dynamic_symbols().begin();
    //      it != libfoo->dynamic_symbols().end();
    //      it++) {
    //     LIEF::ELF::Symbol& symbol = *it;
    //     std::cout << symbol.name() << std::endl;
    // }

    // Static symbols are symbols in .symtab section.
    // readelf --section-headers libfoo.so | grep -E "Nr|.symtab" -A1
    // readelf --symbols libfoo.so | sed -n '/.symtab/,$p'
    // https://stackoverflow.com/questions/3065535/what-are-the-meanings-of-the-columns-of-the-symbol-table-displayed-by-readelf
    //
    // http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi.html
    // st_shndx is set to which means it is associated to the section defined at
    // index n in the section table. If you haven't guessed this is for the
    // .interp section.
    for (auto it = libfoo->static_symbols().begin();
         it != libfoo->static_symbols().end();
         it++) {
        LIEF::ELF::Symbol& symbol = *it;
        std::cout << symbol.name() << std::endl;
    }

    auto dynamic_entries = exec->dynamic_entries();
    exec->remove(dynamic_entries[0]);
    exec->write("main-hooked");
}
