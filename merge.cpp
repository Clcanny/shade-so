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
#include <memory>
#include <string>
#include <vector>

namespace LIEF {
namespace ELF {

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

    const char* symtab_name = ".symtab";
    const LIEF::ELF::Section& libfoo_symtab_section =
        libfoo->get_section(symtab_name);
    std::vector<uint8_t> libfoo_symtab_section_content =
        libfoo_symtab_section.content();
    extend_size =
        LIEF::ELF::SectionExtender(
            exec.get(), symtab_name, libfoo_symtab_section_content.size())
            .extend();
    assert(extend_size >= libfoo_symtab_section_content.size());
    LIEF::ELF::Section& exec_symtab_section = exec->get_section(symtab_name);
    std::vector<uint8_t> exec_symtab_section_content =
        exec_symtab_section.content();
    std::memcpy(exec_symtab_section_content.data() +
                    (exec_symtab_section_content.size() - extend_size),
                libfoo_symtab_section_content.data(),
                libfoo_symtab_section_content.size());
    exec_symtab_section.content(exec_symtab_section_content);

    exec->patch_pltgot("_Z3foov",
                       exec_text_section.virtual_address() +
                           exec_text_section_content.size() - extend_size);
    auto dynamic_entries = exec->dynamic_entries();
    exec->remove(dynamic_entries[0]);
    exec->write("main-hooked");
}
