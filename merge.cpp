// Copyright (c) @ 2020 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2020/10/13
// Description

#include <LIEF/ELF.hpp>
#include <Zydis/Zydis.h>

#include <algorithm>
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
        uint64_t rip = section_virtual_address_ + current_instruction_offset_ +
                       instruction.length;
        if (!(rip + operand.mem.disp.value >= barrier_)) {
          break;
        }
        uint64_t n = 0;
        const std::size_t operand_offset = instruction.raw.disp.offset,
                          operand_size = instruction.raw.disp.size / 8;
        for (std::size_t i = 0; i < operand_size; i++) {
          n |= (data_[current_instruction_offset_ + operand_offset + i] * 1L)
               << (8 * i);
        }
        assert(n == operand.mem.disp.value);
        n += added_;
        std::vector<uint8_t> bytes_to_be_patched;
        for (std::size_t i = 0; i < operand_size; i++) {
          bytes_to_be_patched.emplace_back((n >> (8 * i)) & 0xFF);
        }
        binary_->patch_address(section_virtual_address_ +
                                   current_instruction_offset_ + operand_offset,
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

class Merger {
 public:
  Merger(const std::string& src_file, const std::string& dst_file)
      : src_binary_(Parser::parse(src_file)),
        dst_binary_(Parser::parse(dst_file)),
        output_binary_(Parser::parse(dst_file)) {
    assert(src_binary_);
    assert(dst_binary_);
    assert(output_binary_);
  }

  void operator()(const std::string& filename) {
    merge_section(".data");
    merge_dot_text();
    merge_dot_symtab();
    // output_binary_->patch_pltgot("_Z3foov", 2066);
    patch_pltgot();
    output_binary_->write(filename);
  }

 private:
  void merge_dot_text() {
    uint8_t nop_code = 0x90;
    merge_section(".text", nop_code);
  }

  // Static symbols are symbols in .symtab section.
  // readelf --section-headers libfoo.so | grep -E "Nr|.symtab" -A1
  // readelf --symbols libfoo.so | sed -n '/.symtab/,$p'
  // https://stackoverflow.com/questions/3065535/what-are-the-meanings-of-the-columns-of-the-symbol-table-displayed-by-readelf
  //
  // http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi.html
  // st_shndx is set to which means it is associated to the section
  // defined at index n in the section table. If you haven't guessed this
  // is for the .interp section.
  void merge_dot_symtab() {
    auto it_current = src_binary_->static_symbols().begin();
    auto it_end = src_binary_->static_symbols().end();
    it_current++;
    for (; it_current != it_end &&
           (*it_current).type() == ELF_SYMBOL_TYPES::STT_SECTION;
         it_current++) {
    };

    std::map<std::string, uint32_t> cached_section_indices;
    uint64_t symbol_table_extend_size = 0;
    uint64_t string_table_extend_size = 0;
    uint64_t entry_size = output_binary_->get_section(".symtab").entry_size();
    assert(entry_size == 24);
    for (; it_current != it_end; it_current++) {
      Symbol symbol = *it_current;
      if (symbol.shndx() !=
          static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF)) {
        switch (symbol.type()) {
        case ELF_SYMBOL_TYPES::STT_FUNC:
        case ELF_SYMBOL_TYPES::STT_OBJECT:
          uint32_t src_section_id = symbol.shndx();
          const std::string& section_name =
              (src_binary_->sections() + src_section_id)->name();
          uint32_t dst_section_id = 0;
          auto it_index = cached_section_indices.find(section_name);
          if (it_index != cached_section_indices.end()) {
            dst_section_id = it_index->second;
          } else {
            dst_section_id = get_section_id(dst_binary_.get(), section_name);
            uint16_t output_section_id =
                get_section_id(output_binary_.get(), section_name);
            assert(output_section_id == dst_section_id);
            cached_section_indices.emplace(section_name, dst_section_id);
          }
          assert(dst_section_id != 0);
          symbol.shndx(dst_section_id);
          symbol.value(
              symbol.value() -
              (src_binary_->sections().begin() + src_section_id)
                  ->virtual_address() +
              (output_binary_->sections().begin() + dst_section_id)
                  ->virtual_address() +
              (dst_binary_->sections().begin() + dst_section_id)->size());
          break;
        }
        symbol.binding(SYMBOL_BINDINGS::STB_LOCAL);
        std::string name = symbol.name();
        symbol_table_extend_size += entry_size;
        string_table_extend_size += name.size() + 1;
        // TODO(junbin.rjb)
        // Add filename.
        symbol.name(name);
        output_binary_->add_static_symbol(symbol);
      }
    }
    extend_section(".symtab", symbol_table_extend_size);
    extend_section(".strtab", string_table_extend_size);
  }

  void patch_pltgot() {
    std::for_each(
        output_binary_->static_symbols().begin(),
        output_binary_->static_symbols().end(),
        [this](const LIEF::ELF::Symbol& imported_symbol) {
          if (imported_symbol.shndx() ==
                  static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF) &&
              output_binary_->has_static_symbol(imported_symbol.name())) {
            const Symbol& exported_symbol =
                output_binary_->get_static_symbol(imported_symbol.name());
            if (exported_symbol.shndx() !=
                    static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF) &&
                exported_symbol.binding() == SYMBOL_BINDINGS::STB_LOCAL) {
              output_binary_->patch_pltgot(
                  exported_symbol.name(),
                  output_binary_->get_static_symbol(exported_symbol.name())
                      .value());
            }
          }
        });
  }

  uint16_t get_section_id(Binary* binary, const std::string& section_name) {
    uint16_t section_id = 0;
    for (auto it = binary->sections().begin(); it != binary->sections().end();
         it++) {
      if (it->name() == section_name) {
        assert(section_id == 0);
        section_id = it - binary->sections().begin();
      }
    }
    return section_id;
  }

  void merge_section(const std::string& section_name, uint8_t empty_value = 0) {
    const Section& src_binary_section = src_binary_->get_section(section_name);
    Section& output_binary_section = output_binary_->get_section(section_name);
    assert(src_binary_section.alignment() == output_binary_section.alignment());
    uint64_t dst_original_virtual_address =
        output_binary_section.virtual_address();
    uint64_t dst_original_offset = output_binary_section.offset();
    uint64_t dst_original_size = output_binary_section.size();
    // assert(src_binary_section.information() ==
    //        output_binary_section.information());

    // Extend.
    const std::vector<uint8_t>& src_binary_section_content =
        src_binary_section.content();
    uint64_t extend_size =
        extend_section(section_name, src_binary_section_content.size());
    assert(extend_size >= src_binary_section_content.size());

    // Fill output_binary_section hole with src_binary_section.
    std::vector<uint8_t> output_binary_section_content =
        output_binary_section.content();
    std::memset(output_binary_section_content.data() +
                    (output_binary_section_content.size() - extend_size),
                empty_value,
                extend_size);
    std::memcpy(output_binary_section_content.data() +
                    (output_binary_section_content.size() - extend_size),
                src_binary_section_content.data(),
                src_binary_section_content.size());
    output_binary_section.content(output_binary_section_content);
  }

  uint64_t extend_section(const std::string& section_name,
                          uint64_t extend_size) {
    const LIEF::ELF::Section& section =
        output_binary_->get_section(section_name);
    uint64_t alignment = section.alignment();
    // Ensure section alignment after extending.
    if (extend_size % alignment != 0) {
      extend_size = (extend_size / alignment + 1) * alignment;
    }
    uint64_t section_virtual_address = section.virtual_address();
    uint64_t section_original_virtual_size = section.size();
    assert(section_virtual_address % alignment == 0);
    // assert(section_original_virtual_size_ == section_.physical_size());
    // assert(section_original_virtual_size_ % alignment == 0);

    output_binary_->extend(section, extend_size);

    if (section_virtual_address != 0) {
      for (const std::string& section_name :
           std::vector<std::string>{".init", ".text", ".plt", ".plt.got"}) {
        RipRegisterPatcher(output_binary_.get(),
                           section_name,
                           section_virtual_address +
                               section_original_virtual_size,
                           extend_size)
            .patch();
      }
    }
    return extend_size;
  }

 private:
  std::unique_ptr<Binary> src_binary_;
  std::unique_ptr<Binary> dst_binary_;
  std::unique_ptr<Binary> output_binary_;
};

}  // namespace ELF
}  // namespace LIEF

int main() {
  LIEF::ELF::Merger merger("libfoo.so", "main");
  merger("main-hooked");
}
