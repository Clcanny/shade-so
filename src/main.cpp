// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/08
// Description: https://google.github.io/styleguide/cppguide.html

#include <cstdint>
#include <memory>

#include <LIEF/ELF.hpp>

// #include "spdlog/spdlog.h"
#include "src/elf.h"
#include "src/extend_section.h"
#include "src/handle_lazy_symbol_binding.h"
#include "src/handle_strict_symbol_binding.h"
#include "src/merge_section.h"
#include "src/merge_text_section.h"
#include "src/patch_rip_insts.h"
#include "src/relocate_jump_slot_entry.h"

int main() {
    // spdlog::set_level(spdlog::level::debug);
    // spdlog::set_pattern("[source %s] [function %!] [line %#] %v");

    std::unique_ptr<LIEF::ELF::Binary> src(
        LIEF::ELF::Parser::parse("libfoo.so"));
    std::unique_ptr<LIEF::ELF::Binary> dst(
        LIEF::ELF::Parser::parse("main.out"));
    std::unique_ptr<LIEF::ELF::Binary> out(
        LIEF::ELF::Parser::parse("main.out"));

    for (const std::string& sec_name :
         std::vector<std::string>{".plt.got",
                                  ".got",
                                  ".dynsym",
                                  ".symtab",
                                  ".rela.dyn",
                                  ".strtab",
                                  ".text",
                                  ".plt",
                                  ".got.plt",
                                  ".rela.plt",
                                  ".dynstr",
                                  ".rodata",
                                  ".data",
                                  // ".init",
                                  ".init_array"}) {
        shade_so::ExtendSection(
            out.get(), sec_name, src->get_section(sec_name).size())();
    }

    // do {
    //     if (!src->has_segment(LIEF::ELF::SEGMENT_TYPES::PT_TLS)) {
    //         break;
    //     }
    //     const auto& src_seg = src->get(LIEF::ELF::SEGMENT_TYPES::PT_TLS);
    //     LIEF::ELF::Segment* out_seg = nullptr;
    //     if (out->has_segment(LIEF::ELF::SEGMENT_TYPES::PT_TLS)) {
    //         out_seg = &out->get(LIEF::ELF::SEGMENT_TYPES::PT_TLS);
    //     } else {
    //         LIEF::ELF::Segment seg;
    //         seg.type(LIEF::ELF::SEGMENT_TYPES::PT_TLS);
    //         seg.flags(src_seg.flags());
    //         seg.alignment(src_seg.alignment());
    //         out_seg = &out->add_segment(seg);
    //     }
    //     // if (src->has_section(".tdata")) {
    //     //     if (!out->has_section(".tdata")) {
    //     //         out->add_section
    //     //     }
    //     //     shade_so::ExtendSection(
    //     //         out.get(), ".tdata", src->get_section(".tdata").size())();
    //     // }
    // } while (false);

    shade_so::MergeSection(src.get(), dst.get(), out.get(), ".rodata", 0)();
    // shade_so::MergeSection(src.get(), dst.get(), out.get(), ".init", 0x90)();
    shade_so::MergeSection(
        src.get(), dst.get(), out.get(), ".init_array", 0x0)();
    shade_so::HandleLazySymbolBinding(src.get(), dst.get(), out.get())();
    shade_so::MergeTextSection(src.get(), dst.get(), out.get())();
    shade_so::HandleStrictSymbolBinding(src.get(), dst.get(), out.get())();

    {
        LIEF::ELF::DynamicEntryArray* arr =
            out->get(LIEF::ELF::DYNAMIC_TAGS::DT_INIT_ARRAY)
                .as<LIEF::ELF::DynamicEntryArray>();

        const std::string& sec_name = ".init_array";
        const auto& src_sec = src->get_section(sec_name);
        const auto& dst_sec = dst->get_section(sec_name);
        const auto& out_sec = out->get_section(sec_name);
        std::vector<uint8_t> out_content = out_sec.content();
        for (uint64_t offset = dst_sec.size(); offset < out_content.size();
             offset += out_sec.entry_size()) {
            int64_t value = 0;
            for (auto i = 0; i < out_sec.entry_size(); i++) {
                auto t = out_content[offset + i] * 1L;
                value |= t << (8 * i);
            }
            const auto& src_to_sec = src->section_from_virtual_address(value);
            const auto& dst_to_sec = dst->get_section(src_to_sec.name());
            const auto& out_to_sec = out->get_section(src_to_sec.name());
            value = out_to_sec.virtual_address() + dst_to_sec.size() +
                    (value - src_to_sec.virtual_address());
            arr->append(value);
            std::vector<uint8_t> bytes_to_be_patched;
            for (auto i = 0; i < out_sec.entry_size(); i++) {
                bytes_to_be_patched.emplace_back((value >> (8 * i)) & 0xFF);
            }
            out->patch_address(out_sec.virtual_address() + offset,
                               bytes_to_be_patched);
        }

        // for (auto i = 0; i < out->dynamic_entries().size(); i++) {
        //     LIEF::ELF::DynamicEntry& dynamic_entry =
        //     out->dynamic_entries()[i]; if (dynamic_entry.tag() ==
        //     LIEF::ELF::DYNAMIC_TAGS::DT_INIT_ARRAYSZ) {
        //         std::cout << "here" << std::endl;
        //         std::cout << std::hex << out_content.size() << std::endl;
        //         dynamic_entry.value(out_content.size());
        //     }
        // }
    }

    for (auto i = 0; i < src->relocations().size(); i++) {
        const auto& src_reloc = src->relocations()[i];
        if (src_reloc.type() !=
            static_cast<uint32_t>(shade_so::RelocType::R_X86_64_RELATIVE)) {
            continue;
        }
        // if (src_reloc.address() != 0x4040) {
        //     continue;
        // }
        const LIEF::ELF::Section& src_sec =
            src->section_from_virtual_address(src_reloc.address());
        const LIEF::ELF::Section& dst_sec = dst->get_section(src_sec.name());
        const LIEF::ELF::Section& out_sec = out->get_section(src_sec.name());
        // auto out_sec_id =
        //     std::find_if(out->sections().begin(),
        //                  out->sections().end(),
        //                  [&out_sec](const LIEF::ELF::Section& sec) {
        //                      return sec == out_sec;
        //                  }) -
        //     out->sections().begin();
        // assert(src_reloc.value() == 0);

        const LIEF::ELF::Section& src_to_sec =
            src->section_from_virtual_address(src_reloc.addend());
        const LIEF::ELF::Section& dst_to_sec =
            dst->get_section(src_to_sec.name());
        const LIEF::ELF::Section& out_to_sec =
            out->get_section(src_to_sec.name());

        out->add_dynamic_relocation(LIEF::ELF::Relocation(
            out_sec.virtual_address() + dst_sec.size() +
                (src_reloc.address() - src_sec.virtual_address()),
            src_reloc.type(),
            out_to_sec.virtual_address() + dst_to_sec.size() +
                (src_reloc.addend() - src_to_sec.virtual_address()),
            src_reloc.is_rela()));
    }

    shade_so::PatchRipInsts(src.get(), dst.get(), out.get())();

    // Set relocation and symbol done.
    // Reset symbol value.
    // TODO(junbin.rjb)
    // Fix LIEF bug.
    out->write("modified-main.out");
    out = LIEF::ELF::Parser::parse("modified-main.out");
    shade_so::RelocateJumpSlotEntry(out.get())();
    out->remove_library("libfoo.so");
    out->add_library("libbar.so");
    out->write("modified-main.out");
}
