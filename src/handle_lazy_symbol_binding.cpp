// Copyright (c) @ 2020 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2020/10/13
// Description

#include "src/handle_lazy_symbol_binding.h"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <numeric>
#include <vector>

// #include "spdlog/sinks/file_sinks.h"
// #include "spdlog/spdlog.h"
#include "src/const.h"
#include "src/elf.h"
#include "src/extend_section.h"

namespace shade_so {
namespace {

// static auto kLogger = spdlog::rotating_logger_mt(
//     "HandleLazySymbolBinding", "logs/shade_so.LOG", 5 * 1024 * 1024, 3);

}  // namespace

HandleLazySymbolBinding::HandleLazySymbolBinding(Binary* src,
                                                 Binary* dst,
                                                 Binary* out)
    : src_(src), dst_(dst), out_(out) {
    assert(src_);
    assert(dst_);
    assert(out_);

    ZydisDecoderInit(
        &decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
}

uint64_t HandleLazySymbolBinding::operator()() {
    const Section& plt = src_->get_section(".plt");
    uint64_t plt_entries_num = plt.size() / plt.entry_size();
    assert(plt_entries_num >= 1);
    plt_entries_num -= 1;

    const Section& got_plt = src_->get_section(".got.plt");
    uint64_t got_plt_entries_num = got_plt.size() / got_plt.entry_size();
    assert(got_plt_entries_num >= 3);
    got_plt_entries_num -= 3;
    assert(got_plt_entries_num == plt_entries_num);

    const Section& rela_plt = src_->get_section(".rela.plt");
    uint64_t rela_plt_num = rela_plt.size() / rela_plt.entry_size();
    assert(rela_plt_num == plt_entries_num);

    uint64_t undef_dynsym_entries_num = std::count_if(
        std::begin(src_->dynamic_symbols()),
        std::end(src_->dynamic_symbols()),
        [](const Symbol& sym) {
            return sym.shndx() ==
                   static_cast<uint16_t>(
                       LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF);
        });
    // assert(undef_dynsym_entries_num == plt_entries_num);

    extend(plt_entries_num);

    const Section& plt_got = out_->get_section(".plt.got");
    fill(plt_entries_num);
    return plt_entries_num;
}

void HandleLazySymbolBinding::extend(uint64_t entries_num) {
    namespace names = section_names;

    const Section& plt = out_->get_section(".plt");

    const Section& got_plt = out_->get_section(names::kGotPlt);

    const Section& rela_plt = out_->get_section(".rela.plt");

    const Section& dynsym = out_->get_section(".dynsym");

    // I use a very loose upper bound here.
}

template <int N>
void HandleLazySymbolBinding::handle_plt_entry_inst(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(false);
}

template <>
void HandleLazySymbolBinding::handle_plt_entry_inst<0>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(inst.mnemonic == ZYDIS_MNEMONIC_JMP);
    const ZydisDecodedOperand& operand = get_exactly_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
           operand.mem.base == ZYDIS_REGISTER_RIP &&
           operand.mem.disp.has_displacement);

    const Section& out_plt_sec = out_->get_section(section_names::kPlt);
    const Section& dst_got_plt_sec = dst_->get_section(section_names::kGotPlt);
    const Section& out_got_plt_sec = out_->get_section(section_names::kGotPlt);
    uint64_t cur_va = out_plt_sec.virtual_address() + offset;
    uint64_t rip = cur_va + inst.length;
    uint64_t addend = out_got_plt_sec.virtual_address() +
                      dst_got_plt_sec.size() +
                      entry_id * out_got_plt_sec.entry_size() - rip;
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.disp.size / 8; i++) {
        bytes_to_be_patched.emplace_back((addend >> (8 * i)) & 0xFF);
    }
    assert(cur_va + inst.raw.disp.offset + bytes_to_be_patched.size() <=
           out_plt_sec.virtual_address() + out_plt_sec.size());
    out_->patch_address(cur_va + inst.raw.disp.offset, bytes_to_be_patched);

    bytes_to_be_patched.clear();
    auto got_plt_es = out_got_plt_sec.entry_size();
    for (auto i = 0; i < got_plt_es; i++) {
        bytes_to_be_patched.emplace_back(((cur_va + inst.length) >> (8 * i)) & 0xFF);
    }
    assert(out_got_plt_sec.virtual_address() + dst_got_plt_sec.size() +
               entry_id * got_plt_es + bytes_to_be_patched.size() <=
           out_got_plt_sec.virtual_address() + out_got_plt_sec.size());
    out_->patch_address(out_got_plt_sec.virtual_address() +
                            dst_got_plt_sec.size() + entry_id * got_plt_es,
                        bytes_to_be_patched);
}

template <>
void HandleLazySymbolBinding::handle_plt_entry_inst<1>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(inst.mnemonic == ZYDIS_MNEMONIC_PUSH);
    const ZydisDecodedOperand& operand = get_exactly_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
           operand.imm.is_signed == ZYAN_TRUE &&
           operand.imm.is_relative == ZYAN_FALSE);

    const Section& out_plt_sec = out_->get_section(section_names::kPlt);
    const Section& out_got_plt_sec = out_->get_section(section_names::kGotPlt);
    const Section& out_rela_plt_sec =
        out_->get_section(section_names::kRelaPlt);
    assert(entry_id < src_->pltgot_relocations().size());
    const Relocation& src_reloc = src_->pltgot_relocations()[entry_id];
    Relocation out_reloc = src_reloc;
    if (src_reloc.has_symbol()) {
        const Symbol& src_sym = src_reloc.symbol();
        // Symbol& out_sym = out_->add_dynamic_symbol(
        //     src_sym,
        //     src_sym.has_version() ? const_cast<LIEF::ELF::SymbolVersion*>(
        //                                 &src_sym.symbol_version())
        //                           : nullptr);
        Symbol& out_sym = out_->add_dynamic_symbol(src_sym);
        out_reloc.symbol(&out_sym);
    }
    out_reloc.address(out_got_plt_sec.virtual_address() +
                      (dst_->pltgot_relocations().size() + 3 + entry_id) *
                          out_got_plt_sec.entry_size());
    out_->add_pltgot_relocation(out_reloc);

    auto out_rela_id = out_->pltgot_relocations().size() - 1;
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.imm[0].size / 8; i++) {
        bytes_to_be_patched.emplace_back((out_rela_id >> (8 * i)) & 0xFF);
    }
    assert(out_plt_sec.virtual_address() + offset + inst.raw.imm[0].offset +
               bytes_to_be_patched.size() <=
           out_plt_sec.virtual_address() + out_plt_sec.size());
    out_->patch_address(out_plt_sec.virtual_address() + offset +
                            inst.raw.imm[0].offset,
                        bytes_to_be_patched);
}

template <>
void HandleLazySymbolBinding::handle_plt_entry_inst<2>(
    int entry_id, uint64_t offset, const ZydisDecodedInstruction& inst) {
    assert(inst.mnemonic == ZYDIS_MNEMONIC_JMP);
    const ZydisDecodedOperand& operand = get_exactly_one_visible_operand(inst);
    assert(operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
           operand.imm.is_signed == 1 && operand.imm.is_relative == 1);

    uint64_t out_plt_va =
        out_->get_section(section_names::kPlt).virtual_address();
    // TODO(junbin.rjb)
    // Why?
    // uint64_t value = out_plt_va - (out_plt_va + offset + inst.length);
    uint64_t value = out_plt_va - (out_plt_va + offset + inst.length - 9);
    std::vector<uint8_t> bytes_to_be_patched;
    for (auto i = 0; i < inst.raw.imm[0].size / 8; i++) {
        bytes_to_be_patched.emplace_back((value >> (8 * i)) & 0xFF);
    }
    assert(out_plt_va + offset + inst.raw.imm[0].offset +
               bytes_to_be_patched.size() <=
           out_plt_va + out_->get_section(section_names::kPlt).size());
    out_->patch_address(out_plt_va + offset + inst.raw.imm[0].offset,
                        bytes_to_be_patched);
}

void HandleLazySymbolBinding::fill(uint64_t entries_num) {
    const Section& src_plt = src_->get_section(section_names::kPlt);
    std::vector<uint8_t> src_plt_content = src_plt.content();
    const Section& dst_plt = dst_->get_section(section_names::kPlt);
    const Section& out_plt = out_->get_section(section_names::kPlt);
    auto plt_entry_size = src_plt.entry_size();
    assert(plt_entry_size == dst_plt.entry_size());
    assert(plt_entry_size == out_plt.entry_size());
    // The first entry of .plt section is a stub.
    // TODO(junbin.rjb)
    // assert(out_plt.size() ==
    //        dst_plt.size() + (src_plt.size() - 1 * plt_entry_size));
    out_->patch_address(
        out_plt.virtual_address() + dst_plt.size(),
        std::vector<uint8_t>(src_plt_content.begin() + 1 * plt_entry_size,
                             src_plt_content.end()));
    std::vector<uint8_t> out_plt_content = out_plt.content();
    // TODO(junbin.rjb)
    // assert(out_plt_content.size() ==
    //        dst_plt.size() + (src_plt.size() - 1 * plt_entry_size));

    assert(src_plt.size() == (1 + entries_num) * plt_entry_size);
    for (int entry = 0; entry < entries_num; entry++) {
        uint64_t begin = dst_plt.size() + entry * plt_entry_size;
        uint64_t end = begin + plt_entry_size;
        uint64_t offset = begin;
        for (int inst_id = 0; inst_id < 3; inst_id++) {
            ZydisDecodedInstruction inst;
            assert(ZYAN_SUCCESS(
                ZydisDecoderDecodeBuffer(&decoder_,
                                         out_plt_content.data() + offset,
                                         end - offset,
                                         &inst)));
            switch (inst_id) {
            case 0:
                handle_plt_entry_inst<0>(entry, offset, inst);
                break;
            case 1:
                handle_plt_entry_inst<1>(entry, offset, inst);
                break;
            case 2:
                handle_plt_entry_inst<2>(entry, offset, inst);
                break;
                // default:
                //     assert(false);
            }
            offset += inst.length;
        }
        assert(offset == end);
    }
}

ZydisDecodedOperand HandleLazySymbolBinding::get_exactly_one_visible_operand(
    const ZydisDecodedInstruction& inst) {
    auto begin = inst.operands;
    auto end = inst.operands + inst.operand_count;
    auto visible = [](const ZydisDecodedOperand& operand) {
        return operand.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
    };
    assert(std::count_if(begin, end, visible) == 1);
    return *std::find_if(begin, end, visible);
}

// void HandleLazySymbolBinding::handle_plt() {
//     const Section& src_plt = src_->get_section(section_names::kPlt);
//     std::vector<uint8_t> src_content = src_plt.content();
//     uint8_t* src_data = src_content.data();
//     auto size = src_plt.entry_size();

//     const Section& dst_plt = dst_->get_section(section_names::kPlt);
//     const Section& out_plt = out_->get_section(section_names::kPlt);
//     assert(out_plt.size() == src_plt.size() + dst_plt.size());
//     out_->patch_address(
//         out_plt.virtual_address() + dst_plt.size(),
//         std::vector<uint8_t>(src_data + size, src_data + src_plt.size()));

//     // The first entry of .plt section is a stub.
//     LIEF::ELF::Section& got_plt = src_->get_section(section_names::kGotPlt);
//     decltype(size) offset = 0;
//     for (int i = 0; i < 3; i++) {
//         ZydisDecodedInstruction instr;
//         assert(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
//             &decoder_, data + offset, plt.entry_size() - offset, &instr)));
//         offset += instr.length;

//         // TODO(junbin.rjb)
//         // Refactor.
//         if (i == 0) {
//             assert(instr.mnemonic == ZYDIS_MNEMONIC_PUSH);
//             // kLogger->debug("The 2st instruction of plt stub is push.");

//             auto begin = instr.operands;
//             auto end = instr.operands + instr.operand_count;
//             auto is_visible_operand = [](const ZydisDecodedOperand& operand)
//             {
//                 return operand.visibility ==
//                 ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
//             };
//             assert(std::count_if(begin, end, is_visible_operand) == 1);
//             // kLogger->debug("The 1st instruction has 1 visible operands.");

//             const ZydisDecodedOperand& operand =
//                 *std::find_if(begin, end, is_visible_operand);
//             assert(operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
//                    operand.mem.base == ZYDIS_REGISTER_RIP &&
//                    operand.mem.disp.has_displacement);
//             uint64_t rip = plt.virtual_address() + offset;
//             uint64_t arg = rip + operand.mem.disp.value;
//             // kLogger->debug("Push argument is 0x{0:x}.", arg);
//             uint64_t expected =
//                 got_plt.virtual_address() + 1 * got_plt.entry_size();
//             // kLogger->debug(
//             //     "Start addr of the 2nd entry of {} section is 0x{:x}.",
//             //     section_names::kGotPlt,
//             //     expected);
//             assert(arg == expected);
//         } else if (i == 1) {
//             assert(instr.mnemonic == ZYDIS_MNEMONIC_JMP);
//             // kLogger->debug("The 2nd instruction of plt stub is jmp.");

//             auto begin = instr.operands;
//             auto end = instr.operands + instr.operand_count;
//             auto is_visible_operand = [](const ZydisDecodedOperand& operand)
//             {
//                 return operand.visibility ==
//                 ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
//             };
//             assert(std::count_if(begin, end, is_visible_operand) == 1);
//             // kLogger->debug("The 2nd instruction has 1 visible operands.");

//             const ZydisDecodedOperand& operand =
//                 *std::find_if(begin, end, is_visible_operand);
//             assert(operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
//                    operand.mem.base == ZYDIS_REGISTER_RIP &&
//                    operand.mem.disp.has_displacement);
//             uint64_t rip = plt.virtual_address() + offset;
//             uint64_t arg = rip + operand.mem.disp.value;
//             // kLogger->debug("Jump argument is 0x{0:x}.", arg);
//             uint64_t expected =
//                 got_plt.virtual_address() + 2 * got_plt.entry_size();
//             // kLogger->debug(
//             //     "Start addr of the 3rd entry of {} section is 0x{:x}.",
//             //     section_names::kGotPlt,
//             //     expected);
//             assert(arg == expected);
//         } else if (i == 2) {
//             assert(instr.mnemonic == ZYDIS_MNEMONIC_NOP);
//             // kLogger->debug("The 3rd instruction of plt stub is nop.");
//         }
//     }

//     uint64_t begin = (src_id + 1) * plt.entry_size();
//     uint64_t end = (src_id + 2) * plt.entry_size();
//     // uint64_t offset = begin;
//     offset = begin;
//     uint64_t instrCnt = 0;
//     for (int i = 0; i < 3; i++) {
//         ZydisDecodedInstruction instr;
//         assert(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
//             &decoder_, content.data() + offset, end - offset, &instr)));
//         offset += instr.length;

//         if (i == 0) {
//             assert(instr.mnemonic == ZYDIS_MNEMONIC_JMP);
//             // kLogger->debug("The 1st instruction of plt entry is jmp.");

//             auto b = instr.operands;
//             auto e = instr.operands + instr.operand_count;
//             auto is_visible_operand = [](const ZydisDecodedOperand& operand)
//             {
//                 return operand.visibility ==
//                 ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
//             };
//             assert(std::count_if(b, e, is_visible_operand) == 1);
//             // kLogger->debug("The 2nd instruction has 1 visible operands.");

//             const ZydisDecodedOperand& operand =
//                 *std::find_if(b, e, is_visible_operand);
//             assert(operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
//                    operand.mem.base == ZYDIS_REGISTER_RIP &&
//                    operand.mem.disp.has_displacement);
//             uint64_t rip = plt.virtual_address() + offset;
//             uint64_t arg = rip + operand.mem.disp.value;
//             // kLogger->debug("Jump argument is 0x{0:x}.", arg);
//             uint64_t expected =
//                 got_plt.virtual_address() + (3 + src_id) *
//                 got_plt.entry_size();
//             // kLogger->debug("0x{:x}", got_plt.entry_size());
//             // kLogger->debug(
//             //     "Start addr of the 3rd entry of {} section is 0x{:x}.",
//             //     section_names::kGotPlt,
//             //     expected);
//             assert(arg == expected);
//             // Get got entry.
//             std::vector<uint8_t> g = got_plt.content();
//             uint64_t* d = reinterpret_cast<uint64_t*>(g.data());
//             // Other place has checked size of got entry.
//             // kLogger->debug("got: 0x{:x}", d[src_id + 3]);
//             assert(d[src_id + 3] == plt.virtual_address() + offset);
//         } else if (i == 1) {
//             assert(instr.mnemonic == ZYDIS_MNEMONIC_PUSH);
//             // kLogger->debug("The 2nd instruction of plt stub is push.");

//             auto begin = instr.operands;
//             auto end = instr.operands + instr.operand_count;
//             auto is_visible_operand = [](const ZydisDecodedOperand& operand)
//             {
//                 return operand.visibility ==
//                 ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
//             };
//             assert(std::count_if(begin, end, is_visible_operand) == 1);
//             // kLogger->debug("The 2nd instruction has 1 visible operands.");
//             const ZydisDecodedOperand& operand =
//                 *std::find_if(begin, end, is_visible_operand);
//             assert(operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
//                    operand.imm.is_signed == 1 && operand.imm.is_relative == 0
//                    && operand.imm.value.s == src_id);

//             const Section& rela_plt = src_->get_section(".rela.plt");
//             std::vector<uint8_t> r = rela_plt.content();
//             Elf64_Rela* er = reinterpret_cast<Elf64_Rela*>(r.data());
//             assert(er[src_id].r_offset ==
//                    got_plt.virtual_address() +
//                        (3 + src_id) * got_plt.entry_size());
//         } else if (i == 2) {
//             assert(instr.mnemonic == ZYDIS_MNEMONIC_JMP);
//             // kLogger->debug("The 1st instruction of plt entry is jmp.");

//             auto b = instr.operands;
//             auto e = instr.operands + instr.operand_count;
//             auto is_visible_operand = [](const ZydisDecodedOperand& operand)
//             {
//                 return operand.visibility ==
//                 ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
//             };
//             assert(std::count_if(b, e, is_visible_operand) == 1);
//             // kLogger->debug("The 2nd instruction has 1 visible operands.");

//             const ZydisDecodedOperand& operand =
//                 *std::find_if(b, e, is_visible_operand);
//             assert(operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
//                    operand.imm.is_signed == 1 && operand.imm.is_relative ==
//                    1);
//             // kLogger->debug("{:x}", plt.entry_size());
//             // kLogger->debug("{:d}", 1 + src_id);
//             assert(operand.imm.value.s == -1 * (2 + src_id) *
//             plt.entry_size()); uint64_t ra = begin + offset;
//             assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
//                 &instr,
//                 &operand,
//                 plt.virtual_address() + offset - instr.length,
//                 &ra)));
//             // kLogger->debug("0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}",
//             //                plt.virtual_address(),
//             //                begin,
//             //                offset,
//             //                ra);
//         }
//         // offset += instr.length;
//     }
//     assert(offset == end);
//     // kLogger->debug("here");
// }

}  // namespace shade_so
