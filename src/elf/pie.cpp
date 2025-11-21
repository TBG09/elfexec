#include "elf/pie.hpp"
#include "emu/emulator.hpp"
#include "logging.hpp"
#include <cstring>

PIEHandler::PIEHandler(const ELFParser& parser)
    : m_parser(parser), m_baseAddress(0) {}

PIEHandler::~PIEHandler() = default;

bool PIEHandler::loadRelocations() {
    if (m_parser.is64Bit()) {
        return loadRelocations64();
    } else {
        return loadRelocations32();
    }
}

bool PIEHandler::loadRelocations64() {
    const auto& sections = m_parser.getSectionHeaders64();
    const auto& fileData = m_parser.getFileData();

    for (const auto& section : sections) {
        if (section.sh_type == static_cast<uint32_t>(SHType::SHT_RELA)) {
            uint64_t offset = section.sh_offset;
            uint64_t size = section.sh_size;
            uint64_t entsize = section.sh_entsize;

            if (entsize == 0) continue;

            for (uint64_t i = 0; i < size; i += entsize) {
                if (offset + i + sizeof(Relocation64) > fileData.size()) {
                    LOG_ERROR("Relocation entry out of bounds");
                    return false;
                }
                Relocation64 rel;
                std::memcpy(&rel, fileData.data() + offset + i, sizeof(Relocation64));
                m_relocations64.push_back(rel);
            }
        }
    }
    return true;
}

bool PIEHandler::loadRelocations32() {
    const auto& sections = m_parser.getSectionHeaders32();
    const auto& fileData = m_parser.getFileData();

    for (const auto& section : sections) {
        if (section.sh_type == static_cast<uint32_t>(SHType::SHT_REL)) {
            uint32_t offset = section.sh_offset;
            uint32_t size = section.sh_size;
            uint32_t entsize = section.sh_entsize;

            if (entsize == 0) continue;

            for (uint32_t i = 0; i < size; i += entsize) {
                if (offset + i + sizeof(Relocation32) > fileData.size()) {
                    LOG_ERROR("Relocation entry out of bounds");
                    return false;
                }
                Relocation32 rel;
                std::memcpy(&rel, fileData.data() + offset + i, sizeof(Relocation32));
                m_relocations32.push_back(rel);
            }
        }
    }
    return true;
}

bool PIEHandler::applyRelocations(Emulator& emulator, uint64_t baseAddress) {
    m_baseAddress = baseAddress;
    uc_engine* uc = emulator.getUnicornEngine();

    if (m_parser.is64Bit()) {
        for (const auto& rel : m_relocations64) {
            uint64_t type = ELF64_R_TYPE(rel.r_info);
            uint64_t offset = baseAddress + rel.r_offset;

            if (type == R_X86_64_RELATIVE || type == R_AARCH64_RELATIVE) {
                uint64_t value = baseAddress + rel.r_addend;
                if (uc_mem_write(uc, offset, &value, sizeof(value)) != UC_ERR_OK) {
                    LOG_ERROR("Failed to apply 64-bit relative relocation");
                    return false;
                }
            }
        }
    } else {
        for (const auto& rel : m_relocations32) {
            uint32_t type = ELF32_R_TYPE(rel.r_info);
            uint32_t offset = baseAddress + rel.r_offset;

            if (type == R_386_RELATIVE || type == R_ARM_RELATIVE) {
                uint32_t value;
                if (uc_mem_read(uc, offset, &value, sizeof(value)) != UC_ERR_OK) {
                    LOG_ERROR("Failed to read for 32-bit relative relocation");
                    return false;
                }
                value += baseAddress;
                if (uc_mem_write(uc, offset, &value, sizeof(value)) != UC_ERR_OK) {
                    LOG_ERROR("Failed to apply 32-bit relative relocation");
                    return false;
                }
            }
        }
    }
    return true;
}

// Stubs for unused methods
bool PIEHandler::loadSymbols64() { return true; }
bool PIEHandler::loadSymbols32() { return true; }
bool PIEHandler::loadStringTable() { return true; }