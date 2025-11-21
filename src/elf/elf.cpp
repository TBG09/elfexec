#include "elf/elf.hpp"
#include "logging.hpp"
#include <fstream>
#include <cstring>

ELFParser::ELFParser()
    : m_is64Bit(false), m_isPIE(false), m_isDynamic(false),
      m_entryPoint(0), m_arch(Architecture::ARCH_X64) {}

ELFParser::~ELFParser() = default;

bool ELFParser::load(const std::string& filename) {
    LOG_INFO("Loading ELF file: " + filename);

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open file: " + filename);
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    m_fileData.resize(size);
    if (!file.read(reinterpret_cast<char*>(m_fileData.data()), size)) {
        LOG_ERROR("Failed to read file: " + filename);
        return false;
    }
    file.close();

    LOG_DEBUG("File size: " + std::to_string(size) + " bytes");

    if (m_fileData.size() < sizeof(ELFHeader64)) {
        LOG_ERROR("File too small to be valid ELF");
        return false;
    }

    if (!parseHeader()) {
        LOG_ERROR("Failed to parse ELF header");
        return false;
    }

    if (!parseProgramHeaders()) {
        LOG_ERROR("Failed to parse program headers");
        return false;
    }

    if (!parseSectionHeaders()) {
        LOG_ERROR("Failed to parse section headers");
        return false;
    }

    if (!detectPIE()) {
        LOG_ERROR("Failed to detect PIE");
        return false;
    }

    if (!detectArchitecture()) {
        LOG_ERROR("Failed to detect architecture");
        return false;
    }

    LOG_INFO("ELF file loaded successfully");
    return true;
}

const char* ELFParser::getArchitectureName() const {
    switch (m_arch) {
        case Architecture::ARCH_X86:
            return "x86";
        case Architecture::ARCH_X64:
            return "x86-64";
        case Architecture::ARCH_ARM:
            return "ARM";
        case Architecture::ARCH_ARM64:
            return "ARM64";
        default:
            return "Unknown";
    }
}

bool ELFParser::parseHeader() {
    LOG_DEBUG("Parsing ELF header...");

    if (m_fileData[0] != ELF_MAG0 || m_fileData[1] != ELF_MAG1 ||
        m_fileData[2] != ELF_MAG2 || m_fileData[3] != ELF_MAG3) {
        LOG_ERROR("Invalid ELF magic number");
        return false;
    }
    LOG_DEBUG("ELF magic number is valid");

    uint8_t elfClass = m_fileData[4];
    if (elfClass == static_cast<uint8_t>(ELFClass::ELFCLASS64)) {
        m_is64Bit = true;
        LOG_DEBUG("Detected 64-bit ELF");
    } else if (elfClass == static_cast<uint8_t>(ELFClass::ELFCLASS32)) {
        m_is64Bit = false;
        LOG_DEBUG("Detected 32-bit ELF");
    } else {
        LOG_ERROR("Invalid ELF class: " + std::to_string(static_cast<int>(elfClass)));
        return false;
    }

    uint8_t elfData = m_fileData[5];
    bool isLittleEndian = (elfData == static_cast<uint8_t>(ELFData::ELFDATA2LSB));
    LOG_DEBUG(std::string("Endianness: ") + (isLittleEndian ? "Little-endian" : "Big-endian"));

    if (m_is64Bit) {
        if (m_fileData.size() < sizeof(ELFHeader64)) {
            LOG_ERROR("File too small for 64-bit ELF header");
            return false;
        }

        m_header64 = std::make_unique<ELFHeader64>();
        std::memcpy(m_header64.get(), m_fileData.data(), sizeof(ELFHeader64));
        LOG_DEBUG("Copied 64-bit ELF header");

        uint16_t type = m_header64->e_type;
        if (type == static_cast<uint16_t>(ELFType::ET_DYN)) {
            m_isDynamic = true;
            LOG_DEBUG("Binary is dynamically linked");
        }

        m_entryPoint = m_header64->e_entry;
        LOG_DEBUG("Entry point: 0x" + std::to_string(m_entryPoint));
    } else {
        if (m_fileData.size() < sizeof(ELFHeader32)) {
            LOG_ERROR("File too small for 32-bit ELF header");
            return false;
        }

        m_header32 = std::make_unique<ELFHeader32>();
        std::memcpy(m_header32.get(), m_fileData.data(), sizeof(ELFHeader32));
        LOG_DEBUG("Copied 32-bit ELF header");

        uint16_t type = m_header32->e_type;
        if (type == static_cast<uint16_t>(ELFType::ET_DYN)) {
            m_isDynamic = true;
            LOG_DEBUG("Binary is dynamically linked");
        }

        m_entryPoint = m_header32->e_entry;
        LOG_DEBUG("Entry point: 0x" + std::to_string(m_entryPoint));
    }

    return true;
}

bool ELFParser::parseProgramHeaders() {
    LOG_DEBUG("Parsing program headers...");

    if (m_is64Bit) {
        if (!m_header64) {
            LOG_ERROR("64-bit header not available for parsing program headers");
            return false;
        }

        uint16_t phnum = m_header64->e_phnum;
        uint64_t phoff = m_header64->e_phoff;
        uint16_t phentsize = m_header64->e_phentsize;

        LOG_DEBUG("Program headers: count=" + std::to_string(phnum) + " offset=0x" + std::to_string(phoff));

        if (phoff == 0 || phentsize == 0) {
            LOG_WARN("No program headers found");
            return true;
        }

        for (uint16_t i = 0; i < phnum; ++i) {
            uint64_t offset = phoff + (i * phentsize);
            if (offset + sizeof(ProgramHeader64) > m_fileData.size()) {
                LOG_ERROR("Program header out of bounds");
                return false;
            }

            ProgramHeader64 ph;
            std::memcpy(&ph, m_fileData.data() + offset, sizeof(ProgramHeader64));
            m_progHeaders64.push_back(ph);
            LOG_DEBUG("Loaded program header " + std::to_string(i) + " of type " + std::to_string(ph.p_type));
        }
    } else {
        if (!m_header32) {
            LOG_ERROR("32-bit header not available for parsing program headers");
            return false;
        }

        uint16_t phnum = m_header32->e_phnum;
        uint32_t phoff = m_header32->e_phoff;
        uint16_t phentsize = m_header32->e_phentsize;

        LOG_DEBUG("Program headers: count=" + std::to_string(phnum) + " offset=0x" + std::to_string(phoff));

        if (phoff == 0 || phentsize == 0) {
            LOG_WARN("No program headers found");
            return true;
        }

        for (uint16_t i = 0; i < phnum; ++i) {
            uint32_t offset = phoff + (i * phentsize);
            if (offset + sizeof(ProgramHeader32) > m_fileData.size()) {
                LOG_ERROR("Program header out of bounds");
                return false;
            }

            ProgramHeader32 ph;
            std::memcpy(&ph, m_fileData.data() + offset, sizeof(ProgramHeader32));
            m_progHeaders32.push_back(ph);
            LOG_DEBUG("Loaded program header " + std::to_string(i) + " of type " + std::to_string(ph.p_type));
        }
    }

    LOG_INFO("Loaded " + std::to_string(m_progHeaders64.size() + m_progHeaders32.size()) + " program headers");
    return true;
}

bool ELFParser::parseSectionHeaders() {
    LOG_DEBUG("Parsing section headers...");

    if (m_is64Bit) {
        if (!m_header64) {
            LOG_ERROR("64-bit header not available for parsing section headers");
            return false;
        }

        uint16_t shnum = m_header64->e_shnum;
        uint64_t shoff = m_header64->e_shoff;
        uint16_t shentsize = m_header64->e_shentsize;

        LOG_DEBUG("Section headers: count=" + std::to_string(shnum) + " offset=0x" + std::to_string(shoff));

        if (shoff == 0 || shentsize == 0) {
            LOG_WARN("No section headers found");
            return true;
        }

        for (uint16_t i = 0; i < shnum; ++i) {
            uint64_t offset = shoff + (i * shentsize);
            if (offset + sizeof(SectionHeader64) > m_fileData.size()) {
                LOG_ERROR("Section header out of bounds");
                return false;
            }

            SectionHeader64 sh;
            std::memcpy(&sh, m_fileData.data() + offset, sizeof(SectionHeader64));
            m_sectionHeaders64.push_back(sh);
            LOG_DEBUG("Loaded section header " + std::to_string(i) + " of type " + std::to_string(sh.sh_type));
        }
    } else {
        if (!m_header32) {
            LOG_ERROR("32-bit header not available for parsing section headers");
            return false;
        }

        uint16_t shnum = m_header32->e_shnum;
        uint32_t shoff = m_header32->e_shoff;
        uint16_t shentsize = m_header32->e_shentsize;

        LOG_DEBUG("Section headers: count=" + std::to_string(shnum) + " offset=0x" + std::to_string(shoff));

        if (shoff == 0 || shentsize == 0) {
            LOG_WARN("No section headers found");
            return true;
        }

        for (uint16_t i = 0; i < shnum; ++i) {
            uint32_t offset = shoff + (i * shentsize);
            if (offset + sizeof(SectionHeader32) > m_fileData.size()) {
                LOG_ERROR("Section header out of bounds");
                return false;
            }

            SectionHeader32 sh;
            std::memcpy(&sh, m_fileData.data() + offset, sizeof(SectionHeader32));
            m_sectionHeaders32.push_back(sh);
            LOG_DEBUG("Loaded section header " + std::to_string(i) + " of type " + std::to_string(sh.sh_type));
        }
    }

    LOG_INFO("Loaded " + std::to_string(m_sectionHeaders64.size() + m_sectionHeaders32.size()) + " section headers");
    return true;
}

bool ELFParser::detectPIE() {
    LOG_DEBUG("Detecting if binary is PIE...");
    if (m_is64Bit && m_header64) {
        uint16_t type = m_header64->e_type;
        if (type == static_cast<uint16_t>(ELFType::ET_DYN)) {
            m_isPIE = true;
            LOG_DEBUG("Detected PIE (Position Independent Executable)");
        } else {
            LOG_DEBUG("Binary is not PIE");
        }
    } else if (!m_is64Bit && m_header32) {
        uint16_t type = m_header32->e_type;
        if (type == static_cast<uint16_t>(ELFType::ET_DYN)) {
            m_isPIE = true;
            LOG_DEBUG("Detected PIE (Position Independent Executable)");
        } else {
            LOG_DEBUG("Binary is not PIE");
        }
    }
    return true;
}

bool ELFParser::detectArchitecture() {
    LOG_DEBUG("Detecting architecture...");
    uint16_t machine = m_is64Bit ? m_header64->e_machine : m_header32->e_machine;

    switch (machine) {
        case static_cast<uint16_t>(ELFMachine::EM_386):
            m_arch = Architecture::ARCH_X86;
            LOG_DEBUG("Detected architecture: x86");
            break;
        case static_cast<uint16_t>(ELFMachine::EM_X86_64):
            m_arch = Architecture::ARCH_X64;
            LOG_DEBUG("Detected architecture: x86-64");
            break;
        case static_cast<uint16_t>(ELFMachine::EM_ARM):
            m_arch = Architecture::ARCH_ARM;
            LOG_DEBUG("Detected architecture: ARM");
            break;
        case static_cast<uint16_t>(ELFMachine::EM_AARCH64):
            m_arch = Architecture::ARCH_ARM64;
            LOG_DEBUG("Detected architecture: ARM64");
            break;
        default:
            LOG_ERROR("Unsupported machine type: " + std::to_string(machine));
            return false;
    }

    return true;
}
