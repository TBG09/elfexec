#ifndef ELF_HPP
#define ELF_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <memory>

constexpr uint8_t ELF_MAG0 = 0x7f;
constexpr uint8_t ELF_MAG1 = 'E';
constexpr uint8_t ELF_MAG2 = 'L';
constexpr uint8_t ELF_MAG3 = 'F';

enum class ELFClass : uint8_t {
    ELFCLASSNONE = 0,
    ELFCLASS32   = 1,
    ELFCLASS64   = 2
};

enum class ELFData : uint8_t {
    ELFDATANONE = 0,
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2
};

enum class ELFOSABI : uint8_t {
    ELFOSABI_NONE       = 0,
    ELFOSABI_LINUX      = 3,
    ELFOSABI_STANDALONE = 255
};

enum class ELFType : uint16_t {
    ET_NONE   = 0,
    ET_REL    = 1,
    ET_EXEC   = 2,
    ET_DYN    = 3,
    ET_CORE   = 4
};

enum class ELFMachine : uint16_t {
    EM_NONE   = 0,
    EM_386    = 3,
    EM_ARM    = 40,
    EM_X86_64 = 62,
    EM_AARCH64 = 183
};

enum class PHType : uint32_t {
    PT_NULL    = 0,
    PT_LOAD    = 1,
    PT_DYNAMIC = 2,
    PT_INTERP  = 3,
    PT_NOTE    = 4,
    PT_SHLIB   = 5,
    PT_PHDR    = 6,
    PT_TLS     = 7
};

enum class PHFlags : uint32_t {
    PF_X = 1,
    PF_W = 2,
    PF_R = 4
};

enum class SHType : uint32_t {
    SHT_NULL     = 0,
    SHT_PROGBITS = 1,
    SHT_SYMTAB   = 2,
    SHT_STRTAB   = 3,
    SHT_RELA     = 4,
    SHT_HASH     = 5,
    SHT_DYNAMIC  = 6,
    SHT_NOTE     = 7,
    SHT_NOBITS   = 8,
    SHT_REL      = 9,
    SHT_DYNSYM   = 11
};

enum class DynTag : uint64_t {
    DT_NULL       = 0,
    DT_NEEDED     = 1,
    DT_PLTRELSZ   = 2,
    DT_PLTGOT     = 3,
    DT_HASH       = 4,
    DT_STRTAB     = 5,
    DT_SYMTAB     = 6,
    DT_RELA       = 7,
    DT_RELASZ     = 8,
    DT_RELAENT    = 9,
    DT_STRSZ      = 10,
    DT_SYMENT     = 11,
    DT_INIT       = 12,
    DT_FINI       = 13,
    DT_SONAME     = 14,
    DT_RPATH      = 15,
    DT_SYMBOLIC   = 16,
    DT_REL        = 17,
    DT_RELSZ      = 18,
    DT_RELENT     = 19,
    DT_PLTREL     = 20,
    DT_DEBUG      = 21,
    DT_TEXTREL    = 22,
    DT_JMPREL     = 23,
    DT_BIND_NOW   = 24,
    DT_INIT_ARRAY = 25,
    DT_FINI_ARRAY = 26,
    DT_RUNPATH    = 29,
    DT_FLAGS      = 30
};

struct ELFHeader64 {
    uint8_t     e_ident[16];
    uint16_t    e_type;
    uint16_t    e_machine;
    uint32_t    e_version;
    uint64_t    e_entry;
    uint64_t    e_phoff;
    uint64_t    e_shoff;
    uint32_t    e_flags;
    uint16_t    e_ehsize;
    uint16_t    e_phentsize;
    uint16_t    e_phnum;
    uint16_t    e_shentsize;
    uint16_t    e_shnum;
    uint16_t    e_shstrndx;
};

struct ELFHeader32 {
    uint8_t     e_ident[16];
    uint16_t    e_type;
    uint16_t    e_machine;
    uint32_t    e_version;
    uint32_t    e_entry;
    uint32_t    e_phoff;
    uint32_t    e_shoff;
    uint32_t    e_flags;
    uint16_t    e_ehsize;
    uint16_t    e_phentsize;
    uint16_t    e_phnum;
    uint16_t    e_shentsize;
    uint16_t    e_shnum;
    uint16_t    e_shstrndx;
};

struct ProgramHeader64 {
    uint32_t    p_type;
    uint32_t    p_flags;
    uint64_t    p_offset;
    uint64_t    p_vaddr;
    uint64_t    p_paddr;
    uint64_t    p_filesz;
    uint64_t    p_memsz;
    uint64_t    p_align;
};

struct ProgramHeader32 {
    uint32_t    p_type;
    uint32_t    p_offset;
    uint32_t    p_vaddr;
    uint32_t    p_paddr;
    uint32_t    p_filesz;
    uint32_t    p_memsz;
    uint32_t    p_flags;
    uint32_t    p_align;
};

struct SectionHeader64 {
    uint32_t    sh_name;
    uint32_t    sh_type;
    uint64_t    sh_flags;
    uint64_t    sh_addr;
    uint64_t    sh_offset;
    uint64_t    sh_size;
    uint32_t    sh_link;
    uint32_t    sh_info;
    uint64_t    sh_addralign;
    uint64_t    sh_entsize;
};

struct SectionHeader32 {
    uint32_t    sh_name;
    uint32_t    sh_type;
    uint32_t    sh_flags;
    uint32_t    sh_addr;
    uint32_t    sh_offset;
    uint32_t    sh_size;
    uint32_t    sh_link;
    uint32_t    sh_info;
    uint32_t    sh_addralign;
    uint32_t    sh_entsize;
};

struct DynamicEntry64 {
    uint64_t    d_tag;
    uint64_t    d_un;
};

struct DynamicEntry32 {
    uint32_t    d_tag;
    uint32_t    d_un;
};

class ELFParser {
public:
    enum class Architecture {
        ARCH_X86,
        ARCH_X64,
        ARCH_ARM,
        ARCH_ARM64
    };

    ELFParser();
    ~ELFParser();

    bool load(const std::string& filename);

    bool is64Bit() const { return m_is64Bit; }
    bool isPIE() const { return m_isPIE; }
    bool isDynamic() const { return m_isDynamic; }
    uint64_t getEntryPoint() const { return m_entryPoint; }
    Architecture getArchitecture() const { return m_arch; }
    const char* getArchitectureName() const;
    const std::vector<uint8_t>& getFileData() const { return m_fileData; }

    const ELFHeader64* getHeader64() const { return m_header64.get(); }
    const ELFHeader32* getHeader32() const { return m_header32.get(); }

    const std::vector<ProgramHeader64>& getProgramHeaders64() const { return m_progHeaders64; }
    const std::vector<ProgramHeader32>& getProgramHeaders32() const { return m_progHeaders32; }

    const std::vector<SectionHeader64>& getSectionHeaders64() const { return m_sectionHeaders64; }
    const std::vector<SectionHeader32>& getSectionHeaders32() const { return m_sectionHeaders32; }

private:
    bool parseHeader();
    bool parseProgramHeaders();
    bool parseSectionHeaders();
    bool detectPIE();
    bool detectArchitecture();

    std::vector<uint8_t> m_fileData;
    std::unique_ptr<ELFHeader64> m_header64;
    std::unique_ptr<ELFHeader32> m_header32;

    std::vector<ProgramHeader64> m_progHeaders64;
    std::vector<ProgramHeader32> m_progHeaders32;

    std::vector<SectionHeader64> m_sectionHeaders64;
    std::vector<SectionHeader32> m_sectionHeaders32;

    bool m_is64Bit;
    bool m_isPIE;
    bool m_isDynamic;
    uint64_t m_entryPoint;
    Architecture m_arch;
};

#endif // ELF_HPP
