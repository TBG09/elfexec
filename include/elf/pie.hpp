#ifndef PIE_HPP
#define PIE_HPP

#include "elf.hpp"
#include <vector>
#include <string>

class Emulator;

struct Relocation64 {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

struct Relocation32 {
    uint32_t r_offset;
    uint32_t r_info;
    int32_t  r_addend;
};

struct Symbol64 {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Symbol32 {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
};

#define ELF64_R_TYPE(i) ((i) & 0xffffffff)
#define R_X86_64_RELATIVE 8
#define R_AARCH64_RELATIVE 1027

#define ELF32_R_TYPE(i) ((unsigned char)(i))
#define R_386_RELATIVE 8
#define R_ARM_RELATIVE 23

class PIEHandler {
public:
    PIEHandler(const ELFParser& parser);
    ~PIEHandler();

    bool loadRelocations();
    bool applyRelocations(Emulator& emulator, uint64_t baseAddress);

    size_t getRelocationCount() const { return m_relocations64.size() + m_relocations32.size(); }

private:
    bool loadRelocations64();
    bool loadRelocations32();
    bool loadSymbols64();
    bool loadSymbols32();
    bool loadStringTable();

    const ELFParser& m_parser;
    uint64_t m_baseAddress;

    std::vector<Relocation64> m_relocations64;
    std::vector<Relocation32> m_relocations32;
    std::vector<Symbol64> m_symbols64;
    std::vector<Symbol32> m_symbols32;
    std::vector<char> m_stringTable;
};

#endif // PIE_HPP