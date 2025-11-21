#ifndef ARCH_HPP
#define ARCH_HPP

#include "elf/elf.hpp"
#include "emu/opcodes.hpp"
#include <cstdint>
#include <unicorn/unicorn.h>

class Emulator;

class ArchHandler {
public:
    virtual ~ArchHandler() = default;

    virtual int getUnicornArch() const = 0;

    virtual int getUnicornMode() const = 0;

    virtual bool initializeRegisters(Emulator& emulator) = 0;

    virtual void handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) = 0;

    virtual void printCPUState(uc_engine* uc) = 0;

    virtual bool setPC(uc_engine* uc, uint64_t address) = 0;

    virtual uint64_t getPC(uc_engine* uc) = 0;

    virtual bool setSP(uc_engine* uc, uint64_t address) = 0;

    virtual uint64_t getSP(uc_engine* uc) = 0;

    virtual const char* getName() const = 0;
};

class X64Handler : public ArchHandler {
public:
    int getUnicornArch() const override;
    int getUnicornMode() const override;
    bool initializeRegisters(Emulator& emulator) override;
    void handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) override;
    void printCPUState(uc_engine* uc) override;
    bool setPC(uc_engine* uc, uint64_t address) override;
    uint64_t getPC(uc_engine* uc) override;
    bool setSP(uc_engine* uc, uint64_t address) override;
    uint64_t getSP(uc_engine* uc) override;
    const char* getName() const override;
};

class X86Handler : public ArchHandler {
public:
    int getUnicornArch() const override;
    int getUnicornMode() const override;
    bool initializeRegisters(Emulator& emulator) override;
    void handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) override;
    void printCPUState(uc_engine* uc) override;
    bool setPC(uc_engine* uc, uint64_t address) override;
    uint64_t getPC(uc_engine* uc) override;
    bool setSP(uc_engine* uc, uint64_t address) override;
    uint64_t getSP(uc_engine* uc) override;
    const char* getName() const override;
};

class ARMHandler : public ArchHandler {
public:
    int getUnicornArch() const override;
    int getUnicornMode() const override;
    bool initializeRegisters(Emulator& emulator) override;
    void handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) override;
    void printCPUState(uc_engine* uc) override;
    bool setPC(uc_engine* uc, uint64_t address) override;
    uint64_t getPC(uc_engine* uc) override;
    bool setSP(uc_engine* uc, uint64_t address) override;
    uint64_t getSP(uc_engine* uc) override;
    const char* getName() const override;
};

class ARM64Handler : public ArchHandler {
public:
    int getUnicornArch() const override;
    int getUnicornMode() const override;
    bool initializeRegisters(Emulator& emulator) override;
    void handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) override;
    void printCPUState(uc_engine* uc) override;
    bool setPC(uc_engine* uc, uint64_t address) override;
    uint64_t getPC(uc_engine* uc) override;
    bool setSP(uc_engine* uc, uint64_t address) override;
    uint64_t getSP(uc_engine* uc) override;
    const char* getName() const override;
};

ArchHandler* createArchHandler(ELFParser::Architecture arch);

#endif // ARCH_HPP
