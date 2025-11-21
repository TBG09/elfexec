#ifndef OPCODES_HPP
#define OPCODES_HPP

#include "elf/elf.hpp"
#include <cstdint>
#include <string>
#include <map>
#include <functional>
#include <unicorn/unicorn.h>

class Emulator;

using SyscallHandler = std::function<uint64_t(Emulator&, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)>;

class OpcodeHandler {
public:
    OpcodeHandler(Emulator& emulator);
    ~OpcodeHandler();

    void registerSyscall(uint64_t number, SyscallHandler handler);

    uint64_t handleSyscall(uint64_t number, uint64_t arg1, uint64_t arg2,
                          uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);

    const std::string& getArchName() const { return m_archName; }

    bool initializeSyscalls(ELFParser::Architecture arch);

private:
    Emulator& m_emulator;
    std::string m_archName;

    std::map<uint64_t, SyscallHandler> m_syscallHandlers;

    bool initX64Syscalls();
    bool initX86Syscalls();
    bool initARMSyscalls();
    bool initARM64Syscalls();

    uint64_t handleExit(uint64_t code);
    uint64_t handleWrite(uint64_t fd, uint64_t buf, uint64_t count);
    uint64_t handleRead(uint64_t fd, uint64_t buf, uint64_t count);
    uint64_t handleOpen(uint64_t filename, uint64_t flags, uint64_t mode);
    uint64_t handleClose(uint64_t fd);
    uint64_t handleMmap(uint64_t addr, uint64_t length, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset);
    uint64_t handleMunmap(uint64_t addr, uint64_t length);
    uint64_t handleBrk(uint64_t addr);
};

#endif // OPCODES_HPP
