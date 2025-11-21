#ifndef EMULATOR_HPP
#define EMULATOR_HPP

#include "elf/elf.hpp"
#include "elf/pie.hpp"
#include "emu/arch.hpp"
#include <cstdint>
#include <memory>
#include <map>
#include <vector>
#include <unicorn/unicorn.h>

class OpcodeHandler;

struct MemoryRegion {
    uint64_t baseAddress;
    size_t size;
    uint32_t permissions;
    std::string name;
};

struct CPUContext {
    uint64_t registers[32];

    uint64_t pc;

    uint64_t sp;

    uint64_t flags;
};

struct SyscallInfo {
    uint64_t number;
    uint64_t args[6];
    uint64_t result;
};

class Emulator {
public:
    Emulator(const ELFParser& elfParser);
    ~Emulator();

    bool initialize();

    bool loadBinary();

    bool setupMemory();

    bool execute();

    bool executeInstructions(uint64_t count);

    bool step();

    void stop(int exitCode);

    void setOpcodeHandler(OpcodeHandler* handler);

    bool mapMemoryRegion(uint64_t address, size_t size, uint32_t perms, const std::string& name);
    bool unmapMemoryRegion(uint64_t address, size_t size);
    uint64_t handleBrk(uint64_t addr);
    uint64_t findAvailableMemoryRegion(size_t size);

    int addFileDescriptor(int fd);
    int getFileDescriptor(int fd);
    void removeFileDescriptor(int fd);

    const CPUContext& getCPUContext() const { return m_cpuContext; }

    const SyscallInfo& getLastSyscall() const { return m_lastSyscall; }

    const std::map<uint64_t, MemoryRegion>& getMemoryRegions() const { return m_memoryRegions; }

    int getExitCode() const { return m_exitCode; }

    bool isRunning() const { return m_isRunning; }

    uc_engine* getUnicornEngine() { return m_uc; }

    ArchHandler* getArchHandler() { return m_archHandler.get(); }

    const ELFParser& getELFParser() const { return m_elfParser; }

private:
    const ELFParser& m_elfParser;
    std::unique_ptr<PIEHandler> m_pieHandler;
    OpcodeHandler* m_opcodeHandler;
    std::unique_ptr<ArchHandler> m_archHandler;

    uc_engine* m_uc;

    std::map<uint64_t, MemoryRegion> m_memoryRegions;
    uint64_t m_baseAddress;
    uint64_t m_programBreak;

    std::vector<int> m_fdTable;

    CPUContext m_cpuContext;
    SyscallInfo m_lastSyscall;

    bool m_isRunning;
    int m_exitCode;

    bool setupStack();
    bool setupHeap();
    bool initializeRegisters();
    bool setupUnicorn();
    bool loadProgramSegments();

    static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static void hook_intr(uc_engine* uc, uint32_t intno, void* user_data);
    static void hook_insn_syscall(uc_engine* uc, void* user_data);
};

#endif // EMULATOR_HPP
