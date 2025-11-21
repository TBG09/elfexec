#include "emu/crash_reporter.hpp"
#include "logging.hpp"
#include <iomanip>

CrashReporter::CrashReporter(Emulator& emulator, uc_err error)
    : m_emulator(emulator), m_error(error) {}

void CrashReporter::generateReport() {
    LOG_FATAL("====== CRASH REPORT ======");
    printCrashReason();
    printCPUState();
    printMemoryDump();
    printELFInfo();
    LOG_FATAL("==========================");
}

void CrashReporter::printCrashReason() {
    LOG_FATAL("Reason: " + std::string(uc_strerror(m_error)));
}

void CrashReporter::printCPUState() {
    LOG_FATAL("--- CPU State ---");
    m_emulator.getArchHandler()->printCPUState(m_emulator.getUnicornEngine());
}

void CrashReporter::printMemoryDump() {
    LOG_FATAL("--- Memory Dump ---");
    uint64_t pc = m_emulator.getArchHandler()->getPC(m_emulator.getUnicornEngine());
    uint64_t start_addr = pc - 32;
    uint64_t end_addr = pc + 32;

    LOG_FATAL("Dumping memory from 0x" << std::hex << start_addr << " to 0x" << end_addr);

    std::vector<uint8_t> mem(end_addr - start_addr);
    if (uc_mem_read(m_emulator.getUnicornEngine(), start_addr, mem.data(), mem.size()) == UC_ERR_OK) {
        std::stringstream ss;
        for (size_t i = 0; i < mem.size(); ++i) {
            if (i % 16 == 0) {
                ss << "\n0x" << std::hex << std::setw(16) << std::setfill('0') << start_addr + i << ": ";
            }
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)mem[i] << " ";
        }
        LOG_FATAL(ss.str());
    } else {
        LOG_FATAL("Failed to read memory for dump.");
    }
}

void CrashReporter::printELFInfo() {
    LOG_FATAL("--- ELF Info ---");
    const auto& parser = m_emulator.getELFParser();
    LOG_FATAL("  Bitness: " << (parser.is64Bit() ? "64-bit" : "32-bit"));
    LOG_FATAL("  PIE: " << (parser.isPIE() ? "Yes" : "No"));
    LOG_FATAL("  Dynamic: " << (parser.isDynamic() ? "Yes" : "No"));
    LOG_FATAL("  Entry Point: 0x" << std::hex << parser.getEntryPoint());
    LOG_FATAL("  Architecture: " << parser.getArchitectureName());
}
