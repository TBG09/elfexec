#include "elf/elf.hpp"
#include "emu/emulator.hpp"
#include "emu/opcodes.hpp"
#include "logging.hpp"
#include <iostream>
#include <string>
#include <vector>

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options] <command> <elf_file> [args...]\n\n"
              << "Options:\n"
              << "  -d, --debug          Enable debug logging\n"
              << "  -l, --log              Enable logging\n\n"
              << "Commands:\n"
              << "  info                 Display ELF information\n"
              << "  run                  Execute the ELF binary\n\n"
              << "Examples:\n"
              << "  " << programName << " info /bin/echo\n"
              << "  " << programName << " -d -l run /bin/echo hello world\n"
              << std::endl;
}

bool parseArgs(int argc, char* argv[], bool& debugEnabled, bool& logEnabled, std::string& command,
               std::string& elfFile, std::vector<std::string>& binArgs) {
    if (argc < 3) {
        return false;
    }

    int argIdx = 1;

    while (argIdx < argc && argv[argIdx][0] == '-') {
        std::string opt = argv[argIdx];
        if (opt == "-d" || opt == "--debug") {
            debugEnabled = true;
            argIdx++;
        } else if (opt == "-l" || opt == "--log") {
            logEnabled = true;
            argIdx++;
        } else {
            return false;
        }
    }

    if (argIdx >= argc) {
        return false;
    }
    command = argv[argIdx++];

    if (argIdx >= argc) {
        return false;
    }
    elfFile = argv[argIdx++];

    while (argIdx < argc) {
        binArgs.push_back(argv[argIdx++]);
    }

    return true;
}

void printELFInfo(const ELFParser& parser) {
    std::cout << "=== ELF File Information ===\n";
    std::cout << "Bitness: " << (parser.is64Bit() ? "64-bit" : "32-bit") << "\n";
    std::cout << "PIE: " << (parser.isPIE() ? "Yes" : "No") << "\n";
    std::cout << "Dynamic: " << (parser.isDynamic() ? "Yes" : "No") << "\n";
    std::cout << "Entry Point: 0x" << std::hex << parser.getEntryPoint() << std::dec << "\n";

    std::cout << "Architecture: ";
    switch (parser.getArchitecture()) {
        case ELFParser::Architecture::ARCH_X86:
            std::cout << "x86 (32-bit)\n";
            break;
        case ELFParser::Architecture::ARCH_X64:
            std::cout << "x86-64 (64-bit)\n";
            break;
        case ELFParser::Architecture::ARCH_ARM:
            std::cout << "ARM (32-bit)\n";
            break;
        case ELFParser::Architecture::ARCH_ARM64:
            std::cout << "ARM64 (AArch64)\n";
            break;
    }

    std::cout << "\n=== Program Headers ===\n";
    if (parser.is64Bit()) {
        const auto& headers = parser.getProgramHeaders64();
        std::cout << "Count: " << headers.size() << "\n";
        for (size_t i = 0; i < headers.size(); ++i) {
            const auto& ph = headers[i];
            std::cout << "  [" << i << "] Type: 0x" << std::hex << ph.p_type << std::dec
                      << " VAddr: 0x" << std::hex << ph.p_vaddr << std::dec
                      << " FileSize: " << ph.p_filesz
                      << " MemSize: " << ph.p_memsz << "\n";
        }
    } else {
        const auto& headers = parser.getProgramHeaders32();
        std::cout << "Count: " << headers.size() << "\n";
        for (size_t i = 0; i < headers.size(); ++i) {
            const auto& ph = headers[i];
            std::cout << "  [" << i << "] Type: 0x" << std::hex << ph.p_type << std::dec
                      << " VAddr: 0x" << std::hex << ph.p_vaddr << std::dec
                      << " FileSize: " << ph.p_filesz
                      << " MemSize: " << ph.p_memsz << "\n";
        }
    }

    std::cout << "\n=== Section Headers ===\n";
    if (parser.is64Bit()) {
        const auto& headers = parser.getSectionHeaders64();
        std::cout << "Count: " << headers.size() << "\n";
    } else {
        const auto& headers = parser.getSectionHeaders32();
        std::cout << "Count: " << headers.size() << "\n";
    }

    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    bool debugEnabled = false;
    bool logEnabled = false;
    std::string command;
    std::string elfFile;
    std::vector<std::string> binArgs;

    if (!parseArgs(argc, argv, debugEnabled, logEnabled, command, elfFile, binArgs)) {
        printUsage(argv[0]);
        return 1;
    }

    if (logEnabled) {
        Logger::getInstance().setLogLevel(debugEnabled ? LogLevel::DEBUG : LogLevel::INFO);
    } else {
        Logger::getInstance().setLogLevel(LogLevel::NONE);
    }

    LOG_INFO("ELFExec starting");

    ELFParser parser;
    if (!parser.load(elfFile)) {
        LOG_ERROR("Failed to load ELF file: " + elfFile);
        return 1;
    }

    if (command == "info") {
        printELFInfo(parser);
        return 0;
    } else if (command == "run") {
        LOG_INFO("Starting emulation");

        Emulator emulator(parser);
        if (!emulator.initialize()) {
            LOG_ERROR("Failed to initialize emulator");
            return 1;
        }

        OpcodeHandler opcodeHandler(emulator);
        if (!opcodeHandler.initializeSyscalls(parser.getArchitecture())) {
            LOG_ERROR("Failed to initialize syscalls");
            return 1;
        }

        emulator.setOpcodeHandler(&opcodeHandler);

        if (!emulator.execute()) {
            LOG_ERROR("Emulation failed");
            return 1;
        }

        LOG_INFO("Execution completed with exit code: " + std::to_string(emulator.getExitCode()));
        return emulator.getExitCode();
    } else {
        LOG_ERROR("Unknown command: " + command);
        printUsage(argv[0]);
        return 1;
    }
}
