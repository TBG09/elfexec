#include "emu/opcodes.hpp"
#include "emu/emulator.hpp"
#include "emu/arch.hpp"
#include "emu/opcodes/io.hpp"
#include "emu/opcodes/process.hpp"
#include "emu/opcodes/memory.hpp"
#include "emu/opcodes/fs.hpp"
#include "logging.hpp"
#include <functional>

using namespace std::placeholders;

OpcodeHandler::OpcodeHandler(Emulator& emulator)
    : m_emulator(emulator) {}

OpcodeHandler::~OpcodeHandler() = default;

void OpcodeHandler::registerSyscall(uint64_t number, SyscallHandler handler) {
    m_syscallHandlers[number] = handler;
    LOG_DEBUG("Registered syscall " + std::to_string(number));
}

uint64_t OpcodeHandler::handleSyscall(uint64_t number, uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    auto it = m_syscallHandlers.find(number);
    if (it == m_syscallHandlers.end()) {
        LOG_WARN("Unhandled syscall: " + std::to_string(number));
        return -1;
    }

    LOG_DEBUG("Handling syscall " + std::to_string(number));
    return it->second(m_emulator, arg1, arg2, arg3, arg4, arg5, arg6);
}

bool OpcodeHandler::initializeSyscalls(ELFParser::Architecture arch) {
    LOG_INFO("Initializing syscalls for architecture");

    switch (arch) {
        case ELFParser::Architecture::ARCH_X64:
            m_archName = "x86-64";
            return initX64Syscalls();
        case ELFParser::Architecture::ARCH_X86:
            m_archName = "x86";
            return initX86Syscalls();
        case ELFParser::Architecture::ARCH_ARM:
            m_archName = "ARM";
            return initARMSyscalls();
        case ELFParser::Architecture::ARCH_ARM64:
            m_archName = "ARM64";
            return initARM64Syscalls();
        default:
            LOG_ERROR("Unknown architecture for syscall initialization");
            return false;
    }
}

bool OpcodeHandler::initX64Syscalls() {
    LOG_DEBUG("Initializing x86-64 syscalls");
    
    registerSyscall(0, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleRead(emulator, arg1, arg2, arg3);
    });
    registerSyscall(1, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleWrite(emulator, arg1, arg2, arg3);
    });
    registerSyscall(2, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleOpen(emulator, arg1, arg2, arg3);
    });
    registerSyscall(3, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return fs::handleClose(emulator, arg1);
    });
    registerSyscall(8, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleLseek(emulator, arg1, arg2, arg3);
    });
    registerSyscall(60, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return process::handleExit(emulator, arg1);
    });
    registerSyscall(39, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetpid(); });
    registerSyscall(102, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetuid(); });
    registerSyscall(107, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGeteuid(); });
    registerSyscall(104, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetgid(); });
    registerSyscall(108, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetegid(); });
    registerSyscall(9, memory::handleMmap);
    registerSyscall(11, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, auto, auto, auto, auto) {
        return memory::handleMunmap(emulator, arg1, arg2);
    });
    registerSyscall(12, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return memory::handleBrk(emulator, arg1);
    });

    return true;
}

bool OpcodeHandler::initX86Syscalls() {
    LOG_DEBUG("Initializing x86 syscalls");
    
    registerSyscall(3, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleRead(emulator, arg1, arg2, arg3);
    });
    registerSyscall(4, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleWrite(emulator, arg1, arg2, arg3);
    });
    registerSyscall(5, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleOpen(emulator, arg1, arg2, arg3);
    });
    registerSyscall(6, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return fs::handleClose(emulator, arg1);
    });
    registerSyscall(19, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleLseek(emulator, arg1, arg2, arg3);
    });
    registerSyscall(1, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return process::handleExit(emulator, arg1);
    });
    registerSyscall(20, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetpid(); });
    registerSyscall(24, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetuid(); });
    registerSyscall(49, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGeteuid(); });
    registerSyscall(47, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetgid(); });
    registerSyscall(50, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetegid(); });
    registerSyscall(192, memory::handleMmap);
    registerSyscall(91, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, auto, auto, auto, auto) {
        return memory::handleMunmap(emulator, arg1, arg2);
    });
    registerSyscall(45, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return memory::handleBrk(emulator, arg1);
    });

    return true;
}

bool OpcodeHandler::initARMSyscalls() {
    LOG_DEBUG("Initializing ARM syscalls");
    
    registerSyscall(3, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleRead(emulator, arg1, arg2, arg3);
    });
    registerSyscall(4, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleWrite(emulator, arg1, arg2, arg3);
    });
    registerSyscall(5, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleOpen(emulator, arg1, arg2, arg3);
    });
    registerSyscall(6, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return fs::handleClose(emulator, arg1);
    });
    registerSyscall(19, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleLseek(emulator, arg1, arg2, arg3);
    });
    registerSyscall(1, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return process::handleExit(emulator, arg1);
    });
    registerSyscall(20, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetpid(); });
    registerSyscall(24, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetuid(); });
    registerSyscall(49, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGeteuid(); });
    registerSyscall(47, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetgid(); });
    registerSyscall(50, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetegid(); });
    registerSyscall(192, memory::handleMmap);
    registerSyscall(91, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, auto, auto, auto, auto) {
        return memory::handleMunmap(emulator, arg1, arg2);
    });
    registerSyscall(45, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return memory::handleBrk(emulator, arg1);
    });

    return true;
}

bool OpcodeHandler::initARM64Syscalls() {
    LOG_DEBUG("Initializing ARM64 syscalls");
    
    registerSyscall(63, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleRead(emulator, arg1, arg2, arg3);
    });
    registerSyscall(64, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleWrite(emulator, arg1, arg2, arg3);
    });
    registerSyscall(56, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleOpen(emulator, arg1, arg2, arg3);
    });
    registerSyscall(57, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return fs::handleClose(emulator, arg1);
    });
    registerSyscall(62, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, uint64_t arg3, auto, auto, auto) {
        return fs::handleLseek(emulator, arg1, arg2, arg3);
    });
    registerSyscall(93, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return process::handleExit(emulator, arg1);
    });
    registerSyscall(172, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetpid(); });
    registerSyscall(174, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetuid(); });
    registerSyscall(175, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGeteuid(); });
    registerSyscall(176, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetgid(); });
    registerSyscall(177, [](auto&, auto, auto, auto, auto, auto, auto) { return process::handleGetegid(); });
    registerSyscall(222, memory::handleMmap);
    registerSyscall(215, [](Emulator& emulator, uint64_t arg1, uint64_t arg2, auto, auto, auto, auto) {
        return memory::handleMunmap(emulator, arg1, arg2);
    });
    registerSyscall(214, [](Emulator& emulator, uint64_t arg1, auto, auto, auto, auto, auto) {
        return memory::handleBrk(emulator, arg1);
    });

    return true;
}

uint64_t OpcodeHandler::handleOpen(uint64_t, uint64_t, uint64_t) {
    LOG_DEBUG("Open syscall");
    return -1;
}

uint64_t OpcodeHandler::handleClose(uint64_t fd) {
    LOG_DEBUG("Close syscall: fd=" + std::to_string(fd));
    return 0;
}
