#include "emu/arch.hpp"
#include "emu/emulator.hpp"
#include "logging.hpp"
#include <unicorn/unicorn.h>
#include <iomanip>

int X64Handler::getUnicornArch() const {
    return UC_ARCH_X86;
}

int X64Handler::getUnicornMode() const {
    return UC_MODE_64;
}

bool X64Handler::initializeRegisters(Emulator& /*emulator*/) {
    LOG_DEBUG("Initializing x86-64 registers");
    return true;
}

void X64Handler::handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) {
    uint64_t syscall, arg1, arg2, arg3, arg4, arg5, arg6, result;
    uc_reg_read(uc, UC_X86_REG_RAX, &syscall);
    uc_reg_read(uc, UC_X86_REG_RDI, &arg1);
    uc_reg_read(uc, UC_X86_REG_RSI, &arg2);
    uc_reg_read(uc, UC_X86_REG_RDX, &arg3);
    uc_reg_read(uc, UC_X86_REG_R10, &arg4);
    uc_reg_read(uc, UC_X86_REG_R8, &arg5);
    uc_reg_read(uc, UC_X86_REG_R9, &arg6);

    result = opcodeHandler.handleSyscall(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
    uc_reg_write(uc, UC_X86_REG_RAX, &result);
}

void X64Handler::printCPUState(uc_engine* uc) {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8, r9, r10, r11, r12, r13, r14, r15, eflags;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_RBP, &rbp);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);

    LOG_FATAL("  RAX: 0x" << std::hex << rax << " RBX: 0x" << rbx << " RCX: 0x" << rcx);
    LOG_FATAL("  RDX: 0x" << rdx << " RSI: 0x" << rsi << " RDI: 0x" << rdi);
    LOG_FATAL("  RBP: 0x" << rbp << " RSP: 0x" << rsp << " RIP: 0x" << rip);
    LOG_FATAL("  R8:  0x" << r8  << " R9:  0x" << r9  << " R10: 0x" << r10);
    LOG_FATAL("  R11: 0x" << r11 << " R12: 0x" << r12 << " R13: 0x" << r13);
    LOG_FATAL("  R14: 0x" << r14 << " R15: 0x" << r15 << " EFLAGS: 0x" << eflags);
}

bool X64Handler::setPC(uc_engine* uc, uint64_t address) {
    uc_err err = uc_reg_write(uc, UC_X86_REG_RIP, &address);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to set RIP: ") + uc_strerror(err));
        return false;
    }
    return true;
}

uint64_t X64Handler::getPC(uc_engine* uc) {
    uint64_t rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    return rip;
}

bool X64Handler::setSP(uc_engine* uc, uint64_t address) {
    uc_err err = uc_reg_write(uc, UC_X86_REG_RSP, &address);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to set RSP: ") + uc_strerror(err));
        return false;
    }
    return true;
}

uint64_t X64Handler::getSP(uc_engine* uc) {
    uint64_t rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    return rsp;
}

const char* X64Handler::getName() const {
    return "x86-64";
}

int X86Handler::getUnicornArch() const {
    return UC_ARCH_X86;
}

int X86Handler::getUnicornMode() const {
    return UC_MODE_32;
}

bool X86Handler::initializeRegisters(Emulator& /*emulator*/) {
    LOG_DEBUG("Initializing x86 registers");
    return true;
}

void X86Handler::handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) {
    uint32_t syscall, arg1, arg2, arg3, arg4, arg5, arg6, result;
    uc_reg_read(uc, UC_X86_REG_EAX, &syscall);
    uc_reg_read(uc, UC_X86_REG_EBX, &arg1);
    uc_reg_read(uc, UC_X86_REG_ECX, &arg2);
    uc_reg_read(uc, UC_X86_REG_EDX, &arg3);
    uc_reg_read(uc, UC_X86_REG_ESI, &arg4);
    uc_reg_read(uc, UC_X86_REG_EDI, &arg5);
    uc_reg_read(uc, UC_X86_REG_EBP, &arg6);

    result = opcodeHandler.handleSyscall(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
    uc_reg_write(uc, UC_X86_REG_EAX, &result);
}

void X86Handler::printCPUState(uc_engine* uc) {
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, eip, eflags;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(uc, UC_X86_REG_ESI, &esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &edi);
    uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_EIP, &eip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);

    LOG_FATAL("  EAX: 0x" << std::hex << eax << " EBX: 0x" << ebx << " ECX: 0x" << ecx);
    LOG_FATAL("  EDX: 0x" << edx << " ESI: 0x" << esi << " EDI: 0x" << edi);
    LOG_FATAL("  EBP: 0x" << ebp << " ESP: 0x" << esp << " EIP: 0x" << eip);
    LOG_FATAL("  EFLAGS: 0x" << eflags);
}

bool X86Handler::setPC(uc_engine* uc, uint64_t address) {
    uint32_t eip = static_cast<uint32_t>(address);
    uc_err err = uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to set EIP: ") + uc_strerror(err));
        return false;
    }
    return true;
}

uint64_t X86Handler::getPC(uc_engine* uc) {
    uint32_t eip = 0;
    uc_reg_read(uc, UC_X86_REG_EIP, &eip);
    return static_cast<uint64_t>(eip);
}

bool X86Handler::setSP(uc_engine* uc, uint64_t address) {
    uint32_t esp = static_cast<uint32_t>(address);
    uc_err err = uc_reg_write(uc, UC_X86_REG_ESP, &esp);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to set ESP: ") + uc_strerror(err));
        return false;
    }
    return true;
}

uint64_t X86Handler::getSP(uc_engine* uc) {
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    return static_cast<uint64_t>(esp);
}

const char* X86Handler::getName() const {
    return "x86";
}

int ARMHandler::getUnicornArch() const {
    return UC_ARCH_ARM;
}

int ARMHandler::getUnicornMode() const {
    return UC_MODE_ARM;
}

bool ARMHandler::initializeRegisters(Emulator& /*emulator*/) {
    LOG_DEBUG("Initializing ARM registers");
    return true;
}

void ARMHandler::handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) {
    uint32_t syscall, arg1, arg2, arg3, arg4, arg5, arg6, result;
    uc_reg_read(uc, UC_ARM_REG_R7, &syscall);
    uc_reg_read(uc, UC_ARM_REG_R0, &arg1);
    uc_reg_read(uc, UC_ARM_REG_R1, &arg2);
    uc_reg_read(uc, UC_ARM_REG_R2, &arg3);
    uc_reg_read(uc, UC_ARM_REG_R3, &arg4);
    uc_reg_read(uc, UC_ARM_REG_R4, &arg5);
    uc_reg_read(uc, UC_ARM_REG_R5, &arg6);

    result = opcodeHandler.handleSyscall(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
    uc_reg_write(uc, UC_ARM_REG_R0, &result);
}

void ARMHandler::printCPUState(uc_engine* uc) {
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc, cpsr;
    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    uc_reg_read(uc, UC_ARM_REG_R1, &r1);
    uc_reg_read(uc, UC_ARM_REG_R2, &r2);
    uc_reg_read(uc, UC_ARM_REG_R3, &r3);
    uc_reg_read(uc, UC_ARM_REG_R4, &r4);
    uc_reg_read(uc, UC_ARM_REG_R5, &r5);
    uc_reg_read(uc, UC_ARM_REG_R6, &r6);
    uc_reg_read(uc, UC_ARM_REG_R7, &r7);
    uc_reg_read(uc, UC_ARM_REG_R8, &r8);
    uc_reg_read(uc, UC_ARM_REG_R9, &r9);
    uc_reg_read(uc, UC_ARM_REG_R10, &r10);
    uc_reg_read(uc, UC_ARM_REG_R11, &r11);
    uc_reg_read(uc, UC_ARM_REG_R12, &r12);
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);

    LOG_FATAL("  R0:  0x" << std::hex << r0 << " R1:  0x" << r1 << " R2:  0x" << r2);
    LOG_FATAL("  R3:  0x" << r3 << " R4:  0x" << r4 << " R5:  0x" << r5);
    LOG_FATAL("  R6:  0x" << r6 << " R7:  0x" << r7 << " R8:  0x" << r8);
    LOG_FATAL("  R9:  0x" << r9 << " R10: 0x" << r10 << " R11: 0x" << r11);
    LOG_FATAL("  R12: 0x" << r12 << " SP:  0x" << sp << " LR:  0x" << lr);
    LOG_FATAL("  PC:  0x" << pc << " CPSR: 0x" << cpsr);
}

bool ARMHandler::setPC(uc_engine* uc, uint64_t address) {
    uint32_t pc = static_cast<uint32_t>(address);
    uc_err err = uc_reg_write(uc, UC_ARM_REG_PC, &pc);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to set ARM PC: ") + uc_strerror(err));
        return false;
    }
    return true;
}

uint64_t ARMHandler::getPC(uc_engine* uc) {
    uint32_t pc = 0;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    return static_cast<uint64_t>(pc);
}

bool ARMHandler::setSP(uc_engine* uc, uint64_t address) {
    uint32_t sp = static_cast<uint32_t>(address);
    uc_err err = uc_reg_write(uc, UC_ARM_REG_SP, &sp);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to set ARM SP: ") + uc_strerror(err));
        return false;
    }
    return true;
}

uint64_t ARMHandler::getSP(uc_engine* uc) {
    uint32_t sp = 0;
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    return static_cast<uint64_t>(sp);
}

const char* ARMHandler::getName() const {
    return "ARM";
}

int ARM64Handler::getUnicornArch() const {
    return UC_ARCH_ARM64;
}

int ARM64Handler::getUnicornMode() const {
    return UC_MODE_ARM;
}

bool ARM64Handler::initializeRegisters(Emulator& /*emulator*/) {
    LOG_DEBUG("Initializing ARM64 registers");
    return true;
}

void ARM64Handler::handleSyscall(uc_engine* uc, OpcodeHandler& opcodeHandler) {
    uint64_t syscall, arg1, arg2, arg3, arg4, arg5, arg6, result;
    uc_reg_read(uc, UC_ARM64_REG_X8, &syscall);
    uc_reg_read(uc, UC_ARM64_REG_X0, &arg1);
    uc_reg_read(uc, UC_ARM64_REG_X1, &arg2);
    uc_reg_read(uc, UC_ARM64_REG_X2, &arg3);
    uc_reg_read(uc, UC_ARM64_REG_X3, &arg4);
    uc_reg_read(uc, UC_ARM64_REG_X4, &arg5);
    uc_reg_read(uc, UC_ARM64_REG_X5, &arg6);

    result = opcodeHandler.handleSyscall(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
    uc_reg_write(uc, UC_ARM64_REG_X0, &result);
}

void ARM64Handler::printCPUState(uc_engine* uc) {
    uint64_t x[31], sp, pc, pstate;
    for (int i = 0; i < 31; ++i) {
        uc_reg_read(uc, UC_ARM64_REG_X0 + i, &x[i]);
    }
    uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    uc_reg_read(uc, UC_ARM64_REG_PSTATE, &pstate);

    for (int i = 0; i < 31; i += 2) {
        LOG_FATAL("  X" << std::setw(2) << i << ": 0x" << std::hex << x[i] << " X" << std::setw(2) << (i+1) << ": 0x" << x[i+1]);
    }
    LOG_FATAL("  SP: 0x" << std::hex << sp << " PC: 0x" << pc << " PSTATE: 0x" << pstate);
}

bool ARM64Handler::setPC(uc_engine* uc, uint64_t address) {
    uc_err err = uc_reg_write(uc, UC_ARM64_REG_PC, &address);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to set ARM64 PC: ") + uc_strerror(err));
        return false;
    }
    return true;
}

uint64_t ARM64Handler::getPC(uc_engine* uc) {
    uint64_t pc = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    return pc;
}

bool ARM64Handler::setSP(uc_engine* uc, uint64_t address) {
    uc_err err = uc_reg_write(uc, UC_ARM64_REG_SP, &address);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to set ARM64 SP: ") + uc_strerror(err));
        return false;
    }
    return true;
}

uint64_t ARM64Handler::getSP(uc_engine* uc) {
    uint64_t sp = 0;
    uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
    return sp;
}

const char* ARM64Handler::getName() const {
    return "ARM64";
}

ArchHandler* createArchHandler(ELFParser::Architecture arch) {
    switch (arch) {
        case ELFParser::Architecture::ARCH_X64:
            return new X64Handler();
        case ELFParser::Architecture::ARCH_X86:
            return new X86Handler();
        case ELFParser::Architecture::ARCH_ARM:
            return new ARMHandler();
        case ELFParser::Architecture::ARCH_ARM64:
            return new ARM64Handler();
        default:
            LOG_ERROR("Unknown architecture");
            return nullptr;
    }
}
