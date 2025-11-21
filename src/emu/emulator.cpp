#include "emu/emulator.hpp"
#include "emu/opcodes.hpp"
#include "emu/crash_reporter.hpp"
#include "logging.hpp"
#include <cstring>
#include <algorithm>

Emulator::Emulator(const ELFParser& elfParser)
    : m_elfParser(elfParser), m_opcodeHandler(nullptr), m_archHandler(nullptr), m_uc(nullptr), m_baseAddress(0),
      m_programBreak(0), m_isRunning(false), m_exitCode(0) {
    std::memset(&m_cpuContext, 0, sizeof(m_cpuContext));
    std::memset(&m_lastSyscall, 0, sizeof(m_lastSyscall));

    m_fdTable.push_back(0);
    m_fdTable.push_back(1);
    m_fdTable.push_back(2);
}

Emulator::~Emulator() {
    if (m_uc) {
        uc_close(m_uc);
        LOG_DEBUG("Unicorn engine closed");
    }
}

bool Emulator::initialize() {
    LOG_INFO("Initializing emulator...");

    if (!setupUnicorn()) {
        LOG_ERROR("Failed to setup Unicorn engine");
        return false;
    }

    if (!setupMemory()) {
        LOG_ERROR("Failed to setup memory");
        return false;
    }

    if (!loadBinary()) {
        LOG_ERROR("Failed to load binary");
        return false;
    }

    if (!initializeRegisters()) {
        LOG_ERROR("Failed to initialize registers");
        return false;
    }

    LOG_INFO("Emulator initialized successfully");
    m_isRunning = true;
    return true;
}

bool Emulator::setupUnicorn() {
    LOG_DEBUG("Setting up Unicorn engine...");

    ELFParser::Architecture arch = m_elfParser.getArchitecture();
    m_archHandler = std::unique_ptr<ArchHandler>(createArchHandler(arch));
    
    if (!m_archHandler) {
        LOG_ERROR("Failed to create architecture handler");
        return false;
    }

    auto unicornArch = m_archHandler->getUnicornArch();
    auto unicornMode = m_archHandler->getUnicornMode();

    LOG_DEBUG(std::string("Using architecture: ") + m_archHandler->getName());

    uc_err err = uc_open(static_cast<uc_arch>(unicornArch), static_cast<uc_mode>(unicornMode), &m_uc);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to open Unicorn engine: ") + uc_strerror(err));
        return false;
    }

    uc_hook trace1, trace2, trace3;
    uc_hook_add(m_uc, &trace1, UC_HOOK_CODE, (void*)hook_code, this, 1, 0);
    uc_hook_add(m_uc, &trace2, UC_HOOK_INTR, (void*)hook_intr, this, 1, 0);
    uc_hook_add(m_uc, &trace3, UC_HOOK_INSN, (void*)hook_insn_syscall, this, 1, 0, UC_X86_INS_SYSCALL);

    LOG_DEBUG("Unicorn engine created successfully");
    return true;
}

bool Emulator::setupMemory() {
    LOG_DEBUG("Setting up memory regions...");

    if (m_elfParser.isPIE()) {
        m_baseAddress = 0x555555550000;
        LOG_DEBUG("PIE binary - base address: 0x" + std::to_string(m_baseAddress));
    } else {
        m_baseAddress = 0;
        LOG_DEBUG("Non-PIE binary - base address: 0x0");
    }

    if (!setupStack()) {
        LOG_ERROR("Failed to setup stack");
        return false;
    }

    if (!setupHeap()) {
        LOG_ERROR("Failed to setup heap");
        return false;
    }

    if (!loadProgramSegments()) {
        LOG_ERROR("Failed to load program segments");
        return false;
    }

    LOG_INFO("Memory setup complete. Regions: " + std::to_string(m_memoryRegions.size()));
    return true;
}

bool Emulator::setupStack() {
    LOG_DEBUG("Setting up stack...");

    uint64_t stackSize = 0x100000;
    uint64_t stackTop = 0x7fffffff0000ULL;

    if (!mapMemoryRegion(stackTop - stackSize, stackSize, UC_PROT_READ | UC_PROT_WRITE, "stack")) {
        return false;
    }

    m_cpuContext.sp = stackTop;
    LOG_DEBUG("Stack setup: 0x" + std::to_string(stackTop - stackSize) + " - 0x" + std::to_string(stackTop));
    return true;
}

bool Emulator::setupHeap() {
    LOG_DEBUG("Setting up heap...");

    uint64_t heapStart = m_baseAddress + 0x2000000;
    m_programBreak = heapStart;

    LOG_DEBUG("Heap setup: 0x" << std::hex << heapStart);
    return true;
}

bool Emulator::loadProgramSegments() {
    LOG_DEBUG("Loading program segments...");

    const auto& fileData = m_elfParser.getFileData();
    uint32_t segmentCount = 0;

    if (m_elfParser.is64Bit()) {
        const auto& progHeaders = m_elfParser.getProgramHeaders64();
        
        for (const auto& ph : progHeaders) {
            if (ph.p_type != static_cast<uint32_t>(PHType::PT_LOAD)) {
                continue;
            }

            uint64_t vaddr = ph.p_vaddr + m_baseAddress;
            uint64_t filesz = ph.p_filesz;
            uint64_t memsz = ph.p_memsz;
            uint32_t flags = ph.p_flags;

            uint32_t perms = 0;
            if (flags & static_cast<uint32_t>(PHFlags::PF_R)) perms |= UC_PROT_READ;
            if (flags & static_cast<uint32_t>(PHFlags::PF_W)) perms |= UC_PROT_WRITE;
            if (flags & static_cast<uint32_t>(PHFlags::PF_X)) perms |= UC_PROT_EXEC;

            uint64_t mapAddr = vaddr & ~0xFFF;
            uint64_t mapSize = ((vaddr + memsz + 0xFFF) & ~0xFFF) - mapAddr;

            if (!mapMemoryRegion(mapAddr, mapSize, perms, "segment")) {
                return false;
            }

            if (filesz > 0 && ph.p_offset + filesz <= fileData.size()) {
                uc_err err = uc_mem_write(m_uc, vaddr, fileData.data() + ph.p_offset, filesz);
                if (err != UC_ERR_OK) {
                    LOG_ERROR("Failed to write segment: " << uc_strerror(err));
                    return false;
                }
                LOG_DEBUG("Loaded segment at 0x" << std::hex << vaddr << " size: " << filesz);
            }

            if (memsz > filesz) {
                uint64_t bssAddr = vaddr + filesz;
                uint64_t bssSize = memsz - filesz;
                std::vector<uint8_t> zeros(bssSize, 0);
                
                uc_err err = uc_mem_write(m_uc, bssAddr, zeros.data(), bssSize);
                if (err != UC_ERR_OK) {
                    LOG_ERROR("Failed to zero BSS: " << uc_strerror(err));
                    return false;
                }
                LOG_DEBUG("Zeroed BSS at 0x" << std::hex << bssAddr << " size: " << bssSize);
            }

            segmentCount++;
        }
    } else {
        const auto& progHeaders = m_elfParser.getProgramHeaders32();
        
        for (const auto& ph : progHeaders) {
            if (ph.p_type != static_cast<uint32_t>(PHType::PT_LOAD)) {
                continue;
            }

            uint64_t vaddr = ph.p_vaddr + m_baseAddress;
            uint64_t filesz = ph.p_filesz;
            uint64_t memsz = ph.p_memsz;
            uint32_t flags = ph.p_flags;

            uint32_t perms = 0;
            if (flags & static_cast<uint32_t>(PHFlags::PF_R)) perms |= UC_PROT_READ;
            if (flags & static_cast<uint32_t>(PHFlags::PF_W)) perms |= UC_PROT_WRITE;
            if (flags & static_cast<uint32_t>(PHFlags::PF_X)) perms |= UC_PROT_EXEC;

            uint64_t mapAddr = vaddr & ~0xFFF;
            uint64_t mapSize = ((vaddr + memsz + 0xFFF) & ~0xFFF) - mapAddr;

            if (!mapMemoryRegion(mapAddr, mapSize, perms, "segment")) {
                return false;
            }

            if (filesz > 0 && ph.p_offset + filesz <= fileData.size()) {
                uc_err err = uc_mem_write(m_uc, vaddr, fileData.data() + ph.p_offset, filesz);
                if (err != UC_ERR_OK) {
                    LOG_ERROR("Failed to write segment: " << uc_strerror(err));
                    return false;
                }
            }

            if (memsz > filesz) {
                uint64_t bssAddr = vaddr + filesz;
                uint64_t bssSize = memsz - filesz;
                std::vector<uint8_t> zeros(bssSize, 0);
                
                uc_err err = uc_mem_write(m_uc, bssAddr, zeros.data(), bssSize);
                if (err != UC_ERR_OK) {
                    return false;
                }
            }

            segmentCount++;
        }
    }

    LOG_INFO("Loaded " << segmentCount << " segments");
    return true;
}

bool Emulator::mapMemoryRegion(uint64_t address, size_t size, uint32_t perms, const std::string& name) {
    uint64_t alignedAddr = address & ~0xFFF;
    uint64_t alignedSize = ((address + size + 0xFFF) & ~0xFFF) - alignedAddr;

    uc_err err = uc_mem_map(m_uc, alignedAddr, alignedSize, perms);
    if (err != UC_ERR_OK) {
        LOG_ERROR("Failed to map memory at 0x" << std::hex << alignedAddr << ": " << uc_strerror(err));
        return false;
    }

    MemoryRegion region{alignedAddr, alignedSize, perms, name};
    m_memoryRegions[alignedAddr] = region;

    LOG_DEBUG("Mapped " << name << " at 0x" << std::hex << alignedAddr << " size: " << alignedSize);
    return true;
}

bool Emulator::unmapMemoryRegion(uint64_t address, size_t size) {
    uint64_t unmap_addr = address & ~0xFFF;
    uint64_t unmap_size = (size + 0xFFF) & ~0xFFF;

    auto it = m_memoryRegions.find(unmap_addr);
    if (it == m_memoryRegions.end()) {
        LOG_WARN("Attempted to unmap non-existent region at 0x" << std::hex << unmap_addr);
        return false;
    }

    MemoryRegion& region = it->second;

    if (unmap_addr == region.baseAddress && unmap_size == region.size) {
        uc_err err = uc_mem_unmap(m_uc, unmap_addr, unmap_size);
        if (err != UC_ERR_OK) {
            LOG_ERROR("Failed to unmap memory: " << uc_strerror(err));
            return false;
        }
        m_memoryRegions.erase(it);
    } else if (unmap_addr == region.baseAddress) {
        region.baseAddress += unmap_size;
        region.size -= unmap_size;
        uc_err err = uc_mem_unmap(m_uc, unmap_addr, unmap_size);
        if (err != UC_ERR_OK) {
            LOG_ERROR("Failed to unmap memory prefix: " << uc_strerror(err));
            return false;
        }
    } else if (unmap_addr + unmap_size == region.baseAddress + region.size) {
        region.size -= unmap_size;
        uc_err err = uc_mem_unmap(m_uc, unmap_addr, unmap_size);
        if (err != UC_ERR_OK) {
            LOG_ERROR("Failed to unmap memory suffix: " << uc_strerror(err));
            return false;
        }
    } else {
        uint64_t old_end = region.baseAddress + region.size;
        region.size = unmap_addr - region.baseAddress;

        uint64_t new_base = unmap_addr + unmap_size;
        uint64_t new_size = old_end - new_base;
        
        uc_err err = uc_mem_unmap(m_uc, unmap_addr, unmap_size);
        if (err != UC_ERR_OK) {
            LOG_ERROR("Failed to unmap memory middle: " << uc_strerror(err));
            return false;
        }
        
        mapMemoryRegion(new_base, new_size, region.permissions, region.name);
    }

    return true;
}

uint64_t Emulator::handleBrk(uint64_t addr) {
    if (addr == 0) {
        return m_programBreak;
    }

    uint64_t newBreak = (addr + 0xFFF) & ~0xFFF;
    if (newBreak > m_programBreak) {
        if (!mapMemoryRegion(m_programBreak, newBreak - m_programBreak, UC_PROT_READ | UC_PROT_WRITE, "brk")) {
            return m_programBreak;
        }
    } else if (newBreak < m_programBreak) {
        unmapMemoryRegion(newBreak, m_programBreak - newBreak);
    }
    m_programBreak = newBreak;
    return m_programBreak;
}

uint64_t Emulator::findAvailableMemoryRegion(size_t size) {
    uint64_t search_addr = 0x10000000; 

    while (true) {
        bool available = true;
        for (const auto& pair : m_memoryRegions) {
            const auto& region = pair.second;
            if (search_addr < region.baseAddress + region.size && search_addr + size > region.baseAddress) {
                search_addr = region.baseAddress + region.size;
                available = false;
                break;
            }
        }
        if (available) {
            return search_addr;
        }
    }
}

int Emulator::addFileDescriptor(int fd) {
    if (fd < 0) return -1;
    for (size_t i = 0; i < m_fdTable.size(); ++i) {
        if (m_fdTable[i] == -1) {
            m_fdTable[i] = fd;
            return i;
        }
    }
    m_fdTable.push_back(fd);
    return m_fdTable.size() - 1;
}

int Emulator::getFileDescriptor(int fd) {
    if (fd < 0 || static_cast<size_t>(fd) >= m_fdTable.size()) {
        return -1;
    }
    return m_fdTable[fd];
}

void Emulator::removeFileDescriptor(int fd) {
    if (fd > 2 && static_cast<size_t>(fd) < m_fdTable.size()) {
        m_fdTable[fd] = -1;
    }
}

bool Emulator::initializeRegisters() {
    LOG_DEBUG("Initializing registers...");

    if (!m_archHandler) {
        return false;
    }

    uint64_t entryPoint = m_elfParser.getEntryPoint() + m_baseAddress;
    if (!m_archHandler->setPC(m_uc, entryPoint)) {
        LOG_ERROR("Failed to set program counter");
        return false;
    }

    if (!m_archHandler->setSP(m_uc, m_cpuContext.sp)) {
        LOG_ERROR("Failed to set stack pointer");
        return false;
    }

    LOG_DEBUG("Entry point: 0x" << std::hex << entryPoint);
    LOG_DEBUG("Stack pointer: 0x" << std::hex << m_cpuContext.sp);

    return true;
}

bool Emulator::loadBinary() {
    LOG_INFO("Loading binary...");

    if (m_elfParser.isPIE()) {
        m_pieHandler = std::make_unique<PIEHandler>(m_elfParser);
        if (!m_pieHandler->loadRelocations()) {
            LOG_WARN("Failed to load relocations (may not be needed)");
        }
        if (!m_pieHandler->applyRelocations(*this, m_baseAddress)) {
            LOG_WARN("Failed to apply relocations");
        }
    }

    return true;
}

bool Emulator::execute() {
    LOG_INFO("Starting execution from 0x" << std::hex << m_elfParser.getEntryPoint() + m_baseAddress);

    if (!m_isRunning) {
        LOG_ERROR("Emulator not initialized");
        return false;
    }

    uc_err err = uc_emu_start(m_uc, m_elfParser.getEntryPoint() + m_baseAddress, 0, 0, 0);
    if (err != UC_ERR_OK) {
        CrashReporter reporter(*this, err);
        reporter.generateReport();
        LOG_ERROR("Emulation failed: " << uc_strerror(err));
        return false;
    }

    m_isRunning = false;
    LOG_INFO("Execution completed with exit code: " << m_exitCode);
    return true;
}

bool Emulator::executeInstructions(uint64_t count) {
    LOG_DEBUG("Executing " << count << " instructions");

    uint64_t pc = m_archHandler->getPC(m_uc);

    uc_err err = uc_emu_start(m_uc, pc, 0, count, 0);
    if (err != UC_ERR_OK && err != UC_ERR_INSN_INVALID) {
        CrashReporter reporter(*this, err);
        reporter.generateReport();
        LOG_ERROR("Execution failed: " << uc_strerror(err));
        return false;
    }

    return true;
}

bool Emulator::step() {
    return executeInstructions(1);
}

void Emulator::stop(int exitCode) {
    m_exitCode = exitCode;
    m_isRunning = false;
    uc_emu_stop(m_uc);
}

void Emulator::setOpcodeHandler(OpcodeHandler* handler) {
    m_opcodeHandler = handler;
}

void Emulator::hook_code(uc_engine* /*uc*/, uint64_t address, uint32_t size, void* /*user_data*/) {
    LOG_DEBUG("Executing code at 0x" << std::hex << address << " size: " << size);
}

void Emulator::hook_intr(uc_engine* uc, uint32_t intno, void* user_data) {
    Emulator* emulator = static_cast<Emulator*>(user_data);
    if (emulator && emulator->m_opcodeHandler && emulator->m_archHandler) {
        if (intno == 0x80) {
            emulator->m_archHandler->handleSyscall(uc, *emulator->m_opcodeHandler);
        }
    }
}

void Emulator::hook_insn_syscall(uc_engine* uc, void* user_data) {
    Emulator* emulator = static_cast<Emulator*>(user_data);
    if (emulator && emulator->m_opcodeHandler && emulator->m_archHandler) {
        emulator->m_archHandler->handleSyscall(uc, *emulator->m_opcodeHandler);
    }
}