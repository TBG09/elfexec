#include "emu/opcodes/memory.hpp"
#include "emu/emulator.hpp"
#include "logging.hpp"

#ifdef _WIN32
    #include <windows.h>
    #define MAP_PRIVATE 0x02
    #define MAP_ANONYMOUS 0x20
    #define MAP_FIXED 0x10
    #define PROT_READ 0x1
    #define PROT_WRITE 0x2
    #define PROT_EXEC 0x4
#else
    #include <sys/mman.h>
#endif

namespace memory {

uint64_t handleMmap(Emulator& emulator, uint64_t addr, uint64_t length, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset) {
    LOG_DEBUG("mmap called: addr=0x" << std::hex << addr << ", length=" << length << ", prot=" << prot << ", flags=" << flags << ", fd=" << fd << ", offset=" << offset);

    uint64_t map_addr = addr;

    if (flags & MAP_ANONYMOUS) {
        if (map_addr == 0 && !(flags & MAP_FIXED)) {
            map_addr = emulator.findAvailableMemoryRegion(length);
        }
        
        if (emulator.mapMemoryRegion(map_addr, length, prot, "mmap")) {
            return map_addr;
        }
    } else {
        LOG_WARN("File-backed mmap is not yet supported.");
    }

    LOG_WARN("Unsupported mmap flags or failed to map memory: " << flags);
    return -1; // Return an error
}

uint64_t handleMunmap(Emulator& emulator, uint64_t addr, uint64_t length) {
    LOG_DEBUG("munmap called: addr=0x" << std::hex << addr << ", length=" << length);

    if (emulator.unmapMemoryRegion(addr, length)) {
        return 0; // Success
    }

    return -1; // Error
}

uint64_t handleBrk(Emulator& emulator, uint64_t addr) {
    LOG_DEBUG("brk called: addr=0x" << std::hex << addr);
    return emulator.handleBrk(addr);
}

} // namespace memory