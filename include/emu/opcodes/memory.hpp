#ifndef MEMORY_HPP
#define MEMORY_HPP

#include <cstdint>

class Emulator;

namespace memory {

uint64_t handleMmap(Emulator& emulator, uint64_t addr, uint64_t length, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset);

uint64_t handleMunmap(Emulator& emulator, uint64_t addr, uint64_t length);

uint64_t handleBrk(Emulator& emulator, uint64_t addr);

} // namespace memory

#endif // MEMORY_HPP
