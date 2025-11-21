#ifndef OPCODES_IO_HPP
#define OPCODES_IO_HPP

#include <cstdint>

class Emulator;

namespace io {

    uint64_t handleRead(Emulator& emulator, uint64_t fd, uint64_t buf, uint64_t count);

    uint64_t handleWrite(Emulator& emulator, uint64_t fd, uint64_t buf, uint64_t count);

}  // namespace io

#endif // OPCODES_IO_HPP
