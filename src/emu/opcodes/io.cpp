#include "emu/opcodes/io.hpp"
#include "emu/emulator.hpp"
#include "logging.hpp"
#include <iostream>
#include <cstring>
#include <vector>

namespace io {

uint64_t handleRead(Emulator& emulator, uint64_t fd, uint64_t buf, uint64_t count) {
    LOG_DEBUG("Read: fd=" + std::to_string(fd) + " buf=0x" + std::to_string(buf) +
              " count=" + std::to_string(count));

    if (fd != 0) {
        LOG_WARN("Read from non-stdin fd: " + std::to_string(fd));
        return -1;
    }

    std::vector<uint8_t> buffer(count);
    size_t bytesRead = std::cin.readsome(reinterpret_cast<char*>(buffer.data()), count);

    uc_err err = uc_mem_write(emulator.getUnicornEngine(), buf, buffer.data(), bytesRead);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to write to emulated memory: ") + uc_strerror(err));
        return -1;
    }

    LOG_DEBUG("Read " + std::to_string(bytesRead) + " bytes");
    return bytesRead;
}

uint64_t handleWrite(Emulator& emulator, uint64_t fd, uint64_t buf, uint64_t count) {
    LOG_DEBUG("Write: fd=" + std::to_string(fd) + " buf=0x" + std::to_string(buf) +
              " count=" + std::to_string(count));

    if (fd != 1 && fd != 2) {
        LOG_WARN("Write to non-standard fd: " + std::to_string(fd));
        return -1;
    }

    if (count > 0x100000) {
        LOG_WARN("Write count too large: " + std::to_string(count));
        count = 0x100000;
    }

    std::vector<uint8_t> buffer(count);
    uc_err err = uc_mem_read(emulator.getUnicornEngine(), buf, buffer.data(), count);
    if (err != UC_ERR_OK) {
        LOG_ERROR(std::string("Failed to read from emulated memory: ") + uc_strerror(err));
        return -1;
    }

    std::ostream& out = (fd == 1) ? std::cout : std::cerr;
    out.write(reinterpret_cast<const char*>(buffer.data()), count);
    out.flush();

    LOG_DEBUG("Wrote " + std::to_string(count) + " bytes to fd " + std::to_string(fd));
    return count;
}

}  // namespace io
