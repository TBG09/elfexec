#include "emu/opcodes/fs.hpp"
#include "emu/emulator.hpp"
#include "logging.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <vector>

namespace fs {

uint64_t handleOpen(Emulator& emulator, uint64_t path_addr, int flags, int mode) {
    std::vector<char> path_vec;
    char c;
    do {
        uc_mem_read(emulator.getUnicornEngine(), path_addr++, &c, 1);
        path_vec.push_back(c);
    } while (c != '\0');

    std::string path(path_vec.data());
    LOG_DEBUG("open called: path=" << path << ", flags=" << flags << ", mode=" << mode);

    int host_fd = open(path.c_str(), flags, mode);
    if (host_fd < 0) {
        return -1;
    }

    return emulator.addFileDescriptor(host_fd);
}

uint64_t handleClose(Emulator& emulator, int fd) {
    LOG_DEBUG("close called: fd=" << fd);
    int host_fd = emulator.getFileDescriptor(fd);
    if (host_fd < 0) {
        return -1;
    }
    emulator.removeFileDescriptor(fd);
    return close(host_fd);
}

uint64_t handleRead(Emulator& emulator, int fd, uint64_t buf_addr, size_t count) {
    LOG_DEBUG("read called: fd=" << fd << ", count=" << count);
    int host_fd = emulator.getFileDescriptor(fd);
    if (host_fd < 0) {
        return -1;
    }

    std::vector<uint8_t> buf(count);
    ssize_t bytes_read = read(host_fd, buf.data(), count);
    if (bytes_read < 0) {
        return -1;
    }

    uc_mem_write(emulator.getUnicornEngine(), buf_addr, buf.data(), bytes_read);
    return bytes_read;
}

uint64_t handleWrite(Emulator& emulator, int fd, uint64_t buf_addr, size_t count) {
    LOG_DEBUG("write called: fd=" << fd << ", count=" << count);
    int host_fd = emulator.getFileDescriptor(fd);
    if (host_fd < 0) {
        return -1;
    }

    std::vector<uint8_t> buf(count);
    uc_mem_read(emulator.getUnicornEngine(), buf_addr, buf.data(), count);

    return write(host_fd, buf.data(), count);
}

uint64_t handleLseek(Emulator& emulator, int fd, off_t offset, int whence) {
    LOG_DEBUG("lseek called: fd=" << fd << ", offset=" << offset << ", whence=" << whence);
    int host_fd = emulator.getFileDescriptor(fd);
    if (host_fd < 0) {
        return -1;
    }
    return lseek(host_fd, offset, whence);
}

} // namespace fs
