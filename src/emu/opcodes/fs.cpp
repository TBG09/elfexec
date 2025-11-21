#include "emu/opcodes/fs.hpp"
#include "emu/emulator.hpp"
#include "logging.hpp"
#include <fstream>
#include <vector>
#include <iostream>
#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
using ssize_t = int;
#else
#include <unistd.h>
#endif

namespace fs {

#ifdef _WIN32
int translate_flags(int flags) {
    int windows_flags = 0;
    if (flags & O_RDONLY) windows_flags |= _O_RDONLY;
    if (flags & O_WRONLY) windows_flags |= _O_WRONLY;
    if (flags & O_RDWR)   windows_flags |= _O_RDWR;
    if (flags & O_APPEND) windows_flags |= _O_APPEND;
    if (flags & O_CREAT)  windows_flags |= _O_CREAT;
    if (flags & O_TRUNC)  windows_flags |= _O_TRUNC;
    if (flags & O_EXCL)   windows_flags |= _O_EXCL;
    // Binary and text modes
    if (flags & O_BINARY) windows_flags |= _O_BINARY;
    if (flags & O_TEXT)   windows_flags |= _O_TEXT;
    return windows_flags;
}
#endif

uint64_t handleOpen(Emulator& emulator, uint64_t path_addr, int flags, int mode) {
    std::vector<char> path_vec;
    char c;
    do {
        uc_mem_read(emulator.getUnicornEngine(), path_addr++, &c, 1);
        path_vec.push_back(c);
    } while (c != '\0');

    std::string path(path_vec.data());
    LOG_DEBUG("open called: path=" << path << ", flags=" << flags << ", mode=" << mode);

#ifdef _WIN32
    int host_fd = _open(path.c_str(), translate_flags(flags), mode);
#else
    int host_fd = open(path.c_str(), flags, mode);
#endif

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
#ifdef _WIN32
    return _close(host_fd);
#else
    return close(host_fd);
#endif
}

uint64_t handleRead(Emulator& emulator, int fd, uint64_t buf_addr, size_t count) {
    LOG_DEBUG("read called: fd=" << fd << ", count=" << count);
    int host_fd = emulator.getFileDescriptor(fd);
    if (host_fd < 0) {
        return -1;
    }

    std::vector<uint8_t> buf(count);
#ifdef _WIN32
    ssize_t bytes_read = _read(host_fd, buf.data(), count);
#else
    ssize_t bytes_read = read(host_fd, buf.data(), count);
#endif

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

#ifdef _WIN32
    return _write(host_fd, buf.data(), count);
#else
    return write(host_fd, buf.data(), count);
#endif
}

uint64_t handleLseek(Emulator& emulator, int fd, int64_t offset, int whence) {
    LOG_DEBUG("lseek called: fd=" << fd << ", offset=" << offset << ", whence=" << whence);
    int host_fd = emulator.getFileDescriptor(fd);
    if (host_fd < 0) {
        return -1;
    }
#ifdef _WIN32
    return _lseek(host_fd, offset, whence);
#else
    return lseek(host_fd, offset, whence);
#endif
}

} // namespace fs