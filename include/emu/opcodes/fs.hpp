#ifndef FS_HPP
#define FS_HPP

#include <cstdint>
#include <sys/types.h> 

class Emulator;

namespace fs {

uint64_t handleOpen(Emulator& emulator, uint64_t path_addr, int flags, int mode);

uint64_t handleClose(Emulator& emulator, int fd);

uint64_t handleRead(Emulator& emulator, int fd, uint64_t buf_addr, size_t count);

uint64_t handleWrite(Emulator& emulator, int fd, uint64_t buf_addr, size_t count);

uint64_t handleLseek(Emulator& emulator, int fd, off_t offset, int whence);

} // namespace fs

#endif // FS_HPP
