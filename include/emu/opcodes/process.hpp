#ifndef PROCESS_HPP
#define PROCESS_HPP

#include <cstdint>

class Emulator;

namespace process {

uint64_t handleExit(Emulator& emulator, uint64_t code);

uint64_t handleGetpid();

uint64_t handleGetuid();

uint64_t handleGeteuid();

uint64_t handleGetgid();

uint64_t handleGetegid();

} // namespace process

#endif // PROCESS_HPP
