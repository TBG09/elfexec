cmake_minimum_required(VERSION 3.20)
project(ELFExec CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")

# Unicorn Engine dependency
find_library(UNICORN_LIB unicorn REQUIRED)
find_path(UNICORN_INCLUDE unicorn/unicorn.h REQUIRED)

# Main executable
add_executable(elfexec
        src/main.cpp
        src/logging.cpp
        src/elf/elf.cpp
        src/elf/pie.cpp
        src/emu/emulator.cpp
        src/emu/opcodes.cpp
        src/emu/arch.cpp
        src/emu/opcodes/io.cpp
        src/emu/opcodes/process.cpp
        src/emu/opcodes/memory.cpp
        src/emu/opcodes/fs.cpp
        src/emu/crash_reporter.cpp
)

# Include directories
target_include_directories(elfexec PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${UNICORN_INCLUDE}
)

# Link libraries
target_link_libraries(elfexec PRIVATE
        ${UNICORN_LIB}
)

if(WIN32)
    target_link_libraries(elfexec PRIVATE kernel32)
endif()

# Optional: for debug symbols
if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_options(elfexec PRIVATE -g)
endif()