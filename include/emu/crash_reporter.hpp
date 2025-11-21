#ifndef CRASH_REPORTER_HPP
#define CRASH_REPORTER_HPP

#include "emu/emulator.hpp"
#include <unicorn/unicorn.h>

class CrashReporter {
public:
    CrashReporter(Emulator& emulator, uc_err error);

    void generateReport();

private:
    void printCrashReason();

    void printCPUState();

    void printMemoryDump();

    void printELFInfo();

    Emulator& m_emulator;
    uc_err m_error;
};

#endif // CRASH_REPORTER_HPP
