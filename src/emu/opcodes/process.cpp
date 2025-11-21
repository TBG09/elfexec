#include "emu/opcodes/process.hpp"
#include "emu/emulator.hpp"
#include "logging.hpp"

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <unistd.h>
#endif

namespace process {

uint64_t handleExit(Emulator& emulator, uint64_t code) {
    LOG_INFO("Exit syscall with code: " << code);
    emulator.stop(code);
    return 0;
}

uint64_t handleGetpid() {
    LOG_DEBUG("getpid called");
    return 1000;
}

uint64_t handleGetuid() {
    LOG_DEBUG("getuid called");
#ifdef _WIN32
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength);
    PTOKEN_USER pTokenUser = (PTOKEN_USER) new BYTE[dwLength];
    GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);
    DWORD rid = *GetSidSubAuthority(pTokenUser->User.Sid, *GetSidSubAuthorityCount(pTokenUser->User.Sid) - 1);
    delete[] pTokenUser;
    CloseHandle(hToken);
    return rid;
#else
    return getuid();
#endif
}

uint64_t handleGeteuid() {
    LOG_DEBUG("geteuid called");
    return handleGetuid();
}

uint64_t handleGetgid() {
    LOG_DEBUG("getgid called");
#ifdef _WIN32
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenPrimaryGroup, nullptr, 0, &dwLength);
    PTOKEN_PRIMARY_GROUP pTokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP) new BYTE[dwLength];
    GetTokenInformation(hToken, TokenPrimaryGroup, pTokenPrimaryGroup, dwLength, &dwLength);
    DWORD rid = *GetSidSubAuthority(pTokenPrimaryGroup->PrimaryGroup, *GetSidSubAuthorityCount(pTokenPrimaryGroup->PrimaryGroup) - 1);
    delete[] pTokenPrimaryGroup;
    CloseHandle(hToken);
    return rid;
#else
    return getgid();
#endif
}

uint64_t handleGetegid() {
    LOG_DEBUG("getegid called");
    return handleGetgid();
}

} // namespace process
