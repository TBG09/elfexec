#include "logging.hpp"
#include <ctime>
#include <iomanip>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger()
    : m_minLevel(LogLevel::INFO), m_colorEnabled(false) {
    #ifdef _WIN32
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hStdout != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(hStdout, &mode)) {
                mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                if (SetConsoleMode(hStdout, mode)) {
                    m_colorEnabled = true;
                }
            }
        }
    #else
        m_colorEnabled = isatty(fileno(stdout));
    #endif
}

Logger::~Logger() = default;

void Logger::setLogLevel(LogLevel level) {
    m_minLevel = level;
}

void Logger::setColorEnabled(bool enabled) {
    m_colorEnabled = enabled;
}

void Logger::logMessage(LogLevel level, const std::string& message) {
    if (m_minLevel == LogLevel::NONE || static_cast<int>(level) < static_cast<int>(m_minLevel)) {
        return;
    }

    auto now_time = std::time(nullptr);
    std::tm now_tm;
#ifdef _WIN32
    localtime_s(&now_tm, &now_time);
#else
    now_tm = *std::localtime(&now_time);
#endif

    std::ostringstream oss;
    oss << std::put_time(&now_tm, "%H:%M:%S");
    std::string timestamp = oss.str();

    std::string levelStr = getLevelString(level);
    std::string color = m_colorEnabled ? getColorCode(level) : "";
    std::string reset = m_colorEnabled ? getResetCode() : "";

    std::ostream& out = (level == LogLevel::ERROR || level == LogLevel::FATAL) ? std::cerr : std::cout;

    out << color << "[" << timestamp << "] " << levelStr << ": " << message << reset << std::endl;
}

void Logger::debug(const std::string& message) {
    logMessage(LogLevel::DEBUG, message);
}

void Logger::info(const std::string& message) {
    logMessage(LogLevel::INFO, message);
}

void Logger::warn(const std::string& message) {
    logMessage(LogLevel::WARN, message);
}

void Logger::error(const std::string& message) {
    logMessage(LogLevel::ERROR, message);
}

void Logger::fatal(const std::string& message) {
    logMessage(LogLevel::FATAL, message);
}

std::string Logger::getLevelString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default:              return "UNKNOWN";
    }
}

std::string Logger::getColorCode(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "\033[36m";  // Cyan
        case LogLevel::INFO:  return "\033[32m";  // Green
        case LogLevel::WARN:  return "\033[33m";  // Yellow
        case LogLevel::ERROR: return "\033[31m";  // Red
        case LogLevel::FATAL: return "\033[1;31m"; // Bright Red
        default:              return "";
    }
}

std::string Logger::getResetCode() {
    return "\033[0m";
}

const char* Logger::getFileName(const char* fullPath) {
    const char* lastSlash = std::strrchr(fullPath, '/');
    const char* lastBackslash = std::strrchr(fullPath, '\\');
    const char* lastSeparator = lastSlash > lastBackslash ? lastSlash : lastBackslash;
    return lastSeparator ? lastSeparator + 1 : fullPath;
}