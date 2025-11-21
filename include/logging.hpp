#ifndef LOGGING_HPP
#define LOGGING_HPP

#include <string>
#include <iostream>
#include <sstream>
#include <cstring>

enum class LogLevel {
    NONE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL
};

class Logger {
public:
    static Logger& getInstance();
    
    void setLogLevel(LogLevel level);
    
    void logMessage(LogLevel level, const std::string& message);
    void debug(const std::string& message);
    void info(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);
    void fatal(const std::string& message);
    
    void setColorEnabled(bool enabled);
    
    static const char* getFileName(const char* fullPath);

private:
    Logger();
    ~Logger();
    
    LogLevel m_minLevel;
    bool m_colorEnabled;
    
    std::string getLevelString(LogLevel level);
    std::string getColorCode(LogLevel level);
    std::string getResetCode();
};

#define LOG_STREAM(level, msg) \
    do { \
        std::ostringstream oss; \
        oss << msg; \
        Logger::getInstance().logMessage(level, oss.str()); \
    } while (0)

#define LOG_DEBUG(msg) LOG_STREAM(LogLevel::DEBUG, msg)
#define LOG_INFO(msg) LOG_STREAM(LogLevel::INFO, msg)
#define LOG_WARN(msg) LOG_STREAM(LogLevel::WARN, msg)
#define LOG_ERROR(msg) LOG_STREAM(LogLevel::ERROR, msg)
#define LOG_FATAL(msg) LOG_STREAM(LogLevel::FATAL, msg)

#endif // LOGGING_HPP
