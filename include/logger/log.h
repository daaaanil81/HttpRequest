#ifndef _LOG__H_
#define _LOG__H_

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <sstream>

/*
Example of console output:
23.02.2020 18:06:06; INFO; (1020): Starting the app
23.02.2020 18:06:06; DEBUG; (2561): Running a thread

Example of log.txt output:
23.02.2020 18:06:06; INFO; (2561): Running a thread
23.02.2020 18:06:06; DEBUG; f2(3444): Running a thread
23.02.2020 18:06:06; WARNING; f2(3444): Time spent in the thread: 10.0 seconds

Example of log2.txt:
23.02.2020 18:06:06; INFO; f3(3444): Running a thread
23.02.2020 18:06:06; ERROR; f3(3444): My int is 123;
*/

/*
void f1() {
    auto logger1 = getLogger(); // Log to console
    // output: 23.02.2020 18:06:06; DEBUG; (2561): Running a thread
    logger1(DEBUG) << "Running a thread";

    auto logger2 = getLogger("f1"); // Each message has f1 prefix
    // output: 23.02.2020 18:06:06; INFO; (2561): Running a thread
    logger2 << "Running a thread" << " but log to another logger"; // Default log level INFO
}
*/

enum LogLevel {
    INFO,
    DEBUG,
    WARNING,
    ERROR
};

std::string levelToString(LogLevel level);

class ConsoleLog {

private: /* Structs */
    struct StreamControl {
        std::stringstream& m_ss;
		LogLevel m_level;

        StreamControl(std::stringstream& ss, LogLevel level) : m_ss(ss), m_level(level) {
            std::string level_str = levelToString(level);

            m_ss << __DATE__ << " " << __TIME__ << ";" << " " << level_str << "; ";
        }

        ~StreamControl() {
            /* Concurrent access to a synchronized (29.5.3.4)
             * standard iostream object’s formatted and unformatted input (29.7.4.1) and output (29.7.5.1)
             * functions or a standard C stream by multiple threads does not result in a data race (6.9.2).
             * [Note: Users must still synchronize concurrent use of these objects and streams by multiple
             * threads if they wish to avoid interleaved characters. —end note] */
            // https://isocpp.org/files/papers/N4860.pdf Page: 1358(29.4.2)
            m_ss << std::endl;
            std::cout << m_ss.str();
            m_ss.str("");
        }
    };

private: /* Variables */
    std::stringstream m_ss;

private: /* Functions */
public:
	ConsoleLog::StreamControl operator()(LogLevel level = INFO) {
		return ConsoleLog::StreamControl(this->m_ss, level);
	}

    template <class Type>
    ConsoleLog::StreamControl operator<<(const Type& val) {
        ConsoleLog::StreamControl sc(this->m_ss, INFO);
        sc.m_ss << val;
        return sc;
    }

    template <class Type>
    friend ConsoleLog::StreamControl&& operator<<(ConsoleLog::StreamControl&& sc, const Type& val);
};

template <class Type>
ConsoleLog::StreamControl&& operator<<(ConsoleLog::StreamControl&& sc, const Type& val) {
    sc.m_ss << val;
    return std::move(sc);
}

ConsoleLog getLogger() {
    return ConsoleLog{};
}

std::string levelToString(LogLevel l) {
    switch (l) {
    case INFO:
        return "INFO";
    case DEBUG:
        return "DEBUG";
    case WARNING:
        return "WARNING";
    case ERROR:
        return "ERROR";
    default:
        return "";
    }
}


#endif /* _LOG__H_ */
