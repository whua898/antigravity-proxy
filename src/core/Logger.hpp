#pragma once
#include <fstream>
#include <mutex>
#include <string>
#include <iostream>

namespace Core {
    class Logger {
    public:
        static void Log(const std::string& message) {
            static std::mutex mtx;
            std::lock_guard<std::mutex> lock(mtx);
            std::ofstream logFile("proxy.log", std::ios::app);
            if (logFile.is_open()) {
                logFile << message << "\n";
            }
        }

        static void Error(const std::string& message) {
            Log("[ERROR] " + message);
        }

        static void Info(const std::string& message) {
            Log("[INFO] " + message);
        }
    };
}
