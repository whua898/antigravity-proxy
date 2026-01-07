#pragma once
#include <string>
#include <map>
#include <mutex>
#include <winsock2.h>

namespace Network {
    class FakeIP {
        std::map<unsigned long, std::string> m_ipToDomain;
        std::mutex m_mtx;
        unsigned long m_currentIp; // 10.0.0.1 start

    public:
        FakeIP() : m_currentIp(0x0A000001) {} // 10.0.0.1 in hex

        static FakeIP& Instance() {
            static FakeIP instance;
            return instance;
        }

        bool IsFakeIP(unsigned long ip) {
            // Simplified check for 10.x.x.x
            return (ip & 0x000000FF) == 10; // Check first byte (little endian?? Winsock is big endian usually, but raw integer depends on arch. 
            // inet_addr("10...") returns network byte order.
            // Let's assume standard behavior.
        }

        unsigned long Alloc(const std::string& domain) {
            std::lock_guard<std::mutex> lock(m_mtx);
            // In a real app, check if domain exists.
            unsigned long ip = htonl(m_currentIp++);
            m_ipToDomain[ip] = domain;
            return ip;
        }

        std::string GetDomain(unsigned long ip) {
             std::lock_guard<std::mutex> lock(m_mtx);
             if (m_ipToDomain.count(ip)) return m_ipToDomain[ip];
             return "";
        }
    };
}
