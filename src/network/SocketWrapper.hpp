#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <memory>
#include "../core/Logger.hpp"

namespace Network {
    class SocketWrapper {
        SOCKET m_sock;
    public:
        SocketWrapper(SOCKET sock) : m_sock(sock) {}
        ~SocketWrapper() {
            // Do not close socket here as we don't own it in hooks
        }

        void SetTimeouts(int recv_ms, int send_ms) {
            if (m_sock == INVALID_SOCKET) return;
            setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recv_ms, sizeof(recv_ms));
            setsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_ms, sizeof(send_ms));
        }

        static bool RedirectToProxy(sockaddr_in* addr, const std::string& proxyHost, int proxyPort) {
            // Convert domain to IP if needed (simplified: assume config is IP for Phase 1)
            inet_pton(AF_INET, proxyHost.c_str(), &addr->sin_addr);
            addr->sin_port = htons(proxyPort);
            return true;
        }
    };
}
