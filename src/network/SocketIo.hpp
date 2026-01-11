#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <string>

namespace Network {
namespace SocketIo {

// 使用 select 等待可读/可写，避免非阻塞套接字直接失败
inline bool WaitReadable(SOCKET sock, int timeoutMs) {
    if (sock == INVALID_SOCKET) {
        WSASetLastError(WSAEINVAL);
        return false;
    }
    if (timeoutMs <= 0) timeoutMs = 5000;
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(sock, &readSet);
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    // 注意：select 可能会修改 tv，虽然 Windows 上通常不修改，但标准建议重置
    // 这里是单次调用，所以没问题
    int rc = select(0, &readSet, nullptr, nullptr, &tv);
    if (rc > 0) return true;
    if (rc == 0) WSASetLastError(WSAETIMEDOUT);
    return false;
}

// 使用 select 等待可写，避免非阻塞套接字直接失败
inline bool WaitWritable(SOCKET sock, int timeoutMs) {
    if (sock == INVALID_SOCKET) {
        WSASetLastError(WSAEINVAL);
        return false;
    }
    if (timeoutMs <= 0) timeoutMs = 5000;
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    int rc = select(0, nullptr, &writeSet, nullptr, &tv);
    if (rc > 0) return true;
    if (rc == 0) WSASetLastError(WSAETIMEDOUT);
    return false;
}

// 等待连接完成并检查 SO_ERROR，适配非阻塞 connect
inline bool WaitConnect(SOCKET sock, int timeoutMs) {
    if (!WaitWritable(sock, timeoutMs)) return false;
    int soError = 0;
    int optLen = sizeof(soError);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&soError, &optLen) != 0) {
        return false;
    }
    if (soError != 0) {
        WSASetLastError(soError);
        return false;
    }
    return true;
}

// 确保完整发送，兼容非阻塞套接字
inline bool SendAll(SOCKET sock, const char* data, int len, int timeoutMs) {
    int totalSent = 0;
    while (totalSent < len) {
        int sent = send(sock, data + totalSent, len - totalSent, 0);
        if (sent > 0) {
            totalSent += sent;
            continue;
        }
        if (sent == 0) {
            WSASetLastError(WSAECONNRESET);
            return false;
        }
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            if (!WaitWritable(sock, timeoutMs)) return false;
            continue;
        }
        return false;
    }
    return true;
}

// 精确接收指定字节数，兼容非阻塞套接字
inline bool RecvExact(SOCKET sock, uint8_t* buf, int len, int timeoutMs) {
    int totalRead = 0;
    while (totalRead < len) {
        int read = recv(sock, (char*)buf + totalRead, len - totalRead, 0);
        if (read > 0) {
            totalRead += read;
            continue;
        }
        if (read == 0) {
            WSASetLastError(WSAECONNRESET);
            return false;
        }
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            if (!WaitReadable(sock, timeoutMs)) return false;
            continue;
        }
        return false;
    }
    return true;
}

// 逐字节接收直到命中分隔符，避免吞掉隧道首包数据
inline bool RecvUntil(SOCKET sock, std::string* out, const std::string& delimiter, int timeoutMs, int maxBytes) {
    if (!out) {
        WSASetLastError(WSAEINVAL);
        return false;
    }
    if (maxBytes <= 0) maxBytes = 1024;
    out->clear();
    out->reserve((size_t)maxBytes);
    while ((int)out->size() < maxBytes) {
        char ch = '\0';
        int read = recv(sock, &ch, 1, 0);
        if (read > 0) {
            out->push_back(ch);
            if (out->size() >= delimiter.size() &&
                out->find(delimiter) != std::string::npos) {
                return true;
            }
            continue;
        }
        if (read == 0) {
            WSASetLastError(WSAECONNRESET);
            return false;
        }
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            if (!WaitReadable(sock, timeoutMs)) return false;
            continue;
        }
        return false;
    }
    WSASetLastError(WSAEMSGSIZE);
    return false;
}

} // namespace SocketIo
} // namespace Network
