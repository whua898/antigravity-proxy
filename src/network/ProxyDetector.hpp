#pragma once
#include <vector>
#include <string>
#include <cstdlib>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../core/Logger.hpp"

namespace Network {
    class ProxyDetector {
    public:
        // 执行一次探测，返回可用端口，失败返回 0
        static int Detect() {
            // 1. 优先检查环境变量 (ALL_PROXY, HTTP_PROXY 等)
            int envPort = CheckEnvVars();
            if (envPort > 0) return envPort;

            // 2. 扫描常用代理软件端口
            // 顺序：Clash/Mihomo -> V2RayN -> SSR -> V2RayA -> NekoBox
            static const std::vector<int> commonPorts = {
                7890, // Clash / Mihomo HTTP/Mixed
                7891, // Clash / Mihomo SOCKS
                10808, // V2RayN SOCKS
                10809, // V2RayN HTTP
                1080, // Shadowsocks / SSR
                20171, // V2RayA
                2080, // NekoBox
                2081  // NekoBox
            };

            for (int port : commonPorts) {
                if (TestPort(port)) {
                    Core::Logger::Info("自动探测: 发现可用代理端口 " + std::to_string(port));
                    return port;
                }
            }

            return 0;
        }

    private:
        // 检查环境变量中的端口
        static int CheckEnvVars() {
            const char* vars[] = {"ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"};
            for (const char* var : vars) {
                char* val = nullptr;
                size_t len = 0;
                if (_dupenv_s(&val, &len, var) == 0 && val != nullptr) {
                    std::string s(val);
                    free(val);
                    // 简单解析：查找最后一个冒号后的数字
                    // 例如: "socks5://127.0.0.1:7890" -> 7890
                    size_t colon = s.find_last_of(':');
                    if (colon != std::string::npos && colon + 1 < s.size()) {
                        try {
                            int p = std::stoi(s.substr(colon + 1));
                            if (p > 0 && p < 65536) {
                                Core::Logger::Info("自动探测: 从环境变量 " + std::string(var) + " 获取端口 " + std::to_string(p));
                                return p;
                            }
                        } catch (...) {}
                    }
                }
            }
            return 0;
        }

        // 测试本地端口是否开放
        static bool TestPort(int port) {
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) return false;

            // 设置非阻塞模式以快速超时
            u_long mode = 1;
            ioctlsocket(s, FIONBIO, &mode);

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

            bool result = false;
            // 尝试连接
            int rc = connect(s, (sockaddr*)&addr, sizeof(addr));
            if (rc == 0) {
                result = true;
            } else {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    // 使用 select 等待连接结果，超时 50ms (本地回环通常极快)
                    fd_set writeSet;
                    FD_ZERO(&writeSet);
                    FD_SET(s, &writeSet);
                    timeval tv = {0, 50000}; // 50ms
                    if (select(0, nullptr, &writeSet, nullptr, &tv) > 0) {
                        result = true;
                    }
                }
            }
            closesocket(s);
            return result;
        }
    };
}
