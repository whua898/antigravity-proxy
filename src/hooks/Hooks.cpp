// 防止 windows.h 自动包含 winsock.h (避免与 winsock2.h 冲突)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <MinHook.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "../core/Config.hpp"
#include "../core/Logger.hpp"
#include "../network/SocketWrapper.hpp"
#include "../network/Socks5.hpp"
#include "../network/HttpConnect.hpp"
#include "../network/SocketIo.hpp"
#include "../network/ProxyDetector.hpp"

// ============= 函数指针类型定义 =============
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *WSAConnect_t)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);

// ============= 原始函数指针 =============
connect_t fpConnect = NULL;
WSAConnect_t fpWSAConnect = NULL;

// ============= 辅助函数 =============

static bool BuildProxyAddr(const Core::ProxyConfig& proxy, int port, sockaddr_in* proxyAddr) {
    memset(proxyAddr, 0, sizeof(sockaddr_in));
    proxyAddr->sin_family = AF_INET;
    if (inet_pton(AF_INET, proxy.host.c_str(), &proxyAddr->sin_addr) != 1) {
        return false;
    }
    proxyAddr->sin_port = htons(port);
    return true;
}

static bool DoProxyHandshake(SOCKET s, const std::string& host, uint16_t port) {
    auto& config = Core::Config::Instance();
    if (config.proxy.type == "socks5") {
        return Network::Socks5Client::Handshake(s, host, port);
    } else if (config.proxy.type == "http") {
        return Network::HttpConnectClient::Handshake(s, host, port);
    }
    return false;
}

// 执行代理连接逻辑
int PerformProxyConnect(SOCKET s, const struct sockaddr* name, int namelen, bool isWsa) {
    // 1. 基础检查
    if (!name || namelen < (int)sizeof(sockaddr)) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    // 2. 只处理 IPv4
    if (name->sa_family != AF_INET) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    auto* addr = (sockaddr_in*)name;
    uint16_t originalPort = ntohs(addr->sin_port);

    // 3. 排除本地回环 (127.x.x.x)
    // 注意：这里直接读取 s_addr，不进行字符串转换，速度最快且无内存分配
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    if ((ip >> 24) == 127) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }

    auto& config = Core::Config::Instance();

    // 4. 端口白名单检查
    if (!config.rules.IsPortAllowed(originalPort)) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    // 5. 获取代理端口
    int effectivePort = config.GetEffectivePort();
    if (config.proxy.port == 0 && effectivePort == 0) {
        effectivePort = Network::ProxyDetector::Detect();
        if (effectivePort > 0) config.SetDynamicPort(effectivePort);
    }
    
    if (effectivePort == 0) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    // 6. 防止代理自连接
    // 简单判断：如果目标 IP 是 127.0.0.1 且端口是代理端口，则直连
    if (ip == 0x7F000001 && originalPort == effectivePort) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }

    // 7. 连接代理
    sockaddr_in proxyAddr{};
    if (!BuildProxyAddr(config.proxy, effectivePort, &proxyAddr)) {
        return SOCKET_ERROR;
    }
    
    // 设置超时 (可选，为了稳定先注释掉)
    // Network::SocketWrapper sock(s);
    // sock.SetTimeouts(config.timeout.recv_ms, config.timeout.send_ms);
    
    int result = isWsa ?
        fpWSAConnect(s, (sockaddr*)&proxyAddr, sizeof(proxyAddr), NULL, NULL, NULL, NULL) :
        fpConnect(s, (sockaddr*)&proxyAddr, sizeof(proxyAddr));
    
    if (result != 0) {
        // 简单重试逻辑
        if (config.proxy.port == 0) {
            config.InvalidateDynamicPort();
            // 这里不立即重试，让上层重试，避免递归或阻塞
        }
        return result;
    }
    
    // 8. 握手
    // 由于没有 FakeIP，我们只能拿到目标 IP，无法拿到域名
    // SOCKS5 协议支持传 IP，所以没问题
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
    
    if (!DoProxyHandshake(s, std::string(ipStr), originalPort)) {
        return SOCKET_ERROR;
    }
    
    return 0;
}

int WSAAPI DetourConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    return PerformProxyConnect(s, name, namelen, false);
}

int WSAAPI DetourWSAConnect(SOCKET s, const struct sockaddr* name, int namelen,
                            LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                            LPQOS lpSQOS, LPQOS lpGQOS) {
    return PerformProxyConnect(s, name, namelen, true);
}

namespace Hooks {
    void Install() {
        if (MH_Initialize() != MH_OK) return;
        
        MH_CreateHookApi(L"ws2_32.dll", "connect", (LPVOID)DetourConnect, (LPVOID*)&fpConnect);
        MH_CreateHookApi(L"ws2_32.dll", "WSAConnect", (LPVOID)DetourWSAConnect, (LPVOID*)&fpWSAConnect);
        
        MH_EnableHook(MH_ALL_HOOKS);
        Core::Logger::Info("Antigravity-Proxy: Only Connect Hooks Installed");
    }
    
    void Uninstall() {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
}
