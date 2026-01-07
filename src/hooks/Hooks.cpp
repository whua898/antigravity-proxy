#include <MinHook.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../core/Config.hpp"
#include "../core/Logger.hpp"
#include "../network/SocketWrapper.hpp"
#include "../network/FakeIP.hpp"

// Function Pointers
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);

connect_t fpConnect = NULL;
getaddrinfo_t fpGetAddrInfo = NULL;

// Hooks
int WSAAPI DetourConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    auto& config = Core::Config::Instance();
    
    // Timeout Control
    Network::SocketWrapper sock(s);
    sock.SetTimeouts(config.timeout.recv_ms, config.timeout.send_ms);

    if (name->sa_family == AF_INET) {
        sockaddr_in* addr = (sockaddr_in*)name;
        
        // Proxy Redirection
        // In verify mode: unconditional redirect if config loaded
        // In real mode: check rules
        if (config.proxy.port != 0) {
             Core::Logger::Info("Redirecting connect() to proxy...");
             Network::SocketWrapper::RedirectToProxy(addr, config.proxy.host, config.proxy.port);
        }
    }

    return fpConnect(s, name, namelen);
}

int WSAAPI DetourGetAddrInfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    if (pNodeName && Core::Config::Instance().fakeIp.enabled) {
        Core::Logger::Info(std::string("Intercepted getaddrinfo for: ") + pNodeName);
        // Implement Fake IP return here (Simplified for Phase 1: Pass through but log)
        // To implement correctly, we need to manually construct ADDRINFOA, which is verbose.
        // For Phase 1 demo, we just log.
    }
    return fpGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
}

namespace Hooks {
    void Install() {
        if (MH_Initialize() != MH_OK) {
            Core::Logger::Error("MinHook Init Failed");
            return;
        }

        if (MH_CreateHookApi(L"ws2_32.dll", "connect", (LPVOID)DetourConnect, (LPVOID*)&fpConnect) != MH_OK) {
             Core::Logger::Error("Hook connect failed");
        }

        if (MH_CreateHookApi(L"ws2_32.dll", "getaddrinfo", (LPVOID)DetourGetAddrInfo, (LPVOID*)&fpGetAddrInfo) != MH_OK) {
             Core::Logger::Error("Hook getaddrinfo failed");
        }

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            Core::Logger::Error("Enable Hooks failed");
        } else {
            Core::Logger::Info("Hooks Installed Successfully");
        }
    }

    void Uninstall() {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
}
