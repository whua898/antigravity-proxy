// 防止 windows.h 自动包含 winsock.h (避免与 winsock2.h 冲突)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <MinHook.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mswsock.h>
#include <unordered_map>
#include <mutex>
#include "../core/Config.hpp"
#include "../core/Logger.hpp"
#include "../network/SocketWrapper.hpp"
#include "../network/FakeIP.hpp"
#include "../network/Socks5.hpp"
#include "../network/HttpConnect.hpp"
#include "../network/SocketIo.hpp"
#include "../network/TrafficMonitor.hpp"
#include "../network/ProxyDetector.hpp"
#include "../injection/ProcessInjector.hpp"

// ============= 函数指针类型定义 =============
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *WSAConnect_t)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef struct hostent* (WSAAPI *gethostbyname_t)(const char* name);
typedef int (WSAAPI *getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int (WSAAPI *getaddrinfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef int (WSAAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WSAAPI *WSASend_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecv_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI *WSAConnectByNameA_t)(SOCKET, LPCSTR, LPCSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval*, LPWSAOVERLAPPED);
typedef BOOL (WSAAPI *WSAConnectByNameW_t)(SOCKET, LPWSTR, LPWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval*, LPWSAOVERLAPPED);
typedef int (WSAAPI *WSAIoctl_t)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI *WSAGetOverlappedResult_t)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
typedef BOOL (WINAPI *GetQueuedCompletionStatus_t)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);
typedef BOOL (WINAPI *CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *GetQueuedCompletionStatusEx_t)(
    HANDLE CompletionPort,
    LPOVERLAPPED_ENTRY lpCompletionPortEntries,
    ULONG ulCount,
    PULONG ulNumEntriesRemoved,
    DWORD dwMilliseconds,
    BOOL fAlertable
);

// ============= 原始函数指针 =============
connect_t fpConnect = NULL;
WSAConnect_t fpWSAConnect = NULL;
gethostbyname_t fpGetHostByName = NULL;
getaddrinfo_t fpGetAddrInfo = NULL;
getaddrinfoW_t fpGetAddrInfoW = NULL;
send_t fpSend = NULL;
recv_t fpRecv = NULL;
WSASend_t fpWSASend = NULL;
WSARecv_t fpWSARecv = NULL;
WSAConnectByNameA_t fpWSAConnectByNameA = NULL;
WSAConnectByNameW_t fpWSAConnectByNameW = NULL;
WSAIoctl_t fpWSAIoctl = NULL;
WSAGetOverlappedResult_t fpWSAGetOverlappedResult = NULL;
GetQueuedCompletionStatus_t fpGetQueuedCompletionStatus = NULL;
LPFN_CONNECTEX fpConnectEx = NULL;
CreateProcessW_t fpCreateProcessW = NULL;
GetQueuedCompletionStatusEx_t fpGetQueuedCompletionStatusEx = NULL;

// ============= 辅助函数 =============

// 移除 thread_local，改用简单的局部变量传递（如果可能）
// 或者确保 thread_local 不会引起问题。在 DLL 中 thread_local 确实有风险。
// 这里我们暂时移除 g_currentTarget 的依赖，直接在 PerformProxyConnect 中处理。

struct ConnectExContext {
    SOCKET sock;
    std::string host;
    uint16_t port;
    const char* sendBuf;
    DWORD sendLen;
    LPDWORD bytesSent;
    ULONGLONG createdTick;
};

static std::unordered_map<LPOVERLAPPED, ConnectExContext> g_connectExPending;
static std::mutex g_connectExMtx;
static std::mutex g_connectExHookMtx;
static bool g_connectExHookInstalled = false;
static const ULONGLONG kConnectExPendingTtlMs = 60000;

static std::unordered_map<std::string, bool> g_loggedSkipProcesses;
static std::mutex g_loggedSkipProcessesMtx;
static const size_t kMaxLoggedSkipProcesses = 256;

static std::string WideToUtf8(PCWSTR input) {
    if (!input) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, input, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string result(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input, -1, &result[0], len, NULL, NULL);
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

static bool ResolveOriginalTarget(const sockaddr* name, std::string* host, uint16_t* port) {
    if (!name || name->sa_family != AF_INET) return false;
    auto* addr = (sockaddr_in*)name;
    if (port) *port = ntohs(addr->sin_port);
    if (host) {
        // 优化：减少 FakeIP 锁竞争，先检查是否在 FakeIP 范围内
        // FakeIP::IsFakeIP 内部有锁吗？检查 FakeIP.hpp -> 是的，有锁。
        // 但 IsFakeIP 只是位运算，应该很快。
        if (Network::FakeIP::Instance().IsFakeIP(addr->sin_addr.s_addr)) {
            *host = Network::FakeIP::Instance().GetDomain(addr->sin_addr.s_addr);
            if (host->empty()) {
                *host = Network::FakeIP::IpToString(addr->sin_addr.s_addr);
            }
        } else {
            *host = Network::FakeIP::IpToString(addr->sin_addr.s_addr);
        }
    }
    return true;
}

static bool IsLoopbackHost(const std::string& host) {
    if (host == "127.0.0.1" || host == "localhost" || host == "::1") return true;
    return host.size() >= 4 && host.substr(0, 4) == "127.";
}

static bool IsIpLiteralHost(const std::string& host) {
    in_addr addr4{};
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1) return true;
    in6_addr addr6{};
    if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1) return true;
    return false;
}

static std::string SockaddrToString(const sockaddr* addr) {
    if (!addr) return "";
    if (addr->sa_family == AF_INET) {
        const auto* addr4 = (const sockaddr_in*)addr;
        char buf[INET_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET, &addr4->sin_addr, buf, sizeof(buf))) return "";
        return std::string(buf) + ":" + std::to_string(ntohs(addr4->sin_port));
    }
    return "";
}

static std::wstring Utf8ToWide(const std::string& input) {
    if (input.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, NULL, 0);
    if (len <= 0) return L"";
    std::wstring result(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &result[0], len);
    if (!result.empty() && result.back() == L'\0') result.pop_back();
    return result;
}

static bool IsProxySelfTarget(const std::string& host, uint16_t port, const Core::ProxyConfig& proxy, int effectivePort) {
    return port == effectivePort && (host == proxy.host || host == "127.0.0.1");
}

static bool BuildProxyAddr(const Core::ProxyConfig& proxy, int port, sockaddr_in* proxyAddr, const sockaddr_in* baseAddr) {
    if (!proxyAddr) return false;
    if (baseAddr) {
        *proxyAddr = *baseAddr;
    } else {
        memset(proxyAddr, 0, sizeof(sockaddr_in));
        proxyAddr->sin_family = AF_INET;
    }
    if (inet_pton(AF_INET, proxy.host.c_str(), &proxyAddr->sin_addr) != 1) {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* res = nullptr;
        // 注意：这里调用的是原始函数指针，避免递归
        int rc = fpGetAddrInfo ? fpGetAddrInfo(proxy.host.c_str(), nullptr, &hints, &res)
                               : getaddrinfo(proxy.host.c_str(), nullptr, &hints, &res);
        if (rc != 0 || !res) {
            // 减少日志：仅在失败时记录
            Core::Logger::Error("代理地址解析失败: " + proxy.host);
            return false;
        }
        auto* addr = (sockaddr_in*)res->ai_addr;
        proxyAddr->sin_addr = addr->sin_addr;
        freeaddrinfo(res);
    }
    proxyAddr->sin_port = htons(port);
    return true;
}

static bool ResolveNameToAddr(const std::string& node, const std::string& service, sockaddr_in* out) {
    if (!out || node.empty()) return false;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    const char* serviceStr = service.empty() ? nullptr : service.c_str();
    int rc = fpGetAddrInfo ? fpGetAddrInfo(node.c_str(), serviceStr, &hints, &res)
                           : getaddrinfo(node.c_str(), serviceStr, &hints, &res);
    if (rc != 0 || !res) {
        return false;
    }
    *out = *(sockaddr_in*)res->ai_addr;
    freeaddrinfo(res);
    return true;
}

static bool DoProxyHandshake(SOCKET s, const std::string& host, uint16_t port) {
    auto& config = Core::Config::Instance();
    if (config.proxy.type == "socks5") {
        if (!Network::Socks5Client::Handshake(s, host, port)) {
            // Core::Logger::Error("SOCKS5 握手失败");
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }
    } else if (config.proxy.type == "http") {
        if (!Network::HttpConnectClient::Handshake(s, host, port)) {
            // Core::Logger::Error("HTTP CONNECT 握手失败");
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }
    }
    return true;
}

static void PurgeStaleConnectExContexts(ULONGLONG now) {
    for (auto it = g_connectExPending.begin(); it != g_connectExPending.end(); ) {
        if (now - it->second.createdTick > kConnectExPendingTtlMs) {
            it = g_connectExPending.erase(it);
        } else {
            ++it;
        }
    }
}

static void SaveConnectExContext(LPOVERLAPPED ovl, const ConnectExContext& ctx) {
    std::lock_guard<std::mutex> lock(g_connectExMtx);
    ULONGLONG now = GetTickCount64();
    PurgeStaleConnectExContexts(now);
    ConnectExContext copy = ctx;
    copy.createdTick = now;
    g_connectExPending[ovl] = copy;
}

static bool PopConnectExContext(LPOVERLAPPED ovl, ConnectExContext* out) {
    std::lock_guard<std::mutex> lock(g_connectExMtx);
    auto it = g_connectExPending.find(ovl);
    if (it == g_connectExPending.end()) return false;
    if (out) *out = it->second;
    g_connectExPending.erase(it);
    return true;
}

static void DropConnectExContext(LPOVERLAPPED ovl) {
    std::lock_guard<std::mutex> lock(g_connectExMtx);
    g_connectExPending.erase(ovl);
}

static bool HandleConnectExCompletion(LPOVERLAPPED ovl) {
    ConnectExContext ctx{};
    if (!PopConnectExContext(ovl, &ctx)) return true;
    if (!DoProxyHandshake(ctx.sock, ctx.host, ctx.port)) {
        return false;
    }
    if (ctx.sendBuf && ctx.sendLen > 0) {
        int sent = fpSend ? fpSend(ctx.sock, ctx.sendBuf, (int)ctx.sendLen, 0) : send(ctx.sock, ctx.sendBuf, (int)ctx.sendLen, 0);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            WSASetLastError(err);
            return false;
        }
        if (ctx.bytesSent) {
            *ctx.bytesSent = (DWORD)sent;
        }
    }
    return true;
}

BOOL PASCAL DetourConnectEx(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
);

// 执行代理连接逻辑
int PerformProxyConnect(SOCKET s, const struct sockaddr* name, int namelen, bool isWsa) {
    auto& config = Core::Config::Instance();
    
    // 移除 SocketWrapper 的超时设置，避免干扰原始逻辑
    // Network::SocketWrapper sock(s);
    // sock.SetTimeouts(config.timeout.recv_ms, config.timeout.send_ms);
    
    if (!name || namelen < (int)sizeof(sockaddr)) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    if (name->sa_family != AF_INET) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    std::string originalHost;
    uint16_t originalPort = 0;
    if (!ResolveOriginalTarget(name, &originalHost, &originalPort)) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }

    if (IsLoopbackHost(originalHost)) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    int effectivePort = config.GetEffectivePort();

    if (config.proxy.port == 0 && effectivePort == 0) {
        effectivePort = Network::ProxyDetector::Detect();
        if (effectivePort > 0) {
            config.SetDynamicPort(effectivePort);
        }
    }

    if (IsProxySelfTarget(originalHost, originalPort, config.proxy, effectivePort)) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    if (originalPort == 53) {
        if (config.rules.dns_mode == "direct" || config.rules.dns_mode.empty()) {
            return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL)
                         : fpConnect(s, name, namelen);
        }
    }
    
    if (!config.rules.IsPortAllowed(originalPort)) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL)
                     : fpConnect(s, name, namelen);
    }
    
    if (effectivePort != 0) {
        // 减少日志：仅记录关键重定向
        // Core::Logger::Info("Redirect: " + originalHost + ":" + std::to_string(originalPort));
        
        sockaddr_in proxyAddr{};
        if (!BuildProxyAddr(config.proxy, effectivePort, &proxyAddr, (sockaddr_in*)name)) {
            return SOCKET_ERROR;
        }
        
        int result = isWsa ?
            fpWSAConnect(s, (sockaddr*)&proxyAddr, sizeof(proxyAddr), NULL, NULL, NULL, NULL) :
            fpConnect(s, (sockaddr*)&proxyAddr, sizeof(proxyAddr));
        
        if (result != 0 && config.proxy.port == 0) {
            int err = WSAGetLastError();
            if (err == WSAECONNREFUSED || err == WSAETIMEDOUT) {
                config.InvalidateDynamicPort();
                int newPort = Network::ProxyDetector::Detect();
                if (newPort > 0 && newPort != effectivePort) {
                    config.SetDynamicPort(newPort);
                    if (BuildProxyAddr(config.proxy, newPort, &proxyAddr, (sockaddr_in*)name)) {
                        result = isWsa ?
                            fpWSAConnect(s, (sockaddr*)&proxyAddr, sizeof(proxyAddr), NULL, NULL, NULL, NULL) :
                            fpConnect(s, (sockaddr*)&proxyAddr, sizeof(proxyAddr));
                    }
                }
            }
        }

        if (result != 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                if (!Network::SocketIo::WaitConnect(s, config.timeout.connect_ms)) {
                    return SOCKET_ERROR;
                }
            } else {
                return result;
            }
        }
        
        if (!DoProxyHandshake(s, originalHost, originalPort)) {
            return SOCKET_ERROR;
        }
        
        return 0;
    }
    
    return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
}

// ============= Phase 1: 网络 Hook 函数实现 =============

int WSAAPI DetourConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    return PerformProxyConnect(s, name, namelen, false);
}

int WSAAPI DetourWSAConnect(SOCKET s, const struct sockaddr* name, int namelen, 
                            LPWSABUF lpCallerData, LPWSABUF lpCalleeData, 
                            LPQOS lpSQOS, LPQOS lpGQOS) {
    return PerformProxyConnect(s, name, namelen, true);
}

int WSAAPI DetourGetAddrInfo(PCSTR pNodeName, PCSTR pServiceName, 
                              const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    auto& config = Core::Config::Instance();
    
    if (!fpGetAddrInfo) return EAI_FAIL;

    if (pNodeName && config.fakeIp.enabled) {
        std::string node = pNodeName;
        if (!node.empty() && !IsLoopbackHost(node) && !IsIpLiteralHost(node)) {
            // Core::Logger::Info("DNS: " + node);
            uint32_t fakeIp = Network::FakeIP::Instance().Alloc(node);
            if (fakeIp != 0) {
                std::string fakeIpStr = Network::FakeIP::IpToString(fakeIp);
                return fpGetAddrInfo(fakeIpStr.c_str(), pServiceName, pHints, ppResult);
            }
        }
    }

    return fpGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
}

int WSAAPI DetourGetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, 
                              const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    auto& config = Core::Config::Instance();
    
    if (!fpGetAddrInfoW) return EAI_FAIL;

    if (pNodeName && config.fakeIp.enabled) {
        std::string nodeUtf8 = WideToUtf8(pNodeName);
        if (!nodeUtf8.empty() && !IsLoopbackHost(nodeUtf8) && !IsIpLiteralHost(nodeUtf8)) {
            // Core::Logger::Info("DNS(W): " + nodeUtf8);
            uint32_t fakeIp = Network::FakeIP::Instance().Alloc(nodeUtf8);
            if (fakeIp != 0) {
                std::string fakeIpStr = Network::FakeIP::IpToString(fakeIp);
                std::wstring fakeIpW = Utf8ToWide(fakeIpStr);
                return fpGetAddrInfoW(fakeIpW.c_str(), pServiceName, pHints, ppResult);
            }
        }
    }

    return fpGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

struct hostent* WSAAPI DetourGetHostByName(const char* name) {
    auto& config = Core::Config::Instance();
    if (!fpGetHostByName) return NULL;

    if (name && config.fakeIp.enabled) {
        std::string node = name;
        if (!node.empty() && !IsLoopbackHost(node) && !IsIpLiteralHost(node)) {
            uint32_t fakeIp = Network::FakeIP::Instance().Alloc(node);
            if (fakeIp != 0) {
                std::string fakeIpStr = Network::FakeIP::IpToString(fakeIp);
                return fpGetHostByName(fakeIpStr.c_str());
            }
        }
    }
    return fpGetHostByName(name);
}

BOOL WSAAPI DetourWSAConnectByNameA(
    SOCKET s,
    LPCSTR nodename,
    LPCSTR servicename,
    LPDWORD LocalAddressLength,
    LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength,
    LPSOCKADDR RemoteAddress,
    const struct timeval* timeout,
    LPWSAOVERLAPPED Reserved
) {
    if (!fpWSAConnectByNameA) return FALSE;
    // 简化处理：直接回退到原始函数，暂不支持 WSAConnectByName 的代理
    // 因为这个函数比较少用，且逻辑复杂
    return fpWSAConnectByNameA(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
}

BOOL WSAAPI DetourWSAConnectByNameW(
    SOCKET s,
    LPWSTR nodename,
    LPWSTR servicename,
    LPDWORD LocalAddressLength,
    LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength,
    LPSOCKADDR RemoteAddress,
    const struct timeval* timeout,
    LPWSAOVERLAPPED Reserved
) {
    if (!fpWSAConnectByNameW) return FALSE;
    return fpWSAConnectByNameW(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
}

int WSAAPI DetourWSAIoctl(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    if (!fpWSAIoctl) return SOCKET_ERROR;
    // 暂时禁用 ConnectEx Hook 的安装，以排除 IOCP 导致的崩溃
    return fpWSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer,
                            lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
}

BOOL PASCAL DetourConnectEx(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
) {
    // 永远不会被调用，因为 WSAIoctl Hook 已禁用
    if (fpConnectEx) return fpConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    return FALSE;
}

BOOL WSAAPI DetourWSAGetOverlappedResult(
    SOCKET s,
    LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer,
    BOOL fWait,
    LPDWORD lpdwFlags
) {
    if (!fpWSAGetOverlappedResult) return FALSE;
    return fpWSAGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags);
}

BOOL WINAPI DetourGetQueuedCompletionStatus(
    HANDLE CompletionPort,
    LPDWORD lpNumberOfBytes,
    PULONG_PTR lpCompletionKey,
    LPOVERLAPPED* lpOverlapped,
    DWORD dwMilliseconds
) {
    if (!fpGetQueuedCompletionStatus) return FALSE;
    return fpGetQueuedCompletionStatus(CompletionPort, lpNumberOfBytes, lpCompletionKey, lpOverlapped, dwMilliseconds);
}

BOOL WINAPI DetourGetQueuedCompletionStatusEx(
    HANDLE CompletionPort,
    LPOVERLAPPED_ENTRY lpCompletionPortEntries,
    ULONG ulCount,
    PULONG ulNumEntriesRemoved,
    DWORD dwMilliseconds,
    BOOL fAlertable
) {
    if (!fpGetQueuedCompletionStatusEx) return FALSE;
    return fpGetQueuedCompletionStatusEx(CompletionPort, lpCompletionPortEntries, ulCount, ulNumEntriesRemoved, dwMilliseconds, fAlertable);
}

BOOL WINAPI DetourCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    auto& config = Core::Config::Instance();
    
    DWORD modifiedFlags = dwCreationFlags;
    bool shouldInject = config.childInjection;
    
    if (shouldInject) {
        modifiedFlags |= CREATE_SUSPENDED;
    }
    
    BOOL result = fpCreateProcessW(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, modifiedFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation
    );
    
    if (result && shouldInject && lpProcessInformation) {
        // 简化逻辑：不再解析进程名，直接注入所有子进程（如果配置允许）
        // 或者只做最简单的注入，不写日志

        std::wstring dllPath = Injection::ProcessInjector::GetCurrentDllPath();
        if (!dllPath.empty()) {
            Injection::ProcessInjector::InjectDll(lpProcessInformation->hProcess, dllPath);
        }
        
        if (!(dwCreationFlags & CREATE_SUSPENDED)) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }
    
    return result;
}

int WSAAPI DetourSend(SOCKET s, const char* buf, int len, int flags) {
    // 禁用流量监控日志，避免高频 I/O
    return fpSend(s, buf, len, flags);
}

int WSAAPI DetourRecv(SOCKET s, char* buf, int len, int flags) {
    return fpRecv(s, buf, len, flags);
}

int WSAAPI DetourWSASend(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    return fpWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

int WSAAPI DetourWSARecv(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    return fpWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

namespace Hooks {
    template<typename T>
    void SafeCreateHook(LPCWSTR moduleName, LPCSTR procName, LPVOID detour, T* original) {
        if (MH_CreateHookApi(moduleName, procName, detour, (LPVOID*)original) == MH_OK) {
            MH_EnableHook((LPVOID)*original);
        }
    }

    void Install() {
        if (MH_Initialize() != MH_OK) return;
        
        // 仅启用最核心、最稳定的 Hook
        SafeCreateHook(L"ws2_32.dll", "connect", (LPVOID)DetourConnect, &fpConnect);
        SafeCreateHook(L"ws2_32.dll", "WSAConnect", (LPVOID)DetourWSAConnect, &fpWSAConnect);
        SafeCreateHook(L"ws2_32.dll", "getaddrinfo", (LPVOID)DetourGetAddrInfo, &fpGetAddrInfo);
        SafeCreateHook(L"ws2_32.dll", "GetAddrInfoW", (LPVOID)DetourGetAddrInfoW, &fpGetAddrInfoW);
        SafeCreateHook(L"ws2_32.dll", "gethostbyname", (LPVOID)DetourGetHostByName, &fpGetHostByName);

        // 恢复 CreateProcessW Hook，但逻辑已简化
        SafeCreateHook(L"kernel32.dll", "CreateProcessW", (LPVOID)DetourCreateProcessW, &fpCreateProcessW);
        
        Core::Logger::Info("Antigravity-Proxy Hooks Installed (Minimal Mode)");
    }
    
    void Uninstall() {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
}
