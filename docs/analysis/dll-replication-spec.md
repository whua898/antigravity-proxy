# Technical Specification: Antigravity-Proxy (Scheme B)

## 1. Overview
This document defines the technical specification for the "Antigravity-Proxy" module, a modern C++ implementation of the proxy injection logic found in legacy DLLs.

## 2. Architecture

### 2.1 Design Philosophy
- **KISS**: Simple, stateless network redirection.
- **YAGNI**: No over-engineered "plugin systems" or cross-platform abstractions at the implementation layer.
- **SOLID**:
    - **SRP**: `Config` loads JSON, `Hooks` intercepts API, `Network` handles sockets.
    - **DIP**: High-level logic depends on `IHookBackend` (conceptual), implemented by MinHook.

### 2.2 Module Structure
```
src/
├── core/
│   ├── Config.hpp          # JSON Config Loader (nlohmann/json)
│   ├── Logger.hpp          # File-based logging (proxy.log)
│   └── Globals.hpp         # Global state (Config instance)
├── network/
│   ├── SocketWrapper.hpp   # Winsock RAII wrappers
│   └── FakeIP.hpp          # Fake IP address allocator/mapper
├── hooks/
│   ├── LocalHooks.hpp      # Hook installation logic
│   ├── Hook_Connect.cpp    # connect() interception
│   └── Hook_DNS.cpp        # getaddrinfo() interception
└── main.cpp                # DllMain entry point
```

## 3. Detailed Design

### 3.1 Configuration (`config.json`)
The module loads `config.json` from the DLL directory on startup.
```json
{
    "proxy": {
        "host": "127.0.0.1",
        "port": 7890,
        "type": "socks5"
    },
    "fake_ip": {
        "enabled": true,
        "cidr": "10.0.0.0/8"
    },
    "timeout": {
        "connect": 5000,
        "send": 5000,
        "recv": 5000
    }
}
```

### 3.2 Feature: Proxy Redirection
- **Trigger**: `connect()` API.
- **Logic**:
    1. Check if destination IP matches any rule (or all, if global).
    2. If matched, rewrite `sockaddr_in` to point to `ProxyHost:ProxyPort`.
    3. (Optional) Perform SOCKS5 handshake if `type` is `socks5` (Simplified for Phase 1: Direct TCP forwarding assumed, or basic SOCKS5 handshake implementation if time permits. Defaulting to **Transparent Redirect** or **Basic Forwarding** as per pseudocode).
    *Correction*: Pseudocode implies reading `ProxyHost` and just connecting. It might rely on an external transparency tool or simple redirection. We will implement **Redirection** (changing destination to Proxy).

### 3.3 Feature: Fake IP
- **Trigger**: `getaddrinfo()`, `gethostbyname()`.
- **Logic**:
    1. Generate a unique IP in `10.x.x.x` range.
    2. Store mapping `10.x.x.x -> Real Domain`.
    3. Return `10.x.x.x` to application.
    4. On `connect(10.x.x.x)`, lookup Real Domain and forward to Proxy (socks5 command).

### 3.4 Feature: Timeout Control
- **Logic**:
    - On `socket()` or `connect()`, call `setsockopt` with `SO_RCVTIMEO` and `SO_SNDTIMEO`.

### 4. Implementation Constraints
- **Language**: C++17.
- **Dependencies**: `MinHook` (Existing), `nlohmann/json` (New).
- **Platform**: Windows (Winsock2).
- **Error Handling**: Fail-Safe (Log error, disable feature, continue app execution).

## 5. Build System
- **CMake**: Update `CMakeLists.txt` to include new sources and link `ws2_32`.
