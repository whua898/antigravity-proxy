# Antigravity-Proxy 开发文档

## 📜 项目开发历程

### 2026-01-07: 项目重构 (Scheme B)
- **目标**: 基于现有 MinHook 框架，现代化重构代理注入逻辑
- **决策**: 
  - 放弃 1:1 复刻伪代码方案
  - 采用现代 C++ (C++17) 重写
  - 使用 JSON 配置替代原有的 INI 格式
- **产出**: 
  - 核心模块: `Config.hpp`, `Logger.hpp`
  - 网络模块: `SocketWrapper.hpp`, `FakeIP.hpp`
  - Hook 模块: `Hooks.cpp`

---

## 🏗️ 架构设计说明

### 设计原则
本项目严格遵循以下设计原则:

| 原则 | 应用 |
|------|------|
| **KISS** | 保持简单的网络重定向逻辑，不引入复杂的异步框架 |
| **YAGNI** | 仅实现当前需要的功能，不做过度设计 |
| **SOLID/SRP** | 分离配置 (Config)、日志 (Logger)、网络 (Network)、Hook (Hooks) 职责 |

### 模块架构

```
┌─────────────────────────────────────────────────────────────┐
│                      DLL Entry (main.cpp)                    │
│  - 加载配置                                                   │
│  - 初始化日志                                                 │
│  - 安装 Hooks                                                │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
   │ Core Module  │   │Network Module│   │ Hooks Module │
   │ - Config     │   │ - Socket     │   │ - connect()  │
   │ - Logger     │   │ - FakeIP     │   │ - getaddrinfo│
   └──────────────┘   └──────────────┘   └──────────────┘
```

### 错误处理策略
- **Fail-Safe**: 配置加载失败或 Hook 失败时，不崩溃，仅记录日志并让目标程序继续运行

---

## 🔑 重要技术决策

### 1. 选择 MinHook 作为 Hook 引擎
**原因**:
- 轻量级，无外部依赖
- 支持 x86 和 x64
- 稳定性高，广泛使用

### 2. 使用 nlohmann/json 作为 JSON 库
**原因**:
- 单头文件，易于集成
- 现代 C++ 风格
- 异常安全

### 3. 放弃跨平台支持
**原因**:
- MinHook 仅支持 Windows
- Winsock API 为 Windows 特有
- 跨平台需要大量重构，不符合当前需求优先级

---

## 📋 待改进项

- [ ] 实现完整的 SOCKS5 握手协议
- [ ] 支持 HTTP CONNECT 代理
- [ ] 添加规则匹配 (仅代理特定域名/IP)
- [ ] 配置热重载功能
- [ ] 性能优化 (减少锁竞争)

---

## 📚 参考资料

- [MinHook GitHub](https://github.com/TsudaKageyu/minhook)
- [nlohmann/json](https://github.com/nlohmann/json)
- [Winsock2 Documentation](https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2)
