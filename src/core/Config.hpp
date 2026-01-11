#pragma once
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <atomic>
#include "Logger.hpp"

// 前向声明，避免循环依赖
namespace Network { class ProxyDetector; }

namespace Core {
    struct ProxyConfig {
        std::string host = "127.0.0.1";
        int port = 0; // 默认 0 (自动探测)
        std::string type = "socks5";
    };

    struct FakeIPConfig {
        bool enabled = true;
        std::string cidr = "198.18.0.0/15";
    };

    struct TimeoutConfig {
        int connect_ms = 5000;
        int send_ms = 5000;
        int recv_ms = 5000;
    };

    struct ProxyRules {
        std::vector<uint16_t> allowed_ports = {80, 443};
        std::string dns_mode = "direct";
        
        bool IsPortAllowed(uint16_t port) const {
            if (allowed_ports.empty()) return true;
            return std::find(allowed_ports.begin(), allowed_ports.end(), port) 
                   != allowed_ports.end();
        }
    };

    class Config {
    private:
        // 动态探测到的端口缓存 (原子操作保证线程安全)
        std::atomic<int> m_dynamicPort{0};

        static bool IsAbsolutePath(const std::string& path) {
            if (path.size() >= 2 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':') {
                return true;
            }
            if (path.size() >= 2 &&
                ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/'))) {
                return true;
            }
            return false;
        }

        static std::string GetModuleDirectory() {
            char modulePath[MAX_PATH] = {0};
            HMODULE hModule = NULL;
            if (!GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(&GetModuleDirectory),
                &hModule
            )) {
                return "";
            }
            DWORD len = GetModuleFileNameA(hModule, modulePath, MAX_PATH);
            if (len == 0 || len >= MAX_PATH) {
                return "";
            }
            for (int i = static_cast<int>(len) - 1; i >= 0; --i) {
                if (modulePath[i] == '\\' || modulePath[i] == '/') {
                    modulePath[i] = '\0';
                    break;
                }
            }
            return std::string(modulePath);
        }

    public:
        ProxyConfig proxy;
        FakeIPConfig fakeIp;
        TimeoutConfig timeout;
        ProxyRules rules;
        bool trafficLogging = false;
        bool childInjection = true;
        std::vector<std::string> targetProcesses;

        // 获取当前有效的代理端口
        // 如果配置为 0 (自动)，则尝试返回已探测的端口
        // 注意：这里不执行探测，探测逻辑下沉到 Hooks.cpp 中按需调用，避免引入 Network 依赖
        int GetEffectivePort() const {
            if (proxy.port > 0) return proxy.port;
            return m_dynamicPort.load();
        }

        // 设置动态探测到的端口
        void SetDynamicPort(int port) {
            m_dynamicPort.store(port);
        }

        // 标记当前动态端口无效（触发重探）
        void InvalidateDynamicPort() {
            if (proxy.port == 0) {
                m_dynamicPort.store(0);
            }
        }

        bool ShouldInject(const std::string& processName) const {
            if (targetProcesses.empty()) return true;
            std::string lowerName = processName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), 
                [](unsigned char c) { return std::tolower(c); });
            for (const auto& target : targetProcesses) {
                std::string lowerTarget = target;
                std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
                    [](unsigned char c) { return std::tolower(c); });
                if (lowerName == lowerTarget) return true;
                if (lowerName.find(lowerTarget) != std::string::npos) return true;
            }
            return false;
        }

        static Config& Instance() {
            static Config instance;
            return instance;
        }

        bool Load(const std::string& path = "config.json") {
            try {
                std::vector<std::string> candidates;
                if (IsAbsolutePath(path)) {
                    candidates.push_back(path);
                } else {
                    std::string dllDir = GetModuleDirectory();
                    if (!dllDir.empty()) {
                        candidates.push_back(dllDir + "\\" + path);
                    }
                    candidates.push_back(path);
                }

                std::ifstream f;
                std::string resolvedPath;
                for (const auto& candidate : candidates) {
                    f.open(candidate);
                    if (f.is_open()) {
                        resolvedPath = candidate;
                        break;
                    }
                    f.clear();
                }

                if (!f.is_open()) {
                    if (IsAbsolutePath(path)) {
                        Logger::Error("打开配置文件失败: " + path);
                    } else {
                        Logger::Error("打开配置文件失败: " + path + " (已尝试 DLL 目录与当前目录)");
                    }
                    return false;
                }
                if (!resolvedPath.empty()) {
                    Logger::Info("使用配置文件路径: " + resolvedPath);
                }
                nlohmann::json j = nlohmann::json::parse(f);

                if (j.contains("proxy")) {
                    auto& p = j["proxy"];
                    proxy.host = p.value("host", "127.0.0.1");
                    proxy.port = p.value("port", 0); // 默认 0 (自动探测)
                    proxy.type = p.value("type", "socks5");
                }

                if (j.contains("fake_ip")) {
                    auto& fip = j["fake_ip"];
                    fakeIp.enabled = fip.value("enabled", true);
                    fakeIp.cidr = fip.value("cidr", "198.18.0.0/15");
                }

                if (j.contains("timeout")) {
                    auto& t = j["timeout"];
                    timeout.connect_ms = t.value("connect", 5000);
                    timeout.send_ms = t.value("send", 5000);
                    timeout.recv_ms = t.value("recv", 5000);
                }

                if (j.contains("proxy_rules")) {
                    auto& pr = j["proxy_rules"];
                    if (pr.contains("allowed_ports") && pr["allowed_ports"].is_array()) {
                        rules.allowed_ports.clear();
                        for (const auto& p : pr["allowed_ports"]) {
                            if (p.is_number_unsigned()) {
                                rules.allowed_ports.push_back(static_cast<uint16_t>(p.get<unsigned int>()));
                            }
                        }
                    }
                    rules.dns_mode = pr.value("dns_mode", "direct");
                }

                trafficLogging = j.value("traffic_logging", false);
                childInjection = j.value("child_injection", true);

                if (j.contains("target_processes") && j["target_processes"].is_array()) {
                    targetProcesses.clear();
                    for (const auto& item : j["target_processes"]) {
                        if (item.is_string()) {
                            targetProcesses.push_back(item.get<std::string>());
                        }
                    }
                }

                // 重置动态端口状态
                m_dynamicPort.store(0);

                Logger::Info("配置: proxy=" + proxy.host + ":" + std::to_string(proxy.port) +
                             " type=" + proxy.type +
                             ", fake_ip=" + std::string(fakeIp.enabled ? "true" : "false") +
                             ", child_injection=" + std::string(childInjection ? "true" : "false"));
                return true;
            } catch (const std::exception& e) {
                Logger::Error(std::string("配置解析失败: ") + e.what());
                return false;
            }
        }
    };
}
