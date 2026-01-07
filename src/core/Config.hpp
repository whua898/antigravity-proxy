#pragma once
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include "Logger.hpp"

namespace Core {
    struct ProxyConfig {
        std::string host = "127.0.0.1";
        int port = 7890;
        std::string type = "socks5";
    };

    struct FakeIPConfig {
        bool enabled = true;
        std::string cidr = "10.0.0.0/8";
    };

    struct TimeoutConfig {
        int connect_ms = 5000;
        int send_ms = 5000;
        int recv_ms = 5000;
    };

    class Config {
    public:
        ProxyConfig proxy;
        FakeIPConfig fakeIp;
        TimeoutConfig timeout;
        bool trafficLogging = false;    // Phase 3: 是否启用流量监控日志
        bool childInjection = true;     // Phase 2: 是否自动注入子进程
        std::vector<std::string> targetProcesses; // 目标进程列表 (空=全部)

        // 检查进程名是否在目标列表中 (大小写不敏感)
        bool ShouldInject(const std::string& processName) const {
            // 如果列表为空，注入所有进程
            if (targetProcesses.empty()) return true;
            
            // 将输入转为小写进行比较
            std::string lowerName = processName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), 
                [](unsigned char c) { return std::tolower(c); });
            
            for (const auto& target : targetProcesses) {
                std::string lowerTarget = target;
                std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
                    [](unsigned char c) { return std::tolower(c); });
                
                // 支持完全匹配或不带扩展名匹配
                if (lowerName == lowerTarget) return true;
                // 支持类似 "language_server_windows" 匹配 "language_server_windows.exe"
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
                std::ifstream f(path);
                if (!f.is_open()) {
                    Logger::Error("Failed to open config.json");
                    return false;
                }
                nlohmann::json j = nlohmann::json::parse(f);
                
                if (j.contains("proxy")) {
                    auto& p = j["proxy"];
                    proxy.host = p.value("host", "127.0.0.1");
                    proxy.port = p.value("port", 7890);
                    proxy.type = p.value("type", "socks5");
                }

                if (j.contains("fake_ip")) {
                    auto& fip = j["fake_ip"];
                    fakeIp.enabled = fip.value("enabled", true);
                    fakeIp.cidr = fip.value("cidr", "10.0.0.0/8");
                }

                if (j.contains("timeout")) {
                    auto& t = j["timeout"];
                    timeout.connect_ms = t.value("connect", 5000);
                    timeout.send_ms = t.value("send", 5000);
                    timeout.recv_ms = t.value("recv", 5000);
                }

                // Phase 2/3 配置项
                trafficLogging = j.value("traffic_logging", false);
                childInjection = j.value("child_injection", true);

                // 目标进程列表
                if (j.contains("target_processes") && j["target_processes"].is_array()) {
                    targetProcesses.clear();
                    for (const auto& item : j["target_processes"]) {
                        if (item.is_string()) {
                            targetProcesses.push_back(item.get<std::string>());
                        }
                    }
                    Logger::Info("已加载目标进程列表, 共 " + std::to_string(targetProcesses.size()) + " 项");
                }

                Logger::Info("配置: proxy=" + proxy.host + ":" + std::to_string(proxy.port) +
                             " type=" + proxy.type +
                             ", fake_ip=" + std::string(fakeIp.enabled ? "true" : "false") +
                             ", child_injection=" + std::string(childInjection ? "true" : "false") +
                             ", traffic_logging=" + std::string(trafficLogging ? "true" : "false"));
                Logger::Info("Config loaded successfully.");
                return true;
            } catch (const std::exception& e) {
                Logger::Error(std::string("Config parse error: ") + e.what());
                return false;
            }
        }
    };
}
