#pragma once
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
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
                Logger::Info("Config loaded successfully.");
                return true;
            } catch (const std::exception& e) {
                Logger::Error(std::string("Config parse error: ") + e.what());
                return false;
            }
        }
    };
}
