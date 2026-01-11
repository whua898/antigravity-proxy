// 防止 windows.h 自动包含 winsock.h (避免与 winsock2.h 冲突)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <thread>
#include "core/Config.hpp"
#include "core/Logger.hpp"

// 前向声明
namespace Hooks {
    void Install();
    void Uninstall();
}

namespace VersionProxy {
    bool Initialize();
    void Uninitialize();
}

// 初始化线程函数
// 将 Hook 安装移出 DllMain，避免 Loader Lock 导致的死锁或初始化失败 (如 os error 1114)
void InitializationThread() {
    // 稍微延迟一下，确保宿主进程的主要模块已加载
    Sleep(100);

    // 加载配置
    Core::Config::Instance().Load("config.json");

    // 安装 Hooks
    Hooks::Install();

    Core::Logger::Info("Antigravity-Proxy 初始化完成 (Thread Mode)");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);

        // VersionProxy 采用懒加载模式，此处仅做占位
        VersionProxy::Initialize();
        
        // 关键修正：不要在 DllMain 中直接安装 Hook
        // PyCharm/JVM 等复杂应用在加载 DLL 时非常敏感，直接 Hook 易导致 ERROR_DLL_INIT_FAILED
        // 创建一个线程来异步执行初始化
        {
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitializationThread, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            } else {
                // 如果线程创建失败，回退到同步尝试（虽然风险大，但总比什么都不做强）
                InitializationThread();
            }
        }
        break;
        
    case DLL_PROCESS_DETACH:
        Hooks::Uninstall();
        VersionProxy::Uninitialize();
        break;
    }
    return TRUE;
}
