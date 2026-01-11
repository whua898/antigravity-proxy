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
void InitializationThread() {
    // 针对 PyCharm/JVM 的特殊优化：
    // JVM 启动初期极其脆弱，任何对内存/线程的修改都可能导致 crash 或 1114 错误。
    // 我们给予 1000ms 的"安全窗口"，让 JVM 完成核心初始化 (加载 jvm.dll, 初始化 GC 等)。
    // 对于 IDE 插件代理来说，这个延迟是完全可以接受的。
    Sleep(1000);

    // 加载配置
    Core::Config::Instance().Load("config.json");

    // 安装 Hooks
    // 注意：MinHook 内部会挂起线程，这在 JVM 环境下仍有风险，但延迟 1s 后风险大幅降低
    Hooks::Install();

    Core::Logger::Info("Antigravity-Proxy 初始化完成 (Delayed 1000ms)");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);

        // VersionProxy 懒加载
        VersionProxy::Initialize();
        
        // 启动异步初始化线程
        {
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitializationThread, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            }
        }
        break;
        
    case DLL_PROCESS_DETACH:
        // 卸载时也要小心，避免在 JVM 卸载过程中 crash
        // 简单起见，如果进程正在退出，可能不需要显式卸载 Hook
        if (lpvReserved == NULL) { // FreeLibrary 调用
            Hooks::Uninstall();
            VersionProxy::Uninitialize();
        }
        break;
    }
    return TRUE;
}
