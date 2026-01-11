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
    // 调试模式：先写个日志证明线程跑起来了
    // 注意：此时 Config 还没加载，日志会写到默认位置
    // Core::Logger::Info("Debug: Init thread started, waiting 3s...");

    // 延长等待时间到 3 秒，确保 PyCharm 界面完全出来
    Sleep(3000);

    // Core::Logger::Info("Debug: Loading config...");
    Core::Config::Instance().Load("config.json");

    // Core::Logger::Info("Debug: Installing hooks...");
    Hooks::Install();

    Core::Logger::Info("Antigravity-Proxy 初始化完成 (Delayed 3000ms)");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);

        // 1. 优先保证 DLL 转发功能正常
        VersionProxy::Initialize();
        
        // 2. 启动 Hook 线程
        // 如果 PyCharm 启动失败，请尝试注释掉下面这块代码块，
        // 如果注释后能启动，说明是 Hook 逻辑冲突；如果还不能，说明是 DLL 转发/架构问题。
        {
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitializationThread, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            }
        }
        break;
        
    case DLL_PROCESS_DETACH:
        if (lpvReserved == NULL) {
            Hooks::Uninstall();
            VersionProxy::Uninitialize();
        }
        break;
    }
    return TRUE;
}
