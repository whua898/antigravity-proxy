#include <windows.h>
#include "core/Config.hpp"
#include "core/Logger.hpp"

namespace Hooks {
    void Install();
    void Uninstall();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        Core::Logger::Info("Antigravity-Proxy DLL Loaded");
        Core::Config::Instance().Load("config.json"); // Load config
        Hooks::Install();
        break;
    case DLL_PROCESS_DETACH:
        Hooks::Uninstall();
        Core::Logger::Info("Antigravity-Proxy DLL Unloaded");
        break;
    }
    return TRUE;
}
