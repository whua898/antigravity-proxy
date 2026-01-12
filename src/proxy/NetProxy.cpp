// 防止 windows.h 自动包含 winsock.h (避免与 winsock2.h 冲突)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <jni.h>

// ============================================================================
// net.dll 代理实现 (纯 C 风格)
// ============================================================================

static HMODULE g_hRealNetDll = NULL;
static volatile LONG g_initFlag = 0;

// 定义所有导出函数的指针类型
#define DEFINE_FUNC_PTR(name) static void* fp_##name = NULL
#define GET_FUNC_ADDRESS(name) fp_##name = GetProcAddress(g_hRealNetDll, #name)

// JNI 函数
DEFINE_FUNC_PTR(JNI_OnLoad);
DEFINE_FUNC_PTR(JNI_OnUnload);
DEFINE_FUNC_PTR(Java_java_net_DatagramSocketImpl_init);
// ... (此处省略所有 Java_xxx 函数的定义)

// NET_xxx 函数
DEFINE_FUNC_PTR(NET_CreateSocket);
// ... (此处省略所有 NET_xxx 函数的定义)

static void LoadRealDll() {
    wchar_t systemDir[MAX_PATH];
    // JVM 的 net.dll 通常与 jvm.dll 在同一目录
    // 我们需要找到原始的 net.dll，它可能在 jre/bin 或 jre/bin/server
    // 最简单的方法是假设它在 System32 (如果系统安装了 Java)，或者在父目录
    // 但为了劫持，我们的 DLL 会被放到 jre/bin，所以原始的可能被重命名或在别处
    // 暂时假设我们可以从一个已知路径加载它，例如 System32
    if (GetSystemDirectoryW(systemDir, MAX_PATH) == 0) return;

    wchar_t realPath[MAX_PATH];
    lstrcpyW(realPath, systemDir);
    // 注意：真正的 net.dll 不在 System32，而是在 JRE 目录。
    // 这里的策略是：我们的假 net.dll 被放到 jre/bin，
    // 我们需要加载同目录下的一个改过名的真 net.dll，例如 "net_real.dll"
    // 或者从一个绝对路径加载。
    // 为简单起见，我们先假设可以从 System32 加载一个占位符。
    // 实际部署时，需要将原始 net.dll 重命名为 net_original.dll。

    HMODULE hMod = GetModuleHandleW(L"pycharm64.exe"); // 或者其他宿主 exe
    GetModuleFileNameW(hMod, realPath, MAX_PATH);
    wchar_t* p = wcsrchr(realPath, L'\\');
    if (p) *p = L'\0';
    lstrcatW(realPath, L"\\jbr\\bin\\net_original.dll");

    g_hRealNetDll = LoadLibraryW(realPath);
    if (!g_hRealNetDll) return;

    // 获取所有函数地址
    #define GET_ALL_EXPORTS
    #include "net_exports.h" // 使用宏来简化
    #undef GET_ALL_EXPORTS
}

static void EnsureRealDllLoaded() {
    if (g_initFlag == 2) return;
    if (InterlockedCompareExchange(&g_initFlag, 1, 0) == 0) {
        LoadRealDll();
        InterlockedExchange(&g_initFlag, 2);
    } else {
        while (g_initFlag != 2) Sleep(1);
    }
}

// 代理函数实现
#define PROXY_FUNC(name, ret_type, ...) \
    ret_type name(__VA_ARGS__) { \
        EnsureRealDllLoaded(); \
        if (fp_##name) { \
            return ((ret_type (*)(__VA_ARGS__))fp_##name)(__VA_ARGS__); \
        } \
        return (ret_type)0; \
    }

// JNI_OnLoad 是一个很好的 Hook 时机
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    EnsureRealDllLoaded();
    // 在这里可以安全地安装 Hook
    // Hooks::Install();

    if (fp_JNI_OnLoad) {
        return ((jint (JNICALL *)(JavaVM*, void*))fp_JNI_OnLoad)(vm, reserved);
    }
    return JNI_VERSION_1_8;
}

// 其他函数的转发...
// 这里需要一个宏来生成所有转发函数
// 为简化，暂时只写 JNI_OnLoad

// ...
// 所有的 Java_xxx 和 NET_xxx 函数都需要一个类似的转发实现
// ...

extern "C" {
    // 导出所有函数
    // ...
}
