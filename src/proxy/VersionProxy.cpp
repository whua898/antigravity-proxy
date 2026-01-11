// 防止 windows.h 自动包含 winsock.h (避免与 winsock2.h 冲突)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

// ============================================================================
// 纯 C 风格的 VersionProxy
// 移除所有 C++ 标准库依赖 (std::string, std::mutex 等)，避免 CRT 初始化问题
// ============================================================================

static HMODULE g_hRealVersionDll = NULL;
static volatile LONG g_initFlag = 0; // 0: 未初始化, 1: 初始化中, 2: 已初始化

// 函数指针类型定义
typedef BOOL (WINAPI *GetFileVersionInfoA_t)(LPCSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *GetFileVersionInfoByHandle_t)(DWORD, HANDLE, DWORD, LPVOID);
typedef BOOL (WINAPI *GetFileVersionInfoExA_t)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *GetFileVersionInfoExW_t)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *GetFileVersionInfoSizeA_t)(LPCSTR, LPDWORD);
typedef DWORD (WINAPI *GetFileVersionInfoSizeExA_t)(DWORD, LPCSTR, LPDWORD);
typedef DWORD (WINAPI *GetFileVersionInfoSizeExW_t)(DWORD, LPCWSTR, LPDWORD);
typedef DWORD (WINAPI *GetFileVersionInfoSizeW_t)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *GetFileVersionInfoW_t)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *VerFindFileA_t)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD (WINAPI *VerFindFileW_t)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD (WINAPI *VerInstallFileA_t)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
typedef DWORD (WINAPI *VerInstallFileW_t)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
typedef DWORD (WINAPI *VerLanguageNameA_t)(DWORD, LPSTR, DWORD);
typedef DWORD (WINAPI *VerLanguageNameW_t)(DWORD, LPWSTR, DWORD);
typedef BOOL (WINAPI *VerQueryValueA_t)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL (WINAPI *VerQueryValueW_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

// 函数指针实例
static GetFileVersionInfoA_t fp_GetFileVersionInfoA = NULL;
static GetFileVersionInfoByHandle_t fp_GetFileVersionInfoByHandle = NULL;
static GetFileVersionInfoExA_t fp_GetFileVersionInfoExA = NULL;
static GetFileVersionInfoExW_t fp_GetFileVersionInfoExW = NULL;
static GetFileVersionInfoSizeA_t fp_GetFileVersionInfoSizeA = NULL;
static GetFileVersionInfoSizeExA_t fp_GetFileVersionInfoSizeExA = NULL;
static GetFileVersionInfoSizeExW_t fp_GetFileVersionInfoSizeExW = NULL;
static GetFileVersionInfoSizeW_t fp_GetFileVersionInfoSizeW = NULL;
static GetFileVersionInfoW_t fp_GetFileVersionInfoW = NULL;
static VerFindFileA_t fp_VerFindFileA = NULL;
static VerFindFileW_t fp_VerFindFileW = NULL;
static VerInstallFileA_t fp_VerInstallFileA = NULL;
static VerInstallFileW_t fp_VerInstallFileW = NULL;
static VerLanguageNameA_t fp_VerLanguageNameA = NULL;
static VerLanguageNameW_t fp_VerLanguageNameW = NULL;
static VerQueryValueA_t fp_VerQueryValueA = NULL;
static VerQueryValueW_t fp_VerQueryValueW = NULL;

static void LoadRealDll() {
    wchar_t systemDir[MAX_PATH];
    if (GetSystemDirectoryW(systemDir, MAX_PATH) == 0) return;

    wchar_t realPath[MAX_PATH];
    // 简单的字符串拼接，不使用 std::wstring
    lstrcpyW(realPath, systemDir);
    lstrcatW(realPath, L"\\version.dll");

    g_hRealVersionDll = LoadLibraryW(realPath);
    if (!g_hRealVersionDll) return;

    fp_GetFileVersionInfoA = (GetFileVersionInfoA_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoA");
    fp_GetFileVersionInfoByHandle = (GetFileVersionInfoByHandle_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoByHandle");
    fp_GetFileVersionInfoExA = (GetFileVersionInfoExA_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoExA");
    fp_GetFileVersionInfoExW = (GetFileVersionInfoExW_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoExW");
    fp_GetFileVersionInfoSizeA = (GetFileVersionInfoSizeA_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoSizeA");
    fp_GetFileVersionInfoSizeExA = (GetFileVersionInfoSizeExA_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoSizeExA");
    fp_GetFileVersionInfoSizeExW = (GetFileVersionInfoSizeExW_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoSizeExW");
    fp_GetFileVersionInfoSizeW = (GetFileVersionInfoSizeW_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoSizeW");
    fp_GetFileVersionInfoW = (GetFileVersionInfoW_t)GetProcAddress(g_hRealVersionDll, "GetFileVersionInfoW");
    fp_VerFindFileA = (VerFindFileA_t)GetProcAddress(g_hRealVersionDll, "VerFindFileA");
    fp_VerFindFileW = (VerFindFileW_t)GetProcAddress(g_hRealVersionDll, "VerFindFileW");
    fp_VerInstallFileA = (VerInstallFileA_t)GetProcAddress(g_hRealVersionDll, "VerInstallFileA");
    fp_VerInstallFileW = (VerInstallFileW_t)GetProcAddress(g_hRealVersionDll, "VerInstallFileW");
    fp_VerLanguageNameA = (VerLanguageNameA_t)GetProcAddress(g_hRealVersionDll, "VerLanguageNameA");
    fp_VerLanguageNameW = (VerLanguageNameW_t)GetProcAddress(g_hRealVersionDll, "VerLanguageNameW");
    fp_VerQueryValueA = (VerQueryValueA_t)GetProcAddress(g_hRealVersionDll, "VerQueryValueA");
    fp_VerQueryValueW = (VerQueryValueW_t)GetProcAddress(g_hRealVersionDll, "VerQueryValueW");
}

static void EnsureRealDllLoaded() {
    // 双重检查锁定 (Double-Checked Locking) 的简易实现
    if (g_initFlag == 2) return;

    // 尝试获取初始化锁
    if (InterlockedCompareExchange(&g_initFlag, 1, 0) == 0) {
        LoadRealDll();
        // 标记为已初始化
        InterlockedExchange(&g_initFlag, 2);
    } else {
        // 另一个线程正在初始化，自旋等待
        while (g_initFlag != 2) {
            Sleep(1);
        }
    }
}

namespace VersionProxy {
    bool Initialize() {
        // 可以在这里预加载，也可以完全懒加载
        // EnsureRealDllLoaded();
        return true;
    }
    
    void Uninitialize() {
        if (g_hRealVersionDll) {
            FreeLibrary(g_hRealVersionDll);
            g_hRealVersionDll = NULL;
        }
    }
}

extern "C" {

BOOL WINAPI VersionProxy_GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoA ? fp_GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI VersionProxy_GetFileVersionInfoByHandle(DWORD dwFlags, HANDLE hFile, DWORD dwLen, LPVOID lpData) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoByHandle ? fp_GetFileVersionInfoByHandle(dwFlags, hFile, dwLen, lpData) : 0;
}

BOOL WINAPI VersionProxy_GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoExA ? fp_GetFileVersionInfoExA(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

BOOL WINAPI VersionProxy_GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoExW ? fp_GetFileVersionInfoExW(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI VersionProxy_GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoSizeA ? fp_GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI VersionProxy_GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoSizeExA ? fp_GetFileVersionInfoSizeExA(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI VersionProxy_GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoSizeExW ? fp_GetFileVersionInfoSizeExW(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI VersionProxy_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoSizeW ? fp_GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle) : 0;
}

BOOL WINAPI VersionProxy_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    EnsureRealDllLoaded();
    return fp_GetFileVersionInfoW ? fp_GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI VersionProxy_VerFindFileA(DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir, LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen) {
    EnsureRealDllLoaded();
    return fp_VerFindFileA ? fp_VerFindFileA(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen) : 0;
}

DWORD WINAPI VersionProxy_VerFindFileW(DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir, LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen) {
    EnsureRealDllLoaded();
    return fp_VerFindFileW ? fp_VerFindFileW(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen) : 0;
}

DWORD WINAPI VersionProxy_VerInstallFileA(DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir, LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT puTmpFileLen) {
    EnsureRealDllLoaded();
    return fp_VerInstallFileA ? fp_VerInstallFileA(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen) : 0;
}

DWORD WINAPI VersionProxy_VerInstallFileW(DWORD uFlags, LPCWSTR szSrcFileName, LPCWSTR szDestFileName, LPCWSTR szSrcDir, LPCWSTR szDestDir, LPCWSTR szCurDir, LPWSTR szTmpFile, PUINT puTmpFileLen) {
    EnsureRealDllLoaded();
    return fp_VerInstallFileW ? fp_VerInstallFileW(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen) : 0;
}

DWORD WINAPI VersionProxy_VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang) {
    EnsureRealDllLoaded();
    return fp_VerLanguageNameA ? fp_VerLanguageNameA(wLang, szLang, cchLang) : 0;
}

DWORD WINAPI VersionProxy_VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang) {
    EnsureRealDllLoaded();
    return fp_VerLanguageNameW ? fp_VerLanguageNameW(wLang, szLang, cchLang) : 0;
}

BOOL WINAPI VersionProxy_VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    EnsureRealDllLoaded();
    return fp_VerQueryValueA ? fp_VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}

BOOL WINAPI VersionProxy_VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    EnsureRealDllLoaded();
    return fp_VerQueryValueW ? fp_VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}

} // extern "C"
