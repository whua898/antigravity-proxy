// 防止 windows.h 自动包含 winsock.h (避免与 winsock2.h 冲突)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <mmsystem.h> // 必须包含此头文件以定义 MMRESULT, HWAVEOUT 等类型

// ============================================================================
// winmm.dll 代理实现 (纯 C 风格)
// ============================================================================

static HMODULE g_hRealWinmmDll = NULL;
static volatile LONG g_initFlag = 0;

// 函数指针类型定义
typedef BOOL (WINAPI *PlaySoundA_t)(LPCSTR, HMODULE, DWORD);
typedef BOOL (WINAPI *PlaySoundW_t)(LPCWSTR, HMODULE, DWORD);
typedef MMRESULT (WINAPI *timeBeginPeriod_t)(UINT);
typedef MMRESULT (WINAPI *timeEndPeriod_t)(UINT);
typedef MMRESULT (WINAPI *timeGetDevCaps_t)(LPTIMECAPS, UINT);
typedef DWORD (WINAPI *timeGetTime_t)(void);
typedef MMRESULT (WINAPI *waveOutOpen_t)(LPHWAVEOUT, UINT, LPCWAVEFORMATEX, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *waveOutClose_t)(HWAVEOUT);
typedef MMRESULT (WINAPI *waveOutPrepareHeader_t)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *waveOutUnprepareHeader_t)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *waveOutWrite_t)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *waveOutReset_t)(HWAVEOUT);
typedef MMRESULT (WINAPI *joyGetPosEx_t)(UINT, LPJOYINFOEX);
typedef MMRESULT (WINAPI *mciSendStringA_t)(LPCSTR, LPSTR, UINT, HANDLE);
typedef MMRESULT (WINAPI *mciSendStringW_t)(LPCWSTR, LPWSTR, UINT, HANDLE);

// 函数指针实例
static PlaySoundA_t fp_PlaySoundA = NULL;
static PlaySoundW_t fp_PlaySoundW = NULL;
static timeBeginPeriod_t fp_timeBeginPeriod = NULL;
static timeEndPeriod_t fp_timeEndPeriod = NULL;
static timeGetDevCaps_t fp_timeGetDevCaps = NULL;
static timeGetTime_t fp_timeGetTime = NULL;
static waveOutOpen_t fp_waveOutOpen = NULL;
static waveOutClose_t fp_waveOutClose = NULL;
static waveOutPrepareHeader_t fp_waveOutPrepareHeader = NULL;
static waveOutUnprepareHeader_t fp_waveOutUnprepareHeader = NULL;
static waveOutWrite_t fp_waveOutWrite = NULL;
static waveOutReset_t fp_waveOutReset = NULL;
static joyGetPosEx_t fp_joyGetPosEx = NULL;
static mciSendStringA_t fp_mciSendStringA = NULL;
static mciSendStringW_t fp_mciSendStringW = NULL;

static void LoadRealDll() {
    wchar_t systemDir[MAX_PATH];
    if (GetSystemDirectoryW(systemDir, MAX_PATH) == 0) return;

    wchar_t realPath[MAX_PATH];
    lstrcpyW(realPath, systemDir);
    lstrcatW(realPath, L"\\winmm.dll");

    g_hRealWinmmDll = LoadLibraryW(realPath);
    if (!g_hRealWinmmDll) return;

    fp_PlaySoundA = (PlaySoundA_t)GetProcAddress(g_hRealWinmmDll, "PlaySoundA");
    fp_PlaySoundW = (PlaySoundW_t)GetProcAddress(g_hRealWinmmDll, "PlaySoundW");
    fp_timeBeginPeriod = (timeBeginPeriod_t)GetProcAddress(g_hRealWinmmDll, "timeBeginPeriod");
    fp_timeEndPeriod = (timeEndPeriod_t)GetProcAddress(g_hRealWinmmDll, "timeEndPeriod");
    fp_timeGetDevCaps = (timeGetDevCaps_t)GetProcAddress(g_hRealWinmmDll, "timeGetDevCaps");
    fp_timeGetTime = (timeGetTime_t)GetProcAddress(g_hRealWinmmDll, "timeGetTime");
    fp_waveOutOpen = (waveOutOpen_t)GetProcAddress(g_hRealWinmmDll, "waveOutOpen");
    fp_waveOutClose = (waveOutClose_t)GetProcAddress(g_hRealWinmmDll, "waveOutClose");
    fp_waveOutPrepareHeader = (waveOutPrepareHeader_t)GetProcAddress(g_hRealWinmmDll, "waveOutPrepareHeader");
    fp_waveOutUnprepareHeader = (waveOutUnprepareHeader_t)GetProcAddress(g_hRealWinmmDll, "waveOutUnprepareHeader");
    fp_waveOutWrite = (waveOutWrite_t)GetProcAddress(g_hRealWinmmDll, "waveOutWrite");
    fp_waveOutReset = (waveOutReset_t)GetProcAddress(g_hRealWinmmDll, "waveOutReset");
    fp_joyGetPosEx = (joyGetPosEx_t)GetProcAddress(g_hRealWinmmDll, "joyGetPosEx");
    fp_mciSendStringA = (mciSendStringA_t)GetProcAddress(g_hRealWinmmDll, "mciSendStringA");
    fp_mciSendStringW = (mciSendStringW_t)GetProcAddress(g_hRealWinmmDll, "mciSendStringW");
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

namespace VersionProxy {
    bool Initialize() {
        // 兼容旧接口名，实际初始化 winmm
        return true;
    }
    
    void Uninitialize() {
        if (g_hRealWinmmDll) {
            FreeLibrary(g_hRealWinmmDll);
            g_hRealWinmmDll = NULL;
        }
    }
}

extern "C" {

BOOL WINAPI WinmmProxy_PlaySoundA(LPCSTR pszSound, HMODULE hmod, DWORD fdwSound) {
    EnsureRealDllLoaded();
    return fp_PlaySoundA ? fp_PlaySoundA(pszSound, hmod, fdwSound) : FALSE;
}

BOOL WINAPI WinmmProxy_PlaySoundW(LPCWSTR pszSound, HMODULE hmod, DWORD fdwSound) {
    EnsureRealDllLoaded();
    return fp_PlaySoundW ? fp_PlaySoundW(pszSound, hmod, fdwSound) : FALSE;
}

MMRESULT WINAPI WinmmProxy_timeBeginPeriod(UINT uPeriod) {
    EnsureRealDllLoaded();
    return fp_timeBeginPeriod ? fp_timeBeginPeriod(uPeriod) : TIMERR_NOCANDO;
}

MMRESULT WINAPI WinmmProxy_timeEndPeriod(UINT uPeriod) {
    EnsureRealDllLoaded();
    return fp_timeEndPeriod ? fp_timeEndPeriod(uPeriod) : TIMERR_NOCANDO;
}

MMRESULT WINAPI WinmmProxy_timeGetDevCaps(LPTIMECAPS ptc, UINT cbtc) {
    EnsureRealDllLoaded();
    return fp_timeGetDevCaps ? fp_timeGetDevCaps(ptc, cbtc) : TIMERR_NOCANDO;
}

DWORD WINAPI WinmmProxy_timeGetTime(void) {
    EnsureRealDllLoaded();
    return fp_timeGetTime ? fp_timeGetTime() : 0;
}

MMRESULT WINAPI WinmmProxy_waveOutOpen(LPHWAVEOUT phwo, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) {
    EnsureRealDllLoaded();
    return fp_waveOutOpen ? fp_waveOutOpen(phwo, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen) : MMSYSERR_ERROR;
}

MMRESULT WINAPI WinmmProxy_waveOutClose(HWAVEOUT hwo) {
    EnsureRealDllLoaded();
    return fp_waveOutClose ? fp_waveOutClose(hwo) : MMSYSERR_ERROR;
}

MMRESULT WINAPI WinmmProxy_waveOutPrepareHeader(HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh) {
    EnsureRealDllLoaded();
    return fp_waveOutPrepareHeader ? fp_waveOutPrepareHeader(hwo, pwh, cbwh) : MMSYSERR_ERROR;
}

MMRESULT WINAPI WinmmProxy_waveOutUnprepareHeader(HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh) {
    EnsureRealDllLoaded();
    return fp_waveOutUnprepareHeader ? fp_waveOutUnprepareHeader(hwo, pwh, cbwh) : MMSYSERR_ERROR;
}

MMRESULT WINAPI WinmmProxy_waveOutWrite(HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh) {
    EnsureRealDllLoaded();
    return fp_waveOutWrite ? fp_waveOutWrite(hwo, pwh, cbwh) : MMSYSERR_ERROR;
}

MMRESULT WINAPI WinmmProxy_waveOutReset(HWAVEOUT hwo) {
    EnsureRealDllLoaded();
    return fp_waveOutReset ? fp_waveOutReset(hwo) : MMSYSERR_ERROR;
}

MMRESULT WINAPI WinmmProxy_joyGetPosEx(UINT uJoyID, LPJOYINFOEX pji) {
    EnsureRealDllLoaded();
    return fp_joyGetPosEx ? fp_joyGetPosEx(uJoyID, pji) : JOYERR_PARMS;
}

MMRESULT WINAPI WinmmProxy_mciSendStringA(LPCSTR lpstrCommand, LPSTR lpstrReturnString, UINT uReturnLength, HANDLE hwndCallback) {
    EnsureRealDllLoaded();
    return fp_mciSendStringA ? fp_mciSendStringA(lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback) : MCIERR_INTERNAL;
}

MMRESULT WINAPI WinmmProxy_mciSendStringW(LPCWSTR lpstrCommand, LPWSTR lpstrReturnString, UINT uReturnLength, HANDLE hwndCallback) {
    EnsureRealDllLoaded();
    return fp_mciSendStringW ? fp_mciSendStringW(lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback) : MCIERR_INTERNAL;
}

} // extern "C"
