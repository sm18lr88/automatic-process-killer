/*
  Win32 Process Killer
  ---------------------------------------
  • Fully Unicode (UTF‑16) code path
  • Tray icon with NOTIFYICON_VERSION_4
  • Single-instance via named mutex
  • Wildcard support in blacklist (e.g., chrome*.exe) via PathMatchSpecW
  • Case-insensitive matching; supports base name ("notepad.exe") or full paths
  • Safer startup entry using HKCU\...\Run (RegGetValueW/RegSetValueExW)
  • Uses QueryFullProcessImageNameW + PROCESS_QUERY_LIMITED_INFORMATION for names
  • Optional restart-as-admin
  • DPI awareness set to Per‑Monitor v2 where available (API fallback)

  Notes:
  • Some processes require elevation to terminate.
  • By default, blacklist is stored next to the EXE if writable; otherwise in
    %LOCALAPPDATA%\Win32ProcessKiller\blacklist.txt.

  Build (MSVC):
    cl /nologo /O2 /W4 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN entry_point.c ^
       /link /SUBSYSTEM:WINDOWS

  (No external resources required; uses system icon.)
*/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <shlobj.h>      // SHGetKnownFolderPath
#include <knownfolders.h>
#include <strsafe.h>
#include <psapi.h>
#include <stdint.h>
#include <stdbool.h>
#include <wctype.h>
#include <stdlib.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Ole32.lib") // CoTaskMemFree for SHGetKnownFolderPath

// ---------------------------------------------------------------------------------------------------------------------
// App constants

#define APP_WINDOW_CLASS L"Win32ProcessKillerHiddenWindow"
#define APP_TITLE        L"Win32 Process Killer"
#define APP_TIP          L"Process Killer"
#define RUN_KEY_PATH     L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_VALUE_NAME   L"win32_process_killer"  // preserved for compatibility
#define BLACKLIST_NAME   L"blacklist.txt"

#define TRAY_MSG   (WM_APP + 1)

enum MENU_IDS {
    MENU_ID_RUN_AT_STARTUP = 1001,
    MENU_ID_STOP_AT_STARTUP,
    MENU_ID_OPEN_BLACKLIST,
    MENU_ID_CREATE_BLACKLIST,
    MENU_ID_RELOAD_NOW,
    MENU_ID_RESTART_ADMIN,
    MENU_ID_EXIT
};

// Fixed GUID for tray icon (prevents spoofing and ensures stable identity)
static const GUID kTrayGuid = {0x4e7596f4, 0x1b35, 0x4e8e, {0x91,0x2a,0xd9,0x8e,0x72,0x6d,0x1b,0x73}};

// ---------------------------------------------------------------------------------------------------------------------
// Small helpers

static inline void SafeFree(void* p) { if (p) free(p); }

static BOOL IsRunningAsAdmin(void) {
    BOOL is_admin = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev = {0};
        DWORD cb = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, cb, &cb))
            is_admin = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return is_admin;
}

static void SetBestDpiAwareness(void) {
    // Prefer Per-Monitor v2 if available; fall back to system DPI aware.
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        typedef BOOL (WINAPI *SetProcDpiCtx)(HANDLE);
        SetProcDpiCtx set_ctx = (SetProcDpiCtx)GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4
        if (set_ctx) {
            if (set_ctx((HANDLE)-4)) return;
        }
    }
    // Legacy fallback
    SetProcessDPIAware();
}

static HANDLE g_mutex = NULL;
static BOOL EnsureSingleInstance(void) {
    g_mutex = CreateMutexW(NULL, TRUE, L"Global\\Win32ProcessKiller_Mutex");
    if (!g_mutex) return TRUE; // best effort
    if (GetLastError() == ERROR_ALREADY_EXISTS) return FALSE;
    return TRUE;
}

static void GetExePath(wchar_t* buf, DWORD bufCount) {
    buf[0] = L'\0';
    GetModuleFileNameW(NULL, buf, bufCount);
}

static void GetExeDir(wchar_t* dir, DWORD dirCount) {
    wchar_t path[MAX_PATH];
    GetExePath(path, MAX_PATH);
    StringCchCopyW(dir, dirCount, path);
    PathRemoveFileSpecW(dir);
}

static BOOL DirExists(const wchar_t* path) {
    DWORD attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL FileExists(const wchar_t* path) {
    DWORD attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL EnsureParentDir(const wchar_t* filePath) {
    wchar_t dir[MAX_PATH];
    StringCchCopyW(dir, MAX_PATH, filePath);
    PathRemoveFileSpecW(dir);
    if (DirExists(dir)) return TRUE;
    // Create nested directories:
    return SHCreateDirectoryExW(NULL, dir, NULL) == ERROR_SUCCESS || GetLastError() == ERROR_ALREADY_EXISTS;
}

static BOOL LaunchAsAdmin(void) {
    wchar_t exe[MAX_PATH];
    GetExePath(exe, MAX_PATH);
    HINSTANCE h = ShellExecuteW(NULL, L"runas", exe, NULL, NULL, SW_SHOWNORMAL);
    return ((INT_PTR)h > 32);
}

// ---------------------------------------------------------------------------------------------------------------------
// Blacklist handling

typedef struct Blacklist {
    wchar_t** items;          // array of normalized patterns (lowercased)
    size_t    count;
    FILETIME  lastWriteTime;
    wchar_t   path[MAX_PATH]; // resolved file path
} Blacklist;

static void FreeBlacklist(Blacklist* bl) {
    if (!bl) return;
    for (size_t i = 0; i < bl->count; ++i) free(bl->items[i]);
    free(bl->items);
    bl->items = NULL;
    bl->count = 0;
    bl->lastWriteTime.dwLowDateTime = 0;
    bl->lastWriteTime.dwHighDateTime = 0;
}

static BOOL HasWildcard(const wchar_t* s) {
    return (wcspbrk(s, L"*?") != NULL);
}

static BOOL HasPathSep(const wchar_t* s) {
    return (wcspbrk(s, L"\\/") != NULL);
}

static wchar_t* TrimAndDupLower(const wchar_t* start, size_t len) {
    // Trim whitespace
    while (len && iswspace(start[0])) { start++; len--; }
    while (len && iswspace(start[len-1])) { len--; }
    if (len == 0) return NULL;
    // Ignore comments
    if (start[0] == L'#' || start[0] == L';') return NULL;

    wchar_t* out = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
    if (!out) return NULL;
    for (size_t i = 0; i < len; ++i) {
        wchar_t c = start[i];
        // Normalize slashes to backslashes for path patterns
        if (c == L'/') c = L'\\';
        out[i] = (wchar_t)towlower(c);
    }
    out[len] = 0;
    return out;
}

static BOOL Utf8BytesToWide(const BYTE* bytes, DWORD size, wchar_t** outW) {
    *outW = NULL;
    if (size >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) {
        bytes += 3; size -= 3; // skip BOM
    }
    int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCSTR)bytes, (int)size, NULL, 0);
    if (chars <= 0) {
        // Fallback to ANSI
        chars = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)bytes, (int)size, NULL, 0);
        if (chars <= 0) return FALSE;
        *outW = (wchar_t*)malloc((chars + 1) * sizeof(wchar_t));
        if (!*outW) return FALSE;
        MultiByteToWideChar(CP_ACP, 0, (LPCSTR)bytes, (int)size, *outW, chars);
    } else {
        *outW = (wchar_t*)malloc((chars + 1) * sizeof(wchar_t));
        if (!*outW) return FALSE;
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCSTR)bytes, (int)size, *outW, chars);
    }
    (*outW)[chars] = 0;
    return TRUE;
}

static void ResolveBlacklistPath(wchar_t out[MAX_PATH]) {
    // Prefer EXE directory if writable, otherwise LocalAppData\Win32ProcessKiller\blacklist.txt
    wchar_t exeDir[MAX_PATH];
    GetExeDir(exeDir, MAX_PATH);

    wchar_t exeSide[MAX_PATH];
    PathCombineW(exeSide, exeDir, BLACKLIST_NAME);

    // If exists or directory is writable, use next to exe
    if (FileExists(exeSide)) { StringCchCopyW(out, MAX_PATH, exeSide); return; }

    // Probe writability
    wchar_t probe[MAX_PATH];
    PathCombineW(probe, exeDir, L".write_test.tmp");
    HANDLE h = CreateFileW(probe, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        StringCchCopyW(out, MAX_PATH, exeSide);
        return;
    }

    // LocalAppData fallback
    PWSTR lad = NULL;
    if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_CREATE, NULL, &lad))) {
        wchar_t appDir[MAX_PATH];
        PathCombineW(appDir, lad, L"Win32ProcessKiller");
        CoTaskMemFree(lad);
        wchar_t dummy[MAX_PATH];
        StringCchCopyW(dummy, MAX_PATH, appDir);
        if (!DirExists(dummy)) SHCreateDirectoryExW(NULL, dummy, NULL);
        PathCombineW(out, appDir, BLACKLIST_NAME);
        return;
    }

    // Last resort: exe directory
    StringCchCopyW(out, MAX_PATH, exeSide);
}

static BOOL EnsureBlacklistFileExists(const wchar_t* path) {
    if (FileExists(path)) return TRUE;
    if (!EnsureParentDir(path)) return FALSE;
    HANDLE f = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    static const char kHeader[] =
        "# Win32 Process Killer blacklist\n"
        "# One pattern per line. Examples:\n"
        "#   notepad.exe\n"
        "#   chrome*.exe\n"
        "#   C:\\\\Path\\\\to\\\\someapp.exe\n";
    DWORD written = 0;
    WriteFile(f, kHeader, (DWORD)sizeof(kHeader) - 1, &written, NULL);
    CloseHandle(f);
    return TRUE;
}

static BOOL TryGetLastWriteTime(const wchar_t* path, FILETIME* out) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return FALSE;
    *out = fad.ftLastWriteTime;
    return TRUE;
}

static BOOL BlacklistNeedsReload(Blacklist* bl) {
    FILETIME ft;
    if (!TryGetLastWriteTime(bl->path, &ft)) return FALSE;
    return (ft.dwLowDateTime != bl->lastWriteTime.dwLowDateTime ||
            ft.dwHighDateTime != bl->lastWriteTime.dwHighDateTime);
}

static BOOL LoadBlacklist(Blacklist* bl) {
    HANDLE f = CreateFileW(bl->path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER size; size.QuadPart = 0;
    if (!GetFileSizeEx(f, &size) || size.QuadPart > (LONGLONG)(32 * 1024 * 1024)) { CloseHandle(f); return FALSE; }

    BYTE* bytes = (BYTE*)malloc((size_t)size.QuadPart + 1);
    if (!bytes) { CloseHandle(f); return FALSE; }

    DWORD read = 0;
    BOOL ok = ReadFile(f, bytes, (DWORD)size.QuadPart, &read, NULL);
    CloseHandle(f);
    if (!ok) { free(bytes); return FALSE; }
    bytes[read] = 0;

    wchar_t* wide = NULL;
    if (!Utf8BytesToWide(bytes, read, &wide)) { free(bytes); return FALSE; }
    free(bytes);

    // Parse lines
    FreeBlacklist(bl);

    // Count lines first (upper bound)
    size_t cap = 16, cnt = 0;
    wchar_t** items = (wchar_t**)malloc(cap * sizeof(wchar_t*));
    if (!items) { free(wide); return FALSE; }

    const wchar_t* s = wide;
    while (*s) {
        const wchar_t* line = s;
        while (*s && *s != L'\n' && *s != L'\r') ++s;
        size_t len = (size_t)(s - line);

        wchar_t* normalized = TrimAndDupLower(line, len);
        if (normalized && normalized[0] != 0) {
            if (cnt == cap) {
                cap *= 2;
                wchar_t** ni = (wchar_t**)realloc(items, cap * sizeof(wchar_t*));
                if (!ni) { free(normalized); break; }
                items = ni;
            }
            items[cnt++] = normalized;
        }

        // consume CRLF
        if (*s == L'\r') ++s;
        if (*s == L'\n') ++s;
    }

    free(wide);
    bl->items = items;
    bl->count = cnt;

    // Update timestamp
    TryGetLastWriteTime(bl->path, &bl->lastWriteTime);
    return TRUE;
}

// ---------------------------------------------------------------------------------------------------------------------
// Startup registry (HKCU\...\Run)

static BOOL IsRunAtStartupEnabled(void) {
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY_PATH, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
        return FALSE;

    wchar_t val[1024] = L"";
    DWORD type = 0, cb = sizeof(val);
    LONG r = RegGetValueW(key, NULL, RUN_VALUE_NAME, RRF_RT_REG_SZ, &type, val, &cb);
    RegCloseKey(key);
    if (r != ERROR_SUCCESS) return FALSE;

    // Value typically contains quoted full path
    wchar_t exe[MAX_PATH]; GetExePath(exe, MAX_PATH);
    // Strip surrounding quotes in registry value if present
    wchar_t* p = val;
    size_t n = wcslen(val);
    if (n >= 2 && val[0] == L'"' && val[n-1] == L'"') { val[n-1] = 0; p = val + 1; }
    return CompareStringOrdinal(exe, -1, p, -1, TRUE) == CSTR_EQUAL;
}

static void SetRunAtStartup(BOOL enable) {
    HKEY key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, RUN_KEY_PATH, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL) != ERROR_SUCCESS)
        return;

    if (enable) {
        wchar_t exe[MAX_PATH]; GetExePath(exe, MAX_PATH);
        wchar_t quoted[MAX_PATH + 2];
        StringCchPrintfW(quoted, ARRAYSIZE(quoted), L"\"%s\"", exe);
        RegSetValueExW(key, RUN_VALUE_NAME, 0, REG_SZ, (const BYTE*)quoted, (DWORD)((wcslen(quoted) + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(key, RUN_VALUE_NAME);
    }
    RegCloseKey(key);
}

// ---------------------------------------------------------------------------------------------------------------------
// Tray & window

static NOTIFYICONDATAW g_nid;
static HWND             g_hwnd = NULL;
static volatile BOOL    g_running = TRUE;
static Blacklist        g_blacklist = {0};

static void Tray_Add(void) {
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd   = g_hwnd;
    g_nid.uID    = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON | NIF_GUID;
    g_nid.uCallbackMessage = TRAY_MSG;
    g_nid.guidItem = kTrayGuid;
    StringCchCopyW(g_nid.szTip, ARRAYSIZE(g_nid.szTip), APP_TIP);

    g_nid.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    // Opt into v4 behavior
    g_nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
}

static void Tray_Delete(void) {
    if (g_nid.hWnd) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        g_nid.hWnd = NULL;
    }
}

static void Menu_Show(void) {
    HMENU menu = CreatePopupMenu();
    if (!menu) return;

    BOOL runAtStartup = IsRunAtStartupEnabled();
    BOOL blExists     = FileExists(g_blacklist.path);

    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, APP_TITLE);
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);

    if (runAtStartup)
        AppendMenuW(menu, MF_STRING, MENU_ID_STOP_AT_STARTUP, L"Do not run at start-up");
    else
        AppendMenuW(menu, MF_STRING, MENU_ID_RUN_AT_STARTUP,  L"Run at start-up");

    if (blExists)
        AppendMenuW(menu, MF_STRING, MENU_ID_OPEN_BLACKLIST,   L"Open blacklist");
    else
        AppendMenuW(menu, MF_STRING, MENU_ID_CREATE_BLACKLIST, L"Create and open blacklist");

    AppendMenuW(menu, MF_STRING, MENU_ID_RELOAD_NOW,   L"Reload now");
    if (!IsRunningAsAdmin())
        AppendMenuW(menu, MF_STRING, MENU_ID_RESTART_ADMIN, L"Restart as Administrator");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, MENU_ID_EXIT, L"Exit");

    POINT pt; GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);
    UINT cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, g_hwnd, NULL);
    DestroyMenu(menu);

    switch (cmd) {
        case MENU_ID_EXIT: g_running = FALSE; break;
        case MENU_ID_RUN_AT_STARTUP:  SetRunAtStartup(TRUE);  break;
        case MENU_ID_STOP_AT_STARTUP: SetRunAtStartup(FALSE); break;

        case MENU_ID_OPEN_BLACKLIST:
        case MENU_ID_CREATE_BLACKLIST: {
            if (cmd == MENU_ID_CREATE_BLACKLIST) EnsureBlacklistFileExists(g_blacklist.path);
            ShellExecuteW(NULL, L"open", g_blacklist.path, NULL, NULL, SW_SHOWNORMAL);
        } break;

        case MENU_ID_RELOAD_NOW:
            g_blacklist.lastWriteTime.dwLowDateTime = 0;
            g_blacklist.lastWriteTime.dwHighDateTime = 0;
            break;

        case MENU_ID_RESTART_ADMIN:
            if (LaunchAsAdmin()) g_running = FALSE;
            break;
        default: break;
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == TRAY_MSG) {
        switch (LOWORD(lParam)) {
            case WM_RBUTTONDOWN:
            case WM_LBUTTONDOWN:
            case WM_CONTEXTMENU:
            case NIN_SELECT:
            case NIN_KEYSELECT:
                Menu_Show();
                return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------------------------------------------------
// Process enumeration & kill

static BOOL PatternMatches(const wchar_t* patternLower, const wchar_t* fullPathLower, const wchar_t* baseNameLower) {
    // patternLower is normalized to lowercase with backslashes.
    if (HasWildcard(patternLower)) {
        if (HasPathSep(patternLower)) {
            return PathMatchSpecW(fullPathLower, patternLower);
        } else {
            return PathMatchSpecW(baseNameLower, patternLower);
        }
    } else {
        if (HasPathSep(patternLower)) {
            return CompareStringOrdinal(fullPathLower, -1, patternLower, -1, TRUE) == CSTR_EQUAL;
        } else {
            return CompareStringOrdinal(baseNameLower, -1, patternLower, -1, TRUE) == CSTR_EQUAL;
        }
    }
}

static void ToLowerInplace(wchar_t* s) {
    if (!s) return;
    CharLowerBuffW(s, (DWORD)wcslen(s));
}

static void Tick(void) {
    // refresh blacklist if modified
    if (BlacklistNeedsReload(&g_blacklist)) {
        LoadBlacklist(&g_blacklist);
    }

    DWORD pids[8192];
    DWORD bytes = 0;
    if (!EnumProcesses(pids, sizeof(pids), &bytes)) return;
    DWORD count = bytes / sizeof(DWORD);

    for (DWORD i = 0; i < count && g_running; ++i) {
        DWORD pid = pids[i];
        if (pid == 0) continue;

        HANDLE proc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!proc) continue;

        wchar_t fullPath[32768]; // QueryFullProcessImageNameW can exceed MAX_PATH on modern Windows
        DWORD cch = ARRAYSIZE(fullPath);
        BOOL havePath = QueryFullProcessImageNameW(proc, 0, fullPath, &cch);
        const wchar_t* base = L"";
        wchar_t fullLower[32768] = L"";
        wchar_t baseLower[32768] = L"";

        if (havePath) {
            base = PathFindFileNameW(fullPath);
            StringCchCopyW(fullLower, ARRAYSIZE(fullLower), fullPath);
            ToLowerInplace(fullLower);
            StringCchCopyW(baseLower, ARRAYSIZE(baseLower), base);
            ToLowerInplace(baseLower);
        } else {
            // Fallback: best-effort base name
            HMODULE hMod;
            DWORD needed;
            if (EnumProcessModules(proc, &hMod, sizeof(hMod), &needed)) {
                if (GetModuleBaseNameW(proc, hMod, baseLower, ARRAYSIZE(baseLower))) {
                    StringCchCopyW(fullLower, ARRAYSIZE(fullLower), baseLower);
                }
            }
        }

        BOOL shouldKill = FALSE;
        for (size_t j = 0; j < g_blacklist.count; ++j) {
            if (PatternMatches(g_blacklist.items[j],
                               fullLower[0] ? fullLower : baseLower,
                               baseLower)) { shouldKill = TRUE; break; }
        }

        if (shouldKill) {
            TerminateProcess(proc, 0);
        }

        CloseHandle(proc);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Entry point

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nCmdShow) {
    (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    if (!EnsureSingleInstance()) return 0;
    SetBestDpiAwareness();

    // Resolve blacklist location now
    ResolveBlacklistPath(g_blacklist.path);
    EnsureBlacklistFileExists(g_blacklist.path);
    LoadBlacklist(&g_blacklist);

    // Register & create hidden window
    WNDCLASSW wc = {0};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = APP_WINDOW_CLASS;
    wc.style         = CS_OWNDC;

    if (!RegisterClassW(&wc)) return 0;
    g_hwnd = CreateWindowExW(0, APP_WINDOW_CLASS, APP_TITLE, WS_POPUP,
                             CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                             NULL, NULL, hInst, NULL);
    if (!g_hwnd) return 0;

    // Tray icon
    Tray_Add();

    // Main loop: pump messages and scan
    const DWORD SLEEP_MS = 250;
    MSG msg;
    while (g_running) {
        while (PeekMessageW(&msg, g_hwnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        Tick();
        Sleep(SLEEP_MS);
    }

    Tray_Delete();
    FreeBlacklist(&g_blacklist);
    if (g_mutex) { CloseHandle(g_mutex); g_mutex = NULL; }
    return 0;
}
