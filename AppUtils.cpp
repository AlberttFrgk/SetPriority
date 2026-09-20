#include "pch.h"
#include "AppUtils.h"
#include <shlwapi.h>
#include <shellapi.h>
#include <cwctype>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

// SingleInstanceGuard implementation
SingleInstanceGuard::SingleInstanceGuard() : m_hMutex(nullptr), m_alreadyRunning(false) {
    // Unique GUID-scoped mutex name to prevent local collision attacks or denial of service
    m_hMutex = CreateMutexW(nullptr, FALSE, L"Local\\SetPriority_SingleInstance_{A45C3F08-8422-4DCE-981D-5FCE0A656B24}");
    if (!m_hMutex) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            m_alreadyRunning = true;
        }
    } else if (GetLastError() == ERROR_ALREADY_EXISTS) {
        m_alreadyRunning = true;
    }
}

SingleInstanceGuard::~SingleInstanceGuard() {
    if (m_hMutex) {
        CloseHandle(m_hMutex);
        m_hMutex = nullptr;
    }
}

bool SingleInstanceGuard::IsAlreadyRunning() const {
    return m_alreadyRunning;
}

// Check if running elevated with administrative privileges
BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// Elevate process via ShellExecuteEx runas
bool ElevateProcess() {
    wchar_t szPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, szPath, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        szPath[len] = L'\0';
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = nullptr;
        sei.nShow = SW_NORMAL;
        return ShellExecuteExW(&sei) != FALSE;
    }
    return false;
}

// Center a window on the primary screen work area
void CenterWindow(HWND hwnd) {
    RECT rcWnd, rcScreen;
    GetWindowRect(hwnd, &rcWnd);
    SystemParametersInfo(SPI_GETWORKAREA, 0, &rcScreen, 0);
    int x = (rcScreen.right - rcScreen.left - (rcWnd.right - rcWnd.left)) / 2;
    int y = (rcScreen.bottom - rcScreen.top - (rcWnd.bottom - rcWnd.top)) / 2;
    SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

// App name validation & sanitization
bool SanitizeAndValidateAppName(const std::wstring& input, std::wstring& outAppName, std::wstring& outErrorMessage) {
    size_t start = 0;
    while (start < input.size() && iswspace(input[start])) {
        start++;
    }
    size_t end = input.size();
    while (end > start && iswspace(input[end - 1])) {
        end--;
    }

    if (start >= end) {
        outErrorMessage = L"Please enter or browse for an application executable.";
        return false;
    }

    std::wstring trimmed = input.substr(start, end - start);

    // Strip enclosing quotes if present
    if (trimmed.size() >= 2 && trimmed.front() == L'"' && trimmed.back() == L'"') {
        trimmed = trimmed.substr(1, trimmed.size() - 2);
    }

    // Reject path traversal tokens anywhere in the input string
    if (trimmed == L"." || trimmed == L".." || trimmed.find(L"..") != std::wstring::npos) {
        outErrorMessage = L"Path traversal is not allowed in application names.";
        return false;
    }

    // Extract file name component if user supplied a full or relative path
    size_t lastSep = trimmed.find_last_of(L"\\/");
    std::wstring fileName = (lastSep != std::wstring::npos) ? trimmed.substr(lastSep + 1) : trimmed;

    while (!fileName.empty() && iswspace(fileName.front())) {
        fileName.erase(fileName.begin());
    }
    while (!fileName.empty() && iswspace(fileName.back())) {
        fileName.pop_back();
    }

    if (fileName.empty()) {
        outErrorMessage = L"Invalid application path or filename.";
        return false;
    }

    // Reject illegal filename characters and control characters
    const std::wstring invalidChars = L"<>:\"/\\|?*";
    for (wchar_t ch : fileName) {
        if (ch < 32 || invalidChars.find(ch) != std::wstring::npos) {
            outErrorMessage = L"Application name contains invalid characters (< > : \" / \\ | ? *).";
            return false;
        }
    }

    if (fileName.length() >= MAX_PATH || fileName.length() > 255) {
        outErrorMessage = L"Application name is too long (maximum 255 characters).";
        return false;
    }

    // Check reserved Windows device names
    std::wstring baseName = fileName;
    size_t dotPos = baseName.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        baseName = baseName.substr(0, dotPos);
    }
    std::wstring upperBase = baseName;
    for (auto& c : upperBase) {
        c = (wchar_t)towupper(c);
    }
    if (upperBase == L"CON" || upperBase == L"PRN" || upperBase == L"AUX" || upperBase == L"NUL" ||
        (upperBase.rfind(L"COM", 0) == 0 && upperBase.length() == 4 && iswdigit(upperBase[3])) ||
        (upperBase.rfind(L"LPT", 0) == 0 && upperBase.length() == 4 && iswdigit(upperBase[3]))) {
        outErrorMessage = L"Application name cannot be a reserved Windows device name.";
        return false;
    }

    outAppName = fileName;
    return true;
}

// System application checks
bool IsSystemApp(const std::wstring& exeName) {
    if (exeName.empty() || exeName.find_first_of(L"\\/:") != std::wstring::npos) {
        return false;
    }

    WCHAR path[MAX_PATH];
    WCHAR dir[MAX_PATH];

    // Check System32
    if (GetSystemDirectoryW(dir, MAX_PATH) > 0) {
        if (PathCombineW(path, dir, exeName.c_str()) && PathFileExistsW(path)) {
            return true;
        }
    }

    // Check Windows directory (e.g. C:\Windows) and SysWOW64
    if (GetWindowsDirectoryW(dir, MAX_PATH) > 0) {
        if (PathCombineW(path, dir, exeName.c_str()) && PathFileExistsW(path)) {
            return true;
        }

        WCHAR wow64Path[MAX_PATH];
        if (PathCombineW(wow64Path, dir, L"SysWOW64")) {
            if (PathCombineW(path, wow64Path, exeName.c_str()) && PathFileExistsW(path)) {
                return true;
            }
        }
    }

    return false;
}

bool CheckSystemApp(HWND parent, const std::wstring& appName) {
    if (IsSystemApp(appName)) {
        MessageBoxW(parent, L"System app cannot be deleted!", L"Error", MB_ICONERROR);
        return false;
    }
    return true;
}
