#pragma once

#include <windows.h>
#include <string>

class SingleInstanceGuard {
public:
    SingleInstanceGuard();
    ~SingleInstanceGuard();

    SingleInstanceGuard(const SingleInstanceGuard&) = delete;
    SingleInstanceGuard& operator=(const SingleInstanceGuard&) = delete;

    bool IsAlreadyRunning() const;

private:
    HANDLE m_hMutex;
    bool m_alreadyRunning;
};

// Security & Elevation
BOOL IsRunningAsAdmin();
bool ElevateProcess();

// App name validation & sanitization against path traversal / injection
bool SanitizeAndValidateAppName(const std::wstring& input, std::wstring& outAppName, std::wstring& outErrorMessage);

// System application checks
bool IsSystemApp(const std::wstring& exeName);
bool CheckSystemApp(HWND parent, const std::wstring& appName);

// UI helpers
void CenterWindow(HWND hwnd);
