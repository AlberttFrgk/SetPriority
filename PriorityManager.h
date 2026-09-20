#pragma once

#include <windows.h>
#include <string>
#include <vector>

constexpr auto IFEO_PATH = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
constexpr auto REG_PRIORITY = L"CpuPriorityClass";
constexpr auto REG_MANAGED = L"SetPriorityManaged";
constexpr auto DEFAULT_TEXT = L"Default";

struct PriorityOption {
    DWORD value;
    const wchar_t* displayName;
    const wchar_t* shortName;
};

// Priority mappings and helpers
const std::vector<PriorityOption>& GetPriorityOptions();
const wchar_t* ConvertPriorityToName(DWORD priority);
DWORD GetPriorityValueByIndex(int index);
int GetPriorityIndexByValue(DWORD value);

// Registry IFEO operations (with input validation and type safety)
std::vector<std::wstring> GetRegisteredApps();
std::wstring GetPerfOptionsPath(const std::wstring& appName);
bool GetAppPriority(const std::wstring& appName, DWORD& outPriority);
bool SetAppPriority(const std::wstring& appName, DWORD priority);
bool SetAppDefaultPriority(const std::wstring& appName);
bool RemoveAppPriorityValue(const std::wstring& appName);
bool RemoveApp(const std::wstring& appName);
bool IsAppManaged(const std::wstring& appName);
bool UnmanageApp(const std::wstring& appName);
