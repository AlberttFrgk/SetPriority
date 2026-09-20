#include "pch.h"
#include "PriorityManager.h"
#include "AppUtils.h"
#include <algorithm>

static const std::vector<PriorityOption> g_priorityOptions = {
    { 0,          L"0 - Default (System Managed)", L"Default" },
    { 0x00000001, L"1 - Idle",                     L"Idle" },
    { 0x00000005, L"5 - Below Normal",             L"Below Normal" },
    { 0x00000002, L"2 - Normal",                   L"Normal" },
    { 0x00000006, L"6 - Above Normal",             L"Above Normal" },
    { 0x00000003, L"3 - High",                     L"High" },
    { 0x00000004, L"4 - Realtime (Not Recommend)", L"Realtime" }
};

const std::vector<PriorityOption>& GetPriorityOptions() {
    return g_priorityOptions;
}

const wchar_t* ConvertPriorityToName(DWORD priority) {
    for (const auto& opt : g_priorityOptions) {
        if (opt.value == priority && opt.value != 0) {
            return opt.shortName;
        }
    }
    return (priority == 0) ? DEFAULT_TEXT : L"(Unknown)";
}

DWORD GetPriorityValueByIndex(int index) {
    if (index >= 0 && static_cast<size_t>(index) < g_priorityOptions.size()) {
        return g_priorityOptions[index].value;
    }
    return 0;
}

int GetPriorityIndexByValue(DWORD value) {
    for (size_t i = 0; i < g_priorityOptions.size(); ++i) {
        if (g_priorityOptions[i].value == value) {
            return static_cast<int>(i);
        }
    }
    return 0;
}

static bool IsValidRegistryAppName(const std::wstring& appName) {
    if (appName.empty() || appName.length() > 255) {
        return false;
    }
    if (appName == L"." || appName == L".." || appName.find(L"..") != std::wstring::npos) {
        return false;
    }
    if (appName.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos) {
        return false;
    }
    return true;
}

std::wstring GetPerfOptionsPath(const std::wstring& appName) {
    if (!IsValidRegistryAppName(appName)) {
        return L"";
    }
    return std::wstring(IFEO_PATH) + L"\\" + appName + L"\\PerfOptions";
}

std::vector<std::wstring> GetRegisteredApps() {
    HKEY hKey = nullptr;
    std::vector<std::wstring> appList;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IFEO_PATH, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR name[256];
        DWORD index = 0;

        while (true) {
            DWORD nameSize = static_cast<DWORD>(_countof(name));
            LONG res = RegEnumKeyExW(hKey, index++, name, &nameSize, nullptr, nullptr, nullptr, nullptr);
            if (res != ERROR_SUCCESS) {
                break;
            }

            if (_wcsicmp(name, L"{ApplicationVerifierGlobalSettings}") == 0) {
                continue;
            }

            // Ensure valid string
            name[_countof(name) - 1] = L'\0';
            appList.emplace_back(name);
        }
        RegCloseKey(hKey);
    }
    return appList;
}

bool GetAppPriority(const std::wstring& appName, DWORD& outPriority) {
    std::wstring subkey = GetPerfOptionsPath(appName);
    if (subkey.empty()) {
        return false;
    }

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dataSize = sizeof(DWORD);
        DWORD dataType = 0;
        LONG result = RegQueryValueExW(hKey, REG_PRIORITY, nullptr, &dataType, reinterpret_cast<LPBYTE>(&outPriority), &dataSize);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS && dataType == REG_DWORD && dataSize == sizeof(DWORD));
    }
    return false;
}

static void MarkAsManaged(HKEY hKey) {
    DWORD value = 1;
    RegSetValueExW(hKey, REG_MANAGED, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(DWORD));
}

bool SetAppPriority(const std::wstring& appName, DWORD priority) {
    std::wstring perfKey = GetPerfOptionsPath(appName);
    if (perfKey.empty()) {
        return false;
    }

    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, perfKey.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        LONG result = RegSetValueExW(hKey, REG_PRIORITY, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&priority), sizeof(DWORD));
        MarkAsManaged(hKey);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    }
    return false;
}

bool SetAppDefaultPriority(const std::wstring& appName) {
    std::wstring perfKey = GetPerfOptionsPath(appName);
    if (perfKey.empty()) {
        return false;
    }

    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, perfKey.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        MarkAsManaged(hKey);
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool RemoveAppPriorityValue(const std::wstring& appName) {
    std::wstring perfKey = GetPerfOptionsPath(appName);
    if (perfKey.empty()) {
        return false;
    }

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, perfKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        LONG result = RegDeleteValueW(hKey, REG_PRIORITY);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
    }
    return false;
}

bool RemoveApp(const std::wstring& appName) {
    if (!IsValidRegistryAppName(appName)) {
        return false;
    }

    std::wstring perfKey = GetPerfOptionsPath(appName);
    if (!perfKey.empty()) {
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, perfKey.c_str());
    }

    std::wstring appKey = std::wstring(IFEO_PATH) + L"\\" + appName;
    return (RegDeleteKeyW(HKEY_LOCAL_MACHINE, appKey.c_str()) == ERROR_SUCCESS);
}

bool IsAppManaged(const std::wstring& appName) {
    std::wstring subkey = GetPerfOptionsPath(appName);
    if (subkey.empty()) {
        return false;
    }

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value = 0;
        DWORD valueSize = sizeof(DWORD);
        DWORD dataType = 0;
        LONG result = RegQueryValueExW(hKey, REG_MANAGED, nullptr, &dataType, reinterpret_cast<LPBYTE>(&value), &valueSize);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS && dataType == REG_DWORD && valueSize == sizeof(DWORD) && value == 1);
    }
    return false;
}

bool UnmanageApp(const std::wstring& appName) {
    std::wstring perfKey = GetPerfOptionsPath(appName);
    if (perfKey.empty()) {
        return false;
    }

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, perfKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        LONG result = RegDeleteValueW(hKey, REG_MANAGED);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
    }
    return false;
}
