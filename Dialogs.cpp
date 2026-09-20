#include "pch.h"
#include "Dialogs.h"
#include "AppUtils.h"
#include "PriorityManager.h"
#include "resource.h"
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

void PopulatePriorityCombo(HWND hDlg, int comboId) {
    SendDlgItemMessageW(hDlg, comboId, CB_RESETCONTENT, 0, 0);
    const auto& options = GetPriorityOptions();
    for (const auto& opt : options) {
        SendDlgItemMessageW(hDlg, comboId, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(opt.displayName));
    }
    SendDlgItemMessageW(hDlg, comboId, CB_SETCURSEL, 0, 0);
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG:
        CenterWindow(hDlg);
        return static_cast<INT_PTR>(TRUE);

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return static_cast<INT_PTR>(TRUE);
        }
        break;
    }
    return static_cast<INT_PTR>(FALSE);
}

INT_PTR CALLBACK AddDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INITDIALOG: {
        SetWindowLongPtrW(hDlg, DWLP_USER, static_cast<LONG_PTR>(lParam));
        PopulatePriorityCombo(hDlg, IDC_PRIORITY_COMBO);
        CenterWindow(hDlg);
        return static_cast<INT_PTR>(TRUE);
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_BUTTON_BROWSE: {
            WCHAR filePath[MAX_PATH] = L"";
            OPENFILENAMEW ofn = { sizeof(ofn) };
            ofn.hwndOwner = hDlg;
            ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = filePath;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

            if (GetOpenFileNameW(&ofn)) {
                LPCWSTR filename = PathFindFileNameW(filePath);
                SetDlgItemTextW(hDlg, IDC_EDIT_APPNAME, filename);
            }
            break;
        }

        case IDOK: {
            auto* appPathPtr = reinterpret_cast<std::wstring*>(GetWindowLongPtrW(hDlg, DWLP_USER));
            if (!appPathPtr) {
                EndDialog(hDlg, IDCANCEL);
                return static_cast<INT_PTR>(TRUE);
            }

            WCHAR rawInput[MAX_PATH] = {};
            GetDlgItemTextW(hDlg, IDC_EDIT_APPNAME, rawInput, MAX_PATH);

            std::wstring sanitizedAppName;
            std::wstring errorMsg;
            if (!SanitizeAndValidateAppName(rawInput, sanitizedAppName, errorMsg)) {
                MessageBoxW(hDlg, errorMsg.c_str(), L"Invalid Application Name", MB_ICONERROR);
                break;
            }

            // Check if application already exists in IFEO registry
            auto registeredApps = GetRegisteredApps();
            for (const auto& existing : registeredApps) {
                if (_wcsicmp(existing.c_str(), sanitizedAppName.c_str()) == 0) {
                    std::wstring msg = L"Application \"" + sanitizedAppName + L"\" already exists.";
                    MessageBoxW(hDlg, msg.c_str(), L"Warning", MB_ICONWARNING);
                    return static_cast<INT_PTR>(TRUE);
                }
            }

            *appPathPtr = sanitizedAppName;

            // Set managed by default
            SetAppDefaultPriority(*appPathPtr);

            int index = static_cast<int>(SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_GETCURSEL, 0, 0));
            if (index > 0) {
                SetAppPriority(*appPathPtr, GetPriorityValueByIndex(index));
            }

            EndDialog(hDlg, IDOK);
            return static_cast<INT_PTR>(TRUE);
        }

        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return static_cast<INT_PTR>(TRUE);
        }
        break;
    }
    }
    return static_cast<INT_PTR>(FALSE);
}

INT_PTR CALLBACK EditDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INITDIALOG: {
        SetWindowLongPtrW(hDlg, DWLP_USER, static_cast<LONG_PTR>(lParam));
        auto* appNamePtr = reinterpret_cast<std::wstring*>(lParam);
        if (!appNamePtr) {
            EndDialog(hDlg, IDCANCEL);
            return static_cast<INT_PTR>(TRUE);
        }

        SetDlgItemTextW(hDlg, IDC_EDIT_APPNAME, appNamePtr->c_str());
        PopulatePriorityCombo(hDlg, IDC_PRIORITY_COMBO);

        DWORD currentPriority = 0;
        if (GetAppPriority(*appNamePtr, currentPriority)) {
            int selIndex = GetPriorityIndexByValue(currentPriority);
            SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_SETCURSEL, selIndex, 0);
        } else {
            SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_SETCURSEL, 0, 0);
        }

        EnableWindow(GetDlgItem(hDlg, IDC_UNMANAGED), IsAppManaged(*appNamePtr) ? TRUE : FALSE);
        CenterWindow(hDlg);
        return static_cast<INT_PTR>(TRUE);
    }

    case WM_COMMAND: {
        auto* appNamePtr = reinterpret_cast<std::wstring*>(GetWindowLongPtrW(hDlg, DWLP_USER));
        if (!appNamePtr) {
            break;
        }

        switch (LOWORD(wParam)) {
        case IDOK: {
            int index = static_cast<int>(SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_GETCURSEL, 0, 0));
            if (index > 0) {
                SetAppPriority(*appNamePtr, GetPriorityValueByIndex(index));
            } else if (index == 0) {
                RemoveAppPriorityValue(*appNamePtr);
            }
            EndDialog(hDlg, IDOK);
            return static_cast<INT_PTR>(TRUE);
        }

        case IDC_DELETE: {
            if (!CheckSystemApp(hDlg, *appNamePtr)) {
                return static_cast<INT_PTR>(TRUE);
            }

            std::wstring msg;
            if (!IsAppManaged(*appNamePtr)) {
                msg = L"This app is not managed by SetPriority!\nDelete \"" + *appNamePtr + L"\"?";
            } else {
                msg = L"Delete \"" + *appNamePtr + L"\"?";
            }

            if (MessageBoxW(hDlg, msg.c_str(), L"Confirm Delete", MB_ICONWARNING | MB_OKCANCEL) == IDOK) {
                RemoveApp(*appNamePtr);
                EndDialog(hDlg, EDIT_DLG_DELETED);
            }
            return static_cast<INT_PTR>(TRUE);
        }

        case IDC_UNMANAGED: {
            std::wstring msg = L"This app will no longer be managed.\nUnmanage \"" + *appNamePtr + L"\"?";
            if (MessageBoxW(hDlg, msg.c_str(), L"Confirm", MB_OKCANCEL | MB_ICONQUESTION) == IDOK) {
                UnmanageApp(*appNamePtr);
                EndDialog(hDlg, EDIT_DLG_UNMANAGED);
            }
            return static_cast<INT_PTR>(TRUE);
        }

        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return static_cast<INT_PTR>(TRUE);
        }
        break;
    }
    }
    return static_cast<INT_PTR>(FALSE);
}
