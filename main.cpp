#include "pch.h"
#include "main.h"
#include "AppUtils.h"
#include "PriorityManager.h"
#include "Dialogs.h"
#include <commctrl.h>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")

// Global variables
HINSTANCE hInst = nullptr;
HWND hListView = nullptr;
HWND hStatusBar = nullptr;
bool ShowSystemApps = false;
bool ShowUnmanagedApps = false;

WCHAR szTitle[MAX_STRING];
WCHAR szWindowClass[MAX_STRING];

// Forward declarations
ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

static void SetStatus(const std::wstring& text) {
    if (hStatusBar) {
        SendMessageW(hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(text.c_str()));
    }
}

static std::wstring GetSelectedAppName() {
    if (!hListView) return L"";
    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
    if (sel >= 0) {
        WCHAR buf[MAX_STRING] = {};
        ListView_GetItemText(hListView, sel, 0, buf, _countof(buf));
        buf[_countof(buf) - 1] = L'\0';
        return buf;
    }
    return L"";
}

static void SelectAppByName(const std::wstring& targetApp) {
    if (!hListView || targetApp.empty()) return;
    int count = ListView_GetItemCount(hListView);
    for (int i = 0; i < count; ++i) {
        WCHAR buf[MAX_STRING] = {};
        ListView_GetItemText(hListView, i, 0, buf, _countof(buf));
        buf[_countof(buf) - 1] = L'\0';
        if (_wcsicmp(buf, targetApp.c_str()) == 0) {
            ListView_SetItemState(hListView, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(hListView, i, FALSE);
            return;
        }
    }
}

static void ListApps(bool updateStatus = true) {
    if (!hListView) return;

    ListView_DeleteAllItems(hListView);

    auto apps = GetRegisteredApps();
    int userCount = 0, systemCount = 0, managedCount = 0;

    for (const auto& app : apps) {
        bool isSystem = IsSystemApp(app);
        if (isSystem) systemCount++;
        else userCount++;

        bool isManaged = IsAppManaged(app);
        if (isManaged) {
            managedCount++;
        }

        if (isSystem) {
            if (!isManaged && !ShowSystemApps)
                continue;
        } else {
            if (!ShowUnmanagedApps && !isManaged)
                continue;
        }

        LVITEMW lvItem = {};
        lvItem.mask = LVIF_TEXT;
        lvItem.iItem = ListView_GetItemCount(hListView);
        lvItem.iSubItem = 0;
        lvItem.pszText = const_cast<LPWSTR>(app.c_str());

        int insertedIndex = ListView_InsertItem(hListView, &lvItem);
        if (insertedIndex >= 0) {
            DWORD priority = 0;
            const wchar_t* prioName = GetAppPriority(app, priority) ? ConvertPriorityToName(priority) : DEFAULT_TEXT;
            ListView_SetItemText(hListView, insertedIndex, 1, const_cast<LPWSTR>(prioName));
        }
    }

    if (updateStatus) {
        std::wstring status =
            L"Found " + std::to_wstring(userCount) + L" user app(s), " +
            std::to_wstring(systemCount) + L" system app(s), " +
            std::to_wstring(managedCount) + L" managed by SetPriority";
        SetStatus(status);
    }
}

static void RefreshAndRestoreSelection(const std::wstring& preferredSelection = L"") {
    if (!hListView) return;
    std::wstring appToSelect = preferredSelection.empty() ? GetSelectedAppName() : preferredSelection;
    int topIndex = ListView_GetTopIndex(hListView);

    ListApps(false);

    if (!appToSelect.empty()) {
        SelectAppByName(appToSelect);
    }

    int newTopIndex = ListView_GetTopIndex(hListView);
    ListView_Scroll(hListView, 0, topIndex - newTopIndex);
}

static void OpenEditDialog(HWND parent, const std::wstring& appName) {
    std::wstring targetApp = appName;
    INT_PTR result = DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_EDIT), parent, EditDlg, reinterpret_cast<LPARAM>(&targetApp));
    if (result == IDOK) {
        RefreshAndRestoreSelection(targetApp);
        DWORD priority = 0;
        std::wstring prioName = GetAppPriority(targetApp, priority) ? ConvertPriorityToName(priority) : DEFAULT_TEXT;
        SetStatus(L"Changed app \"" + targetApp + L"\" and set priority to " + prioName);
    } else if (result == EDIT_DLG_UNMANAGED) {
        RefreshAndRestoreSelection(targetApp);
        SetStatus(L"Unmanaged \"" + targetApp + L"\"");
    } else if (result == EDIT_DLG_DELETED) {
        RefreshAndRestoreSelection();
        SetStatus(L"Deleted app \"" + targetApp + L"\"");
    }
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                      _In_opt_ HINSTANCE hPrevInstance,
                      _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    if (!IsRunningAsAdmin()) {
        if (!ElevateProcess()) {
            MessageBoxW(nullptr, L"Please run as administrator.", L"Error", MB_ICONERROR);
        }
        return 0;
    }

    SingleInstanceGuard singleInstance;
    if (singleInstance.IsAlreadyRunning()) {
        MessageBoxW(nullptr, L"The application is already running.", L"Error", MB_ICONERROR);
        return 0;
    }

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_STRING);
    LoadStringW(hInstance, IDC_MAIN, szWindowClass, MAX_STRING);
    MyRegisterClass(hInstance);

    if (!InitInstance(hInstance, nCmdShow)) {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_MAIN));
    MSG msg;

    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return static_cast<int>(msg.wParam);
}

ATOM MyRegisterClass(HINSTANCE hInstance) {
    WNDCLASSEXW wcex = {};
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MAIN));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_MAIN);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_MAIN));

    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    hInst = hInstance;

    constexpr int windowWidth = 650, windowHeight = 550;

    HWND hWnd = CreateWindowW(
        szWindowClass, szTitle,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, windowWidth, windowHeight,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!hWnd) return FALSE;

    CenterWindow(hWnd);
    ShowWindow(hWnd, nCmdShow);

    InitCommonControls();

    hListView = CreateWindowExW(0, WC_LISTVIEW, nullptr,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        0, 0, windowWidth, 450,
        hWnd, reinterpret_cast<HMENU>(LISTVIEW), hInst, nullptr
    );

    hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        hWnd, reinterpret_cast<HMENU>(STATUSBAR), hInst, nullptr
    );

    ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    const struct {
        const wchar_t* text;
        int width;
    } columns[] = {
        { L"Application Name", 314 },
        { L"Priority",         314 }
    };

    for (int i = 0; i < _countof(columns); ++i) {
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = const_cast<LPWSTR>(columns[i].text);
        col.cx = columns[i].width;
        col.iSubItem = i;
        ListView_InsertColumn(hListView, i, &col);
    }

    ListApps();
    return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        switch (wmId) {
        case IDM_SHORTCUT:
            MessageBoxW(
                hWnd,
                L"Insert = Add new app\n"
                L"Delete = Delete an app\n"
                L"Alt + F4 = Exit",
                L"Keyboard Shortcuts",
                MB_ICONINFORMATION | MB_OK
            );
            break;

        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;

        case IDM_REFRESH:
            ListApps();
            break;

        case IDM_SHOW_SYSTEM: {
            ShowSystemApps = !ShowSystemApps;
            HMENU hMenu = GetMenu(hWnd);
            CheckMenuItem(hMenu, IDM_SHOW_SYSTEM, ShowSystemApps ? MF_CHECKED : MF_UNCHECKED);
            ListApps();
            break;
        }

        case IDM_SHOW_UNMANAGED: {
            ShowUnmanagedApps = !ShowUnmanagedApps;
            HMENU hMenu = GetMenu(hWnd);
            CheckMenuItem(hMenu, IDM_SHOW_UNMANAGED, ShowUnmanagedApps ? MF_CHECKED : MF_UNCHECKED);
            ListApps();
            break;
        }

        case ID_BUTTON_ADD: {
            std::wstring addedApp;
            if (DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_ADD), hWnd, AddDlg, reinterpret_cast<LPARAM>(&addedApp)) == IDOK) {
                ListApps();
                SelectAppByName(addedApp);
                DWORD priority = 0;
                std::wstring priorityName = GetAppPriority(addedApp, priority) ? ConvertPriorityToName(priority) : DEFAULT_TEXT;
                SetStatus(L"Added app \"" + addedApp + L"\" and set priority to " + priorityName);
            }
            break;
        }

        case ID_BUTTON_DELETE: {
            std::wstring appName = GetSelectedAppName();
            if (!appName.empty()) {
                if (!CheckSystemApp(hWnd, appName)) {
                    break;
                }

                std::wstring msg;
                if (!IsAppManaged(appName)) {
                    msg = L"This app is not managed by SetPriority!\nDelete \"" + appName + L"\"?";
                } else {
                    msg = L"Delete \"" + appName + L"\"?";
                }

                if (MessageBoxW(hWnd, msg.c_str(), L"Confirm Delete", MB_ICONWARNING | MB_OKCANCEL) != IDOK) {
                    break;
                }

                RemoveApp(appName);
                RefreshAndRestoreSelection();
                SetStatus(L"Deleted app \"" + appName + L"\"");
            }
            break;
        }

        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    }

    case WM_NOTIFY: {
        auto list = reinterpret_cast<LPNMHDR>(lParam);
        if (list->code == LVN_KEYDOWN) {
            auto keyDown = reinterpret_cast<LPNMLVKEYDOWN>(lParam);
            if (keyDown->wVKey == VK_DELETE) {
                PostMessageW(hWnd, WM_COMMAND, ID_BUTTON_DELETE, 0);
            } else if (keyDown->wVKey == VK_INSERT) {
                PostMessageW(hWnd, WM_COMMAND, ID_BUTTON_ADD, 0);
            }
        }

        if (list->idFrom == LISTVIEW && list->code == NM_DBLCLK) {
            auto pnmItem = reinterpret_cast<LPNMITEMACTIVATE>(lParam);
            if (pnmItem->iItem >= 0) {
                WCHAR appName[MAX_STRING] = {};
                ListView_GetItemText(hListView, pnmItem->iItem, 0, appName, _countof(appName));
                appName[_countof(appName) - 1] = L'\0';
                OpenEditDialog(hWnd, appName);
            }
        }

        if (list->idFrom == LISTVIEW && list->code == NM_CUSTOMDRAW) {
            auto lvcd = reinterpret_cast<LPNMLVCUSTOMDRAW>(lParam);
            switch (lvcd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;

            case CDDS_ITEMPREPAINT:
                return CDRF_NOTIFYSUBITEMDRAW;

            case CDDS_SUBITEM | CDDS_ITEMPREPAINT: {
                if (lvcd->iSubItem == 0) {
                    WCHAR buf[MAX_STRING] = {};
                    ListView_GetItemText(hListView, static_cast<int>(lvcd->nmcd.dwItemSpec), 0, buf, _countof(buf));
                    buf[_countof(buf) - 1] = L'\0';
                    if (IsSystemApp(buf)) {
                        lvcd->clrText = RGB(255, 0, 0);
                    }
                } else if (lvcd->iSubItem == 1) {
                    WCHAR buf[MAX_STRING] = {};
                    ListView_GetItemText(hListView, static_cast<int>(lvcd->nmcd.dwItemSpec), 1, buf, _countof(buf));
                    buf[_countof(buf) - 1] = L'\0';

                    if (wcslen(buf) == 0 || wcscmp(buf, DEFAULT_TEXT) == 0) {
                        lvcd->clrText = RGB(0, 0, 0);
                    } else if (wcscmp(buf, L"Realtime") == 0) {
                        lvcd->clrText = RGB(139, 0, 0);
                    } else if (wcscmp(buf, L"High") == 0) {
                        lvcd->clrText = RGB(205, 92, 0);
                    } else if (wcscmp(buf, L"Above Normal") == 0) {
                        lvcd->clrText = RGB(218, 165, 32);
                    } else if (wcscmp(buf, L"Normal") == 0) {
                        lvcd->clrText = RGB(0, 100, 0);
                    } else if (wcscmp(buf, L"Below Normal") == 0) {
                        lvcd->clrText = RGB(0, 139, 139);
                    } else if (wcscmp(buf, L"Idle") == 0) {
                        lvcd->clrText = RGB(105, 105, 105);
                    }
                }
                return CDRF_DODEFAULT;
            }
            }
        }
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}