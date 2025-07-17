#include "pch.h"
#include "resource.h"
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <windows.h>
#include <winreg.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comctl32.lib")

constexpr auto IFEO_PATH = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"; // Registry path
constexpr size_t MAX_STRING = 256;

HINSTANCE hInst;
HWND hListView, hStatusBar;
bool ShowSystemApps = false;
bool ShowUnmanagedApps = false;
constexpr auto DEFAULT_TEXT = L"Default";
constexpr auto RegPriority = L"CpuPriorityClass";
constexpr auto RegManaged = L"SetPriorityManaged";

const wchar_t* ConvertHexToName(DWORD priority)
{
	switch (priority)
	{
	case 1: return L"Idle";
	case 5: return L"Below Normal";
	case 2: return L"Normal";
	case 6: return L"Above Normal";
	case 3: return L"High";
	case 4: return L"Realtime";
	default: return L"(Unknown)";
	}
}

DWORD PriorityValues[] = {
	0,             // Not Set
	0x00000001,     // Idle
	0x00000005,     // Below Normal
	0x00000002,     // Normal
	0x00000006,     // Above Normal
	0x00000003,     // High
	0x00000004      // Realtime
};

void CenterWindow(HWND hwnd) { // make everything centered
	RECT rcWnd, rcScreen;
	GetWindowRect(hwnd, &rcWnd);
	SystemParametersInfo(SPI_GETWORKAREA, 0, &rcScreen, 0);
	int x = (rcScreen.right - rcScreen.left - (rcWnd.right - rcWnd.left)) / 2;
	int y = (rcScreen.bottom - rcScreen.top - (rcWnd.bottom - rcWnd.top)) / 2;
	SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

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

bool IsAlreadyRunning(const wchar_t* mutexName = L"Instance") {
	HANDLE hMutex = CreateMutexW(NULL, FALSE, mutexName);
	return (hMutex && GetLastError() == ERROR_ALREADY_EXISTS);
}

static bool ResolveFullPath(const std::wstring& exeName, std::wstring& outPath) {
	WCHAR buf[MAX_PATH];
	DWORD result = SearchPathW(NULL, exeName.c_str(), NULL, MAX_PATH, buf, NULL);
	if (result > 0 && result < MAX_PATH) {
		outPath = buf;
		return true;
	}
	return false;
}

static bool IsSystemApp(const std::wstring& exeName) {
	WCHAR path[MAX_PATH], systemPath[MAX_PATH];
	GetSystemDirectoryW(systemPath, MAX_PATH);
	PathCombineW(path, systemPath, exeName.c_str());
	if (PathFileExistsW(path)) return TRUE;

	WCHAR windowsPath[MAX_PATH];
	if (GetWindowsDirectoryW(windowsPath, MAX_PATH)) {
		PathCombineW(path, windowsPath, L"SysWOW64");
		PathCombineW(path, path, exeName.c_str());
		if (PathFileExistsW(path)) return TRUE;
	}
	return FALSE;
}

static bool CheckSystemApp(HWND parent, const std::wstring& appName) {
	if (IsSystemApp(appName)) {
		MessageBoxW(parent, L"System app cannot be deleted!", L"Error", MB_ICONERROR);
		return false;
	}
	return true;
}

std::vector<std::wstring> GetApps() {
	HKEY hKey;
	std::vector<std::wstring> appList;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IFEO_PATH, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		WCHAR name[256];
		DWORD nameSize, index = 0;

		while (true) {
			nameSize = _countof(name);
			if (RegEnumKeyExW(hKey, index++, name, &nameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
				break;

			if (_wcsicmp(name, L"{ApplicationVerifierGlobalSettings}") == 0)
				continue; // skip this key

			appList.push_back(name);
		}
		RegCloseKey(hKey);
	}
	return appList;
}

std::wstring GetRegPath(const std::wstring& appName) {
	return IFEO_PATH + std::wstring(L"\\") + appName + L"\\PerfOptions";
}

static bool GetPriority(const std::wstring& appName, DWORD& priority) {
	std::wstring subkey = GetRegPath(appName);
	HKEY hKey;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD dataSize = sizeof(DWORD);
		LONG result = RegQueryValueExW(hKey, RegPriority, NULL, NULL, (LPBYTE)&priority, &dataSize);
		RegCloseKey(hKey);
		return result == ERROR_SUCCESS;
	}
	return false;
}

static void SetPriorityManage(HKEY hKey) {
	DWORD value = 1;
	RegSetValueExW(hKey, RegManaged, 0, REG_DWORD,
		reinterpret_cast<const BYTE*>(&value),
		sizeof(DWORD)
	);
}

static bool SetPriority(const std::wstring& appName, DWORD priority) {
	std::wstring perfKey = GetRegPath(appName);
	HKEY hKey;
	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, perfKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
		LONG result = RegSetValueExW(hKey, RegPriority, 0, REG_DWORD, (const BYTE*)&priority, sizeof(DWORD));
		SetPriorityManage(hKey);
		RegCloseKey(hKey);
		return result == ERROR_SUCCESS;
	}
	return false;
}

static void DefaultPriority(const std::wstring& appName) {
	std::wstring perfKey = GetRegPath(appName);
	HKEY hKey;
	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, perfKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
		SetPriorityManage(hKey);
		RegCloseKey(hKey);
	}
}

static bool RemovePriority(const std::wstring& appName) {
	std::wstring perfKey = GetRegPath(appName);
	return RegDeleteTreeW(HKEY_LOCAL_MACHINE, perfKey.c_str()) == ERROR_SUCCESS;
}

static bool RemoveApp(const std::wstring& appName) {
	std::wstring appKey = IFEO_PATH + std::wstring(L"\\") + appName;
	RemovePriority(appName);
	return RegDeleteKeyW(HKEY_LOCAL_MACHINE, appKey.c_str()) == ERROR_SUCCESS;
}

static bool IsSetPriorityApp(const std::wstring& appName) {
	std::wstring subkey = GetRegPath(appName);
	HKEY hKey;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD value = 0;
		DWORD valueSize = sizeof(DWORD);
		LONG result = RegQueryValueExW(hKey, RegManaged, NULL, NULL, (LPBYTE)&value, &valueSize);
		RegCloseKey(hKey);
		return (result == ERROR_SUCCESS && value == 1);
	}
	return false;
}

static void SetStatus(const std::wstring& text) {
	if (hStatusBar) {
		SendMessageW(hStatusBar, SB_SETTEXT, 0, (LPARAM)text.c_str());
	}
}

WCHAR szTitle[MAX_STRING];
WCHAR szWindowClass[MAX_STRING];

ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    AddDlg(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    EditDlg(HWND, UINT, WPARAM, LPARAM);


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	if (!IsRunningAsAdmin()) {
		wchar_t szPath[MAX_PATH];
		if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
			SHELLEXECUTEINFOW sei = { sizeof(sei) };
			sei.lpVerb = L"runas";
			sei.lpFile = szPath;
			sei.hwnd = NULL;
			sei.nShow = SW_NORMAL;

			if (!ShellExecuteExW(&sei)) {
				MessageBoxW(NULL, L"Please run as administrator.", L"Error", MB_ICONERROR);
			}
		}
		return 0; // Exit process if no admin
	}

	if (IsAlreadyRunning()) {
		MessageBoxW(NULL, L"The application is already running.", L"Error", MB_ICONERROR);
		return 0;
	}

	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	// Initialize global strings
	LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_STRING);
	LoadStringW(hInstance, IDC_MAIN, szWindowClass, MAX_STRING);
	MyRegisterClass(hInstance);

	// Perform initialization
	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}

	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_MAIN));

	MSG msg;

	// Main message loop
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;
}

static void PriorityList(HWND hDlg) {
	const wchar_t* priority[] = {
		L"0 - Default (System Managed)",
		L"1 - Idle",
		L"5 - Below Normal",
		L"2 - Normal",
		L"6 - Above Normal",
		L"3 - High",
		L"4 - Realtime (Not Recommend)" // not recommended for most apps
	};

	for (const auto& prio : priority) {
		SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_ADDSTRING, 0, (LPARAM)prio);
	}
	SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_SETCURSEL, 0, 0); // Default selection
}

static void ListApps(bool updateStatus = true) {
	if (!hListView) return;

	ListView_DeleteAllItems(hListView);

	auto apps = GetApps();
	int userCount = 0, systemCount = 0, managedCount = 0;

	for (const auto& app : apps) {
		bool isSystem = IsSystemApp(app);
		if (isSystem) systemCount++;
		else userCount++;

		if (IsSetPriorityApp(app)) {
			managedCount++;
		}

		if (isSystem) { //fix
			if (!IsSetPriorityApp(app) && !ShowSystemApps)
				continue; // Skip un-managed system app unless ShowSystemApps is enabled
		}
		else {
			if (!ShowUnmanagedApps && !IsSetPriorityApp(app))
				continue; // Skip non-system apps not managed by SetPriority
		}

		// insert into ListView
		LVITEMW lvItem{};
		lvItem.mask = LVIF_TEXT;
		lvItem.iItem = ListView_GetItemCount(hListView);
		lvItem.iSubItem = 0;
		lvItem.pszText = (LPWSTR)app.c_str();
		ListView_InsertItem(hListView, &lvItem);

		DWORD priority;
		const wchar_t* prioName = GetPriority(app, priority) ? ConvertHexToName(priority) : DEFAULT_TEXT;
		ListView_SetItemText(hListView, lvItem.iItem, 1, const_cast<LPWSTR>(prioName));
	}

	if (updateStatus) {
		std::wstring status =
			L"Found " + std::to_wstring(userCount) + L" user app(s), " +
			std::to_wstring(systemCount) + L" system app(s), " +
			std::to_wstring(managedCount) + L" managed by SetPriority";
		SetStatus(status);
	}
}

void StoreSelection() {
	if (!hListView) return;

	int selIndex = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
	int topIndex = ListView_GetTopIndex(hListView);

	ListApps(false); // don't update status here

	if (selIndex >= 0) {
		ListView_SetItemState(hListView, selIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
		ListView_EnsureVisible(hListView, selIndex, FALSE);
	}

	ListView_Scroll(hListView, 0, topIndex - ListView_GetTopIndex(hListView));
}

static void RefreshList(HWND parent, const std::wstring& appName) {
	INT_PTR result = DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_EDIT), parent, EditDlg, (LPARAM)&appName);
	if (result == IDOK || result == 1001) {
		StoreSelection(); // Refresh without status overwrite
	}
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEXW wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MAIN));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_MAIN);
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	hInst = hInstance;

	constexpr int windowWidth = 650, windowHeight = 550;

	HWND hWnd = CreateWindowW(
		szWindowClass, szTitle,
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
		CW_USEDEFAULT, CW_USEDEFAULT, windowWidth, windowHeight,
		nullptr, nullptr, hInstance, nullptr
	);

	if (!hWnd)
		return FALSE;

	CenterWindow(hWnd);
	ShowWindow(hWnd, nCmdShow);

	InitCommonControls();

	hListView = CreateWindowExW(0, WC_LISTVIEW, nullptr,
		WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
		0, 0, windowWidth, 450,
		hWnd, (HMENU)LISTVIEW, hInst, nullptr
	);

	hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
		WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0,
		hWnd, (HMENU)STATUSBAR, hInst, nullptr
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

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_COMMAND:
	{
		int wmId = LOWORD(wParam);
		switch (wmId)
		{
		case IDM_SHORTCUT:
			MessageBoxW( // show keyboard shortcuts
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

		case IDM_SHOW_SYSTEM:
		{
			ShowSystemApps = !ShowSystemApps;  // toggle system apps visibility

			// update menu checkmark
			HMENU hMenu = GetMenu(hWnd);
			CheckMenuItem(hMenu, IDM_SHOW_SYSTEM, ShowSystemApps ? MF_CHECKED : MF_UNCHECKED);

			ListApps();  // refresh list
			break;
		}

		case IDM_SHOW_UNMANAGED:
		{
			ShowUnmanagedApps = !ShowUnmanagedApps;  // toggle unmanaged apps visibility
			// update menu checkmark
			HMENU hMenu = GetMenu(hWnd);
			CheckMenuItem(hMenu, IDM_SHOW_UNMANAGED, ShowUnmanagedApps ? MF_CHECKED : MF_UNCHECKED);
			ListApps();  // refresh list
			break;
		}

		case ID_BUTTON_ADD:
		{
			std::wstring appPath;
			if (DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_ADD), hWnd, AddDlg, (LPARAM)&appPath) == IDOK) {
				ListApps();

				int itemCount = ListView_GetItemCount(hListView);
				for (int i = 0; i < itemCount; ++i) {
					WCHAR buf[MAX_STRING] = {};
					ListView_GetItemText(hListView, i, 0, buf, 255);
					buf[MAX_STRING - 1] = L'\0';// null-termination

					if (_wcsicmp(buf, appPath.c_str()) == 0) {
						// Select the item in the ListView
						ListView_SetItemState(hListView, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
						ListView_EnsureVisible(hListView, i, FALSE);
						DWORD priority = 0;
						std::wstring priorityName = DEFAULT_TEXT;
						if (GetPriority(appPath, priority)) {
							priorityName = ConvertHexToName(priority);
						}

						std::wstring status = L"Added app \"" + appPath + L"\" and set priority to " + priorityName;
						SetStatus(status);
						break;
					}
				}
			}
		}
		break;

		case ID_BUTTON_DELETE:
		{
			int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
			if (sel >= 0) {
				WCHAR appName[MAX_STRING] = {};
				ListView_GetItemText(hListView, sel, 0, appName, MAX_STRING);
				appName[MAX_STRING - 1] = L'\0';

				if (!CheckSystemApp(hWnd, appName)) {
					break;
				}

				if (!IsSetPriorityApp(appName)) {
					std::wstring msg = L"This app is not managed by SetPriority!\nDelete \"" + std::wstring(appName) + L"\"?";
					if (MessageBoxW(hWnd, msg.c_str(), L"Warning", MB_ICONWARNING | MB_OKCANCEL) != IDOK) {
						break; // cancel deletion
					}
				}
				else {
					std::wstring msg = L"Delete \"" + std::wstring(appName) + L"\"?";
					if (MessageBoxW(hWnd, msg.c_str(), L"Confirm", MB_ICONINFORMATION | MB_OKCANCEL) != IDOK) {
						break; // cancel deletion
					}
				}

				RemoveApp(appName);
				StoreSelection();
				std::wstring status = L"Deleted app \"" + std::wstring(appName);
				SetStatus(status);
			}
		}
		break;

		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;

		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
	}
	break;
	case WM_NOTIFY:
	{
		LPNMHDR list = (LPNMHDR)lParam;
		if (list->code == LVN_KEYDOWN)
		{
			LPNMLVKEYDOWN keyDown = (LPNMLVKEYDOWN)lParam;
			if (keyDown->wVKey == VK_DELETE)
			{
				PostMessageW(hWnd, WM_COMMAND, ID_BUTTON_DELETE, 0);
			}

			if (keyDown->wVKey == VK_INSERT)
			{
				PostMessageW(hWnd, WM_COMMAND, ID_BUTTON_ADD, 0);
			}
		}

		if (list->idFrom == 1001 && list->code == NM_DBLCLK) {
			LPNMITEMACTIVATE pnmItem = (LPNMITEMACTIVATE)lParam;
			if (pnmItem->iItem >= 0) {
				WCHAR appName[MAX_STRING];
				ListView_GetItemText(hListView, pnmItem->iItem, 0, appName, 256);
				appName[MAX_STRING - 1] = L'\0'; // null-termination
				RefreshList(hWnd, appName);
			}
		}
		if (list->idFrom == 1001 && list->code == NM_CUSTOMDRAW) {
			LPNMLVCUSTOMDRAW lvcd = (LPNMLVCUSTOMDRAW)lParam;

			switch (lvcd->nmcd.dwDrawStage) {
			case CDDS_PREPAINT:
				return CDRF_NOTIFYITEMDRAW;

			case CDDS_ITEMPREPAINT:
				return CDRF_NOTIFYSUBITEMDRAW;

			case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
			{
				if (lvcd->iSubItem == 0) { // App Name
					WCHAR buf[MAX_STRING];
					ListView_GetItemText(hListView, (int)lvcd->nmcd.dwItemSpec, 0, buf, _countof(buf));
					buf[MAX_STRING - 1] = L'\0'; // null-termination

					if (IsSystemApp(buf)) {
						lvcd->clrText = RGB(255, 0, 0); // Red
					}
				}
				else if (lvcd->iSubItem == 1) { // Priority
					WCHAR buf[MAX_STRING] = {};
					ListView_GetItemText(hListView, (int)lvcd->nmcd.dwItemSpec, 1, buf, MAX_STRING);
					buf[MAX_STRING - 1] = L'\0'; // null-termination

					if (wcslen(buf) == 0 || wcscmp(buf, DEFAULT_TEXT) == 0) {
						lvcd->clrText = RGB(0, 0, 0); // Black
					}
					else if (wcscmp(buf, L"Realtime") == 0) {
						lvcd->clrText = RGB(139, 0, 0); // Dark Red
					}
					else if (wcscmp(buf, L"High") == 0) {
						lvcd->clrText = RGB(205, 92, 0); // Dark Orange
					}
					else if (wcscmp(buf, L"Above Normal") == 0) {
						lvcd->clrText = RGB(218, 165, 32); // Gold
					}
					else if (wcscmp(buf, L"Normal") == 0) {
						lvcd->clrText = RGB(0, 100, 0); // Dark Green
					}
					else if (wcscmp(buf, L"Below Normal") == 0) {
						lvcd->clrText = RGB(0, 139, 139); // Dark Cyan
					}
					else if (wcscmp(buf, L"Idle") == 0) {
						lvcd->clrText = RGB(105, 105, 105); // Dim Gray
					}
				}
				return CDRF_DODEFAULT;
			}
			}
		}
	}
	break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		CenterWindow(hDlg);
		return (INT_PTR)TRUE;
	}

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK AddDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	static std::wstring* appPathPtr = nullptr;

	switch (message)
	{
	case WM_INITDIALOG:
	{
		appPathPtr = (std::wstring*)lParam;

		PriorityList(hDlg);
		CenterWindow(hDlg);
		return (INT_PTR)TRUE;
	}

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_BROWSE:
		{
			WCHAR filePath[MAX_PATH] = L"";
			OPENFILENAMEW ofn = { sizeof(ofn) };
			ofn.hwndOwner = hDlg;
			ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files ? (*.*)\0*.*\0";
			ofn.lpstrFile = filePath;
			ofn.nMaxFile = MAX_PATH;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			if (GetOpenFileNameW(&ofn)) {
				WCHAR* filename = wcsrchr(filePath, L'\\');
				if (filename) filename++;
				else filename = filePath;

				SetDlgItemTextW(hDlg, IDC_EDIT_APPNAME, filename);
			}
			break;
		}

		case IDOK:
		{
			WCHAR appPath[MAX_PATH];
			GetDlgItemTextW(hDlg, IDC_EDIT_APPNAME, appPath, MAX_PATH);

			if (wcslen(appPath) == 0) {
				MessageBoxW(hDlg, L"Please type something or browse for an application executable.", L"Error", MB_ICONERROR);
				break;
			}

			// Check if app already exists in the ListView
			bool alreadyExists = false;
			if (hListView) {
				int itemCount = ListView_GetItemCount(hListView);
				for (int i = 0; i < itemCount; ++i) {
					WCHAR buf[MAX_STRING];
					ListView_GetItemText(hListView, i, 0, buf, 256);
					buf[MAX_STRING - 1] = L'\0'; // null-termination

					if (_wcsicmp(buf, appPath) == 0) {
						alreadyExists = true;
						break;
					}
				}
			}
			if (alreadyExists) {
				std::wstring msg = L"Application \"" + std::wstring(appPath) + L"\" already exists.";
				MessageBoxW(hDlg, msg.c_str(), L"Warning", MB_ICONWARNING);
				break;
			}

			*appPathPtr = appPath;

			// Set the SetPriorityManaged by default
			DefaultPriority(*appPathPtr);

			int index = (int)SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_GETCURSEL, 0, 0);
			if (index > 0 && index < std::size(PriorityValues)) {
				SetPriority(*appPathPtr, PriorityValues[index]);
			}

			EndDialog(hDlg, IDOK);
			break;
		}

		case IDCANCEL:
			EndDialog(hDlg, IDCANCEL);
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK EditDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	static std::wstring* appNamePtr = nullptr;

	switch (message)
	{
	case WM_INITDIALOG:
	{
		appNamePtr = (std::wstring*)lParam;
		SetDlgItemTextW(hDlg, IDC_EDIT_APPNAME, appNamePtr->c_str());

		PriorityList(hDlg);

		DWORD currentPriority = 0;
		if (GetPriority(*appNamePtr, currentPriority)) {
			int selIndex = 0;
			for (int i = 0; i < std::size(PriorityValues); ++i) {
				if (PriorityValues[i] == currentPriority) {
					selIndex = i;
					break;
				}
			}
			SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_SETCURSEL, selIndex, 0);
		}
		else {
			SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_SETCURSEL, 0, 0); // Default
		}

		if (IsSetPriorityApp(*appNamePtr)) { // check if app is managed by SetPriority
			EnableWindow(GetDlgItem(hDlg, IDC_UNMANAGED), TRUE);
		}
		else {
			EnableWindow(GetDlgItem(hDlg, IDC_UNMANAGED), FALSE);
		}

		CenterWindow(hDlg);
		return (INT_PTR)TRUE;
	}

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
		{
			int index = (int)SendDlgItemMessageW(hDlg, IDC_PRIORITY_COMBO, CB_GETCURSEL, 0, 0);
			if (index > 0 && index < std::size(PriorityValues)) {
				SetPriority(*appNamePtr, PriorityValues[index]);
			}
			else if (index == 0) {
				std::wstring perfKey = GetRegPath(*appNamePtr);
				HKEY hKey;
				if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, perfKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
					RegDeleteValueW(hKey, RegPriority); // Only remove priority value
					RegCloseKey(hKey);
				}
			}

			DWORD priority = 0;
			std::wstring priorityName = DEFAULT_TEXT;
			if (GetPriority(*appNamePtr, priority)) {
				priorityName = ConvertHexToName(priority);
			}

			std::wstring status = L"Changed app \"" + *appNamePtr + L"\" and set priority to " + priorityName;
			SetStatus(status);

			EndDialog(hDlg, IDOK);
			return (INT_PTR)TRUE;
		}

		case IDC_DELETE:
			if (appNamePtr) {
				if (!CheckSystemApp(hDlg, *appNamePtr)) {
					return (INT_PTR)TRUE;
				}

				HWND hParent = GetParent(hDlg);
				if (hParent) {
					PostMessageW(hParent, WM_COMMAND, ID_BUTTON_DELETE, 0);
				}
				EndDialog(hDlg, IDCANCEL);
			}
			return (INT_PTR)TRUE;


		case IDC_UNMANAGED:
		{
			if (appNamePtr) {
				std::wstring msg = L"This app will now unmanaged\nUnmanaged \"" + *appNamePtr + L"\"?";
				if (MessageBoxW(hDlg, msg.c_str(), L"Confirm", MB_OKCANCEL | MB_ICONQUESTION) == IDOK) {
					std::wstring perfKey = GetRegPath(*appNamePtr);
					HKEY hKey;
					if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, perfKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
						RegDeleteValueW(hKey, RegManaged);
						RegCloseKey(hKey);
					}

					std::wstring status = L"Unmanaged \"" + *appNamePtr + L"\"";
					SetStatus(status);

					EndDialog(hDlg, 1001); // custom code for unmanaged
				}
			}
			return (INT_PTR)TRUE;
		}

		case IDCANCEL:
			EndDialog(hDlg, IDCANCEL);
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}