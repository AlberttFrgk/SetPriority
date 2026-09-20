#pragma once

#include <windows.h>
#include <string>

constexpr INT_PTR EDIT_DLG_UNMANAGED = 1001;
constexpr INT_PTR EDIT_DLG_DELETED   = 1002;

void PopulatePriorityCombo(HWND hDlg, int comboId);

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK AddDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK EditDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
