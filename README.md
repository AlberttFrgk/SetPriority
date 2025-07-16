
# SetPriority - App Priority Manager

![SetPriority](https://i.imgur.com/EGmVMgn.png)

**SetPriority** is a lightweight native Windows tool to set and manage CPU priority for specific applications via the Windows Registry, particularly using **Image File Execution Options (IFEO) PerfOptions, built with C++ (Win32 API)**.

## ✅ Features
- View applications with custom CPU priority settings.
- Set the CPU priority of any application
- Mark apps as managed by SetPriority.
- Filter display:
  - Show system apps (optional)
  - Show existing (non-SetPriority managed) apps
- Double-click to edit any app's priority.
- Safe deletion with system app protection.
- Auto prompts for **Administrator privilege**.
- Minimal dependencies (pure Win32 API + common controls).
- Status bar summary of user, system, and managed apps.
- Visual indicators via colored priority labels.

## ⚡ Usage Shortcuts
| Key         | Action             |
|-------------|--------------------|
| **Insert**  | Add a new app       |
| **Delete**  | Remove selected app |
| **Double-click** | Edit priority  |
| **Alt + F4**| Exit                |

## 🛠 How It Works
SetPriority modifies:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<AppName>\PerfOptions
```

Setting the `CpuPriorityClass` DWORD defines the CPU priority for that app globally when launched.

Example:
```
CpuPriorityClass = 0x00000003 // High
```

## ⚙ Requirements
- Windows OS
- Administrator rights

## ⬆️ Priority List
  - **Idle**
  - **Below Normal**
  - **Normal**
  - **Above Normal**
  - **High**
  - **Realtime** (⚠️ not recommended for most apps)

