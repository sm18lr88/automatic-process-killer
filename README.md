# Automatic Process Killer for Windows

Fork of [DeliciousLines/automatic-process-killer](https://github.com/DeliciousLines/automatic-process-killer), modernized (Unicode, safer APIs, wildcards, startup toggle, DPI-aware). Tiny, no external deps. Runs in the tray and continuously terminates processes that match your patterns.

## Features
- Tray icon with context menu (NOTIFYICON_VERSION_4).
- Wildcards and full-path matching (e.g., `chrome*.exe`, `C:\Tools\foo.exe`).
- Case-insensitive match against **base filename** _or_ **full path**.
- Safe process queries via `QueryFullProcessImageNameW` + `PROCESS_QUERY_LIMITED_INFORMATION`.
- “Run at start-up” toggle via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- Optional “Restart as Administrator” (for protected processes).

> **Admin note:** Some processes require elevation to terminate. Use **Restart as Administrator** from the tray menu.

---

## Blacklist file
- Searched **next to the EXE**: `blacklist.txt`. If not writable, falls back to  
  `%LOCALAPPDATA%\Win32ProcessKiller\blacklist.txt` (auto-created).
- Encoding: UTF-8 (BOM or not) or ANSI. One **pattern** per line. Lines starting with `#` or `;` are comments.
- Wildcards follow Windows rules: `*` and `?`.
- If a pattern contains a path separator (`\` or `/`), it’s matched against the **full path**; otherwise against the **base name**.

**Examples**
```

# Base name

notepad.exe
chrome\*.exe

# Full path (normalize to backslashes recommended)

C:\Program Files\SomeApp\app.exe
D:\Tools\*\helper?.exe

```

The file is auto-reloaded when modified; you can also **Reload now** from the tray.

---

## Usage
1. Run `pk.exe`. The tray icon appears.
2. Right-click:
   - **Open blacklist** / **Create and open blacklist**
   - **Run at start-up** / **Do not run at start-up**
   - **Reload now**
   - **Restart as Administrator**
   - **Exit**

---

## Build (MSVC, no resources required)
Using the “Developer Command Prompt for VS”:

```powershell
# Release (GUI subsystem)
cl /nologo /O2 /W4 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN entry_point.c /link /SUBSYSTEM:WINDOWS

# Debug (console for logs & easy Ctrl+C close)
cl /nologo /Od /Z7 /W4 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN entry_point.c

# x64 explicit
cl /nologo /O2 /W4 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /favor:INTEL64 entry_point.c /link /SUBSYSTEM:WINDOWS
```

> You can add your own icon via a `.rc` file if desired; this build uses the default application icon.

---

## FAQ / Notes

* **Does the match include path?**
  Yes if your pattern contains `\` or `/`; otherwise it matches only the base filename (both are case-insensitive).
* **Why didn’t a process terminate?**
  It may require elevation, its image path wasn’t readable, or the pattern didn’t match. Try **Restart as Administrator** and confirm the pattern (use full path).
* **Where’s the config?**
  Only `blacklist.txt`. Startup is toggled via the tray (writes to HKCU **Run**).
* **Uninstall?**
  Disable **Run at start-up**, exit the app, then delete the EXE and (optionally)
  `%LOCALAPPDATA%\Win32ProcessKiller\blacklist.txt`.

---

## License

MIT (see header in `entry_point.c`).
This fork does **not** require `stb_sprintf`; the stub remains for compatibility and can be removed.

