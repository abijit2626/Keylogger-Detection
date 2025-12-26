# 🔐 Keylogger Detection (Behavioral, User-Mode)

## Overview

This project is a **Windows user-mode behavioral scanner** designed to identify **processes capable of installing keyboard hooks** — a technique commonly used by keyloggers, accessibility tools, hotkey managers, and some malware.

Instead of using unsafe or invasive techniques (kernel drivers, live API hooking, code injection), the tool focuses on **capability detection combined with temporal behavior analysis**, similar to early-stage **Endpoint Detection & Response (EDR)** systems.

⚠️ **This is not a malware classifier.**  
It is a **precondition and behavior detector**.

---

## 🧠 Detection Philosophy

Most keyloggers rely on Windows APIs such as:

- `SetWindowsHookEx`
- `WH_KEYBOARD` / `WH_KEYBOARD_LL`
- `user32.dll` input interception

This tool answers the question:

> **Which processes can hook the keyboard, and do they persist over time?**

Rather than attempting to intercept keystrokes, it identifies **processes with the capability and behavior patterns required to do so**.

---

## 🔍 Detection Signals

Detection is based on the following signals:

- Use of `user32.dll`
- Presence of **user-space DLLs or executables**
- Digital signature verification (signed vs unsigned)
- Process location (system directory vs user space)
- Persistence across multiple scan cycles

Processes are classified as **suspects**, not threats.

---

## 🏗️ Architecture
```
Keylogger-Dection/
├── scanner/
│ ├── scanner.py # Orchestrates one scan cycle
│ ├── keyboard_hook_detector.py # Core hook-capability detection
│ ├── temporal_analyzer.py # Time-based behavior correlation
│ ├── temporal_risk_engine.py
│ └── init.py
│
├── snapshots/ # Scan snapshots (JSON)
├── temporal_events.json # Derived behavioral events
├── main_controller.py # Periodic scanning controller
└── README.md
```
---

## 🧪 Detection Categories

Each scan produces a snapshot containing **keyboard hook suspects**, categorized as:

### 1️⃣ EXE_HOOK_SUSPECT

Processes that:
- Load `user32.dll`
- Run from **user-space** (not `C:\Windows`)
- May implement keyboard hooks internally

Examples:
- AutoHotkey
- Electron-based apps (Discord, Signal)
- Accessibility tools

---

### 2️⃣ DLL_HOOK_SUSPECT

Processes that:
- Load `user32.dll`
- Also load **non-Windows DLLs**
- May install hooks via injected or bundled libraries

---

## ⏱️ Temporal Analysis

The temporal analyzer correlates multiple scan snapshots over time to identify:

- Hook appearance
- Hook persistence
- New hook owners
- Changes in signed vs unsigned components

This reduces noise and helps distinguish:

- Transient legitimate behavior
- Persistent suspicious behavior

---

## ⚠️ Expected False Positives

Some legitimate applications will appear as hook-capable suspects, including:

- Discord
- Signal
- Wallpaper engines
- Hotkey managers
- Accessibility software

This is **expected and correct behavior**.

False positives are addressed through **temporal correlation and refinement**, not aggressive detection.

---

## 🛡️ Safety & Ethics

- User-mode only
- Read-only inspection
- No code injection
- No keystroke capture
- No system modification

This project is suitable for **learning, research, and experimentation**.

---

## 🚀 How to Run

### Single Scan

From the project root (Windows, Administrator):

```powershell
python -m scanner.scanner
