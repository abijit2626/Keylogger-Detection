import ctypes
import ctypes.wintypes as wt
import subprocess
import hashlib


# Windows DLLs


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)


# Constants


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03

# ctypes SIGNATURE FIXES (MANDATORY on 64-bit Windows)


psapi.EnumProcessModulesEx.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(wt.HMODULE),
    wt.DWORD,
    ctypes.POINTER(wt.DWORD),
    wt.DWORD
]
psapi.EnumProcessModulesEx.restype = wt.BOOL

psapi.GetModuleFileNameExW.argtypes = [
    wt.HANDLE,
    wt.HMODULE,
    wt.LPWSTR,
    wt.DWORD
]
psapi.GetModuleFileNameExW.restype = wt.DWORD

psapi.EnumProcesses.argtypes = [
    ctypes.POINTER(wt.DWORD),
    wt.DWORD,
    ctypes.POINTER(wt.DWORD)
]
psapi.EnumProcesses.restype = wt.BOOL

kernel32.OpenProcess.argtypes = [
    wt.DWORD,
    wt.BOOL,
    wt.DWORD
]
kernel32.OpenProcess.restype = wt.HANDLE

kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL


# Helper Functions


def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def is_signed(path):
    try:
        out = subprocess.check_output(
            ["powershell", "-Command",
             f"(Get-AuthenticodeSignature '{path}').Status"],
            stderr=subprocess.DEVNULL
        ).decode()
        return "Valid" in out
    except Exception:
        return False


def enum_processes():
    arr = (wt.DWORD * 4096)()
    needed = wt.DWORD()
    psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(needed))
    return arr[: needed.value // ctypes.sizeof(wt.DWORD)]


def open_process(pid):
    return kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid
    )


def enum_modules(h):
    mods = (wt.HMODULE * 1024)()
    needed = wt.DWORD()

    psapi.EnumProcessModulesEx(
        h,
        mods,
        ctypes.sizeof(mods),
        ctypes.byref(needed),
        LIST_MODULES_ALL
    )

    modules = []
    count = needed.value // ctypes.sizeof(wt.HMODULE)

    for i in range(count):
        path = ctypes.create_unicode_buffer(260)
        psapi.GetModuleFileNameExW(h, mods[i], path, 260)
        modules.append(path.value)

    return modules


def get_process_exe(h):
   
    buf = ctypes.create_unicode_buffer(260)
    psapi.GetModuleFileNameExW(h, None, buf, 260)
    return buf.value


# Risk Scoring (False Positive Reduction)


def calculate_risk(entry):
    score = 0
    reasons = []

    path = (entry.get("executable") or "").lower()
    signed = entry.get("signed", True)
    hook_type = entry.get("type")

    # Unsigned binary
    if not signed:
        score += 25
        reasons.append("unsigned_binary")

    # Suspicious locations
    if "appdata" in path or "temp" in path:
        score += 20
        reasons.append("runs_from_user_space")

    if "program files" in path:
        score -= 20
        reasons.append("program_files_location")

    # DLL-based hooks are riskier
    if hook_type == "DLL_HOOK_SUSPECT":
        score += 15
        reasons.append("dll_based_hook")

    # Known trusted apps
    trusted = [
        "discord.exe",
        "signal.exe",
        "chrome.exe",
        "msedge.exe",
        "explorer.exe"
    ]

    for t in trusted:
        if t in path:
            score -= 30
            reasons.append("known_trusted_app")
            break

    # Risk level
    if score <= 0:
        level = "LOW"
    elif score <= 30:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return score, level, reasons


# Detection Logic


def detect_keyboard_hook_suspects():
    

    suspects = []

    for pid in enum_processes():
        h = open_process(pid)
        if not h:
            continue

        try:
            modules = enum_modules(h)
            exe_path = get_process_exe(h)
        except Exception:
            kernel32.CloseHandle(h)
            continue

        kernel32.CloseHandle(h)

        # Must load user32.dll
        if not any("user32.dll" in m.lower() for m in modules):
            continue

        # ---------------- DLL-based hook ----------------
        suspicious_dlls = []

        for m in modules:
            m_lower = m.lower()

            if "\\windows\\" in m_lower:
                continue

            if m_lower.endswith(".dll"):
                suspicious_dlls.append({
                    "dll": m,
                    "signed": is_signed(m),
                    "hash": sha256(m)
                })

        if suspicious_dlls:
            entry = {
                "pid": pid,
                "type": "DLL_HOOK_SUSPECT",
                "executable": suspicious_dlls[0]["dll"],
                "signed": all(d["signed"] for d in suspicious_dlls),
                "suspicious_modules": suspicious_dlls
            }

            score, level, reasons = calculate_risk(entry)
            entry["risk_score"] = score
            entry["risk_level"] = level
            entry["risk_reasons"] = reasons

            suspects.append(entry)
            continue

        # ---------------- EXE-based hook ----------------
        if exe_path and "\\windows\\" not in exe_path.lower():
            signed = is_signed(exe_path)

            entry = {
                "pid": pid,
                "type": "EXE_HOOK_SUSPECT",
                "executable": exe_path,
                "signed": signed,
                "hash": sha256(exe_path)
            }

            score, level, reasons = calculate_risk(entry)
            entry["risk_score"] = score
            entry["risk_level"] = level
            entry["risk_reasons"] = reasons

            suspects.append(entry)

    return suspects
