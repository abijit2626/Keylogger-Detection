import psutil
import os
import hashlib
import subprocess

WINDOWS_DIR = os.environ.get("WINDIR", "C:\\Windows").lower()



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


def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def detect_keyboard_hook_suspects():
    """
    Capability-based detector.
    Emits stable process identity using lifetime, not PID.
    """

    suspects = []

    for proc in psutil.process_iter(attrs=["pid", "exe", "create_time"]):
        try:
            pid = proc.info["pid"]
            exe = proc.info["exe"]
            create_time = proc.info["create_time"]

            if not exe or not create_time:
                continue  # identity impossible

            try:
                modules = [m.path for m in proc.memory_maps() if m.path]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

            if not any("user32.dll" in m.lower() for m in modules):
                continue

            suspicious_dlls = []
            for m in modules:
                m_lower = m.lower()
                if m_lower.startswith(WINDOWS_DIR):
                    continue
                if m_lower.endswith(".dll"):
                    suspicious_dlls.append({
                        "dll": m,
                        "signed": is_signed(m),
                        "hash": sha256(m)
                    })

            entry = {
                "pid": pid,
                "executable": exe,
                "create_time": create_time
            }

            if suspicious_dlls:
                entry["type"] = "DLL_HOOK_SUSPECT"
                entry["suspicious_modules"] = suspicious_dlls
            else:
                if exe.lower().startswith(WINDOWS_DIR):
                    continue
                entry["type"] = "EXE_HOOK_SUSPECT"
                entry["signed"] = is_signed(exe)
                entry["hash"] = sha256(exe)

            suspects.append(entry)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return suspects
