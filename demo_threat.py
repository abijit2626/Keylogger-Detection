import sys
import time
import ctypes
from ctypes import wintypes
import os

# Define Windows API constants and types
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100

def hook_proc(nCode, wParam, lParam):
    # Pass the event to the next hook in the chain (don't actually block/log keys)
    return user32.CallNextHookEx(None, nCode, wParam, lParam)

# Define the callback function type
CMPFUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
pointer = CMPFUNC(hook_proc)

def main():
    print(f"PID: {os.getpid()}")
    print("Installing dummy keyboard hook...")
    
    # Install the low-level keyboard hook
    # GetModuleHandleW(None) gets the handle to the current process (python.exe)
    try:
        hook = user32.SetWindowsHookExW(
            WH_KEYBOARD_LL,
            pointer,
            kernel32.GetModuleHandleW(None),
            0
        )
    except Exception as e:
        print(f"Failed to install hook: {e}")
        return
    
    if not hook:
        print("Failed to install hook. Run as Administrator might be required (but usually not for user hooks).")
        return

    print("Hook installed. This process is now acting like a keylogger.")
    print("The detector should identify it as a suspect due to behavior and loaded modules.")
    print("Press Ctrl+C to stop.")

    # Windows message loop is required for hooks to work
    msg = wintypes.MSG()
    try:
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        if hook:
            user32.UnhookWindowsHookEx(hook)
            print("Hook removed.")

if __name__ == "__main__":
    main()