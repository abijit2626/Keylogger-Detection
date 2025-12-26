import os
import sys
import json
from datetime import datetime, UTC

#  OS GUARD 
if os.name != "nt":
    print("[!] This scanner only runs on Windows.")
    sys.exit(1)

# IMPORT DETECTORS 
from scanner.keyboard_hook_detector import detect_keyboard_hook_suspects




def main():
    os.makedirs("snapshots", exist_ok=True)

    print("[*] Scanning processes...")

    # Run keyboard hook detector
    keyboard_hooks = detect_keyboard_hook_suspects()

    results = {
        "timestamp": datetime.now(UTC).isoformat(),
        "keyboard_hook_suspects": keyboard_hooks
    }

    filename = f"snapshots/scan_{results['timestamp'].replace(':', '-')}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Scan complete -> {filename}")


if __name__ == "__main__":
    main()
