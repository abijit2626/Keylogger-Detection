import os
import sys
import json
from datetime import datetime, UTC

if os.name != "nt":
    print("[!] Windows only.")
    sys.exit(1)

from scanner.keyboard_hook_detector import detect_keyboard_hook_suspects


def main():
    os.makedirs("snapshots", exist_ok=True)

    suspects = detect_keyboard_hook_suspects()

    result = {
        "timestamp": datetime.now(UTC).isoformat(),
        "keyboard_hook_suspects": suspects
    }

    fname = f"snapshots/scan_{result['timestamp'].replace(':','-')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Snapshot written: {fname}")


if __name__ == "__main__":
    main()
