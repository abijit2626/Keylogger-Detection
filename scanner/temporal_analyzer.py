import os
import json
from collections import defaultdict

SNAPSHOT_DIR = "snapshots"
OUTPUT_FILE = "temporal_events.json"


def load_snapshots():
    files = sorted(
        f for f in os.listdir(SNAPSHOT_DIR)
        if f.endswith(".json")
    )

    snapshots = []
    for f in files:
        with open(os.path.join(SNAPSHOT_DIR, f), "r") as fp:
            snapshots.append({
                "time": f,
                "data": json.load(fp)
            })
    return snapshots


def index_hooks(snapshot):
   
    hooks = {}

    for entry in snapshot.get("keyboard_hook_suspects", []):
        pid = entry["pid"]

        # DLL-based hook suspects
        if "suspicious_modules" in entry:
            dlls = {m["dll"] for m in entry["suspicious_modules"]}

        # EXE-based hook suspects
        else:
            exe = entry.get("executable")
            dlls = {exe} if exe else set()

        hooks[pid] = dlls

    return hooks


def analyze():
    snapshots = load_snapshots()
    if len(snapshots) < 2:
        print("[!] Need at least 2 snapshots for temporal analysis")
        return

    history = defaultdict(list)

    # Build time series
    for snap in snapshots:
        hook_map = index_hooks(snap["data"])
        for pid, dlls in hook_map.items():
            history[pid].append({
                "time": snap["time"],
                "dlls": dlls
            })

    events = []

    for pid, records in history.items():
        for i in range(1, len(records)):
            prev = records[i - 1]
            curr = records[i]

            # Hook appeared
            if not prev["dlls"] and curr["dlls"]:
                events.append({
                    "event": "HOOK_APPEARED",
                    "pid": pid,
                    "time": curr["time"],
                    "dlls": list(curr["dlls"])
                })

            # Hook persisted
            if prev["dlls"] and curr["dlls"]:
                events.append({
                    "event": "HOOK_PERSISTED",
                    "pid": pid,
                    "time": curr["time"],
                    "dlls": list(curr["dlls"])
                })

            # New DLL added
            new_dlls = curr["dlls"] - prev["dlls"]
            if new_dlls:
                events.append({
                    "event": "NEW_HOOK_MODULE",
                    "pid": pid,
                    "time": curr["time"],
                    "dlls": list(new_dlls)
                })

            # Hook removed
            removed = prev["dlls"] - curr["dlls"]
            if removed:
                events.append({
                    "event": "HOOK_REMOVED",
                    "pid": pid,
                    "time": curr["time"],
                    "dlls": list(removed)
                })

    with open(OUTPUT_FILE, "w") as f:
        json.dump(events, f, indent=2)

    print("\n========== TEMPORAL KEYBOARD HOOK REPORT ==========\n")
    for e in events:
        print(f"[{e['event']}] PID {e['pid']} @ {e['time']}")
        for d in e["dlls"]:
            print(f"  - {d}")
        print()

    print(f"[+] Temporal events written to {OUTPUT_FILE}")
    print("=============================================\n")


if __name__ == "__main__":
    analyze()
