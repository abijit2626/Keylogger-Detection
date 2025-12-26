from collections import defaultdict
import time
import json
import os

STATE_FILE = "temporal_state.json"

# ===================== CONFIG =====================

EVENT_WEIGHTS = {
    "HOOK_APPEARED": 8,        # weak signal
    "NEW_HOOK_MODULE": 30,     # strong signal
    "HOOK_REMOVED": -5,        # weak relief
    "HOOK_PERSISTED": 0        # CONTEXT ONLY
}

DECAY_PER_UPDATE = 2

ESCALATE_MEDIUM = 30
ESCALATE_HIGH = 60

# ===================== STATE =====================

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# ===================== CORE =====================

def update_temporal_risk(events):
    state = load_state()
    now = time.time()

    for event in events:
        pid = str(event["pid"])
        etype = event["event"]

        if pid not in state:
            state[pid] = {
                "risk_score": 0,
                "risk_level": "LOW",
                "event_counts": defaultdict(int),
                "first_seen": now,
                "last_seen": now
            }

        entry = state[pid]

        # ---------- update counters ----------
        entry["event_counts"][etype] += 1
        entry["last_seen"] = now

        # ---------- apply event weight ----------
        entry["risk_score"] += EVENT_WEIGHTS.get(etype, 0)

        # ---------- decay ----------
        entry["risk_score"] = max(0, entry["risk_score"] - DECAY_PER_UPDATE)

        # ---------- persistence amplifier ----------
        has_persistence = entry["event_counts"].get("HOOK_PERSISTED", 0) >= 2
        has_real_signal = (
            entry["event_counts"].get("HOOK_APPEARED", 0) > 0 or
            entry["event_counts"].get("NEW_HOOK_MODULE", 0) > 0
        )

        if has_persistence and has_real_signal:
            entry["risk_score"] += 5

        # ---------- risk level ----------
        if entry["risk_score"] >= ESCALATE_HIGH:
            entry["risk_level"] = "HIGH"
        elif entry["risk_score"] >= ESCALATE_MEDIUM:
            entry["risk_level"] = "MEDIUM"
        else:
            entry["risk_level"] = "LOW"

    save_state(state)
    return state