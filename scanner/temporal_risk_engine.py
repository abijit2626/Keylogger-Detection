import time
import json
import os

STATE_FILE = "temporal_state.json"

EVENT_WEIGHTS = {
    "HOOK_APPEARED": 8,
    "NEW_HOOK_MODULE": 30,
    "HOOK_REMOVED": -5
}

DECAY = 2
MEDIUM = 30
HIGH = 60

# seconds the identity must live before we consider it persistent
PERSISTENCE_THRESHOLD = 120  # one scan interval


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def update_temporal_risk(events):
    state = load_state()
    now = time.time()
    touched = set()

    # --- ingest real events only ---
    for e in events:
        identity = e["identity"]
        etype = e["event"]

        if identity not in state:
            state[identity] = {
                "risk_score": 0,
                "risk_level": "LOW",
                "event_counts": {},
                "first_seen": now,
                "last_seen": now,
                "exe": e["exe"]
            }

        s = state[identity]
        touched.add(identity)

        s["event_counts"][etype] = s["event_counts"].get(etype, 0) + 1
        s["risk_score"] += EVENT_WEIGHTS.get(etype, 0)
        s["last_seen"] = now

    # --- infer persistence + decay ---
    for identity in touched:
        s = state[identity]

        lifetime = s["last_seen"] - s["first_seen"]
        is_persistent = lifetime >= PERSISTENCE_THRESHOLD

        has_real_signal = (
            s["event_counts"].get("HOOK_APPEARED", 0) > 0 or
            s["event_counts"].get("NEW_HOOK_MODULE", 0) > 0
        )

        # persistence only boosts confidence after a real signal
        if is_persistent and has_real_signal:
            s["risk_score"] += 5

        # decay always applies
        s["risk_score"] = max(0, s["risk_score"] - DECAY)

        # classify
        if s["risk_score"] >= HIGH:
            s["risk_level"] = "HIGH"
        elif s["risk_score"] >= MEDIUM:
            s["risk_level"] = "MEDIUM"
        else:
            s["risk_level"] = "LOW"

    save_state(state)
    return state
