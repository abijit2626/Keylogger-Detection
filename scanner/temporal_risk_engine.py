import time
import json
import os

from scanner.logger_config import setup_logger

STATE_FILE = "temporal_state.json"

EVENT_WEIGHTS = {
    "HOOK_APPEARED": 10,     # weak-to-medium signal
    "NEW_HOOK_MODULE": 35,   # strong signal
    "HOOK_REMOVED": -10     # relief
}

DECAY = 3
MEDIUM = 30
HIGH = 60

logger = setup_logger(__name__)


def load_state():
    """Load temporal risk state from file."""
    if not os.path.exists(STATE_FILE):
        logger.debug(f"State file {STATE_FILE} does not exist, returning empty state")
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
            logger.debug(f"Loaded state for {len(state)} process identities")
            return state
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load state from {STATE_FILE}: {e}")
        return {}


def save_state(state):
    """Save temporal risk state to file."""
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        logger.debug(f"Saved state for {len(state)} process identities to {STATE_FILE}")
    except IOError as e:
        logger.error(f"Failed to save state to {STATE_FILE}: {e}")
        raise


def update_temporal_risk(events):
    """Update risk scores based on temporal events."""
    logger.info(f"Updating temporal risk for {len(events)} events")
    
    state = load_state()
    now = time.time()
    touched = set()

    # --- ingest change events only ---
    for e in events:
        identity = e["identity"]
        etype = e["event"]

        if identity not in state:
            logger.debug(f"New process identity detected: {identity} ({e['exe']})")
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

        old_score = s["risk_score"]
        s["event_counts"][etype] = s["event_counts"].get(etype, 0) + 1
        weight = EVENT_WEIGHTS.get(etype, 0)
        s["risk_score"] += weight
        s["last_seen"] = now
        
        logger.debug(
            f"Event {etype} for {identity}: "
            f"score {old_score} -> {s['risk_score']} (weight: {weight})"
        )

    # --- decay & classification ---
    for identity in touched:
        s = state[identity]
        old_level = s["risk_level"]
        old_score = s["risk_score"]

        s["risk_score"] = max(0, s["risk_score"] - DECAY)

        if s["risk_score"] >= HIGH:
            s["risk_level"] = "HIGH"
        elif s["risk_score"] >= MEDIUM:
            s["risk_level"] = "MEDIUM"
        else:
            s["risk_level"] = "LOW"
        
        # Log level changes
        if old_level != s["risk_level"]:
            logger.warning(
                f"Risk level changed for {identity} ({s['exe']}): "
                f"{old_level} -> {s['risk_level']} (score: {s['risk_score']})"
            )
        elif s["risk_level"] == "HIGH":
            logger.warning(
                f"High risk maintained for {identity} ({s['exe']}): "
                f"score {s['risk_score']}"
            )

    save_state(state)
    logger.info(f"Risk update complete: {len(touched)} process(es) updated")
    return state


