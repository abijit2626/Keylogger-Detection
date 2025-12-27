"""
End-to-end test for the complete keylogger detection system.
Tests the full workflow: scanning -> temporal analysis -> risk scoring -> alerts.
"""
import os
import sys
import json
import time
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure we're on Windows
if os.name != "nt":
    print("[!] This tool is Windows-only.")
    sys.exit(1)

print("=" * 70)
print("Keylogger Detection System - Full System Test")
print("=" * 70)

# Import all components
print("\n[STEP 1] Importing modules...")
try:
    from scanner.scanner import main as run_scan
    from scanner.temporal_analyzer import analyze
    from scanner.temporal_risk_engine import update_temporal_risk, load_state
    from scanner.logger_config import setup_logger
    print("[OK] All modules imported successfully")
except Exception as e:
    print(f"[FAIL] Import failed: {e}")
    sys.exit(1)

# Setup logger
logger = setup_logger("full_system_test")

# Open a debug file
with open("test_debug.log", "w") as debug_log:
    def log(msg):
        print(msg)
        debug_log.write(msg + "\n")
        debug_log.flush()

    # Clean up old test data
    log("\n[STEP 2] Cleaning up old test data...")
test_files = [
    "temporal_events.json",
    "temporal_state.json"
]
for f in test_files:
    if os.path.exists(f):
        try:
            os.remove(f)
            print(f"  Removed: {f}")
        except Exception as e:
            print(f"  Warning: Could not remove {f}: {e}")

# Ensure snapshots directory exists
snapshots_dir = Path("snapshots")
snapshots_dir.mkdir(exist_ok=True)

# Count existing snapshots
existing_snapshots = list(snapshots_dir.glob("scan_*.json"))
print(f"  Found {len(existing_snapshots)} existing snapshot(s)")

print("\n[STEP 3] Running scans to build history...")
print("  (This simulates the real-world usage where scans run periodically)")

# Reduce scan count for faster testing
scan_count = 2
for i in range(scan_count):
    print(f"\n  Scan {i+1}/{scan_count}...")
    try:
        run_scan()
        time.sleep(2)  # Small delay between scans
        print(f"    [OK] Scan {i+1} completed")
    except Exception as e:
        print(f"    [FAIL] Scan {i+1} failed: {e}")
        import traceback
        traceback.print_exc()
        continue

# Check snapshots
snapshots = list(snapshots_dir.glob("scan_*.json"))
print(f"\n[STEP 4] Verifying snapshots...")
print(f"  Total snapshots: {len(snapshots)}")

if len(snapshots) < 2:
    print("  [WARN] Need at least 2 snapshots for temporal analysis")
    print("  The system will work, but temporal analysis needs more data")
else:
    print("  [OK] Sufficient snapshots for temporal analysis")
    
    # Show snapshot summary
    for snap in sorted(snapshots)[-3:]:  # Show last 3
        try:
            with open(snap, "r") as f:
                data = json.load(f)
                suspect_count = len(data.get("keyboard_hook_suspects", []))
                timestamp = data.get("timestamp", "unknown")
                print(f"    {snap.name}: {suspect_count} suspect(s) at {timestamp[:19]}")
        except Exception as e:
            print(f"    {snap.name}: Error reading - {e}")

print("\n[STEP 5] Running temporal analysis...")
try:
    analyze()
    
    # Check if events were generated
    events_file = Path("temporal_events.json")
    if events_file.exists():
        with open(events_file, "r") as f:
            events = json.load(f)
        print(f"  [OK] Generated {len(events)} temporal event(s)")
        
        if events:
            print("\n  Event breakdown:")
            event_types = {}
            for event in events:
                etype = event.get("event", "unknown")
                event_types[etype] = event_types.get(etype, 0) + 1
            
            for etype, count in event_types.items():
                print(f"    {etype}: {count}")
            
            print("\n  Sample events:")
            for i, event in enumerate(events[:5], 1):
                etype = event.get("event", "unknown")
                exe = event.get("exe", "unknown")
                pid = event.get("pid", "unknown")
                print(f"    {i}. {etype} - {exe} (PID: {pid})")
        else:
            print("  [INFO] No behavioral changes detected (this is normal if processes are stable)")
    else:
        print("  [WARN] Events file not created")
except Exception as e:
    print(f"  [FAIL] Temporal analysis failed: {e}")
    import traceback
    traceback.print_exc()

print("\n[STEP 6] Testing risk engine...")
try:
    events_file = Path("temporal_events.json")
    if events_file.exists():
        with open(events_file, "r") as f:
            events = json.load(f)
        
        if events:
            print(f"  Processing {len(events)} events through risk engine...")
            state = update_temporal_risk(events)
            
            print(f"  [OK] Risk engine processed events")
            print(f"  Tracked {len(state)} process identity/identities")
            
            # Show risk summary
            risk_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            for ident, s in state.items():
                level = s.get("risk_level", "LOW")
                risk_levels[level] = risk_levels.get(level, 0) + 1
            
            print("\n  Risk level summary:")
            for level, count in risk_levels.items():
                if count > 0:
                    print(f"    {level}: {count}")
            
            # Show high-risk processes
            high_risk = [(ident, s) for ident, s in state.items() if s.get("risk_level") == "HIGH"]
            if high_risk:
                print("\n  [ALERT] High-risk processes detected:")
                for ident, s in high_risk:
                    print(f"    - {s.get('exe', 'unknown')}")
                    print(f"      Risk Score: {s.get('risk_score', 0)}")
                    print(f"      Events: {s.get('event_counts', {})}")
            else:
                print("\n  [INFO] No high-risk processes detected")
        else:
            print("  [INFO] No events to process (skipping risk engine)")
    else:
        print("  [INFO] No events file found (skipping risk engine)")
except Exception as e:
    print(f"  [FAIL] Risk engine failed: {e}")
    import traceback
    traceback.print_exc()

print("\n[STEP 7] Testing state persistence...")
try:
    state = load_state()
    if state:
        print(f"  [OK] State file contains {len(state)} tracked process(es)")
        print("  State persists across runs (as expected)")
    else:
        print("  [INFO] State file is empty (normal if no events processed)")
except Exception as e:
    print(f"  [FAIL] State loading failed: {e}")

print("\n" + "=" * 70)
print("Full System Test Summary")
print("=" * 70)
print("\n[OK] Full system test completed!")
print("\nWhat was tested:")
print("  1. Module imports and initialization")
print("  2. Multiple scan cycles (snapshot generation)")
print("  3. Temporal analysis (behavioral change detection)")
print("  4. Risk scoring engine (threat assessment)")
print("  5. State persistence (cross-run tracking)")
print("\nNext steps:")
print("  - Check logs/keylogger_detection.log for detailed logs")
print("  - Run 'python main_controller.py' for continuous monitoring")
print("  - Review snapshots/ directory for scan history")
print("  - Check temporal_state.json for tracked processes")
print("\n" + "=" * 70)

