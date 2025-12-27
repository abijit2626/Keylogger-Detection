"""
Quick test script for the keylogger detection system.
Tests individual components and the full scan cycle.
"""
import os
import sys
import json
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure we're on Windows
if os.name != "nt":
    print("[!] This tool is Windows-only.")
    sys.exit(1)

print("=" * 60)
print("Keylogger Detection System - Test Script")
print("=" * 60)

# Test 1: Import check
print("\n[TEST 1] Checking imports...")
try:
    from scanner.keyboard_hook_detector import detect_keyboard_hook_suspects
    from scanner.scanner import main as scanner_main
    from scanner.temporal_analyzer import analyze
    from scanner.temporal_risk_engine import update_temporal_risk
    from scanner.logger_config import setup_logger
    print("[OK] All imports successful")
except ImportError as e:
    print(f"[FAIL] Import failed: {e}")
    sys.exit(1)

# Test 2: Logger setup
print("\n[TEST 2] Testing logger configuration...")
try:
    logger = setup_logger("test")
    logger.info("Logger test message")
    print("[OK] Logger configured successfully")
except Exception as e:
    print(f"[FAIL] Logger setup failed: {e}")
    sys.exit(1)

# Test 3: Single scan
print("\n[TEST 3] Running single scan...")
try:
    scanner_main()
    print("[OK] Scan completed successfully")
    
    # Check if snapshot was created
    snapshots_dir = Path("snapshots")
    if snapshots_dir.exists():
        snapshot_files = list(snapshots_dir.glob("scan_*.json"))
        if snapshot_files:
            latest = max(snapshot_files, key=lambda p: p.stat().st_mtime)
            print(f"[OK] Snapshot created: {latest.name}")
            
            # Show summary
            with open(latest, "r") as f:
                data = json.load(f)
                suspect_count = len(data.get("keyboard_hook_suspects", []))
                print(f"  Found {suspect_count} keyboard hook suspect(s)")
                
                if suspect_count > 0:
                    print("\n  Sample suspects:")
                    for i, suspect in enumerate(data["keyboard_hook_suspects"][:3], 1):
                        exe = suspect.get("executable", "unknown")
                        ptype = suspect.get("type", "unknown")
                        print(f"    {i}. {exe} ({ptype})")
        else:
            print("[FAIL] No snapshot files found")
    else:
        print("[FAIL] Snapshots directory not created")
except Exception as e:
    print(f"[FAIL] Scan failed: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Direct detection function
print("\n[TEST 4] Testing direct detection function...")
try:
    suspects = detect_keyboard_hook_suspects()
    print(f"[OK] Detection function returned {len(suspects)} suspect(s)")
    
    if suspects:
        print("\n  Detection summary:")
        exe_suspects = sum(1 for s in suspects if s.get("type") == "EXE_HOOK_SUSPECT")
        dll_suspects = sum(1 for s in suspects if s.get("type") == "DLL_HOOK_SUSPECT")
        print(f"    EXE_HOOK_SUSPECT: {exe_suspects}")
        print(f"    DLL_HOOK_SUSPECT: {dll_suspects}")
except Exception as e:
    print(f"[FAIL] Detection failed: {e}")
    import traceback
    traceback.print_exc()

# Test 5: Temporal analysis (if we have snapshots)
print("\n[TEST 5] Testing temporal analysis...")
try:
    snapshots_dir = Path("snapshots")
    if snapshots_dir.exists():
        snapshot_files = list(snapshots_dir.glob("scan_*.json"))
        if len(snapshot_files) >= 2:
            analyze()
            print("[OK] Temporal analysis completed")
            
            # Check events file
            events_file = Path("temporal_events.json")
            if events_file.exists():
                with open(events_file, "r") as f:
                    events = json.load(f)
                    print(f"  Generated {len(events)} temporal event(s)")
                    if events:
                        print("\n  Sample events:")
                        for i, event in enumerate(events[:3], 1):
                            etype = event.get("event", "unknown")
                            exe = event.get("exe", "unknown")
                            print(f"    {i}. {etype} - {exe}")
        else:
            print(f"  [INFO] Need at least 2 snapshots for analysis (found {len(snapshot_files)})")
            print("    Run the scanner a few more times to test temporal analysis")
    else:
        print("  [INFO] No snapshots directory found")
except Exception as e:
    print(f"[FAIL] Temporal analysis failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("Test Summary")
print("=" * 60)
print("[OK] Basic functionality tests completed")
print("\nTo test the full system:")
print("  1. Run: python -m scanner.scanner (multiple times to create snapshots)")
print("  2. Run: python -m scanner.temporal_analyzer (after 2+ snapshots)")
print("  3. Run: python main_controller.py (for continuous monitoring)")
print("\nCheck logs/ directory for detailed logs")
print("=" * 60)

