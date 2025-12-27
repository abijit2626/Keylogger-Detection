# Testing Guide

This guide explains how to test the keylogger detection system at different levels.

## Prerequisites

1. **Windows OS** (required - the system is Windows-only)
2. **Administrator privileges** (recommended - needed to scan all processes)
3. **Python dependencies** installed:
   ```powershell
   pip install -r requirements.txt
   ```

## Quick Tests

### 1. Test Single Scan
Run a single scan cycle:
```powershell
python -m scanner.scanner
```
**Expected output:**
- Creates a snapshot file in `snapshots/scan_YYYY-MM-DDTHH-MM-SS.json`
- Logs to console and `logs/keylogger_detection.log`
- Shows count of detected suspects

**Verify:**
- Check `snapshots/` directory for new JSON file
- Check log file for scan details

### 2. Test Detection Function Directly
Test just the core detection:
```powershell
python -c "from scanner.keyboard_hook_detector import detect_keyboard_hook_suspects; suspects = detect_keyboard_hook_suspects(); print(f'Found {len(suspects)} suspects')"
```

### 3. Test Temporal Analysis
After running at least 2 scans:
```powershell
python -m scanner.temporal_analyzer
```
**Expected output:**
- Creates `temporal_events.json` with behavioral change events
- Shows event counts and types

## Full System Test

### Automated Full System Test
Run the comprehensive test script:
```powershell
python test_full_system.py
```

This test:
1. ✅ Imports all modules
2. ✅ Runs multiple scan cycles (builds history)
3. ✅ Performs temporal analysis
4. ✅ Tests risk scoring engine
5. ✅ Verifies state persistence

**Duration:** ~30-60 seconds (depends on system)

### Manual Full System Test

#### Step 1: Run Multiple Scans
```powershell
# Run 3-5 scans with delays between them
python -m scanner.scanner
# Wait 10-30 seconds
python -m scanner.scanner
# Wait 10-30 seconds
python -m scanner.scanner
```

#### Step 2: Run Temporal Analysis
```powershell
python -m scanner.temporal_analyzer
```

#### Step 3: Check Generated Events
```powershell
# View events file
type temporal_events.json
```

#### Step 4: Test Risk Engine
```powershell
python -c "from scanner.temporal_risk_engine import update_temporal_risk; import json; events = json.load(open('temporal_events.json')); state = update_temporal_risk(events); print(f'Tracked {len(state)} processes')"
```

## Continuous Monitoring Test

Test the full controller (runs continuously):
```powershell
python main_controller.py
```

**What it does:**
- Runs scans every 120 seconds (2 minutes)
- Runs temporal analysis every 3 scans
- Processes events through risk engine
- Alerts on HIGH risk processes

**To stop:** Press `Ctrl+C`

**Expected behavior:**
- Logs scan cycles
- Creates snapshots periodically
- Runs analysis every 3 scans
- Shows HIGH risk alerts if detected

## Testing Scenarios

### Scenario 1: Fresh System
**Goal:** Test on a clean system with no existing data

```powershell
# Clean old data
del temporal_events.json
del temporal_state.json
rmdir /s /q snapshots
mkdir snapshots

# Run test
python test_full_system.py
```

### Scenario 2: Existing Data
**Goal:** Test with existing snapshots and state

```powershell
# Just run the test (preserves existing data)
python test_full_system.py
```

### Scenario 3: Simulate Keylogger Behavior
**Goal:** Test detection of suspicious behavior

1. Run baseline scan
2. Install/run a legitimate hook-capable app (e.g., AutoHotkey)
3. Run another scan
4. Check if temporal analysis detects the change
5. Verify risk scoring increases

## Verification Checklist

After running tests, verify:

- [ ] Snapshots created in `snapshots/` directory
- [ ] Logs written to `logs/keylogger_detection.log`
- [ ] Temporal events generated (if 2+ snapshots exist)
- [ ] State file created/updated (`temporal_state.json`)
- [ ] No Python errors in console or logs
- [ ] Processes detected (check snapshot JSON files)
- [ ] Risk levels assigned correctly

## Troubleshooting

### Issue: "No module named 'psutil'"
**Solution:**
```powershell
pip install psutil
```

### Issue: "Access denied" errors
**Solution:** Run as Administrator

### Issue: No suspects detected
**Possible reasons:**
- No processes with keyboard hook capability running
- All hook-capable processes are in Windows directory (filtered out)
- This is normal - not all systems have hook-capable processes

### Issue: Temporal analysis says "Need at least 2 snapshots"
**Solution:** Run the scanner multiple times:
```powershell
python -m scanner.scanner
python -m scanner.scanner
python -m scanner.scanner
```

### Issue: Test script hangs
**Possible reasons:**
- Scanning all processes takes time (30-60 seconds is normal)
- Some processes may be slow to access
- Run as Administrator for better access

## Expected Results

### Normal System
- **Suspects detected:** 0-20 (depends on installed software)
- **Common suspects:** Discord, Signal, AutoHotkey, accessibility tools
- **Risk levels:** Mostly LOW, occasional MEDIUM
- **HIGH risk:** Rare (only with persistent suspicious behavior)

### Test System
- **Snapshots:** 3+ files after running test
- **Events:** 0-10 events (depends on process changes)
- **State:** 0-10 tracked processes
- **Logs:** Detailed entries for each operation

## Performance Benchmarks

Typical performance on a modern Windows system:
- **Single scan:** 5-15 seconds
- **Temporal analysis:** <1 second
- **Risk engine update:** <1 second
- **Full test script:** 30-60 seconds

## Next Steps After Testing

1. Review logs in `logs/keylogger_detection.log`
2. Examine snapshot JSON files for detected processes
3. Check `temporal_state.json` for tracked processes
4. Run continuous monitoring if tests pass
5. Customize risk thresholds if needed (in `temporal_risk_engine.py`)

