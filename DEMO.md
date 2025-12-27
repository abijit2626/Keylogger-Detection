# Demo Guide: Keylogger Detection System

This guide will help you demonstrate the Keylogger Detection System to your teacher.

## 1. Setup

Open two terminals in VS Code.

**Terminal 1 (The Detector):**
This will run the defense system.

**Terminal 2 (The Threat):**
This will run a simulated keylogger.

## 2. The Demo Script

### Step 1: Start the Detector
In **Terminal 1**, run the main controller:
```bash
python main_controller.py
```
*Explain:* "The system is now running in the background. It takes snapshots of all running processes every 10 seconds (configurable) and analyzes their behavior."

### Step 2: Start the Threat
In **Terminal 2**, run the simulation script:
```bash
python demo_threat.py
```
*Explain:* "I am now starting a simulated threat. This script installs a global keyboard hook (like a keylogger) and loads dynamic libraries."

### Step 3: Observe Detection
Watch **Terminal 1**.
Within a few seconds/minutes (depending on the configured interval), you will see logs indicating detection.

*Look for:*
- `SUSPECT_DETECTED`: The system notices a new process with suspicious characteristics.
- `Risk Score Increasing`: The risk engine assigns points to the process.
- `HIGH RISK DETECTED`: If the behavior persists or worsens.

### Step 4: Neutralize
Stop the threat in **Terminal 2** (Press `Ctrl+C`).
*Explain:* "Once the threat is removed, the system will eventually decay the risk score, but the incident is logged."

## 3. Key Concepts to Mention
- **Behavioral Analysis**: "We don't just look for filenames; we look for *capabilities* like keyboard hooks."
- **Temporal Tracking**: "We track processes over time to detect *changes* in behavior."
- **Risk Scoring**: "Not everything is black and white. We assign risk scores that decay over time to reduce false positives."