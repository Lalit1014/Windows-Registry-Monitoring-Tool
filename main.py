"""
Windows Registry Change Monitoring System
Entry Point: main.py

Usage:
    python main.py --mode baseline          # Create a new baseline snapshot
    python main.py --mode monitor           # Start real-time polling monitor
    python main.py --mode check             # Run one-time integrity check
    python main.py --mode report --fmt txt  # Generate report from change log
    python main.py --mode demo              # Demo mode (simulated changes for testing)
"""

import argparse
import time
import json
import os
import sys
import logging
from datetime import datetime

# ── Guard: only import winreg on Windows ──────────────────────────
IS_WINDOWS = sys.platform.startswith("win")
if IS_WINDOWS:
    from registry_monitor import snapshot_all_keys, compare_snapshots, setup_logging
    from baseline_manager  import create_baseline, load_baseline, baseline_summary
    from alert_reporter    import emit_alert, generate_report, print_session_summary
else:
    # Allow the script to be parsed/imported on non-Windows for demonstration
    def setup_logging(*a, **kw):
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
        return logging.getLogger("RegistryMonitor")


POLL_INTERVAL_SEC = 30       # How often to poll the registry (seconds)
CHANGE_LOG        = "logs/changes.jsonl"
BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║      Windows Registry Change Monitoring System               ║
║      Unified Mentor Internship Project                       ║
║      Author: Intern | Version: 1.0                           ║
╚══════════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────
#  Mode: Create Baseline
# ─────────────────────────────────────────────

def mode_baseline(logger):
    logger.info("[MODE] Creating registry baseline snapshot...")
    snap = snapshot_all_keys()
    path = create_baseline(snap)
    baseline_summary(snap)
    print(f"\n✅ Baseline saved to: {path}")
    print("   Run `python main.py --mode monitor` to start monitoring.\n")


# ─────────────────────────────────────────────
#  Mode: Real-Time Monitor
# ─────────────────────────────────────────────

def mode_monitor(logger, interval: int):
    baseline = load_baseline()
    if not baseline:
        print("\n❌ No baseline found. Run `python main.py --mode baseline` first.\n")
        return

    baseline_summary(baseline)
    all_changes = []
    iteration   = 0

    print(f"🔍 Monitoring started. Polling every {interval}s. Press Ctrl+C to stop.\n")

    try:
        while True:
            iteration += 1
            current = snapshot_all_keys()
            changes = compare_snapshots(baseline, current)

            if changes:
                for change in changes:
                    emit_alert(change)
                    all_changes.append(change)
            else:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"  [{ts}] Scan #{iteration:04d} — No changes detected.", end="\r")

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n⛔ Monitoring stopped by user.\n")
        if all_changes:
            print_session_summary(all_changes)
            txt_path  = generate_report(all_changes, "txt")
            csv_path  = generate_report(all_changes, "csv")
            json_path = generate_report(all_changes, "json")
            print(f"\n📄 Reports saved:\n   {txt_path}\n   {csv_path}\n   {json_path}\n")
        else:
            print("ℹ️  No changes were detected during this session.\n")


# ─────────────────────────────────────────────
#  Mode: One-Time Integrity Check
# ─────────────────────────────────────────────

def mode_check(logger):
    baseline = load_baseline()
    if not baseline:
        print("\n❌ No baseline found. Run `python main.py --mode baseline` first.\n")
        return

    baseline_summary(baseline)
    print("🔍 Running one-time integrity check...\n")

    current = snapshot_all_keys()
    changes = compare_snapshots(baseline, current)

    if not changes:
        print("✅ INTEGRITY CHECK PASSED — Registry matches the baseline.\n")
    else:
        print(f"⚠️  INTEGRITY CHECK FAILED — {len(changes)} changes detected!\n")
        for change in changes:
            emit_alert(change)
        print_session_summary(changes)

        # Auto-generate report
        path = generate_report(changes, "txt")
        print(f"\n📄 Integrity report saved: {path}\n")


# ─────────────────────────────────────────────
#  Mode: Generate Report from Saved Logs
# ─────────────────────────────────────────────

def mode_report(logger, fmt: str):
    if not os.path.exists(CHANGE_LOG):
        print(f"\n❌ No change log found at: {CHANGE_LOG}\n")
        return

    changes = []
    with open(CHANGE_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    changes.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not changes:
        print("\nℹ️  Change log is empty — no report generated.\n")
        return

    path = generate_report(changes, fmt)
    print(f"\n✅ Report generated: {path}\n")
    print_session_summary(changes)


# ─────────────────────────────────────────────
#  Mode: Demo (Non-Windows simulation)
# ─────────────────────────────────────────────

def mode_demo(logger):
    """Simulate detected changes for demonstration / testing purposes."""
    print("\n🎭 DEMO MODE — Simulating registry change detections...\n")
    demo_changes = [
        {
            "change_type": "ADDED",
            "key_label": "AUTORUN_HKCU_RUN",
            "key_path": r"Software\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "MalwareLoader",
            "old_value": None,
            "new_value": r"C:\Users\User\AppData\Roaming\malware.exe",
            "timestamp": datetime.now().isoformat(),
            "severity": "HIGH",
            "malware_flag": None,
            "suspicious_path": True,
        },
        {
            "change_type": "MODIFIED",
            "key_label": "DEFENDER_DISABLE",
            "key_path": r"SOFTWARE\Policies\Microsoft\Windows Defender",
            "value_name": "DisableAntiSpyware",
            "old_value": "0",
            "new_value": "1",
            "timestamp": datetime.now().isoformat(),
            "severity": "CRITICAL",
            "malware_flag": "Disables Windows Defender AntiSpyware",
            "suspicious_path": False,
        },
        {
            "change_type": "MODIFIED",
            "key_label": "WINLOGON",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "value_name": "Shell",
            "old_value": "explorer.exe",
            "new_value": r"explorer.exe,C:\malware\backdoor.exe",
            "timestamp": datetime.now().isoformat(),
            "severity": "CRITICAL",
            "malware_flag": "Shell Value Changed in Winlogon (possible backdoor)",
            "suspicious_path": True,
        },
        {
            "change_type": "MODIFIED",
            "key_label": "FIREWALL_PROFILES",
            "key_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            "value_name": "EnableFirewall",
            "old_value": "1",
            "new_value": "0",
            "timestamp": datetime.now().isoformat(),
            "severity": "CRITICAL",
            "malware_flag": "Firewall setting changed",
            "suspicious_path": False,
        },
        {
            "change_type": "ADDED",
            "key_label": "AUTORUN_HKLM_RUN",
            "key_path": r"Software\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "Updater",
            "old_value": None,
            "new_value": r"C:\Windows\Temp\svchost32.exe /hidden",
            "timestamp": datetime.now().isoformat(),
            "severity": "HIGH",
            "malware_flag": None,
            "suspicious_path": True,
        },
    ]

    from alert_reporter import emit_alert, generate_report, print_session_summary
    for change in demo_changes:
        emit_alert(change)
        time.sleep(0.4)

    print_session_summary(demo_changes)
    txt  = generate_report(demo_changes, "txt")
    csv  = generate_report(demo_changes, "csv")
    jn   = generate_report(demo_changes, "json")
    print(f"\n📄 Demo reports generated:\n   {txt}\n   {csv}\n   {jn}\n")


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Windows Registry Change Monitoring System")
    parser.add_argument("--mode",     choices=["baseline", "monitor", "check", "report", "demo"],
                        default="demo", help="Operating mode")
    parser.add_argument("--interval", type=int, default=POLL_INTERVAL_SEC,
                        help=f"Poll interval in seconds (default: {POLL_INTERVAL_SEC})")
    parser.add_argument("--fmt",      choices=["txt", "csv", "json"], default="txt",
                        help="Report format (for --mode report)")
    args = parser.parse_args()

    logger = setup_logging()

    if not IS_WINDOWS and args.mode != "demo":
        print("⚠️  Non-Windows OS detected. Only '--mode demo' is supported outside Windows.\n")
        mode_demo(logger)
        return

    dispatch = {
        "baseline": lambda: mode_baseline(logger),
        "monitor":  lambda: mode_monitor(logger, args.interval),
        "check":    lambda: mode_check(logger),
        "report":   lambda: mode_report(logger, args.fmt),
        "demo":     lambda: mode_demo(logger),
    }
    dispatch[args.mode]()


if __name__ == "__main__":
    main()
