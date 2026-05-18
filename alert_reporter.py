"""
Windows Registry Change Monitoring System
Module: Alert & Report Generator
"""

import json
import os
import csv
import logging
from datetime import datetime
from typing import List, Dict

REPORT_DIR    = "reports"
ALERT_LOG     = "logs/alerts.log"
CHANGE_LOG    = "logs/changes.jsonl"

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

CHANGE_EMOJI = {
    "ADDED":    "➕",
    "MODIFIED": "✏️ ",
    "DELETED":  "❌",
}


# ─────────────────────────────────────────────
#  Real-Time Alert
# ─────────────────────────────────────────────

def emit_alert(change: Dict) -> None:
    """Print and log a real-time alert for a detected change."""
    sev   = change.get("severity", "LOW")
    ctype = change.get("change_type", "?")
    path  = change.get("key_path", "")
    vname = change.get("value_name", "")
    new_v = change.get("new_value", "N/A")
    old_v = change.get("old_value", "N/A")
    ts    = change.get("timestamp", datetime.now().isoformat())
    mflag = change.get("malware_flag")
    spath = change.get("suspicious_path", False)

    sev_icon  = SEVERITY_EMOJI.get(sev, "⚪")
    chg_icon  = CHANGE_EMOJI.get(ctype, "?")

    line = (
        f"\n{'─'*65}\n"
        f"  {sev_icon} [{sev}] REGISTRY CHANGE DETECTED  {chg_icon} {ctype}\n"
        f"{'─'*65}\n"
        f"  Time       : {ts}\n"
        f"  Key Path   : {path}\n"
        f"  Value Name : {vname}\n"
        f"  Old Value  : {old_v}\n"
        f"  New Value  : {new_v}\n"
    )
    if mflag:
        line += f"  ⚠️  MALWARE PATTERN : {mflag}\n"
    if spath:
        line += f"  ⚠️  SUSPICIOUS PATH DETECTED IN VALUE\n"
    line += f"{'─'*65}\n"

    print(line)

    # Write to alert log
    os.makedirs("logs", exist_ok=True)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(line)

    # Append to JSONL change log
    with open(CHANGE_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(change, default=str) + "\n")


# ─────────────────────────────────────────────
#  Session Summary
# ─────────────────────────────────────────────

def print_session_summary(all_changes: List[Dict]) -> None:
    """Print a session-level summary to the console."""
    total     = len(all_changes)
    critical  = sum(1 for c in all_changes if c["severity"] == "CRITICAL")
    high      = sum(1 for c in all_changes if c["severity"] == "HIGH")
    medium    = sum(1 for c in all_changes if c["severity"] == "MEDIUM")
    low       = sum(1 for c in all_changes if c["severity"] == "LOW")
    malware   = sum(1 for c in all_changes if c.get("malware_flag"))
    autorun   = sum(1 for c in all_changes if "AUTORUN" in c.get("key_label", ""))

    print("\n" + "═" * 65)
    print("  MONITORING SESSION SUMMARY")
    print("═" * 65)
    print(f"  Total Changes Detected : {total}")
    print(f"  🔴 Critical            : {critical}")
    print(f"  🟠 High                : {high}")
    print(f"  🟡 Medium              : {medium}")
    print(f"  🟢 Low                 : {low}")
    print(f"  ⚠️  Malware Patterns    : {malware}")
    print(f"  🚀 Autorun Changes     : {autorun}")
    print("═" * 65 + "\n")


# ─────────────────────────────────────────────
#  Full Report Generator
# ─────────────────────────────────────────────

def generate_report(all_changes: List[Dict], format: str = "txt") -> str:
    """
    Generate a consolidated change-analysis report.
    Supports: txt, csv, json
    Returns the path to the generated report.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format == "json":
        return _generate_json_report(all_changes, ts_str)
    elif format == "csv":
        return _generate_csv_report(all_changes, ts_str)
    else:
        return _generate_txt_report(all_changes, ts_str)


def _generate_txt_report(changes: List[Dict], ts: str) -> str:
    path = os.path.join(REPORT_DIR, f"registry_report_{ts}.txt")
    total     = len(changes)
    critical  = [c for c in changes if c["severity"] == "CRITICAL"]
    high      = [c for c in changes if c["severity"] == "HIGH"]
    malware   = [c for c in changes if c.get("malware_flag")]

    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  WINDOWS REGISTRY CHANGE MONITORING SYSTEM — ANALYSIS REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total Changes : {total}\n")
        f.write(f"  Critical    : {len(critical)}\n")
        f.write(f"  High        : {len(high)}\n")
        f.write(f"  Malware Patterns Matched : {len(malware)}\n")
        f.write("=" * 70 + "\n\n")

        if malware:
            f.write("⚠️  MALWARE / SUSPICIOUS BEHAVIOR DETECTIONS\n")
            f.write("-" * 70 + "\n")
            for c in malware:
                f.write(f"  [{c['severity']}] {c['change_type']} | {c['key_path']} | {c['value_name']}\n")
                f.write(f"         Pattern : {c['malware_flag']}\n")
                f.write(f"         New Val : {c.get('new_value', 'N/A')}\n")
                f.write(f"         Time    : {c['timestamp']}\n\n")

        if critical:
            f.write("\n🔴 CRITICAL SEVERITY CHANGES\n")
            f.write("-" * 70 + "\n")
            for c in critical:
                f.write(f"  {c['change_type']} | {c['key_path']} \\ {c['value_name']}\n")
                f.write(f"    Old : {c.get('old_value', 'N/A')}\n")
                f.write(f"    New : {c.get('new_value', 'N/A')}\n")
                f.write(f"    At  : {c['timestamp']}\n\n")

        f.write("\n📋 ALL CHANGES (Chronological)\n")
        f.write("-" * 70 + "\n")
        for c in changes:
            sev_icon  = SEVERITY_EMOJI.get(c["severity"], "⚪")
            chg_icon  = CHANGE_EMOJI.get(c["change_type"], "?")
            f.write(f"  {sev_icon} [{c['severity']:8s}] {chg_icon} {c['change_type']:8s} | {c['value_name']}\n")
            f.write(f"    Path    : {c['key_path']}\n")
            f.write(f"    Old Val : {c.get('old_value', 'N/A')}\n")
            f.write(f"    New Val : {c.get('new_value', 'N/A')}\n")
            f.write(f"    Time    : {c['timestamp']}\n")
            if c.get("malware_flag"):
                f.write(f"    ⚠️  MALWARE : {c['malware_flag']}\n")
            f.write("\n")

        f.write("=" * 70 + "\n")
        f.write("  END OF REPORT\n")
        f.write("=" * 70 + "\n")

    logging.info(f"[REPORT] Text report saved: {path}")
    return path


def _generate_csv_report(changes: List[Dict], ts: str) -> str:
    path = os.path.join(REPORT_DIR, f"registry_report_{ts}.csv")
    fields = ["timestamp", "change_type", "severity", "key_label", "key_path",
              "value_name", "old_value", "new_value", "malware_flag", "suspicious_path"]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(changes)

    logging.info(f"[REPORT] CSV report saved: {path}")
    return path


def _generate_json_report(changes: List[Dict], ts: str) -> str:
    path = os.path.join(REPORT_DIR, f"registry_report_{ts}.json")
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_changes": len(changes),
        "changes": changes
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    logging.info(f"[REPORT] JSON report saved: {path}")
    return path
