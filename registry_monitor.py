"""
Windows Registry Change Monitoring System
Module: Registry Monitor (Core Engine)
Author: Unified Mentor Internship Project
"""

import winreg
import json
import hashlib
import time
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────────────────────
#  Registry Key Definitions
# ─────────────────────────────────────────────

MONITORED_KEYS = {
    # Autorun / Persistence keys
    "AUTORUN_HKCU_RUN":      (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
    "AUTORUN_HKCU_RUNONCE":  (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    "AUTORUN_HKLM_RUN":      (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    "AUTORUN_HKLM_RUNONCE":  (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    "AUTORUN_HKLM_RUN32":    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),

    # Windows Defender / Security
    "DEFENDER_DISABLE":      (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
    "DEFENDER_RTPROTECT":    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"),

    # Windows Firewall
    "FIREWALL_PROFILES":     (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
    "FIREWALL_DOMAIN":       (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),

    # UAC Settings
    "UAC_SETTINGS":          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),

    # Shell / Explorer Settings
    "WINLOGON":              (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    "EXPLORER":              (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"),

    # System Policies
    "SYSTEM_POLICIES":       (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),

    # Image File Execution Options (IFEO) — used for debugger hijacking
    "IFEO":                  (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),

    # Services
    "SERVICES":              (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
}

# ─────────────────────────────────────────────
#  Malware Behavior Patterns
# ─────────────────────────────────────────────

MALWARE_PATTERNS = {
    "DisableAntiSpyware":      "Disables Windows Defender AntiSpyware",
    "DisableRealtimeMonitoring": "Disables Defender Real-Time Monitoring",
    "DisableFirewall":         "Windows Firewall Disabled",
    "EnableFirewall":          "Firewall setting changed",
    "DisableTaskMgr":          "Task Manager Disabled (common ransomware tactic)",
    "DisableRegistryTools":    "Registry Editor Disabled",
    "DisableCMD":              "Command Prompt Disabled",
    "HideFileExt":             "File Extensions Hidden (common malware concealment)",
    "NoControlPanel":          "Control Panel Access Disabled",
    "Shell":                   "Shell Value Changed in Winlogon (possible backdoor)",
    "Userinit":                "Userinit Changed in Winlogon (persistence mechanism)",
    "EnableLUA":               "UAC Changed — Possible Privilege Escalation",
    "ConsentPromptBehaviorAdmin": "UAC Admin Prompt Behavior Changed",
    "Debugger":                "Debugger set in IFEO — Possible Hijacking",
}

SUSPICIOUS_PATH_PATTERNS = [
    "\\AppData\\Roaming",
    "\\AppData\\Local\\Temp",
    "\\Temp\\",
    "%temp%",
    "%appdata%",
    "powershell",
    "cmd.exe /c",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    ".vbs",
    ".bat",
    ".ps1",
]


# ─────────────────────────────────────────────
#  Core Registry Reader
# ─────────────────────────────────────────────

def read_registry_key(hive: int, key_path: str) -> Optional[Dict]:
    """Read all values from a registry key and return as dict."""
    result = {}
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            i = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(key, i)
                    result[name] = {
                        "data": str(data),
                        "type": reg_type,
                        "hash": hashlib.sha256(str(data).encode()).hexdigest()
                    }
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        return None   # Key doesn't exist — not an error
    except PermissionError:
        logging.warning(f"[PERMISSION DENIED] Cannot read: {key_path}")
        return None
    except Exception as e:
        logging.error(f"[ERROR] Reading {key_path}: {e}")
        return None
    return result


def snapshot_all_keys() -> Dict:
    """Capture a snapshot of all monitored registry keys."""
    snapshot = {
        "timestamp": datetime.now().isoformat(),
        "keys": {}
    }
    for label, (hive, path) in MONITORED_KEYS.items():
        data = read_registry_key(hive, path)
        snapshot["keys"][label] = {
            "hive": hive,
            "path": path,
            "values": data if data is not None else {}
        }
    return snapshot


# ─────────────────────────────────────────────
#  Change Detection
# ─────────────────────────────────────────────

def compare_snapshots(baseline: Dict, current: Dict) -> List[Dict]:
    """Compare two snapshots and return list of changes."""
    changes = []

    for label in MONITORED_KEYS:
        base_vals   = baseline["keys"].get(label, {}).get("values", {}) or {}
        cur_vals    = current["keys"].get(label, {}).get("values",  {}) or {}
        path        = MONITORED_KEYS[label][1]

        all_keys = set(base_vals.keys()) | set(cur_vals.keys())

        for value_name in all_keys:
            change = None

            if value_name not in base_vals and value_name in cur_vals:
                # ── ADDED ──
                change = {
                    "change_type":  "ADDED",
                    "key_label":    label,
                    "key_path":     path,
                    "value_name":   value_name,
                    "old_value":    None,
                    "new_value":    cur_vals[value_name]["data"],
                    "timestamp":    current["timestamp"],
                    "severity":     _assess_severity("ADDED", label, value_name, cur_vals[value_name]["data"]),
                    "malware_flag": _check_malware_pattern(value_name, cur_vals[value_name]["data"]),
                    "suspicious_path": _check_suspicious_path(cur_vals[value_name]["data"]),
                }

            elif value_name in base_vals and value_name not in cur_vals:
                # ── DELETED ──
                change = {
                    "change_type":  "DELETED",
                    "key_label":    label,
                    "key_path":     path,
                    "value_name":   value_name,
                    "old_value":    base_vals[value_name]["data"],
                    "new_value":    None,
                    "timestamp":    current["timestamp"],
                    "severity":     _assess_severity("DELETED", label, value_name, None),
                    "malware_flag": _check_malware_pattern(value_name, base_vals[value_name]["data"]),
                    "suspicious_path": False,
                }

            elif value_name in base_vals and value_name in cur_vals:
                if base_vals[value_name]["hash"] != cur_vals[value_name]["hash"]:
                    # ── MODIFIED ──
                    change = {
                        "change_type":  "MODIFIED",
                        "key_label":    label,
                        "key_path":     path,
                        "value_name":   value_name,
                        "old_value":    base_vals[value_name]["data"],
                        "new_value":    cur_vals[value_name]["data"],
                        "timestamp":    current["timestamp"],
                        "severity":     _assess_severity("MODIFIED", label, value_name, cur_vals[value_name]["data"]),
                        "malware_flag": _check_malware_pattern(value_name, cur_vals[value_name]["data"]),
                        "suspicious_path": _check_suspicious_path(cur_vals[value_name]["data"]),
                    }

            if change:
                changes.append(change)

    return changes


def _assess_severity(change_type: str, label: str, value_name: str, value_data: Optional[str]) -> str:
    """Assign a severity level: CRITICAL / HIGH / MEDIUM / LOW."""
    # Critical labels
    if label in ("DEFENDER_DISABLE", "DEFENDER_RTPROTECT", "FIREWALL_PROFILES", "FIREWALL_DOMAIN", "IFEO"):
        return "CRITICAL"
    if label in ("AUTORUN_HKCU_RUN", "AUTORUN_HKLM_RUN", "AUTORUN_HKCU_RUNONCE", "AUTORUN_HKLM_RUNONCE"):
        if change_type == "ADDED":
            return "HIGH"
        return "MEDIUM"
    if label in ("UAC_SETTINGS", "SYSTEM_POLICIES") and change_type == "MODIFIED":
        return "HIGH"
    if label == "WINLOGON" and value_name in ("Shell", "Userinit"):
        return "CRITICAL"
    if value_data and _check_suspicious_path(value_data):
        return "HIGH"
    return "LOW"


def _check_malware_pattern(value_name: str, value_data: Optional[str]) -> Optional[str]:
    """Check if the changed value matches a known malware behavior pattern."""
    for pattern, description in MALWARE_PATTERNS.items():
        if pattern.lower() in value_name.lower():
            return description
    return None


def _check_suspicious_path(value_data: Optional[str]) -> bool:
    """Return True if value data contains a suspicious path pattern."""
    if not value_data:
        return False
    val_lower = value_data.lower()
    return any(p.lower() in val_lower for p in SUSPICIOUS_PATH_PATTERNS)


# ─────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────

def setup_logging(log_dir: str = "logs") -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"registry_monitor_{datetime.now().strftime('%Y%m%d')}.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("RegistryMonitor")
