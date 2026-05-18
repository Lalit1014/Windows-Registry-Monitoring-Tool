"""
Windows Registry Change Monitoring System
Module: Baseline Manager
"""

import json
import os
import hashlib
import logging
from datetime import datetime
from typing import Optional, Dict

BASELINE_DIR  = "baselines"
BASELINE_FILE = os.path.join(BASELINE_DIR, "registry_baseline.json")
BACKUP_DIR    = os.path.join(BASELINE_DIR, "backups")


def create_baseline(snapshot: Dict, output_path: str = BASELINE_FILE) -> str:
    """
    Save a registry snapshot as the official baseline.
    Returns the path to the saved baseline.
    """
    os.makedirs(BASELINE_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

    # If a baseline already exists, back it up
    if os.path.exists(output_path):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"baseline_backup_{ts}.json")
        with open(output_path, "r") as f_in:
            old = f_in.read()
        with open(backup_path, "w") as f_out:
            f_out.write(old)
        logging.info(f"[BASELINE] Previous baseline backed up to: {backup_path}")

    # Add integrity checksum
    payload = json.dumps(snapshot, indent=2, default=str)
    checksum = hashlib.sha256(payload.encode()).hexdigest()
    snapshot["_integrity"] = checksum

    with open(output_path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    logging.info(f"[BASELINE] New baseline created at: {output_path}")
    logging.info(f"[BASELINE] Captured keys: {len(snapshot.get('keys', {}))}")
    logging.info(f"[BASELINE] SHA-256 checksum: {checksum}")
    return output_path


def load_baseline(path: str = BASELINE_FILE) -> Optional[Dict]:
    """
    Load and validate an existing baseline.
    Returns None if baseline is missing or tampered.
    """
    if not os.path.exists(path):
        logging.warning(f"[BASELINE] No baseline found at: {path}")
        return None

    with open(path, "r") as f:
        data = json.load(f)

    stored_checksum = data.pop("_integrity", None)
    recalculated   = hashlib.sha256(
        json.dumps(data, indent=2, default=str).encode()
    ).hexdigest()

    if stored_checksum and stored_checksum != recalculated:
        logging.critical("[BASELINE] ⚠️  INTEGRITY CHECK FAILED — Baseline may have been tampered with!")
        logging.critical(f"[BASELINE]   Stored   checksum: {stored_checksum}")
        logging.critical(f"[BASELINE]   Current  checksum: {recalculated}")
        data["_tampered"] = True
    else:
        logging.info(f"[BASELINE] ✓ Integrity check passed. Loaded: {path}")
        data["_tampered"] = False

    return data


def baseline_summary(baseline: Dict) -> None:
    """Print a human-readable summary of the baseline."""
    ts   = baseline.get("timestamp", "Unknown")
    keys = baseline.get("keys", {})

    print("\n" + "═" * 60)
    print("  REGISTRY BASELINE SUMMARY")
    print("═" * 60)
    print(f"  Captured At  : {ts}")
    print(f"  Total Groups : {len(keys)}")
    total_vals = sum(len(v.get("values", {}) or {}) for v in keys.values())
    print(f"  Total Values : {total_vals}")
    if baseline.get("_tampered"):
        print("  STATUS       : ⚠️  INTEGRITY FAILED — POSSIBLE TAMPERING")
    else:
        print("  STATUS       : ✓ Integrity Verified")
    print("═" * 60 + "\n")
