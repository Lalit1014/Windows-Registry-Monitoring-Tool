# Windows Registry Change Monitoring System
### Unified Mentor Internship Project | Blue Team Security Tool

---

## 📌 Project Overview

A Python + PowerShell toolkit that monitors Windows Registry keys for unauthorized or
suspicious changes. It captures a baseline, continuously polls sensitive registry paths,
detects malware-like behavior patterns, generates real-time alerts, and produces
consolidated analysis reports.

---

## 🗂️ Project Structure

```
registry_monitor/
├── main.py                # Entry point — all modes
├── registry_monitor.py    # Core engine (key definitions, snapshot, compare)
├── baseline_manager.py    # Baseline create / load / integrity verify
├── alert_reporter.py      # Real-time alerts + report generator
├── monitor.ps1            # PowerShell companion script
├── README.md              # This file
│
├── baselines/             # Auto-created — baseline snapshots stored here
│   └── backups/           # Old baselines auto-backed up here
├── logs/                  # Auto-created — monitoring logs
│   ├── registry_monitor_YYYYMMDD.log
│   ├── alerts.log
│   └── changes.jsonl      # Machine-readable change events
└── reports/               # Auto-created — generated reports
```

---

## ⚙️ Setup

**Requirements:**
- Windows OS (for live registry monitoring)
- Python 3.8+
- No external pip packages required (uses stdlib only: `winreg`, `hashlib`, `json`, `csv`, `logging`)

**Install (no dependencies needed):**
```bash
git clone <your-repo>
cd registry_monitor
```

---

## 🚀 Usage

### 1. Create Baseline
```bash
python main.py --mode baseline
```
Captures a SHA-256-verified snapshot of all monitored registry keys.

### 2. Start Real-Time Monitor
```bash
python main.py --mode monitor --interval 30
```
Polls the registry every 30 seconds and alerts on any change.  
Press `Ctrl+C` to stop and auto-generate reports.

### 3. One-Time Integrity Check
```bash
python main.py --mode check
```
Compares current registry state to the baseline and reports differences.

### 4. Generate Report from Saved Logs
```bash
python main.py --mode report --fmt txt   # or csv / json
```

### 5. Demo Mode (Works on non-Windows)
```bash
python main.py --mode demo
```
Simulates 5 real-world attack scenarios for testing/demonstration.

---

## PowerShell Usage

```powershell
# Create baseline
.\monitor.ps1 -Mode baseline

# One-time check
.\monitor.ps1 -Mode check

# Live monitoring (60s interval)
.\monitor.ps1 -Mode monitor -IntervalSeconds 60

# Export CSV report
.\monitor.ps1 -Mode export
```

---

## 🔍 Monitored Registry Keys

| Category | Key Path |
|----------|----------|
| Autorun (HKCU) | `...\CurrentVersion\Run` / `RunOnce` |
| Autorun (HKLM) | `...\CurrentVersion\Run` / `RunOnce` |
| Windows Defender | `Policies\Microsoft\Windows Defender` |
| Firewall | `SharedAccess\Parameters\FirewallPolicy\*` |
| UAC / Policies | `Policies\System` |
| Winlogon | `Windows NT\CurrentVersion\Winlogon` |
| IFEO (Debugger hijacking) | `Image File Execution Options` |
| Services | `SYSTEM\CurrentControlSet\Services` |

---

## ⚠️ Malware Behavior Patterns Detected

| Value Name | Threat |
|------------|--------|
| `DisableAntiSpyware` | Windows Defender disabled |
| `DisableRealtimeMonitoring` | Real-time protection off |
| `DisableFirewall` | Firewall disabled |
| `DisableTaskMgr` | Task Manager blocked (ransomware) |
| `Shell` (Winlogon) | Shell hijacking / backdoor |
| `Userinit` (Winlogon) | Persistence mechanism |
| `EnableLUA` | UAC bypass |
| `Debugger` (IFEO) | Process hijacking |

---

## 📊 Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| CRITICAL | 🔴 | Security tool disabled, shell hijacked, IFEO |
| HIGH | 🟠 | New autorun entry, UAC changed |
| MEDIUM | 🟡 | Autorun deleted, policy modification |
| LOW | 🟢 | Benign registry change |

---

## 📄 Output Files

- **`logs/registry_monitor_YYYYMMDD.log`** — Full session log
- **`logs/alerts.log`** — Human-readable alert history
- **`logs/changes.jsonl`** — Machine-readable JSON lines (one change per line)
- **`reports/registry_report_*.txt`** — Full text report
- **`reports/registry_report_*.csv`** — Spreadsheet-compatible report
- **`reports/registry_report_*.json`** — JSON report for SIEM integration
- **`baselines/registry_baseline.json`** — SHA-256 integrity-verified baseline

---

## 🛡️ Blue Team Techniques Implemented

- ✅ Polling-based continuous monitoring
- ✅ SHA-256 baseline integrity verification
- ✅ Autorun persistence detection
- ✅ Malware behavior pattern matching
- ✅ Suspicious path detection (AppData, Temp, scripts)
- ✅ Severity-based alert triage
- ✅ Multi-format report generation (TXT / CSV / JSON)
- ✅ Automated baseline backup on update

---

## 📖 Learning Outcomes

This project covers:
- Windows Registry structure (HKCU, HKLM, key types)
- How malware maintains persistence via registry
- Blue team registry monitoring and forensics
- Python scripting with `winreg` module
- Hashing for integrity verification
- Structured logging and reporting

---

## 👨‍💻 Author :- Lalit Keer
