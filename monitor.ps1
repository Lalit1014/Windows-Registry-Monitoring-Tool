# ============================================================
# Windows Registry Change Monitoring System
# PowerShell Companion Script
# Unified Mentor Internship Project
# ============================================================

param(
    [ValidateSet("baseline","monitor","check","export")]
    [string]$Mode = "check",
    [int]$IntervalSeconds = 30,
    [string]$BaselinePath = ".\baselines\ps_baseline.xml"
)

# ── Sensitive Registry Paths to Monitor ─────────────────────
$MonitoredPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
)

# ── Helper Functions ─────────────────────────────────────────

function Get-RegistrySnapshot {
    $snapshot = @{}
    foreach ($path in $MonitoredPaths) {
        try {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                $snapshot[$path] = $props
            } else {
                $snapshot[$path] = @{}
            }
        } catch {
            Write-Warning "Cannot access: $path"
            $snapshot[$path] = $null
        }
    }
    return $snapshot
}

function Save-Baseline {
    param([hashtable]$Snapshot, [string]$Path)
    
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    
    $Snapshot | Export-Clixml -Path $Path -Force
    Write-Host "`n✅ Baseline saved to: $Path" -ForegroundColor Green
    Write-Host "   Keys captured: $($Snapshot.Count)" -ForegroundColor Cyan
}

function Load-Baseline {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Warning "No baseline found at: $Path"
        return $null
    }
    return Import-Clixml -Path $Path
}

function Compare-Snapshots {
    param([hashtable]$Baseline, [hashtable]$Current)
    
    $changes = @()
    
    foreach ($path in $MonitoredPaths) {
        $baseVals = $Baseline[$path]
        $currVals = $Current[$path]
        
        if ($null -eq $currVals) { continue }
        
        # Get property names (exclude PS* auto-props)
        $baseProps = if ($baseVals) { $baseVals.PSObject.Properties.Name | Where-Object { $_ -notlike "PS*" } } else { @() }
        $currProps = if ($currVals) { $currVals.PSObject.Properties.Name | Where-Object { $_ -notlike "PS*" } } else { @() }
        
        $allProps = ($baseProps + $currProps) | Sort-Object -Unique

        foreach ($prop in $allProps) {
            $oldVal = if ($baseProps -contains $prop) { $baseVals.$prop } else { $null }
            $newVal = if ($currProps -contains $prop) { $currVals.$prop } else { $null }

            if ($null -eq $oldVal -and $null -ne $newVal) {
                $changes += [PSCustomObject]@{
                    ChangeType  = "ADDED"
                    KeyPath     = $path
                    ValueName   = $prop
                    OldValue    = "N/A"
                    NewValue    = $newVal
                    Timestamp   = (Get-Date -Format "o")
                }
            } elseif ($null -ne $oldVal -and $null -eq $newVal) {
                $changes += [PSCustomObject]@{
                    ChangeType  = "DELETED"
                    KeyPath     = $path
                    ValueName   = $prop
                    OldValue    = $oldVal
                    NewValue    = "N/A"
                    Timestamp   = (Get-Date -Format "o")
                }
            } elseif ("$oldVal" -ne "$newVal") {
                $changes += [PSCustomObject]@{
                    ChangeType  = "MODIFIED"
                    KeyPath     = $path
                    ValueName   = $prop
                    OldValue    = $oldVal
                    NewValue    = $newVal
                    Timestamp   = (Get-Date -Format "o")
                }
            }
        }
    }
    return $changes
}

function Show-Alert {
    param([PSCustomObject]$Change)
    
    $color = switch ($Change.ChangeType) {
        "ADDED"    { "Yellow" }
        "MODIFIED" { "Magenta" }
        "DELETED"  { "Red" }
        default    { "White" }
    }
    Write-Host "`n[$($Change.Timestamp)] [$($Change.ChangeType)] $($Change.KeyPath)" -ForegroundColor $color
    Write-Host "  Value : $($Change.ValueName)" -ForegroundColor $color
    Write-Host "  Old   : $($Change.OldValue)"
    Write-Host "  New   : $($Change.NewValue)"
}

# ── Mode Dispatch ────────────────────────────────────────────

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Windows Registry Monitoring System (PowerShell)" -ForegroundColor Cyan
Write-Host "  Mode: $Mode" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

switch ($Mode) {
    "baseline" {
        Write-Host "📸 Capturing registry baseline..." -ForegroundColor Yellow
        $snap = Get-RegistrySnapshot
        Save-Baseline -Snapshot $snap -Path $BaselinePath
    }
    
    "monitor" {
        $baseline = Load-Baseline -Path $BaselinePath
        if (-not $baseline) { Write-Error "Run with -Mode baseline first."; exit 1 }
        
        Write-Host "🔍 Monitoring started (every ${IntervalSeconds}s). Press Ctrl+C to stop.`n" -ForegroundColor Green
        $allChanges = @()
        
        while ($true) {
            $current = Get-RegistrySnapshot
            $changes = Compare-Snapshots -Baseline $baseline -Current $current
            
            foreach ($c in $changes) {
                Show-Alert $c
                $allChanges += $c
            }
            
            if ($changes.Count -eq 0) {
                Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] No changes." -NoNewline
                Write-Host "`r" -NoNewline
            }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
    
    "check" {
        $baseline = Load-Baseline -Path $BaselinePath
        if (-not $baseline) { Write-Error "Run with -Mode baseline first."; exit 1 }
        
        Write-Host "🔍 Running integrity check..." -ForegroundColor Yellow
        $current = Get-RegistrySnapshot
        $changes = Compare-Snapshots -Baseline $baseline -Current $current
        
        if ($changes.Count -eq 0) {
            Write-Host "`n✅ Registry matches baseline — no changes detected.`n" -ForegroundColor Green
        } else {
            Write-Host "`n⚠️  $($changes.Count) change(s) detected!`n" -ForegroundColor Red
            foreach ($c in $changes) { Show-Alert $c }
        }
    }
    
    "export" {
        $baseline = Load-Baseline -Path $BaselinePath
        if (-not $baseline) { Write-Error "Run with -Mode baseline first."; exit 1 }
        
        $current = Get-RegistrySnapshot
        $changes = Compare-Snapshots -Baseline $baseline -Current $current
        
        $outPath = ".\reports\ps_registry_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        New-Item -ItemType Directory -Path ".\reports" -Force | Out-Null
        $changes | Export-Csv -Path $outPath -NoTypeInformation
        Write-Host "`n📄 Report exported to: $outPath`n" -ForegroundColor Green
    }
}
