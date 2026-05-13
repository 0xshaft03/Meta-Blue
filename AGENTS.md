# Meta-Blue — Agent Guide

## What it is

PowerShell-based Windows host forensic collection framework. Collects 76
MITRE ATT&CK-aligned data points from local or remote hosts.

**Core design: LFO (Least Frequency of Occurrence) analysis.** Every data
point is designed to return structured, comparable rows so that stacking
results across machines surfaces rare values — the one host with a unique
startup key, the single machine missing a Defender exclusion, the odd
service path that doesn't match the median.

## Constraints

- **PowerShell 5.1 (Windows PowerShell) only.** Uses `Get-WmiObject`,
  `Add-Type` with inline C#, `Register-PSSessionConfiguration`. Not
  compatible with PowerShell 7+ or non-Windows.
- **No package manager, no build, no tests, no linter, no formatter,
  no CI.** Run by dot-sourcing or `using module` directly.
- **All paths are hardcoded Windows paths** (C:\Meta-Blue\,
  C:\Program Files\ etc.). Default output: `C:\Meta-Blue\<timestamp>\`.

## Entrypoints

| File | Status |
|---|---|
| `Invoke-Collection.ps1` — `Invoke-Collection` | Active. Local + remote collection. |
| `Invoke-BaselineDiff.ps1` — `Invoke-BaselineDiff` | Active. Compare two collection runs. |
| `Invoke-Discovery.ps1` — `Invoke-Discovery` | Stub (empty BEGIN/PROCESS/END). |
| `Invoke-MetaBlue.ps1` — `Invoke-MetaBlue` | Stub (placeholder). Also gitignored. |

## Directory layout

- `Modules/DataPoint/` — `DataPoint` class, `TechniqueCategory` enum,
  `New-DataPoints()` factory (76 data points, 25 tagged Persistence).
- `Modules/JobController/` — `Get-Artifact` (local job reaping),
  `New-RemoteRunspacePool`, `Get-ArtifactFromRemoteRunspacePool`
  (non-blocking `WaitHandle.WaitAny()` polling, tiered timeout, `List[PSObject]`).
  **Exports nothing** (`FunctionsToExport = @()`).
- `Modules/Node/` — Thin `Node` class (4 string properties).
- `Legacy/` — Old monolithic scripts. Not actively developed.

### Output structure

```
<OutFolder>\<timestamp>\Raw\            # One CSV per data point (or per-host for remote)
<OutFolder>\<timestamp>\Anomalies\      # Baseline diff output (-Added.csv / -Removed.csv)
<OutFolder>\<timestamp>\collection.json  # Collection manifest (timestamp, profile, DPs, row counts)
```

## How to run

```powershell
using module .\Modules\DataPoint\DataPoint.psm1
using module .\Modules\JobController\JobController.psm1
. .\Invoke-Collection.ps1

# All 76 data points locally
Invoke-Collection -LocalCollectAll -OutFolder C:\Results

# Quick triage (~20 highest-signal data points, finishes in seconds)
Invoke-Collection -LocalCollectAll -CollectionProfile Quick -OutFolder C:\Results

# Exclude low-quality data points
Invoke-Collection -LocalCollectAll -Except ProgramData,KnownDLLs -OutFolder C:\Results

# Specific data points by name
Invoke-Collection -LocalCollectByName Processes,Services -OutFolder C:\Results

# By MITRE technique category (25 Persistence data points now properly categorized)
Invoke-Collection -LocalCollectByCategory Persistence -OutFolder C:\Results

# Remote collection across Active Directory
Invoke-Collection -RemoteCollectAll -ComputerSet ActiveDirectory -OutFolder C:\Results

# Baseline diff — compare two collection runs
. .\Invoke-BaselineDiff.ps1
Invoke-BaselineDiff -CurrentPath C:\Results\2025_02_01_14_00_00 -BaselinePath C:\Results\2025_01_25_14_00_00
```

## Parameters

| Parameter | Sets | Purpose |
|---|---|---|
| `-LocalCollectAll` | Local | Collect all 76 data points on local host |
| `-LocalCollectByName` | Local | Collect specific DPs by name (tab-completable) |
| `-LocalCollectByCategory` | Local | Collect DPs matching a technique category |
| `-RemoteCollectAll` | Remote | Collect all 76 from remote hosts |
| `-RemoteCollectByName` | Remote | Collect specific DPs from remote hosts |
| `-RemoteCollectByCategory` | Remote | Collect DPs by category from remote hosts |
| `-CollectionProfile` | All | `Quick` (~20 fast DPs) or `Full` (all 76, default) |
| `-Except` | All | Exclude specific DPs by name (works with any set) |
| `-ComputerSet` | Remote | `ActiveDirectoryComputers`, `TextFile`, `CSVFile` |
| `-OutFolder` | All | Output parent directory (default: C:\Meta-Blue) |
| `-OutputFormat` | All | `csv` (default) or `json` |

## Design philosophy (LFO analysis)

Meta-Blue is built for **cross-machine stacking**, not single-host collection.

**Stackable data points** return rows with scalar values that are directly
comparable across hosts. For example, `UserInitMprLogonScript` returns
`{SID, ScriptPath}` rows per user — not a `$true`/`$false` boolean.
`AppCertDLLS` returns actual DLL names and paths, not a `Test-Path` bool.
`PowershellProfile` returns `{FullName, Length, LastWriteTime, Hash}`
across all user profile paths on every host.

The goal: collect from N hosts, stack each data point, and the values
appearing on <5% of hosts are your investigative leads.

**Data points that still need stacking work** (return single blobs or
dynamic property names):
- `RegistryRunKeys` — returns one `PSCustomObject` with dynamic properties
  per SID+path. Should emit `{Sid, RegPath, ValueName, Value}` rows.
- `netsh`/`klist` parsers — use hardcoded `Substring(N)` offsets
  that break on localized Windows builds.

## Gotchas

- **Some data points are self-acknowledged low quality** — check comments
  in `DataPoint.psm1` before relying on them (`ProgramData`, `KnownDLLs`,
  `Startup`, `Services` are flagged).
- **`JobController.psd1` has `FunctionsToExport = @()`** — functions are
  accessible via `using module` but not auto-discovered by `Get-Command`.
- **`Get-Artifact` now polls every 1 second** (was 10s) and handles unexpected
  job states (`Blocked`, `Suspended`, `Stopped`) instead of hanging forever.
- **Remote collection** uses runspace pools (WinRM, up to 75 concurrent)
  and writes per-host CSVs to `$rawFolder\<ComputerName>\` instead of
  stacking all hosts into one CSV. Per-host `PSComputerName` tagging is
  not yet added to output rows.
- **`Get-ArtifactFromRemoteRunspacePool` uses non-blocking polling** —
  replaced sequential `WaitOne(300000)` per job with `WaitHandle.WaitAny()`
  across all outstanding handles. Tiered timeout: 30s poll interval, 5 min
  per-job max. Uses `List[PSObject]` instead of `ArrayList`.
- **`RegistryRunKeys` is the largest data point** — iterates all HKU SIDs
  × 10+ reg paths per user. Also has a single-SID array coercion bug
  and no HKU PSDrive guard. Needs restructuring for stacking.
- **Persistence category works now** — all 25 T1546/T1547/T1053/T1197/
  T1505/T1543/T1574 data points were recategorized from `Uncategorized`
  to `Persistence`. `-LocalCollectByCategory Persistence` no longer
  returns empty.
- **`$collection.json` manifest** is written automatically with every
  collection run. Contains timestamp, computer name, profile, data point
  list, and per-DP row counts.

## Git conventions

- Lowercase imperative commit messages.
- Use approved PowerShell verbs and `$null` on left of comparisons.
