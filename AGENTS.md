# Meta-Blue — Agent Guide

## What it is

PowerShell-based Windows host forensic collection framework. Collects 76
MITRE ATT&CK-aligned data points from local or remote hosts.

## Constraints

- **PowerShell 5.1 (Windows PowerShell) only.** Uses `Get-WmiObject`,
  `Add-Type` with inline C#, `Register-PSSessionConfiguration`. Not
  compatible with PowerShell 7+ or non-Windows.
- **No package manager, no build, no tests, no linter, no formatter,
  no CI.** Run by dot-sourcing or `using module` directly.
- **All paths are hardcoded Windows paths** (C:\Meta-Blue\,
  C:\Program Files\ etc.). Default output: `C:\Meta-Blue\<timestamp>\Raw\`.

## Entrypoints

| File | Status |
|---|---|
| `Invoke-Collection.ps1` — `Invoke-Collection` | Active. Local + remote collection. |
| `Invoke-Discovery.ps1` — `Invoke-Discovery` | Stub (empty BEGIN/PROCESS/END). |
| `Invoke-MetaBlue.ps1` — `Invoke-MetaBlue` | Stub (placeholder). Also gitignored. |

## Directory layout

- `Modules/DataPoint/` — `DataPoint` class, `TechniqueCategory` enum,
  `New-DataPoints()` factory (76 data points).
- `Modules/JobController/` — `Get-Artifact` (local job reaping),
  `New-RemoteRunspacePool`, `Get-ArtifactFromRemoteRunspacePool`.
  **Exports nothing** (`FunctionsToExport = @()`).
- `Modules/Node/` — Thin `Node` class (4 string properties).
- `Legacy/` — Old monolithic scripts. Not actively developed.

## How to run

```powershell
using module .\Modules\DataPoint\DataPoint.psm1
using module .\Modules\JobController\JobController.psm1
. .\Invoke-Collection.ps1

# All data points locally
Invoke-Collection -LocalCollection -CollectAll -OutFolder C:\Results

# Specific data points
Invoke-Collection -LocalCollection -Collect Processes,Services

# By category
Invoke-Collection -LocalCollection -CollectCategory Persistence

# Remote collection
Invoke-Collection -RemoteCollection -ComputerSet ActiveDirectory -CollectAll
```

## Gotchas

- Some data points are self-acknowledged low quality — check comments in
  `DataPoint.psm1` before relying on them (`ProgramData`, `KnownDLLs`,
  `Startup`, `Services` are flagged).
- `$rawFolder` global variable controls output path used by `Get-Artifact`.
- `JobController.psd1` has `FunctionsToExport = @()` — functions are
  accessible via `using module` but not auto-discovered by `Get-Command`.
- Remote collection uses runspace pools (WinRM, up to 75 concurrent)
  and writes per-host CSVs to `$rawFolder\<ComputerName>\` instead of
  stacking all hosts into one CSV.
- `RegistryRunKeys` data point is the largest — iterates all HKU SIDs × 10+
  reg paths per user.

## Git conventions

- Lowercase imperative commit messages.
- Use approved PowerShell verbs and `$null` on left of comparisons.
