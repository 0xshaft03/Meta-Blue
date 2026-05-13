# Meta-Blue

PowerShell-based Windows hunt framework. Collects 76
MITRE ATT&CK-aligned data points from local or remote hosts.

## Prerequisites

- **Windows PowerShell 5.1** 
- **Local administrator rights** on target hosts (for most data points)
- **WinRM access** to targets (for remote collection)
- **ActiveDirectory module** (for `-ComputerSet ActiveDirectory`)

## Quickstart

```powershell
git clone https://github.com/0xshaft03/Meta-Blue
cd Meta-Blue
using module .\Modules\DataPoint\DataPoint.psm1
using module .\Modules\JobController\JobController.psm1
. .\Invoke-Collection.ps1

# Collect all 76 data points on the local machine
Invoke-Collection -LocalCollectAll -OutFolder C:\Results
```

## Usage

```powershell
# Collect specific data points
Invoke-Collection -LocalCollectByName Processes,Services -OutFolder C:\Results

# Collect by MITRE ATT&CK category
Invoke-Collection -LocalCollectByCategory Persistence -OutFolder C:\Results

# Quick triage — ~20 highest-signal data points, finishes in seconds
Invoke-Collection -LocalCollectAll -CollectionProfile Quick -OutFolder C:\Results

# Collect from all Active Directory computers
Invoke-Collection -RemoteCollectAll -ComputerSet ActiveDirectory -OutFolder C:\Results

# Choose output format (csv or json)
Invoke-Collection -LocalCollectAll -OutFolder C:\Results -OutputFormat json
```

## Baseline diff

Compare two collection runs to find new/changed/removed rows per data point:

```powershell
. .\Invoke-BaselineDiff.ps1
Invoke-BaselineDiff -CurrentPath C:\Meta-Blue\2025_02_01_14_00_00 -BaselinePath C:\Meta-Blue\2025_01_25_14_00_00
```

Output is written to `CurrentPath\Anomalies\` as `<DataPoint>-Added.csv` and
`<DataPoint>-Removed.csv` for each data point that differs.

## Output

```
<OutFolder>\<timestamp>\Raw\            # One CSV per data point (or per-host for remote)
<OutFolder>\<timestamp>\Anomalies\      # Baseline diff output
<OutFolder>\<timestamp>\collection.json  # Collection manifest
```

- **Local collection:** one CSV/JSON file per data point
- **Remote collection:** per-host folders, each with per-data-point files
- **collection.json:** metadata (timestamp, computer, profile, data point names, row counts)

## Project status

| Entrypoint | Status |
|---|---|
| `Invoke-Collection` | Active — local and remote collection |
| `Invoke-BaselineDiff` | Active — compare two collection runs |
| `Invoke-Discovery` | Stub — network discovery not yet implemented |
| `Invoke-MetaBlue` | Stub — placeholder for unified orchestrator |
| `Legacy/` | Archived monolithic scripts, not actively developed |

### Modules

| Module | Purpose |
|---|---|
| `Modules/DataPoint/` | DataPoint class, TechniqueCategory enum, 76 data point factory, Quick profile flag |
| `Modules/JobController/` | Background job reaping and WinRM runspace pool management |
| `Modules/Node/` | Simple node class with 4 string properties |

## Caveats

Some data points are self-acknowledged low quality — see comments in
`Modules/DataPoint/DataPoint.psm1` for details (`ProgramData`, `KnownDLLs`,
`Startup`, `Services` are flagged).

## License

MIT — see [LICENSE](LICENSE).
