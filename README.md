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

# Collect from all Active Directory computers
Invoke-Collection -RemoteCollectAll -ComputerSet ActiveDirectory -OutFolder C:\Results

# Choose output format (csv or json)
Invoke-Collection -LocalCollectAll -OutFolder C:\Results -OutputFormat json
```

## Output

Files are written to `<OutFolder>\<timestamp>\Raw\`.

- **Local collection:** one CSV/JSON file per data point
- **Remote collection:** per-host folders, each with per-data-point files

## Project status

| Entrypoint | Status |
|---|---|
| `Invoke-Collection` | Active — local and remote collection |
| `Invoke-Discovery` | Stub — network discovery not yet implemented |
| `Invoke-MetaBlue` | Stub — placeholder for unified orchestrator |
| `Legacy/` | Archived monolithic scripts, not actively developed |

### Modules

| Module | Purpose |
|---|---|
| `Modules/DataPoint/` | DataPoint class, TechniqueCategory enum, 76 data point factory |
| `Modules/JobController/` | Background job reaping and WinRM runspace pool management |
| `Modules/Node/` | Simple node class with 4 string properties |

## Caveats

Some data points are self-acknowledged low quality — see comments in
`Modules/DataPoint/DataPoint.psm1` for details (`ProgramData`, `KnownDLLs`,
`Startup`, `Services` are flagged).

## License

MIT — see [LICENSE](LICENSE).
