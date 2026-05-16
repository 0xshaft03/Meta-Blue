# Meta-Blue

PowerShell-based Windows hunt framework. Collects 84
MITRE ATT&CK-aligned data points from local or remote hosts.

## Prerequisites

- **Windows PowerShell 5.1** 
- **Local administrator rights** on target hosts (for most data points)
- **WinRM access** to targets (for remote collection)
- **ActiveDirectory module** (for `-ComputerSet ActiveDirectoryComputers`)

## Design philosophy

Meta-Blue is **agentless**, **state-based**, and built for **fleet-wide
stacking**. Each of these is deliberate.

### Agentless

Meta-Blue installs nothing. It ships no driver, no service, no scheduled
task, no telemetry pipeline. A collection run uses only what's already
on the box (PowerShell 5.1, WMI, the registry) and writes its output
to a folder you choose. When the run is over, nothing persists.

This matters in environments where you can't deploy agents: air-gapped
networks, OT/ICS segments, contractually restricted estates, vendor
appliances, hosts your team doesn't own. It also matters in environments
that *used* to deploy agents and have since pulled back — the
July 2024 EDR kernel-driver incident that grounded airlines and stalled
hospitals reminded everyone that an agent on every host is also a single
point of failure on every host. Meta-Blue is something you run *at* a
fleet, not something you live *on* the fleet.

### State-based, not event-based

Modern EDR/XDR platforms are event-driven: they ingest a stream of
process creations, network connections, file writes, and registry edits
*as they happen*, and let you query the stream after the fact. That model
is powerful, but it has a blind spot — **it can only see what happened
since the agent was installed**. An adversary who established persistence
last year, before your EDR rollout, leaves no event for your event
pipeline to catch.

Meta-Blue inverts the model. It snapshots the *state* of each host: the
current contents of every Run key, the current Defender exclusions, the
current scheduled tasks, the current local Administrator group. Whether
that state was placed there yesterday or three years ago doesn't matter
— if it's there now, Meta-Blue sees it.

### Built for LFO stacking

Every data point is designed to return structured rows so that the same
data point's output from N hosts can be concatenated and analyzed with
**LFO** (Least Frequency of Occurrence) techniques: the values appearing
on a small minority of hosts are your investigative leads. The single
host with a unique startup key, the one machine missing a Defender
exclusion, the odd service path that doesn't match the median — these
are the kinds of outliers Meta-Blue surfaces by collecting consistent,
comparable rows from every host in scope.

Tools like WinPEAS catalog "what's exploitable on this host." Meta-Blue
catalogs the same surface, but in a row schema you can stack across a
fleet to find the host that doesn't match the rest.

## Quickstart

```powershell
git clone https://github.com/0xshaft03/Meta-Blue
cd Meta-Blue
. .\Invoke-Collection.ps1

# Collect all 84 data points on the local machine
Invoke-Collection -LocalCollectAll -OutFolder C:\Results
```

## Usage

```powershell
# Collect specific data points
Invoke-Collection -LocalCollectByName Processes,Services -OutFolder C:\Results

# Collect by MITRE ATT&CK tactic
#   Available: Persistence, Discovery, DefenseEvasion, LateralMovement,
#   CommandAndControl, PrivilegeEscalation, CredentialAccess, Uncategorized
Invoke-Collection -LocalCollectByCategory Persistence -OutFolder C:\Results

# Skip specific data points (works with any parameter set)
Invoke-Collection -LocalCollectAll -Except ProgramData,KnownDLLs -OutFolder C:\Results

# Quick triage — ~24 highest-signal data points, finishes in seconds
Invoke-Collection -LocalCollectAll -CollectionProfile Quick -OutFolder C:\Results

# Collect from all Active Directory computers
Invoke-Collection -RemoteCollectAll -ComputerSet ActiveDirectoryComputers -OutFolder C:\Results

# Choose output format (csv or json)
Invoke-Collection -LocalCollectAll -OutFolder C:\Results -OutputFormat json

# Pipeline mode — emit row objects to stdout (files still written)
Invoke-Collection -LocalCollectByName UnquotedServicePaths -PassThru |
    Where-Object FirstWritableSegment |
    Format-Table
```

With `-PassThru`, every row is tagged with `DataPoint` and `ComputerName`
note properties so multi-data-point or multi-host streams can be grouped
downstream:

```powershell
Invoke-Collection -LocalCollectByName LocalAdministrators,Services -PassThru |
    Group-Object DataPoint
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
| `Modules/DataPoint/` | DataPoint class, TechniqueCategory enum (8 MITRE tactic values), 84 data point factory, Quick profile flag |
| `Modules/JobController/` | Background job reaping and WinRM runspace pool management |
| `Modules/Node/` | Simple node class with 4 string properties |

## Roadmap

A living list of known gaps and planned work. Not strictly prioritized —
this is an honest enumeration of where Meta-Blue can grow.

### Data quality / LFO stacking

- [ ] Add a `ComputerName` column to every output row so local and remote
  CSVs can be concatenated directly for cross-host LFO stacking.
- [ ] Restructure `RegistryRunKeys` to emit flat `{Sid, RegPath, ValueName,
  Value}` rows instead of one `PSCustomObject` with dynamic per-SID
  properties (current shape can't be stacked across hosts).
- [ ] Standardize per-user data points to always emit both `Sid` and
  `Username` columns. Prefer `HKU:\<sid>` enumeration over `C:\Users\*`
  iteration where reasonable.
- [ ] Drop `PSPath` / `PSChildName` / `PSProvider` / `PSDrive` columns from
  registry-derived data points that currently leak them.
- [ ] Replace locale-sensitive `Substring(N)` parsers in
  `VisibleWirelessNetworks`, `HistoricalWiFiConnections`, and `PassTheHash`
  (klist) with regex-based field extraction so they work on non-English
  Windows builds.
- [ ] Tag or remove the remaining Uncategorized data points. Specifically:
  delete the self-acknowledged low-quality `ProgramData`, `KnownDLLs`,
  `Startup`; decide a tactic for `Logon`, `SMBConnections`,
  `PrefetchListing`, `LoadedDLLs`, `CapabilityAccessManager`,
  `DLLsInTempDirs`, `NamedPipes`.
- [ ] Eliminate `Get-FileHash -Path $null` error spam from hash-augmenting
  data points (`Processes`, `Drivers`, `LoadedDLLs`, `DLLsInTempDirs`).

### Robustness / observability

- [ ] Add `collection.errors.csv` — capture error streams from local jobs
  and remote runspaces so analysts can distinguish "data point returned
  0 rows" from "data point failed with access denied."
- [ ] Wrap every data point scriptblock in try/catch with structured error
  emission so the error log gets useful context.
- [ ] Switch `Invoke-BaselineDiff` from line-diff to schema-aware diff
  using `Import-Csv` + `Compare-Object -Property *` so column reorders
  and locale-dependent whitespace don't produce false positives.
- [ ] Track `Invoke-BaselineDiff.ps1` in git — currently untracked.
- [ ] Surface `JobController` functions properly. `JobController.psd1` has
  `FunctionsToExport = @()` so they aren't `Get-Command`-discoverable.

### Coverage expansion (WinPEAS-inspired surface inventory)

Phase 1 (PrivilegeEscalation primitives) shipped. Remaining phases:

- [ ] **Phase 2 — Credential exposure surface (CredentialAccess):**
  `CredentialManagerEntries`, `WiFiProfilesXML`, `VaultEntries`,
  `DPAPIMasterKeyFiles`, `UnattendXMLFiles`, `CredentialsInRegistry`,
  `GroupPolicyPreferencePasswords`.
- [ ] **Phase 3 — Defense posture (DefenseEvasion):** `AppLockerPolicy`,
  `WDACPolicy`, `PowerShellLoggingConfig`, `AuditPolicy`,
  `WindowsDefenderASRRules`, `LSAProtection`, `CredentialGuardStatus`,
  `SMBSigningRequired`, `LLMNRNetBIOSStatus`, `WPADConfig`, `WSUSConfig`.
- [ ] **Phase 4 — Lateral movement surface (LateralMovement):**
  `RDPConfig`, `WinRMConfig`, `PSRemotingEndpoints`,
  `NamedPipePermissions` (replace existing `NamedPipes`), `SMBv1Enabled`,
  `NetworkSharePermissions` (augment `SMBShares` with ACLs),
  `DomainTrusts`, `DefaultDomainPolicy`.
- [ ] **Phase 5 — Discovery / inventory:** `InstalledRoles`,
  `WindowsLicenseStatus`, `InstalledCertificates`, `EFSEncryptedFiles`,
  `LocalUsers`, `AutorunsViaRegistry` (broader than current
  `RegistryRunKeys`), `EventForwardingConfig`, `HostsFile`,
  `TrustedRootCAFingerprints`, `OpenFirewallRulesInbound`,
  `NetworkProfile`, `PendingReboots`, `SystemLocale`.
- [ ] **Phase 6 — Initial access / Execution evidence:**
  `OfficeMacroSettings`, `OfficeAddIns`, `OfficeTrustedLocations`,
  `OutlookHomePageURL`, `BrowserExtensions`, `AppCompatCache`,
  `UserAssistEntries`, `MUICache`.

### Tooling / orchestration

- [ ] Implement `Invoke-Discovery` — currently an empty stub. Should
  resolve hosts via AD, IP range, or file input and emit a node list
  consumable by `Invoke-Collection -ComputerSet`.
- [ ] Decide the fate of `Invoke-MetaBlue` — gitignored stub. Either
  build it as a unified orchestrator chaining
  Discovery → Collection → BaselineDiff, or delete it.
- [ ] Decide the fate of `Modules/Node/` — currently only conceptually
  used by the unfinished Discovery work. Wire it into Discovery output
  or remove it.

### Documentation

- [ ] Per-tactic README files in `Modules/DataPoint/Tactics/` documenting
  each data point's hunt question and the LFO interpretation of its rows.
- [ ] `docs/HuntQueries.md` — sample LFO queries against collected CSVs
  (e.g., "find the rare local Administrator across the fleet").
- [ ] `docs/AddingADataPoint.md` — how-to guide pointing at the right
  `Tactics/<Tactic>.ps1` file, with row-schema and scope conventions.

## Caveats

Some data points are self-acknowledged low quality — see scriptblock
comments in `Modules/DataPoint/Tactics/*.ps1` for details (`ProgramData`,
`KnownDLLs`, `Startup`, `Services` are flagged).

## License

MIT — see [LICENSE](LICENSE).
