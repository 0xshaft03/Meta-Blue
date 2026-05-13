enum TechniqueCategory {
    Uncategorized
    Persistence
    Discovery
    DefenseEvasion
    LateralMovement
    CommandAndControl
    PrivilegeEscalation
    CredentialAccess
}
class DataPoint {
    [string]$jobname
    [scriptblock]$scriptblock
    [bool]$isEnabled
    [string]$mitreID
    [TechniqueCategory]$techniqueCategory
    [bool]$isQuick = $false

    DataPoint([string]$jobname, [scriptblock]$scriptblock, [bool]$isEnabled, [string]$mitreID, [TechniqueCategory]$techniqueCategory){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = $mitreID
        $this.techniqueCategory = $techniqueCategory
    }

    DataPoint([string]$jobname, [scriptblock]$scriptblock, [bool]$isEnabled){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = "N/A"
    }

    DataPoint([string]$jobname, [scriptblock]$scriptblock, [bool]$isEnabled, [string]$mitreID, [TechniqueCategory]$techniqueCategory, [bool]$isQuick){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = $mitreID
        $this.techniqueCategory = $techniqueCategory
        $this.isQuick = $isQuick
    }

    DataPoint([string]$jobname, [scriptblock]$scriptblock, [bool]$isEnabled, [bool]$isQuick){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = "N/A"
        $this.isQuick = $isQuick
    }

    enable(){
        $this.isEnabled = $true
    }

    disable(){
        $this.isEnabled = $false
    }

    [string] ToString(){
        return $this.jobname
    }
}

<#
.SYNOPSIS
    Build the full set of 84 data point definitions by dot-sourcing one
    file per MITRE ATT&CK tactic from .\Tactics\.

.DESCRIPTION
    Each .\Tactics\<Tactic>.ps1 file contains a sequence of
        $scriptblock = { ... }
        $datapoints.Add([DataPoint]::new(...)) | Out-Null
    pairs. The files are dot-sourced into this function's scope so they
    share the local $datapoints ArrayList and the [DataPoint] /
    [TechniqueCategory] types defined above.

    Adding a new data point: edit the appropriate Tactics\<Tactic>.ps1
    file. Adding a new tactic: create Tactics\<NewTactic>.ps1 and append
    a dot-source line below (enum value must already exist).
#>
function New-DataPoints(){
    $datapoints = [System.Collections.ArrayList]@()

    $tacticsRoot = Join-Path $PSScriptRoot 'Tactics'
    . (Join-Path $tacticsRoot 'Persistence.ps1')
    . (Join-Path $tacticsRoot 'Discovery.ps1')
    . (Join-Path $tacticsRoot 'DefenseEvasion.ps1')
    . (Join-Path $tacticsRoot 'PrivilegeEscalation.ps1')
    . (Join-Path $tacticsRoot 'LateralMovement.ps1')
    . (Join-Path $tacticsRoot 'CommandAndControl.ps1')
    . (Join-Path $tacticsRoot 'CredentialAccess.ps1')
    . (Join-Path $tacticsRoot 'Uncategorized.ps1')

    return $datapoints
}
