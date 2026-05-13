using module .\Modules\DataPoint\DataPoint.psm1
using module .\Modules\JobController\JobController.psm1
function Invoke-Collection {
<#
.SYNOPSIS
    Collect forensic data points from local or remote Windows hosts.

.DESCRIPTION
    Invoke-Collection is part of the Meta-Blue forensics framework. It runs 76
    MITRE ATT&CK-aligned data points against local or remote Windows hosts via
    PowerShell background jobs (local) or WinRM runspace pools (remote).

    Parameter sets control scope and target:
      LocalCollectAll / LocalCollectByName / LocalCollectByCategory
      RemoteCollectAll / RemoteCollectByName / RemoteCollectByCategory

    Output is written as CSV or JSON files under
    <OutFolder>\<timestamp>\Raw\  — one file per data point for local runs,
    or per-host per data point for remote runs.

.PARAMETER LocalCollectAll
    Collect all data points on the local machine.

.PARAMETER LocalCollectByName
    Collect specific data points by name on the local machine.
    Accepts one or more values from the built-in ValidateSet (76 names).

.PARAMETER LocalCollectByCategory
    Collect data points matching a MITRE ATT&CK technique category on
    the local machine. Valid values: Uncategorized, Persistence,
    LateralMovement, ImpairDefenses.

.PARAMETER RemoteCollectAll
    Collect all data points from remote hosts.

.PARAMETER RemoteCollectByName
    Collect specific data points by name from remote hosts.

.PARAMETER RemoteCollectByCategory
    Collect data points matching a technique category from remote hosts.

.PARAMETER ComputerSet
    Source of remote target computers. Valid values:
      ActiveDirectoryComputers — pulls from AD (requires ActiveDirectory module)
      TextFile / CSVFile       — not yet implemented

.PARAMETER Subnet
    CIDR subnet for network discovery (used with -Enumerate).

.PARAMETER Enumerate
    Perform network discovery before remote collection. Currently a stub.

.PARAMETER OutFolder
    Parent directory for output. Default: C:\Meta-Blue.
    A subfolder named <timestamp> is created automatically, containing Raw\
    and Anomalies\ directories.

.PARAMETER OutputFormat
    Output file format. Valid values: csv, json. Default: csv.

.EXAMPLE
    Invoke-Collection -LocalCollectAll -OutFolder C:\Results -OutputFormat json

    Collect all data points on the local machine, output as JSON.

.EXAMPLE
    Invoke-Collection -RemoteCollectAll -ComputerSet ActiveDirectory -OutFolder C:\Results

    Collect all data points from all Active Directory computers via WinRM.

.EXAMPLE
    Invoke-Collection -LocalCollectByName Processes,Services -OutFolder C:\Results

    Collect only Processes and Services data points on the local machine.

.EXAMPLE
    Invoke-Collection -LocalCollectByCategory Persistence -OutFolder C:\Results

    Collect all data points in the Persistence category on the local machine.

.INPUTS
    None. Does not accept pipeline input.

.OUTPUTS
    CSV or JSON files. One file per data point (local) or one per-host
    folder with per-data-point files (remote).

.NOTES
    Author: 0xshaft03
    Requires: Windows PowerShell 5.1, local administrator rights
    Remote collection requires WinRM access to target hosts.

.LINK
    https://github.com/0xshaft03/Meta-Blue
#>
[CmdletBinding(DefaultParameterSetName = 'LocalCollectAll')]
    param(
        [Parameter(ParameterSetName = 'LocalCollectAll')]
        [switch]$LocalCollectAll,

        [Parameter(ParameterSetName = 'LocalCollectByName')]
        # Keep in sync with the RemoteCollectByName ValidateSet and New-DataPoints() in DataPoint.psm1
        [ValidateSet("TerminalServicesDLL","Screensaver","WMIEventSubscription","NetshHelperDLL","AccessibilityFeature","AppCertDLLS","AppInitDLLS","ApplicationShimming","ImageFileExecutionOptions","PowershellProfile","AuthenticationPackage",
        "TimeProviders","WinlogonHelperDLL","SecuritySupportProvider","LSASSDriverWindowsEvents","LSASSDriverRegistry","PortMonitors",
        "PrintProcessors","ActiveSetup","Processes","DNSCache","AlternateDataStreams","KnownDLLs","DLLSearchOrderHijacking",
        "BITSJobsLogs","BITSTransfer","SystemFirmware","UserInitMprLogonScript","InstalledSoftare","AVProduct","Services","PowerShellVersion",
        "Startup","StartupFolder","Drivers","EnvironmentVariables","NetworkAdapters","SystemInfo","Logon","NetworkConnections","SMBShares",
        "SMBConnections","ScheduledTasks","PrefetchListing","PNPDevices","LogicalDisks","DiskDrives","LoadedDLLs","UnsignedDrivers","Hotfixes",
        "ArpCache","NewlyRegisteredServices","AppPaths","UACBypassFodHelper","VisibleWirelessNetworks","HistoricalWiFiConnections",
        "HistoricalFirewallChanges","PortProxies","CapabilityAccessManager","DnsClientServerAddress","ShortcutModifications",
        "DLLsInTempDirs","RDPHistoricallyConnectedIPs","MpComputerStatus","MpPreference","COMObjects","CodeIntegrityLogs",
        "SecurityLogCleared","SIPandTrustProviderHijacking","PassTheHash","NamedPipes","RegistryRunKeys","DefenderExclusionPath",
        "DefenderExclusionIpAddress","DefenderExclusionExtension")]
        [String[]]$LocalCollectByName,

        [Parameter(ParameterSetName = 'LocalCollectByCategory')]
        [ValidateSet('Uncategorized','Persistence','LateralMovement','ImpairDefenses')]
        [String]$LocalCollectByCategory,

        [Parameter(ParameterSetName = 'RemoteCollectAll')]
        [switch]$RemoteCollectAll,

        [Parameter(ParameterSetName = 'RemoteCollectByName')]
        # Keep in sync with the LocalCollectByName ValidateSet and New-DataPoints() in DataPoint.psm1
        [ValidateSet("TerminalServicesDLL","Screensaver","WMIEventSubscription","NetshHelperDLL","AccessibilityFeature","AppCertDLLS","AppInitDLLS","ApplicationShimming","ImageFileExecutionOptions","PowershellProfile","AuthenticationPackage",
        "TimeProviders","WinlogonHelperDLL","SecuritySupportProvider","LSASSDriverWindowsEvents","LSASSDriverRegistry","PortMonitors",
        "PrintProcessors","ActiveSetup","Processes","DNSCache","AlternateDataStreams","KnownDLLs","DLLSearchOrderHijacking",
        "BITSJobsLogs","BITSTransfer","SystemFirmware","UserInitMprLogonScript","InstalledSoftare","AVProduct","Services","PowerShellVersion",
        "Startup","StartupFolder","Drivers","EnvironmentVariables","NetworkAdapters","SystemInfo","Logon","NetworkConnections","SMBShares",
        "SMBConnections","ScheduledTasks","PrefetchListing","PNPDevices","LogicalDisks","DiskDrives","LoadedDLLs","UnsignedDrivers","Hotfixes",
        "ArpCache","NewlyRegisteredServices","AppPaths","UACBypassFodHelper","VisibleWirelessNetworks","HistoricalWiFiConnections",
        "HistoricalFirewallChanges","PortProxies","CapabilityAccessManager","DnsClientServerAddress","ShortcutModifications",
        "DLLsInTempDirs","RDPHistoricallyConnectedIPs","MpComputerStatus","MpPreference","COMObjects","CodeIntegrityLogs",
        "SecurityLogCleared","SIPandTrustProviderHijacking","PassTheHash","NamedPipes","RegistryRunKeys","DefenderExclusionPath",
        "DefenderExclusionIpAddress","DefenderExclusionExtension")]
        [String[]]$RemoteCollectByName,

        [Parameter(ParameterSetName = 'RemoteCollectByCategory')]
        [ValidateSet('Uncategorized','Persistence','LateralMovement','ImpairDefenses')]
        [String]$RemoteCollectByCategory,


        [Parameter(ParameterSetName = 'RemoteCollectAll')]
        [Parameter(ParameterSetName = 'RemoteCollectByName')]
        [Parameter(ParameterSetName = 'RemoteCollectByCategory')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [switch]$Enumerate,

        [Parameter(ParameterSetName = 'RemoteCollectAll')]
        [Parameter(ParameterSetName = 'RemoteCollectByName')]
        [Parameter(ParameterSetName = 'RemoteCollectByCategory')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [ValidateNotNullOrEmpty()]
        [string]$Subnet,

        [Parameter(ParameterSetName = 'RemoteCollectAll')]
        [Parameter(ParameterSetName = 'RemoteCollectByName')]
        [Parameter(ParameterSetName = 'RemoteCollectByCategory')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ActiveDirectoryComputers', 'TextFile', 'CSVFile')]
        [string]$ComputerSet,
        
        [Parameter()]
        [string]$OutFolder = "C:\Meta-Blue",

        [ValidateSet('csv','json')]
        [string]$OutputFormat = 'csv'
    )
    BEGIN {
        if($ComputerSet -eq "ActiveDirectoryComputers"){
            if(-not (Get-Module -Name ActiveDirectory -ListAvailable)){
                throw "ActiveDirectory module is required for -ComputerSet ActiveDirectoryComputers"
            }
            Write-Verbose "ActiveDirectory Module Found!"

        }
        $timestamp = (Get-Date).ToString("yyyy_MM_dd_HH_mm_ss")
        Write-Verbose "Folder Timestamp: $timestamp"

        $datapoints = New-DataPoints
        Write-Verbose "$($datapoints.Count) DataPoints configured"

        $global:rawFolder = "$OutFolder\$timestamp\Raw"
        Write-Verbose "Raw collect will be saved here: $global:rawFolder"

        if(!(Test-Path -Path "$OutFolder\$timestamp")){
            Write-Verbose "Creating $OutFolder\$timestamp"
            new-item -itemtype directory -path "$outFolder\$timestamp" -Force | Out-Null
            
            Write-Verbose "Creating $rawFolder"
            new-item -itemtype directory -path $rawFolder -Force | out-null
            
            Write-Verbose "Creating $OutFolder\$timestamp\Anomalies"
            new-item -itemtype directory -path "$outFolder\$timestamp\Anomalies" -Force | out-null  
        } else {
            Write-Verbose "$OutFolder\$timestamp already exists" 
        }

        
        
    }
    PROCESS {
        Write-Debug "ParameterSetName = $($PSCmdlet.ParameterSetName)"

        if($LocalCollectAll -or $RemoteCollectAll){
            Write-Verbose "Collecting Everything!"
        }
        elseif($LocalCollectByName -or $RemoteCollectByName){
            if($LocalCollectByName){
                Write-Verbose "Collecting: $LocalCollectByName"
            } elseif ($RemoteCollectByName) {
                
                Write-Verbose "Collecting: $RemoteCollectByName"
            }
            
        }
        elseif($LocalCollectByCategory -or $RemoteCollectByCategory){
            if($LocalCollectByCategory){
                Write-Verbose "Collecting: $LocalCollectByCategory"
            } elseif ($RemoteCollectByCategory) {
                
                Write-Verbose "Collecting: $RemoteCollectByCategory"
            }
            
        }

        if($PSCmdlet.ParameterSetName -like "Local*"){
            Write-Verbose "Starting the Local Collecter"
            
            if($LocalCollectByName){
                Write-Verbose "Collecting: $LocalCollectByName"
                if($LocalCollectByName){
                    foreach($datapoint in $datapoints){
                        if($LocalCollectByName.Contains($datapoint.jobname)){
                            Start-Job -Name $datapoint.jobname -ScriptBlock $datapoint.scriptblock
                        }
                    }

                }
            } elseif ($LocalCollectAll) {
                Write-Verbose "Collecting: $datapoints"
                foreach($datapoint in $datapoints){
                    Start-Job -Name $datapoint.jobname -ScriptBlock $datapoint.scriptblock
                }
            } elseif ($LocalCollectByCategory) {
                Write-Verbose "Collecting from category: $LocalCollectByCategory"
                foreach($datapoint in $datapoints){
                    if($datapoint.techniqueCategory -eq $LocalCollectByCategory){
                        Start-Job -Name $datapoint.jobname -ScriptBlock $datapoint.scriptblock
                    }
                }
            }
            Get-Artifact -rawFolder $global:rawFolder
            

        } elseif ($PSCmdlet.ParameterSetName -like "Remote*") {
            Write-Verbose "Starting the Remote Collector"
            $RemoteRunspaces = [System.Collections.ArrayList]@()
            $RemoteJobs = [System.Collections.ArrayList]@()
            
            if($ComputerSet -eq "ActiveDirectoryComputers"){
                try {
                    $computers = Get-AdComputer -filter 'DNSHostName -ne "dc.foo.local"'
                } catch {
                    Write-Error "Failed to query Active Directory: $($_.Exception.Message)"
                    return
                }

                if($null -ne $computers){
                    foreach($computer in $computers){
                        #Invoke-Command -ComputerName $computer.DNSHostName -ScriptBlock {if(!(Get-PSSessionConfiguration -Name metablue)){Register-PSSessionConfiguration -ThreadApartmentState MTA -ThreadOptions UseNewThread -name metablue}}
                        #$s = New-PSSession -ComputerName $computer.DNSHostName -ConfigurationName metablue
                        #$RemoteRunspaces.add($s)
                        $RemoteRunspace = New-RemoteRunspacePool -ComputerName $computer.DNSHostName -MaxRunspaces 75
                        if($RemoteRunspace){
                            $RemoteRunspaces.Add($RemoteRunspace) | out-null
                        }

                    }
                }

                if($null -ne $RemoteRunspaces){
                    if($RemoteCollectAll){
                        foreach($datapoint in $datapoints){
                            foreach($RemoteRunspace in $RemoteRunspaces){
                                $RemoteJob = New-RemoteRunspacePoolScriptBlock -HostRunspacePool $RemoteRunspace -ScriptBlock $datapoint.scriptblock -Datapointname $datapoint.jobname
                                if($RemoteJob){
                                    $RemoteJobs.Add($RemoteJob) | Out-Null
                                }
                            }
                        }
                    }

                    if($RemoteCollectByName){
                        foreach($datapoint in $datapoints){
                            if($RemoteCollectByName.Contains($datapoint.jobname)){
                                foreach($RemoteRunspace in $RemoteRunspaces){
                                    $RemoteJob = New-RemoteRunspacePoolScriptBlock -HostRunspacePool $RemoteRunspace -ScriptBlock $datapoint.scriptblock -Datapointname $datapoint.jobname
                                    if($RemoteJob){
                                        $RemoteJobs.Add($RemoteJob) | Out-Null
                                    }
                                }
                            }
                        }
                    }

                    if($RemoteCollectByCategory){
                        foreach($datapoint in $datapoints){
                            if($datapoint.techniqueCategory -eq $RemoteCollectByCategory){
                                foreach($RemoteRunspace in $RemoteRunspaces){
                                    $RemoteJob = New-RemoteRunspacePoolScriptBlock -HostRunspacePool $RemoteRunspace -ScriptBlock $datapoint.scriptblock -Datapointname $datapoint.jobname
                                    if($RemoteJob){
                                        $RemoteJobs.Add($RemoteJob) | Out-Null
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Get-ArtifactFromRemoteRunspacePool -RemoteJobs $RemoteJobs -rawFolder $global:rawFolder
        }

    }
    END {
        foreach($RemoteRunspace in $RemoteRunspaces){
            $RemoteRunspace.dispose()
        }
    }
}