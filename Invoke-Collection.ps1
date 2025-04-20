using module .\Modules\DataPoint\DataPoint.psm1
using module .\Modules\JobController\JobController.psm1
function Invoke-Collection {
<#
.SYNOPSIS
    Invoke-Collection is one part of mass survey tool that facilitates the rapid collection 
    of curated data points from Microsoft Windows hosts.

.DESCRIPTION
.PARAMETER LocalCollection
    Use this to run the collector against the local machine only.
.PARAMETER RemoteCollection
    Use this to run the collecter against one or more remote hosts.
.PARAMETER CollectAll
    Use this to collect all datapoints.
.PARAMETER Collect
    Use this to collect specific datapoints.
.PARAMETER CollectCategory
    Use this to collect all datapoints that can help hunt for a specific technique category such as persistence, lateral movement, etc.
.PARAMETER OutFolder
    The parent directory that you want the collection stored under.
.PARAMETER OutputFormat
    Currently supports output as csv or json.
.EXAMPLE
    Invoke-Collection -LocalCollection -CollectAll -OutFolder C:\Meta-Blue\ -OutputFormat json
.EXAMPLE
    Invoke-Collection -RemoteCollection -ComputerSet ActiveDirectory -Collect Processes -OutFolder C:\Meta-Blue\ -OutputFormat json
.INPUTS
.OUTPUTS
    An ungodly amount of CSVs in your specified directory.
.NOTES
    Author: 0xshaft03
#>
[CmdletBinding(DefaultParameterSetName = 'LocalCollectAll')]
    param(
        [Parameter(ParameterSetName = 'LocalCollectAll')]
        [switch]$LocalCollectAll,

        [Parameter(ParameterSetName = 'LocalCollectByName')]
        [ValidateSet("TerminalServicesDLL","Screensaver","WMIEventSubscription","NetshHelperDLL","AccessibilityFeature","AppCertDLLS","AppInitDLLS","ApplicationShimming","ImageFileExecutionOptions","PowershellProfile","AuthenticationPackage",
        "TimeProviders","WinlogonHelperDLL","SecuritySupportProvider","LSASSDriverWindowsEvents","LSASSDriverRegistry","PortMonitors",
        "PrintProcessors","ActiveSetup","Processes","DNSCache","ProgramData","AlternateDataStreams","KnownDLLs","DLLSearchOrderHijacking",
        "BITSJobsLogs","BITSTransfer","SystemFirmware","UserInitMprLogonScript","InstalledSoftare","AVProduct","Services","PowerShellVersion",
        "Startup","StartupFolder","Drivers","EnvironmentVariables","NetworkAdapters","SystemInfo","Logon","NetworkConnections","SMBShares",
        "SMBConnections","ScheduledTasks","PrefetchListing","PNPDevices","LogicalDisks","DiskDrives","LoadedDLLs","UnsignedDrivers","Hotfixes",
        "ArpCache","NewlyRegisteredServices","AppPaths","UACBypassFodHelper","VisibleWirelessNetworks","HistoricalWiFiConnections",
        "HistoricalFirewallChanges","PortProxies","CapabilityAccessManager","DnsClientServerAddress","ShortcutModifications",
        "DLLsInTempDirs","RDPHistoricallyConnectedIPs","MpComputerStatus","MpPreference","COMObjects","CodeIntegrityLogs",
        "SecurityLogCleared","SIPandTrustProviderHijacking","PassTheHash","NamedPipes","RegistryRunKeys","DefenderExclusionPath",
        "DefenderExclusionIpAddress","DefenderExclusionExtension")]
        [String]$LocalCollectByName,

        [Parameter(ParameterSetName = 'LocalCollectByCategory')]
        [ValidateSet('Uncategorized','Persistence','LateralMovement','ImpairDefenses')]
        [String]$LocalCollectByCategory,

        [Parameter(ParameterSetName = 'RemoteCollectAll')]
        [switch]$RemoteCollectAll,

        [Parameter(ParameterSetName = 'RemoteCollectByName')]
        [ValidateSet("TerminalServicesDLL","Screensaver","WMIEventSubscription","NetshHelperDLL","AccessibilityFeature","AppCertDLLS","AppInitDLLS","ApplicationShimming","ImageFileExecutionOptions","PowershellProfile","AuthenticationPackage",
        "TimeProviders","WinlogonHelperDLL","SecuritySupportProvider","LSASSDriverWindowsEvents","LSASSDriverRegistry","PortMonitors",
        "PrintProcessors","ActiveSetup","Processes","DNSCache","ProgramData","AlternateDataStreams","KnownDLLs","DLLSearchOrderHijacking",
        "BITSJobsLogs","BITSTransfer","SystemFirmware","UserInitMprLogonScript","InstalledSoftare","AVProduct","Services","PowerShellVersion",
        "Startup","StartupFolder","Drivers","EnvironmentVariables","NetworkAdapters","SystemInfo","Logon","NetworkConnections","SMBShares",
        "SMBConnections","ScheduledTasks","PrefetchListing","PNPDevices","LogicalDisks","DiskDrives","LoadedDLLs","UnsignedDrivers","Hotfixes",
        "ArpCache","NewlyRegisteredServices","AppPaths","UACBypassFodHelper","VisibleWirelessNetworks","HistoricalWiFiConnections",
        "HistoricalFirewallChanges","PortProxies","CapabilityAccessManager","DnsClientServerAddress","ShortcutModifications",
        "DLLsInTempDirs","RDPHistoricallyConnectedIPs","MpComputerStatus","MpPreference","COMObjects","CodeIntegrityLogs",
        "SecurityLogCleared","SIPandTrustProviderHijacking","PassTheHash","NamedPipes","RegistryRunKeys","DefenderExclusionPath",
        "DefenderExclusionIpAddress","DefenderExclusionExtension")]
        [String]$RemoteCollectByName,

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
            $ad = Get-Module -name ActiveDirectory
            if($ad){
                Write-Verbose "ActiveDirectory Module Found!"
            }elseif(!$ad){
                Write-Verbose "ActiveDirectory Module is not Found!"
            }

        }
        $timestamp = (get-date).Tostring("yyyy_MM_dd_hh_mm_ss")
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

            Create-Artifact

        } elseif ($PSCmdlet.ParameterSetName -like "Remote*") {
            Write-Verbose "Starting the Remote Collector"

            if($ComputerSet -eq "ActiveDirectoryComputers"){
                $computers = Get-AdComputer
            }
        }
    }
    END {

    }
}