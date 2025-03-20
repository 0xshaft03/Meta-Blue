using module .\Modules\DataPoint\DataPoint.psm1
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
[CmdletBinding(DefaultParameterSetName = 'LocalCollection')]
    param(
        [Parameter(ParameterSetName = 'LocalCollection')]
        [switch]$LocalCollection,

        [Parameter(ParameterSetName = 'RemoteCollection')]
        [switch]$RemoteCollection,

        [switch]$CollectAll,

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
        [string[]]$Collect,

        [ValidateSet('Uncategorized','Persistence','LateralMovement','ImpairDefenses')]
        [string[]]$CollectCategory,

        [Parameter(ParameterSetName = 'RemoteCollection')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [switch]$Enumerate,

        [Parameter(ParameterSetName = 'RemoteCollection')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [ValidateNotNullOrEmpty()]
        [string]$Subnet,

        [Parameter(ParameterSetName = 'RemoteCollection')]
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

        if($CollectAll){
            Write-Verbose "Collecting Everything!"
        }
        elseif($Collect){
            Write-Verbose "Collecting: $Collect"
        }
        elseif($CollectCategory){
            Write-Verbose "Collecting $CollectCategory"
        }

        if($PSCmdlet.ParameterSetName -eq "LocalCollection"){
            Write-Verbose "Starting the Local Collecter"

            <#
                This is the action that the following event that is registered takes 
            #>
            $action =  {
                Write-Verbose "Output Format is: $OutputFormat"
                $Task = $Sender.name;
                $state = $Sender.state
                if($state -eq "Completed"){
    
                    $jobcontent = Receive-Job $Sender | Select-Object -Property *,CompName
                    foreach($j in $jobcontent){
                        $j.CompName = $Event.MessageData
                    }

                    $jobcontent | export-csv -force -append -NoTypeInformation -path "$rawFolder\Host_$Task.csv" | out-null;

                    if(!$Sender.HasMoreData){
                        Unregister-Event -subscriptionid $EventSubscriber.SubscriptionId -Force;
                        Remove-Job -name $EventSubscriber.sourceidentifier -Force;
                        Remove-job $Sender
                        
                    }
                
                } 
                elseif($state -eq "Failed"){
                    $Sender | export-csv -Append -NoTypeInformation "$outFolder\failedjobs.csv"
                    Remove-Job $job.id -force
                
                }
                elseif($state -eq "Disconnected"){
                    $Sender | export-csv -Append -NoTypeInformation "$outFolder\failedjobs.csv"
                    Remove-Job $job.id -force
                
                }
            
            }
            
            if($Collect){
                Write-Verbose "Collecting: $Collect"
                foreach($datapoint in $datapoints){
                    if($Collect.Contains($datapoint.jobname)){
                        Register-ObjectEvent -MessageData $env:COMPUTERNAME -InputObject (Start-Job -Name $datapoint.jobname -ScriptBlock $datapoint.scriptblock) -EventName StateChanged -Action $action | out-null
                    }
                }
            } elseif ($CollectAll) {
                Write-Verbose "Collecting: $datapoints"
                foreach($datapoint in $datapoints){
                    Register-ObjectEvent -MessageData $env:COMPUTERNAME -InputObject (Start-Job -Name $datapoint.jobname -ScriptBlock $datapoint.scriptblock) -EventName StateChanged -Action $action | out-null
                }
            } elseif ($CollectCategory) {
                Write-Verbose "Collecting from category: $CollectCategory"
                foreach($datapoint in $datapoints){
                    if($datapoint.techniqueCategory -eq $CollectCategory){
                        Register-ObjectEvent -MessageData $env:COMPUTERNAME -InputObject (Start-Job -Name $datapoint.jobname -ScriptBlock $datapoint.scriptblock) -EventName StateChanged -Action $action | out-null
                    }
                }
            }
            

            while($true){
                $jobs = Get-Job
                
                if($null -ne $jobs) {

                    $jobs | Format-Table -RepeatHeader
                    Start-Sleep -Seconds 10

                } else {

                    break

                }
                
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "RemoteCollection") {
            Write-Verbose "Starting the Remote Collector"
        }
    }
    END {

    }
}