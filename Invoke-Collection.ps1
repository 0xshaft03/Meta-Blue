using module .\Modules\DataPoint\DataPoint.psm1
function Invoke-Collection {
<#
.SYNOPSIS
    Invoke-Collection is a mass survey tool that facilitates the rapid collection 
    of curated data points from Microsoft Windows hosts.

.DESCRIPTION
    
.PARAMETER ComputerName
.EXAMPLE
.EXAMPLE
.INPUTS
.OUTPUTS
    An ungodly amount of CSVs in your specified directory.
.NOTES
    Author: 0xshaft03
#>
[CmdletBinding(DefaultParameterSetName = 'LocalCollect')]
    param(
        [ValidateSet('TerminalServicesDLL','Screensaver','WMIEventSubscription','NetshHelperDLL','AccessibilityFeature',
        'DefenderExclusionPath','DefenderExclusionIpAddress','DefenderExclusionExtension','Processes')]
        [string[]]$Collect,

        [ValidateSet('Uncategorized','Persistence','LateralMovement','ImpairDefenses')]
        [string[]]$CollectCategory,

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [switch]$Enumerate,

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [ValidateNotNullOrEmpty()]
        [string]$Subnet,

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ActiveDirectoryComputers', 'TextFile', 'CSVFile')]
        [string]$ComputerSet,
        
        [Parameter()]
        [string]$OutFolder = "C:\Meta-Blue"
    )
    BEGIN {
        $timestamp = (get-date).Tostring("yyyy_MM_dd_hh_mm_ss")
        $datapoints = Create-DataPoints
        $global:rawFolder = "$OutFolder\$timestamp\Raw"

        if($Null -eq $ComputerSet){
        }
        if(!(Test-Path -Path "$OutFolder\$timestamp")){
            Write-Verbose "Creating $OutFolder\$timestamp"
            new-item -itemtype directory -path "$outFolder\$timestamp" -Force | Out-Null
            
            Write-Verbose "Creating $rawFolder"
            new-item -itemtype directory -path $rawFolder -Force | out-null
            
            Write-Verbose "Creating $OutFolder\$timestamp\Anomalies"
            new-item -itemtype directory -path "$outFolder\$timestamp\Anomalies" -Force | out-null  
        }

        if($CollecterSize -eq "Light"){
            Write-Verbose "Starting Light Collector"
        }
        elseif($CollecterSize -eq "Medium"){
            Write-Verbose "Starting Medium Collector"
        }
        elseif($CollecterSize -eq "Heavy"){
            Write-Verbose "Starting Heavy Collector"
        }
        elseif($CollecterSize -eq "Dreadnought"){
            Write-Verbose "Starting Dreadnought Collector"
        }
    
    }
    PROCESS {
        if($PSCmdlet.ParameterSetName -eq "LocalCollect"){
            Write-Verbose "Starting the Local Collecter"

            <#
                This is the action that the following event that is registered takes 
            #>
            $action =  {
                $Task = $Sender.name;
                if($Sender.state -eq "Completed"){
    
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
                elseif($Sender.state -eq "Failed"){
                    $Sender | export-csv -Append -NoTypeInformation "$outFolder\failedjobs.csv"
                    Remove-Job $job.id -force
                
                }
                elseif($Sender.state -eq "Disconnected"){
                    $Sender | export-csv -Append -NoTypeInformation "$outFolder\failedjobs.csv"
                    Remove-Job $job.id -force
                
                }
            
            }
            
            #foreach($datapoint in $datapoints){
            #    if($datapoint.isEnabled){
            foreach($datapoint in $datapoints){
                if($Collect.Contains($datapoint.jobname)){
                    Register-ObjectEvent -MessageData $env:COMPUTERNAME -InputObject (Start-Job -Name $datapoint.jobname -ScriptBlock $datapoint.scriptblock) -EventName StateChanged -Action $action | out-null
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
        }
    }
    END {

    }
}