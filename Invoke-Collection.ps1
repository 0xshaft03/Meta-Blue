using module .\Modules\DataPoint.psm1
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
        [ValidateSet('Light', 'Medium', 'Heavy', 'Dreadnought', 'Custom')]
        [string]$CollecterSize = 'Light',

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
        
        [Parameter(Mandatory)]
        [string]$OutFolder = "C:\Meta-Blue"
    )
    BEGIN {
        $timestamp = (get-date).Tostring("yyyy_MM_dd_hh_mm_ss")
        $datapoints = [System.Collections.ArrayList]@()
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
        $scriptblock = {
            $processes = Get-WmiObject win32_process
            $processes | ForEach-Object{
                Add-Member -InputObject $_ -Name Hash -Value (Get-FileHash -Path $_.ExecutablePath -ea SilentlyContinue).hash -MemberType NoteProperty 
            } 
            $processes | Select-Object processname,handles,path.pscomputernamename,commandline,creationdate,executablepath,parentprocessid,processid,Hash
        }
        $datapoints.Add([DataPoint]::new("Process", $scriptblock, $true)) | Out-Null
        
    
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
            
            foreach($datapoint in $datapoints){
                if($datapoint.isEnabled){
                                    
                    Register-ObjectEvent -MessageData $env:COMPUTERNAME -InputObject (Start-Job -Name $datapoint.jobname -ScriptBlock $datapoint.scriptblock) -EventName StateChanged -Action $action | out-null
                
                }
            }

            while($true){
                $jobs = Get-Job
                $events = Get-Event
                if($null -ne $jobs){
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