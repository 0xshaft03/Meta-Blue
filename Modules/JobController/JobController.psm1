function New-RemoteRunspacePool(){
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Computername,
        [int32]$MaxRunspaces = 10
    )

    $wsmanconnection = [System.Management.Automation.Runspaces.WSManConnectionInfo]::new()
    $wsmanconnection.ComputerName = $Computername

    $HostRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(2,$MaxRunspaces,$wsmanconnection)
    $HostRunspacePool.Open()
    return $HostRunspacePool
}

function New-RemoteRunspacePoolScriptBlock(){
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [System.Management.Automation.Runspaces.RunspacePool]$HostRunspacePool,
        [scriptblock]$ScriptBlock,
        [ValidateNotNullOrEmpty()]
        [String]$DatapointName
    )
    $RemoteRunspaceJob = [System.Management.Automation.PowerShell]::Create()
    $RemoteRunspaceJob.addscript($ScriptBlock)
    $RemoteRunspaceJob.RunspacePool = $HostRunspacePool

    $RemoteRunspaceJobOject = [PSCustomObject]@{
        JobHandle = $RemoteRunspaceJob;
        AsyncHandle = $RemoteRunspaceJob.BeginInvoke();
        JobName = $DatapointName;
        RemoteComputerName = $HostRunspacePool.ConnectionInfo.ComputerName;
    }

    return $RemoteRunspaceJobOject

}

function Create-ArtifactFromRemoteRunspacePool(){
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [ValidateNotNullOrEmpty()]
        [System.Collections.ArrayList]$RemoteJobs,
        [String]$rawFolder
    )
    
    $asynchandles = $RemoteJobs.AsyncHandle
    [System.Threading.WaitHandle]::WaitAll($asynchandles)


    foreach($job in $RemoteJobs){
        $compname = $job.RemoteComputerName
        if(!(Test-Path "$rawFolder\$($job.RemoteComputerName)")){new-item -ItemType Directory -Path "$rawFolder\$compname" -Force |out-null}
        $job.jobhandle.endinvoke($job.asynchandle) | export-csv -Force -Append -NoTypeInformation -Path "$rawFolder\$compname\Host_$($job.jobname).csv";
        #$job.jobhandle.endinvoke($job.asynchandle) | export-csv -Force -Append -NoTypeInformation -Path "$rawFolder\Host_$($job.jobname).csv";
        $job.JobHandle.dispose();
    }

}

function Create-Artifact(){
    
    while($true){
        $jobs = Get-Job
        foreach($job in $jobs){
            $ComputerName = $job.Location
            $Task = $job.name

            if($job.state -eq "Completed" -or $job.state -eq "Running"){
                
                Receive-Job $job.id | export-csv -force -Append -NoTypeInformation -Path "$rawFolder\Host_$Task.csv"

            } elseif($job.state -eq "Failed"){
                Write-Verbose "$Task failed on $ComputerName"
                Receive-Job $job
            }

            if(!($job.hasmoredata)){
                remove-job $job.id -force
            }
        }
        if($null -eq $(Get-Job)){
            return
        } else {
            #$jobs | Format-Table -RepeatHeader
            $jobs | Format-Table
            Start-Sleep -Seconds 10
        }

    }
}