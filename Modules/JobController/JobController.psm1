<#
.SYNOPSIS
    Creates a remote runspace pool connected to a target host via WinRM.

.DESCRIPTION
    Creates a WSManConnectionInfo-based runspace pool with 2 to MaxRunspaces
    concurrent threads. Returns $null if the pool cannot be created or opened.

.PARAMETER ComputerName
    Target hostname for the remote runspace pool.

.PARAMETER MaxRunspaces
    Maximum concurrent runspaces in the pool (default 10).

.OUTPUTS
    System.Management.Automation.Runspaces.RunspacePool or $null on failure.
#>
function New-RemoteRunspacePool() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [int32]$MaxRunspaces = 10
    )

    try {
        $wsmanconnection = [System.Management.Automation.Runspaces.WSManConnectionInfo]::new()
        $wsmanconnection.ComputerName = $ComputerName

        $HostRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(2, $MaxRunspaces, $wsmanconnection)
        $HostRunspacePool.Open()

        return $HostRunspacePool
    } catch {
        Write-Warning "Failed to create remote runspace pool for $ComputerName : $($_.Exception.Message)"
        if ($HostRunspacePool) { $HostRunspacePool.Dispose() }
        return $null
    }
}

<#
.SYNOPSIS
    Queues a script block onto a remote runspace pool for async execution.

.DESCRIPTION
    Creates a PowerShell instance, assigns the script block and runspace pool,
    and begins async invocation. Returns a custom object with handles for
    tracking and collecting results. Returns $null on failure.

.PARAMETER HostRunspacePool
    The remote runspace pool to execute on.

.PARAMETER ScriptBlock
    The script block to execute remotely.

.PARAMETER DatapointName
    Name of the data point for output file naming.

.OUTPUTS
    PSCustomObject with JobHandle, AsyncHandle, JobName, RemoteComputerName.
    Returns $null on failure.
#>
function New-RemoteRunspacePoolScriptBlock() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Management.Automation.Runspaces.RunspacePool]$HostRunspacePool,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [String]$DatapointName
    )

    try {
        $RemoteRunspaceJob = [System.Management.Automation.PowerShell]::Create()
        $RemoteRunspaceJob.AddScript($ScriptBlock)
        $RemoteRunspaceJob.RunspacePool = $HostRunspacePool

        $RemoteRunspaceJobObject = [PSCustomObject]@{
            JobHandle     = $RemoteRunspaceJob
            AsyncHandle   = $RemoteRunspaceJob.BeginInvoke()
            JobName       = $DatapointName
            RemoteComputerName = $HostRunspacePool.ConnectionInfo.ComputerName
        }

        return $RemoteRunspaceJobObject
    } catch {
        Write-Warning "Failed to start data point '$DatapointName' on remote host: $($_.Exception.Message)"
        if ($RemoteRunspaceJob) { $RemoteRunspaceJob.Dispose() }
        return $null
    }
}

<#
.SYNOPSIS
    Polls remote runspace pool jobs and writes completed results to CSV files.

.DESCRIPTION
    Polls an ArrayList of remote job objects, waiting for each to complete
    (with a 5-minute timeout per job). Completed jobs are drained via
    EndInvoke, written to per-host CSV files, and removed from the list.
    Returns when all jobs have been collected or failed.

.PARAMETER RemoteJobs
    ArrayList of job objects created by New-RemoteRunspacePoolScriptBlock.

.PARAMETER rawFolder
    Root output directory. Per-host subdirectories are created under this.

.OUTPUTS
    CSV files at <rawFolder>\<ComputerName>\Host_<DataPoint>.csv
#>
function Get-ArtifactFromRemoteRunspacePool() {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [System.Collections.ArrayList]$RemoteJobs,

        [string]$rawFolder
    )

    if ([String]::IsNullOrEmpty($rawFolder)) {
        Write-Error "rawFolder cannot be null or empty"
        return
    }

    $workingJobCount = $RemoteJobs.Count
    while ($workingJobCount -gt 0) {
        $completedJobs = [System.Collections.ArrayList]@()
        foreach ($job in $RemoteJobs) {
            try {
                if ($job.AsyncHandle.AsyncWaitHandle.WaitOne(300000)) {
                    $compname = $job.RemoteComputerName
                    $destPath = "$rawFolder\$compname"
                    if (!(Test-Path $destPath)) {
                        New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                    }
                    $job.JobHandle.EndInvoke($job.AsyncHandle) |
                        Export-Csv -Force -Append -NoTypeInformation -Path "$destPath\Host_$($job.JobName).csv"
                    $job.JobHandle.Dispose()
                    $completedJobs.Add($job) | Out-Null
                    $workingJobCount--
                } else {
                    Write-Warning "Job '$($job.JobName)' on $($job.RemoteComputerName) timed out after 300s"
                    $job.JobHandle.Dispose()
                    $completedJobs.Add($job) | Out-Null
                    $workingJobCount--
                }
            } catch {
                Write-Warning "Error collecting '$($job.JobName)' from $($job.RemoteComputerName): $($_.Exception.Message)"
                if ($job.JobHandle) { $job.JobHandle.Dispose() }
                $completedJobs.Add($job) | Out-Null
                $workingJobCount--
            }
        }
        foreach ($completedJob in $completedJobs) {
            $RemoteJobs.Remove($completedJob)
        }
    }
}

<#
.SYNOPSIS
    Polls local background jobs and writes completed output to CSV files.

.DESCRIPTION
    Polls all local PowerShell background jobs every 10 seconds. Completed
    jobs are drained via Receive-Job and written to individual CSV files.
    Failed jobs log to verbose stream and are removed. Returns when no jobs
    remain.

.PARAMETER rawFolder
    Directory path where CSV output files are written.

.OUTPUTS
    CSV files at <rawFolder>\Host_<DataPoint>.csv
#>
function Get-Artifact() {
    [CmdletBinding()]
    param(
        [string]$rawFolder = $global:rawFolder
    )

    if ([String]::IsNullOrEmpty($rawFolder)) {
        Write-Error "rawFolder cannot be null or empty"
        return
    }

    while ($true) {
        $jobs = Get-Job
        $remaining = 0
        foreach ($job in $jobs) {
            if ($job.State -eq 'Completed') {
                Receive-Job $job.Id |
                    Export-Csv -Force -Append -NoTypeInformation -Path "$rawFolder\Host_$($job.Name).csv"
                if (!$job.HasMoreData) {
                    Remove-Job $job.Id -Force
                }
            } elseif ($job.State -eq 'Failed') {
                Write-Verbose "Job '$($job.Name)' failed on $($job.Location)"
                Receive-Job $job | Out-Null
                Remove-Job $job.Id -Force
            } elseif ($job.State -eq 'Running') {
                $remaining++
            }
        }
        if ($null -eq (Get-Job)) {
            return
        }
        Write-Verbose "$remaining jobs still running"
        Start-Sleep -Seconds 10
    }
}