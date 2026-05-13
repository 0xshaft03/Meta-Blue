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
    Polls a List[PSObject] of remote job objects using non-blocking
    WaitHandle.WaitAny() to detect completion without sequentially blocking
    on each job. Each job has a configurable overall timeout (default 5 min).
    Completed jobs are drained via EndInvoke, written to per-host CSV files,
    and removed from the list. Returns when all jobs have been collected,
    failed, or timed out.

.PARAMETER RemoteJobs
    List[PSObject] of job objects created by New-RemoteRunspacePoolScriptBlock.

.PARAMETER rawFolder
    Root output directory. Per-host subdirectories are created under this.

.PARAMETER PollIntervalMs
    Milliseconds to wait for any job to complete per poll cycle (default 30000).

.PARAMETER JobTimeoutMs
    Maximum milliseconds a job is allowed to run before being considered
    timed out and cleaned up (default 300000).

.OUTPUTS
    CSV files at <rawFolder>\<ComputerName>\Host_<DataPoint>.csv
#>
function Get-ArtifactFromRemoteRunspacePool() {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[PSObject]]$RemoteJobs,

        [string]$rawFolder,

        [int]$PollIntervalMs = 30000,
        [int]$JobTimeoutMs = 300000
    )

    if ([String]::IsNullOrEmpty($rawFolder)) {
        Write-Error "rawFolder cannot be null or empty"
        return
    }

    if ($null -eq $RemoteJobs -or $RemoteJobs.Count -eq 0) {
        return
    }

    $jobStartTimes = @{}
    foreach ($job in $RemoteJobs) {
        $key = $job.JobName + '|' + $job.RemoteComputerName
        $jobStartTimes[$key] = [datetime]::UtcNow
    }

    while ($RemoteJobs.Count -gt 0) {
        $handles = New-Object System.Collections.Generic.List[System.Threading.WaitHandle]
        foreach ($job in $RemoteJobs) {
            $handles.Add($job.AsyncHandle.AsyncWaitHandle)
        }

        $waitIndex = [System.Threading.WaitHandle]::WaitAny($handles.ToArray(), $PollIntervalMs)
        $now = [datetime]::UtcNow

        if ($waitIndex -eq 258) {
            for ($i = $RemoteJobs.Count - 1; $i -ge 0; $i--) {
                $job = $RemoteJobs[$i]
                $key = $job.JobName + '|' + $job.RemoteComputerName
                if ($jobStartTimes.ContainsKey($key)) {
                    $elapsed = ($now - $jobStartTimes[$key]).TotalMilliseconds
                    if ($elapsed -ge $JobTimeoutMs) {
                        Write-Warning "Job '$($job.JobName)' on $($job.RemoteComputerName) timed out after $([math]::Round($elapsed/1000))s"
                        try { $job.JobHandle.Dispose() } catch {}
                        $RemoteJobs.RemoveAt($i)
                        $jobStartTimes.Remove($key)
                    }
                }
            }
            continue
        }

        for ($i = $RemoteJobs.Count - 1; $i -ge 0; $i--) {
            $job = $RemoteJobs[$i]
            if ($job.AsyncHandle.IsCompleted) {
                try {
                    $compname = $job.RemoteComputerName
                    $destPath = "$rawFolder\$compname"
                    if (!(Test-Path $destPath)) {
                        New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                    }
                    $results = $job.JobHandle.EndInvoke($job.AsyncHandle)
                    if ($null -ne $results) {
                        $results | Export-Csv -Force -Append -NoTypeInformation -Path "$destPath\Host_$($job.JobName).csv"
                    }
                    $job.JobHandle.Dispose()
                } catch {
                    Write-Warning "Error collecting '$($job.JobName)' from $($job.RemoteComputerName): $($_.Exception.Message)"
                    try { $job.JobHandle.Dispose() } catch {}
                }

                $key = $job.JobName + '|' + $job.RemoteComputerName
                $jobStartTimes.Remove($key)
                $RemoteJobs.RemoveAt($i)
            }
        }
    }
}

<#
.SYNOPSIS
    Polls local background jobs and writes completed output to CSV files.

.DESCRIPTION
    Polls all local PowerShell background jobs every 1 second. Completed
    jobs are drained via Receive-Job and written to individual CSV files.
    Failed and unexpected-state jobs are cleaned up. Returns when no jobs
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

    do {
        $jobs = Get-Job
        if ($null -eq $jobs) { break }

        $remaining = 0

        foreach ($job in $jobs) {
            $jobName = $job.Name
            $jobId = $job.Id
            $filePath = "$rawFolder\Host_${jobName}.csv"

            switch ($job.State) {
                'Completed' {
                    Receive-Job -Id $jobId |
                        Export-Csv -Force -Append -NoTypeInformation -Path $filePath
                    if (-not $job.HasMoreData) {
                        Remove-Job -Id $jobId -Force
                    }
                }
                'Failed' {
                    Write-Verbose "Job '${jobName}' failed on $($job.Location)"
                    Receive-Job -Id $jobId | Out-Null
                    Remove-Job -Id $jobId -Force
                }
                'Running' {
                    $remaining++
                }
                'Stopped' {
                    Receive-Job -Id $jobId |
                        Export-Csv -Force -Append -NoTypeInformation -Path $filePath
                    Remove-Job -Id $jobId -Force
                }
                default {
                    Write-Verbose "Job '${jobName}' state '$($job.State)' - draining and removing"
                    Receive-Job -Id $jobId | Out-Null
                    Remove-Job -Id $jobId -Force
                }
            }
        }

        if ($remaining -gt 0) {
            Write-Verbose "$remaining jobs still running"
            Start-Sleep -Seconds 1
        }
    } while ($remaining -gt 0)
}