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