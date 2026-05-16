# ============================================================
# Uncategorized data points
# Dot-sourced by Modules/DataPoint/DataPoint.psm1::New-DataPoints
# Relies on $datapoints (ArrayList), [DataPoint], [TechniqueCategory]
# being in scope from the caller.
# ============================================================


    # I don't know how to feel about this one. Seems trash.
    $scriptblock = {Get-ChildItem -Recurse c:\ProgramData\ | Select-Object -Property Fullname,Pscomputername,creationtimeutc,lastaccesstimeutc,attributes} 
    $datapoints.Add([DataPoint]::new("ProgramData", $scriptblock, $true)) | Out-Null


    # This one is hot garbage as well. 
    $scriptblock = {(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs\')}
    $datapoints.Add([DataPoint]::new("KnownDLLs", $scriptblock, $true)) | Out-Null


    # I don't like this one either.
    $scriptblock = {Get-CimInstance win32_startupcommand | Select-Object -Property PSComputerName,Caption,Command,Description,Location,User}
    $datapoints.Add([DataPoint]::new("Startup", $scriptblock, $true, $true)) | Out-Null


    $scriptblock = {Get-WmiObject win32_networkloginprofile}
    $datapoints.Add([DataPoint]::new("Logon", $scriptblock, $true)) | Out-Null


    $scriptblock = {try {Get-SmbConnection} catch {}}
    $datapoints.Add([DataPoint]::new("SMBConnections", $scriptblock, $true)) | Out-Null


    $scriptblock = {Get-ChildItem "C:\Windows\Prefetch"}
    $datapoints.Add([DataPoint]::new("PrefetchListing", $scriptblock, $true)) | Out-Null


    $scriptblock = {
        $modules = Get-Process -Module -ErrorAction SilentlyContinue
        $modules | ForEach-Object {
            if($null -ne $_.filename){
                Add-Member -InputObject $_ -Name Hash -Value (Get-FileHash -Path $_.filename -ea SilentlyContinue).hash -MemberType NoteProperty -ErrorAction SilentlyContinue
            }
        }
        $modules
    }
    $datapoints.Add([DataPoint]::new("LoadedDLLs", $scriptblock, $true)) | Out-Null


    $scriptblock = {(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*\NonPackaged\*)}
    $datapoints.Add([DataPoint]::new("CapabilityAccessManager", $scriptblock, $true)) | Out-Null


    $scriptblock = {(Get-Process -Module -ea 0).FileName|Where-Object{$_ -notlike "*system32*"}|Select-String "Appdata","ProgramData","Temp","Users","public"|Get-unique|ForEach-Object{Get-FileHash -Path $_}}
    $datapoints.Add([DataPoint]::new("DLLsInTempDirs", $scriptblock, $true)) | Out-Null


    $scriptblock = {get-childitem \\.\pipe\ | Select-Object fullname}
    $datapoints.Add([DataPoint]::new("NamedPipes", $scriptblock, $true)) | Out-Null


    <#
        LocalAdministrators: members of the local Administrators group. Falls
        back to ADSI WinNT enumeration when Get-LocalGroupMember chokes on
        orphaned domain SIDs (known 5.1 bug).
    #>
    $scriptblock = {
        $rows = [System.Collections.ArrayList]@()
        $used = $false
        try {
            Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
                $rows.Add([PSCustomObject]@{
                    MemberName      = $_.Name
                    MemberSid       = $_.SID.Value
                    MemberClass     = $_.ObjectClass
                    Source          = $_.PrincipalSource
                    PrincipalSource = $_.PrincipalSource
                }) | Out-Null
            }
            $used = $true
        } catch {}

        if (-not $used) {
            try {
                $group = [ADSI]"WinNT://./Administrators,group"
                $members = @($group.psbase.Invoke('Members'))
                foreach ($m in $members) {
                    $name = $m.GetType().InvokeMember('Name','GetProperty',$null,$m,$null)
                    $class = $m.GetType().InvokeMember('Class','GetProperty',$null,$m,$null)
                    $path = $m.GetType().InvokeMember('ADsPath','GetProperty',$null,$m,$null)
                    $sidBytes = $m.GetType().InvokeMember('objectSid','GetProperty',$null,$m,$null)
                    $sid = $null
                    if ($sidBytes) {
                        try { $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes,0)).Value } catch {}
                    }
                    $source = if ($path -like "WinNT://$env:COMPUTERNAME/*") { 'Local' } else { 'ActiveDirectory' }
                    $rows.Add([PSCustomObject]@{
                        MemberName      = $name
                        MemberSid       = $sid
                        MemberClass     = $class
                        Source          = $source
                        PrincipalSource = $source
                    }) | Out-Null
                }
            } catch {}
        }
        $rows
    }
    $datapoints.Add([DataPoint]::new("LocalAdministrators", $scriptblock, $true, $true)) | Out-Null

