enum TechniqueCategory {
    Uncategorized
    Persistence
    Discovery
    DefenseEvasion
    LateralMovement
    CommandAndControl
    PrivilegeEscalation
    CredentialAccess
}
class DataPoint {
    [string]$jobname
    [scriptblock]$scriptblock
    [bool]$isEnabled
    [string]$mitreID
    [TechniqueCategory]$techniqueCategory
    [bool]$isQuick = $false

    DataPoint([string]$jobname, [scriptblock]$scriptblock, [bool]$isEnabled, [string]$mitreID, [TechniqueCategory]$techniqueCategory){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = $mitreID
        $this.techniqueCategory = $techniqueCategory
    }

    DataPoint([string]$jobname, [scriptblock]$scriptblock, [bool]$isEnabled){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = "N/A"
    }

    DataPoint([string]$jobname, [scriptblock]$scriptblock, [bool]$isEnabled, [string]$mitreID, [TechniqueCategory]$techniqueCategory, [bool]$isQuick){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = $mitreID
        $this.techniqueCategory = $techniqueCategory
        $this.isQuick = $isQuick
    }

    DataPoint([string]$jobname, [scriptblock]$scriptblock, [bool]$isEnabled, [bool]$isQuick){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = "N/A"
        $this.isQuick = $isQuick
    }

    enable(){
        $this.isEnabled = $true
    }

    disable(){
        $this.isEnabled = $false
    }

    [string] ToString(){
        return $this.jobname
    }
}

function New-DataPoints(){

    <#
        Right now all of these are just out in the open.
        They need to be added to $datapoints or whatever based off of the commandline.
        so something like: Invoke-Collection -light --> that instantiates a lightweight
        collector class etc.
    #>
    $datapoints = [System.Collections.ArrayList]@()
    $scriptblock = {Get-ItemProperty "HKLM:\System\CurrentControlSet\services\TermService\Parameters\"}
    $datapoints.Add([DataPoint]::new("TerminalServicesDLL", $scriptblock, $true, "T1505.005", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {$(
        if(!(test-path HKU:)){
            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
        }
        $UserInstalls = Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
        foreach($user in $UserInstalls){
            Get-ItemProperty "HKU:\$User\Control Panel\Desktop" -Name ScreenSaveActive;
            Get-ItemProperty "HKU:\$User\Control Panel\Desktop" -Name SCRNSAVE.exe;
            Get-ItemProperty "HKU:\$User\Control Panel\Desktop" -Name ScreenSaverIsSecure;
        }
    )   
    }
    $datapoints.Add([DataPoint]::new("Screensaver", $scriptblock, $true, "T1546.002", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {
        $(Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Select-Object -Property __SERVER, __CLASS, EventNamespace, Name, Query;
        Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object -Property __SERVER, __CLASS, Name;
        Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Select-Object -Property __server, __CLASS, consumer, filter) 
    } 
    $datapoints.Add([DataPoint]::new("WMIEventSubscription", $scriptblock, $true, "T1546.003", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Netsh')}
    $datapoints.Add([DataPoint]::new("NetshHelperDLL", $scriptblock, $true, "T1546.007", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*' | Select-Object DisableExeptionChainValidation,MitigationOptions,PSPath,PSChildName,PSComputerName}
    $datapoints.Add([DataPoint]::new("AccessibilityFeature", $scriptblock, $true, "T1546.008", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue}
    $datapoints.Add([DataPoint]::new("AppCertDLLS", $scriptblock, $true, "T1546.009", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {$(
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\" -name AppInit_DLLs; 
        Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\" -name AppInit_DLLs;
        if(!(test-path HKU:)){
            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
        }
        #This is a handy line that gets all the sids for users from the registry.
        $UserInstalls = Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
        $(foreach ($User in $UserInstalls){
            Get-ItemProperty "HKU:\$User\Software\Microsoft\Windows NT\CurrentVersion\Windows\" -name AppInit_DLLs;
            Get-ItemProperty "HKU:\$User\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\" -name AppInit_DLLs
        });
        $UserInstalls = $null;) | Where-Object {($null -ne $_.DisplayName) -and ($null -ne $_.Publisher)}}
    $datapoints.Add([DataPoint]::new("AppInitDLLS", $scriptblock, $true, "T1546.010", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-ShimEngine/Operational'} -ErrorAction SilentlyContinue | Select-Object Message,TimeCreated,ProcessId,ThreadId}
    $datapoints.Add([DataPoint]::new("ApplicationShimming", $scriptblock, $true, "T1546.011", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" -name Debugger -ErrorAction SilentlyContinue}
    $datapoints.Add([DataPoint]::new("ImageFileExecutionOptions", $scriptblock, $true, "T1546.012", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {
                $results = [System.Collections.ArrayList]@()

                $systemPaths = @(
                    "$pshome\profile.ps1",
                    "$pshome\Microsoft.PowerShell_profile.ps1"
                )
                foreach ($path in $systemPaths) {
                    if (Test-Path $path) {
                        $results.Add((Get-Item $path | Select-Object FullName, Length, LastWriteTime, @{N='Hash';E={(Get-FileHash $path -ea SilentlyContinue).Hash}}, @{N='Username';E={'ALL USERS'}})) | Out-Null
                    }
                }

                foreach ($userDir in (Get-ChildItem C:\Users\* -Directory -ErrorAction SilentlyContinue)) {
                    $userDoc = $userDir.FullName
                    $userName = $userDir.Name
                    $userPaths = @(
                        "$userDoc\Documents\WindowsPowerShell\Profile.ps1",
                        "$userDoc\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
                        "$userDoc\Documents\PowerShell\Profile.ps1",
                        "$userDoc\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
                    )
                    foreach ($path in $userPaths) {
                        if (Test-Path $path) {
                            $results.Add((Get-Item $path | Select-Object FullName, Length, LastWriteTime, @{N='Hash';E={(Get-FileHash $path -ea SilentlyContinue).Hash}}, @{N='Username';E={$userName}})) | Out-Null
                        }
                    }
                }

                $results
            }
    $datapoints.Add([DataPoint]::new("PowershellProfile", $scriptblock, $true, "T1546.013", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {get-itemproperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -name "Authentication Packages"}
    $datapoints.Add([DataPoint]::new("AuthenticationPackage", $scriptblock, $true, "T1547.002", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {Get-ItemProperty HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\* | Select-Object dllname,pspath}
    $datapoints.Add([DataPoint]::new("TimeProviders", $scriptblock, $true, "T1547.003", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {
        $(
            Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -name UserInit, shell
            if(!(test-path HKU:)){
                New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
            }
            #This is a handy line that gets all the sids for users from the registry.
            $UserInstalls = Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
            $(foreach ($User in $UserInstalls){
                Get-ItemProperty "HKU:\$User\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -name UserInit, shell -ErrorAction SilentlyContinue
            });
            $UserInstalls = $null;)

    }
    $datapoints.Add([DataPoint]::new("WinlogonHelperDLL", $scriptblock, $true, "T1547.004", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {
        $(
            Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "Security Packages";
            Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\" -Name "Security Packages" -ErrorAction SilentlyContinue
        )
    }
    $datapoints.Add([DataPoint]::new("SecuritySupportProvider", $scriptblock, $true, "T1547.005", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {
                Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4614';} -ErrorAction SilentlyContinue;
                Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='3033';} -ErrorAction SilentlyContinue;
                Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='3063';} -ErrorAction SilentlyContinue
                }
    $datapoints.Add([DataPoint]::new("LSASSDriverWindowsEvents", $scriptblock, $true, "T1547.008", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\" -Name LsaDbExtPt -ErrorAction SilentlyContinue;
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\" -Name DirectoryServiceExtPt -ErrorAction SilentlyContinue;
        }
    $datapoints.Add([DataPoint]::new("LSASSDriverRegistry", $scriptblock, $true, "T1547.008", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\*" -name driver}
    $datapoints.Add([DataPoint]::new("PortMonitors", $scriptblock, $true, "T1547.010", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {
        $(
            Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Control\Print\Environments\*\Print Processors\*";
            Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors\*"
        )    
    }
    $datapoints.Add([DataPoint]::new("PrintProcessors", $scriptblock, $true, "T1547.012", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {get-itemproperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*" | Select-Object "(default)",componentid,stubpath,pspath}
    $datapoints.Add([DataPoint]::new("ActiveSetup", $scriptblock, $true, "T1547.014", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {
        $processes = Get-WmiObject win32_process
        $processes | ForEach-Object{
            Add-Member -InputObject $_ -Name Hash -Value (Get-FileHash -Path $_.ExecutablePath -ea SilentlyContinue).hash -MemberType NoteProperty 
        } 
        $processes | Select-Object processname,handles,path.pscomputernamename,commandline,creationdate,executablepath,parentprocessid,processid, Hash
    }
    $datapoints.Add([DataPoint]::new("Processes", $scriptblock, $true, "T1057", [TechniqueCategory]::Discovery, $true)) | Out-Null

    $scriptblock = {try {Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -Property TTL,pscomputername,data,entry,name} catch {}}
    $datapoints.Add([DataPoint]::new("DNSCache", $scriptblock, $true, "T1016", [TechniqueCategory]::Discovery, $true)) | Out-Null

    # I don't know how to feel about this one. Seems trash.
    $scriptblock = {Get-ChildItem -Recurse c:\ProgramData\ | Select-Object -Property Fullname,Pscomputername,creationtimeutc,lastaccesstimeutc,attributes} 
    $datapoints.Add([DataPoint]::new("ProgramData", $scriptblock, $true)) | Out-Null

    $scriptblock = {Get-ChildItem -Path C:\Users\* -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object FullName | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ':$DATA'} | Select-Object -Property Filename, PSComputerName, Stream}
    $datapoints.Add([DataPoint]::new("AlternateDataStreams", $scriptblock, $true, "T1564.004", [TechniqueCategory]::DefenseEvasion)) | Out-Null

    # This one is hot garbage as well. 
    $scriptblock = {(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs\')}
    $datapoints.Add([DataPoint]::new("KnownDLLs", $scriptblock, $true)) | Out-Null


    $scriptblock = {
        (Get-ChildItem -path C:\Windows\System32\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid");
        (Get-ChildItem -path C:\Windows\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid")
    }
    $datapoints.Add([DataPoint]::new("DLLSearchOrderHijacking", $scriptblock, $true, "T1574.001", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Bits-Client/Operational'; Id='59'} -ErrorAction SilentlyContinue | Select-Object -Property message,pscomputername,id,logname,processid,userid,timecreated}
    $datapoints.Add([DataPoint]::new("BITSJobsLogs", $scriptblock, $true, "T1197", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {try {Get-BitsTransfer -AllUsers} catch {}}
    $datapoints.Add([DataPoint]::new("BITSTransfer", $scriptblock, $true, "T1197", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {Get-WmiObject win32_bios | Select-Object -Property pscomputername,biosversion,caption,currentlanguage,manufacturer,name,serialnumber}
    $datapoints.Add([DataPoint]::new("SystemFirmware", $scriptblock, $true, "T1542.001", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {
                    $logonScriptsArrayList = [System.Collections.ArrayList]@();

                    New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null;
                    Set-Location HKU: | Out-Null;

                    $SIDS = Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };

                    foreach($SID in $SIDS){
                        $scriptPath = (Get-ItemProperty HKU:\$SID\Environment\ -Name userinitmprlogonscript -ErrorAction SilentlyContinue).userinitmprlogonscript
                        $logonscriptObject = [PSCustomObject]@{
                            SID = $SID
                            ScriptPath = if ($scriptPath) { $scriptPath } else { $null }
                        }
                        $logonScriptsArrayList.Add($logonscriptObject) | Out-Null
                    }
                    $logonScriptsArrayList
                }
    $datapoints.Add([DataPoint]::new("UserInitMprLogonScript", $scriptblock, $true, "T1037.001", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {
                    $(
                        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*; 
                        Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*;
                        if(!(test-path HKU:)){
                            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
                        }
                        #This is a handy line that gets all the sids for users from the registry.
        $UserInstalls = Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
                        $(foreach ($User in $UserInstalls){
                            Get-ItemProperty HKU:\$User\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*;
                            Get-ItemProperty HKU:\$User\SOFTWARE\Wow6432Node\Windows\CurrentVersion\Uninstall\*
                        });
                        $UserInstalls = $null;) | Where-Object {($null -ne $_.DisplayName) -and ($null -ne $_.Publisher)}
                }
    $datapoints.Add([DataPoint]::new("InstalledSoftare", $scriptblock, $true, "T1518", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object PSComputerName,displayName,pathToSignedProductExe,pathToSignedReportingExe}
    $datapoints.Add([DataPoint]::new("AVProduct", $scriptblock, $true, "T1518.001", [TechniqueCategory]::Discovery, $true)) | Out-Null

    # This lil guy needs to be straight rippin from the registry and manually parsing.
    $scriptblock = {Get-WmiObject win32_service | Select-Object -Property PSComputerName,caption,description,pathname,processid,startname,state}
    $datapoints.Add([DataPoint]::new("Services", $scriptblock, $true, "T1543.003", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {try {Get-WindowsOptionalFeature -Online -FeatureName microsoftwindowspowershellv2 | Select-Object -Property PSComputerName,FeatureName,State,LogPath} catch {}}
    $datapoints.Add([DataPoint]::new("PowerShellVersion", $scriptblock, $true, "T1082", [TechniqueCategory]::Discovery)) | Out-Null

    # I don't like this one either.
    $scriptblock = {Get-CimInstance win32_startupcommand | Select-Object -Property PSComputerName,Caption,Command,Description,Location,User}
    $datapoints.Add([DataPoint]::new("Startup", $scriptblock, $true, $true)) | Out-Null

    $scriptblock = {
                    Get-ChildItem -path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"<# -include *.lnk,*.url#> -ErrorAction SilentlyContinue| Select-Object -Property PSComputerName,Length,FullName,Extension,CreationTime,LastAccessTime;
                    Get-ChildItem -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" <#-include *.lnk,*.url#> -ErrorAction SilentlyContinue | Select-Object -Property PSComputerName,Length,FullName,Extension,CreationTime,LastAccessTime
                }
    $datapoints.Add([DataPoint]::new("StartupFolder", $scriptblock, $true, "T1547.001", [TechniqueCategory]::Persistence, $true)) | Out-Null

    # Can we get this from the registry with higher fidelity instead or no?
    $scriptblock = {
        $drivers = Get-WmiObject win32_systemdriver
        $drivers | ForEach-Object {
            Add-Member -InputObject $_ -Name Hash -Value (Get-FileHash -Path $_.pathname -ea SilentlyContinue).hash -MemberType NoteProperty
        } | Select-Object -Property PSComputerName,caption,description,name,pathname,started,startmode,state,hash
        $drivers
    }
    $datapoints.Add([DataPoint]::new("Drivers", $scriptblock, $true, "T1082", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WmiObject win32_environment |Where-Object{$_.name -ne "OneDrive"}}
    $datapoints.Add([DataPoint]::new("EnvironmentVariables", $scriptblock, $true, "T1082", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WmiObject win32_networkadapterconfiguration | Select-Object -Property PSComputerName,Description,IPAddress,IPSubnet,MACAddress,servicename,__server}
    $datapoints.Add([DataPoint]::new("NetworkAdapters", $scriptblock, $true, "T1016", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WmiObject win32_computersystem | Select-Object -Property PSComputerName,domain,manufacturer,model,primaryownername,totalphysicalmemory,username}
    $datapoints.Add([DataPoint]::new("SystemInfo", $scriptblock, $true, "T1082", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WmiObject win32_networkloginprofile}
    $datapoints.Add([DataPoint]::new("Logon", $scriptblock, $true)) | Out-Null

    $scriptblock = {try {Get-NetTcpConnection} catch {}}
    $datapoints.Add([DataPoint]::new("NetworkConnections", $scriptblock, $true, "T1049", [TechniqueCategory]::Discovery, $true)) | Out-Null

    $scriptblock = {try {Get-SmbShare} catch {}}
    $datapoints.Add([DataPoint]::new("SMBShares", $scriptblock, $true, "T1135", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {try {Get-SmbConnection} catch {}}
    $datapoints.Add([DataPoint]::new("SMBConnections", $scriptblock, $true)) | Out-Null


    <#
        We created a class named ScheduledTask and manually parse
        the xml files located at C:\Windows\System32\Tasks\
    #>
    $scriptblock = {
        class ScheduledTask {
            [string]$Author
            [string]$Description
            [string]$URI
            [string]$RunLevel
            [string]$GroupId
            [System.Collections.ArrayList]$Commands
            [System.Collections.ArrayList]$Arguments
            [string]$ActionsContext
        
            ScheduledTask([System.Xml.XmlDocument]$scheduledTask){
                # Manually set field if it is null
                if($null -eq $scheduledTask.Task.RegistrationInfo.Author){
                    $this.Author = "Null"
                }
                else{
                    $this.Author = $scheduledTask.Task.RegistrationInfo.Author
                    $this.Description = $scheduledTask.Task.RegistrationInfo.Description
                    $this.URI = $scheduledTask.Task.RegistrationInfo.URI
                
                }
        
                if($null -eq $scheduledTask.Task.principals.Principal.RunLevel){
                    $this.RunLevel = "Null"
                } else {
                    $this.RunLevel = $scheduledTask.Task.principals.Principal.RunLevel
                }
        
                if($null -eq $scheduledTask.task.Principals.Principal.GroupId){
                    $this.GroupId = 'Null'
                } else {
                    $this.GroupId = $scheduledTask.task.Principals.Principal.GroupId
                }
        
                if($null -eq $scheduledTask.Task.Actions.context){
                    $this.ActionsContext = "Null"
                } else {
                    $this.ActionsContext = $scheduledTask.Task.Actions.Context
                }
        
        
                $this.Commands = [System.Collections.ArrayList]@()
                if($scheduledTask.Task.Actions.Exec.Count -gt 1) {
        
                    foreach($exec in $scheduledTask.task.actions.exec.Command){
                        $this.Commands.Add($exec)
                    }
                
                } elseif ($null -eq $scheduledTask.Task.Actions.Exec.command){
                    $this.Commands.Add("Null")
                } else {
                    $this.Commands.Add($scheduledTask.Task.Actions.Exec.Command)
                }

                $this.Arguments = [System.Collections.ArrayList]@()
                if($scheduledTask.Task.Actions.Exec.Arguments.Count -gt 1) {
        
                    foreach($exec in $scheduledTask.task.actions.exec.arguments){
                        $this.Arguments.Add($exec)
                    }
                
                } elseif ($null -eq $scheduledTask.Task.Actions.Exec.arguments){
                    $this.Arguments.Add("Null")
                } else {
                    $this.Arguments.Add($scheduledTask.Task.Actions.Exec.arguments)
                }
            }
        
        }
        $tasks = (Get-ChildItem -Recurse C:\Windows\system32\Tasks).fullname
        $parsedTasks = [System.Collections.ArrayList]@();
        foreach($task in $tasks){
        
            # Try to get content. Don't know why there is some protected stuff...
            try{
                $fullXML = [xml](Get-Content $task)
            } catch {
                continue;
            }
            
            $schtask = [ScheduledTask]::new($fullXML)
            
        
            $parsedTasks.Add($schtask) | Out-Null
        }
        $parsedTasks
    }
    $datapoints.Add([DataPoint]::new("ScheduledTasks", $scriptblock, $true, "T1053.005", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {Get-ChildItem "C:\Windows\Prefetch"}
    $datapoints.Add([DataPoint]::new("PrefetchListing", $scriptblock, $true)) | Out-Null

    $scriptblock = {Get-WmiObject win32_pnpentity}
    $datapoints.Add([DataPoint]::new("PNPDevices", $scriptblock, $true, "T1120", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WmiObject win32_logicaldisk} 
    $datapoints.Add([DataPoint]::new("LogicalDisks", $scriptblock, $true, "T1083", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WmiObject win32_diskdrive | Select-Object pscomputername,DeviceID,Capabilities,CapabilityDescriptions,Caption,FirmwareRevision,Model,PNPDeviceID,SerialNumber}
    $datapoints.Add([DataPoint]::new("DiskDrives", $scriptblock, $true, "T1083", [TechniqueCategory]::Discovery)) | Out-Null

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

    $scriptblock = {Get-ChildItem -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | Get-AuthenticodeSignature | Where-Object {$_.status -ne 'Valid'}}
    $datapoints.Add([DataPoint]::new("UnsignedDrivers", $scriptblock, $true, "T1553", [TechniqueCategory]::DefenseEvasion)) | Out-Null

    $scriptblock = {Get-HotFix -ErrorAction SilentlyContinue}
    $datapoints.Add([DataPoint]::new("Hotfixes", $scriptblock, $true, "T1082", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {try {Get-NetNeighbor -ErrorAction SilentlyContinue} catch {}}
    $datapoints.Add([DataPoint]::new("ArpCache", $scriptblock, $true, "T1018", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'} -ErrorAction SilentlyContinue | Select-Object timecreated,message}
    $datapoints.Add([DataPoint]::new("NewlyRegisteredServices", $scriptblock, $true, "T1543.003", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*' -Name *}
    $datapoints.Add([DataPoint]::new("AppPaths", $scriptblock, $true, "T1546.012", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {
                    if(!(test-path HKU:)){
                        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
                    }
                    $UserInstalls = Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
                    foreach($user in $UserInstalls){
                        if(test-path HKU\$user\Software\Classes\ms-settings\shell\open\command){
                            Get-ItemProperty HKU:\$User\SOFTWARE\classes\ms-settings-shell\open\command -ErrorAction SilentlyContinue
                        }
                    }
                
                }
    $datapoints.Add([DataPoint]::new("UACBypassFodHelper", $scriptblock, $true, "T1548.002", [TechniqueCategory]::PrivilegeEscalation)) | Out-Null

    $scriptblock = {
                    $netshresults = (netsh wlan show networks mode=bssid);
                    $networksarraylist = [System.Collections.ArrayList]@();
                    if((($netshresults.gettype()).basetype.name -eq "Array") -and ($netshresults.count -gt 10)){
                        for($i = 4; $i -lt ($netshresults.Length); $i+=11){
                            $WLANobject = [PSCustomObject]@{
                                SSID = ""
                                NetworkType = ""
                                Authentication = ""
                                Encryption = ""
                                BSSID = ""
                                SignalPercentage = ""
                                RadioType = ""
                                Channel = ""
                                BasicRates = ""
                                OtherRates = ""
                            }
                            for($j=0;$j -lt 10;$j++){
                                $currentline = $netshresults[$i + $j]
                                if($currentline -like "SSID*"){
                                    $currentline = $currentline.substring(9)
                                    if($currentline.startswith(" ")){

                                        $currentline = $currentline.substring(1)
                                        $WLANobject.SSID = $currentline

                                    }else{

                                        $WLANobject.SSID = $currentline

                                    }

                                }elseif($currentline -like "*Network type*"){

                                    $WLANobject.NetworkType = $currentline.Substring(30)

                                }elseif($currentline -like "*Authentication*"){

                                    $WLANobject.Authentication = $currentline.Substring(30)

                                }elseif($currentline -like "*Encryption*"){

                                    $WLANobject.Encryption = $currentline.Substring(30)

                                }elseif($currentline -like "*BSSID 1*"){

                                    $WLANobject.BSSID = $currentline.Substring(30)

                                }elseif($currentline -like "*Signal*"){

                                    $WLANobject.SignalPercentage = $currentline.Substring(30)

                                }elseif($currentline -like "*Radio type*"){
            
                                    $WLANobject.RadioType = $currentline.Substring(30)
            
                                }elseif($currentline -like "*Channel*"){
                
                                    $WLANobject.Channel = $currentline.Substring(30)
                                }elseif($currentline -like "*Basic rates*"){
            
                                    $WLANobject.BasicRates = $currentline.Substring(30)

                                }elseif($currentline -like "*Other rates*"){
                
                                    $WLANobject.OtherRates = $currentline.Substring(30)

                                }
                            }

                            $networksarraylist.Add($WLANobject) | Out-Null
                        }
                        $networksarraylist
                    }
                                    
                }
    $datapoints.Add([DataPoint]::new("VisibleWirelessNetworks", $scriptblock, $true, "T1016", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {
                    $netshresults = (netsh wlan show profiles);
                    $networksarraylist = [System.Collections.ArrayList]@();
                    if((($netshresults.gettype()).basetype.name -eq "Array") -and (!($netshresults[9].contains("<None>")))){
                        for($i = 9;$i -lt ($netshresults.Length -1);$i++){
                            $WLANProfileObject = [PSCustomObject]@{
                                ProfileName = ""
                                Type = ""
                                ConnectionMode = ""
                            }
                            $WLANProfileObject.profilename = $netshresults[$i].Substring(27)
                            $networksarraylist.Add($WLANProfileObject) | out-null
                            $individualProfile = (netsh wlan show profiles name="$($WLANProfileObject.ProfileName)")
                            $WLANProfileObject.type = $individualProfile[9].Substring(29)
                            $WLANProfileObject.connectionmode = $individualProfile[12].substring(29)
                        }
                    }
                    $networksarraylist
                
                }
    $datapoints.Add([DataPoint]::new("HistoricalWiFiConnections", $scriptblock, $true, "T1016", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message}
    $datapoints.Add([DataPoint]::new("HistoricalFirewallChanges", $scriptblock, $true, "T1562.004", [TechniqueCategory]::DefenseEvasion)) | Out-Null

    $scriptblock = {
                    $portProxies = [System.Collections.ArrayList]@();
                    $portProxyRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy'
                    $directions = @('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')
                    foreach ($direction in $directions) {
                        $subkey = Join-Path $portProxyRoot "$direction\tcp"
                        if (-not (Test-Path -LiteralPath $subkey)) { continue }

                        try {
                            $props = Get-ItemProperty -LiteralPath $subkey -ErrorAction Stop
                        } catch {
                            continue
                        }

                        $props.PSObject.Properties |
                            Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' } |
                            ForEach-Object {
                                $listen  = $_.Name  -split '/', 2
                                $connect = $_.Value -split '/', 2

                                $portProxies.Add([PSCustomObject]@{
                                    Direction       = $direction
                                    Protocol        = 'tcp'
                                    ListenAddress   = $listen[0]
                                    ListenPort      = $listen[1]
                                    ConnectAddress  = $connect[0]
                                    ConnectPort     = $connect[1]
                                    RegistryPath    = $subkey
                                }) | Out-Null
                            }
                    } $portProxies
                }
    $datapoints.Add([DataPoint]::new("PortProxies", $scriptblock, $true, "T1090.001", [TechniqueCategory]::CommandAndControl)) | Out-Null

    $scriptblock = {(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*\NonPackaged\*)}
    $datapoints.Add([DataPoint]::new("CapabilityAccessManager", $scriptblock, $true)) | Out-Null

    $scriptblock = {try {Get-DnsClientServerAddress} catch {}}
    $datapoints.Add([DataPoint]::new("DnsClientServerAddress", $scriptblock, $true, "T1016", [TechniqueCategory]::Discovery)) | Out-Null

    $scriptblock = {
                    Select-String -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "exe";
                    Select-String -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "dll";
                    Select-String -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Pattern "dll";
                    Select-String -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Pattern "exe";
                    Get-ChildItem -path "C:\Users\" -recurse -include *.lnk -ea SilentlyContinue | Select-String -Pattern "exe";
                    Get-ChildItem -path "C:\Users\" -recurse -include *.lnk -ea SilentlyContinue | Select-String -Pattern "dll";
                }
    $datapoints.Add([DataPoint]::new("ShortcutModifications", $scriptblock, $true, "T1547.009", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {(Get-Process -Module -ea 0).FileName|Where-Object{$_ -notlike "*system32*"}|Select-String "Appdata","ProgramData","Temp","Users","public"|Get-unique|ForEach-Object{Get-FileHash -Path $_}}
    $datapoints.Add([DataPoint]::new("DLLsInTempDirs", $scriptblock, $true)) | Out-Null

    $scriptblock = {Get-WinEvent -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -ErrorAction SilentlyContinue | Select-Object -exp Properties | Where-Object {$_.Value -like '*.*.*.*' } | Sort-Object Value -u }
    $datapoints.Add([DataPoint]::new("RDPHistoricallyConnectedIPs", $scriptblock, $true, "T1021.001", [TechniqueCategory]::LateralMovement)) | Out-Null

    $scriptblock = {try {Get-MpComputerStatus} catch {}}
    $datapoints.Add([DataPoint]::new("MpComputerStatus", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion)) | Out-Null

    $scriptblock = {try {Get-MpPreference} catch {}}
    $datapoints.Add([DataPoint]::new("MpPreference", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion)) | Out-Null

    # I need to go through the keys and pullout the actual dlls and stuff for the com objects.
    $scriptblock = {Get-ChildItem HKLM:\Software\Classes -ea 0| Where-Object {$_.PSChildName -match '^\w+\.\w+$' -and(Get-ItemProperty "$($_.PSPath)\CLSID" -ea 0)} | Select-Object Name}
    $datapoints.Add([DataPoint]::new("COMObjects", $scriptblock, $true, "T1546.015", [TechniqueCategory]::Persistence)) | Out-Null

    $scriptblock = {Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'} -ErrorAction SilentlyContinue | Where-Object{$_.leveldisplayname -eq 'Error'} | Select-Object Message, id, processid, timecreated}
    $datapoints.Add([DataPoint]::new("CodeIntegrityLogs", $scriptblock, $true, "T1553.006", [TechniqueCategory]::DefenseEvasion)) | Out-Null

    $scriptblock = {Get-WinEvent -FilterHashtable @{LogName='Security'} -ErrorAction SilentlyContinue | Where-Object{$_.id -eq 1102} | Select-Object TimeCreated, Id, Message}
    $datapoints.Add([DataPoint]::new("SecurityLogCleared", $scriptblock, $true, "T1070.001", [TechniqueCategory]::DefenseEvasion, $true)) | Out-Null

    $scriptblock = {
        $(
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\*" -name Dll,FuncName;
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\*" -name Dll,FuncName;
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy\*" -name '$DLL' , '$Function';
            Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\*" -name Dll,FuncName;
            Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\*" -name Dll,FuncName;
            Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust\FinalPolicy\*" -name '$DLL', '$Function'
        )
    }
    $datapoints.Add([DataPoint]::new("SIPandTrustProviderHijacking", $scriptblock, $true, "T1553.003", [TechniqueCategory]::DefenseEvasion)) | Out-Null

    $scriptblock = {
                    $regexa = '.+Domain="(.+)",Name="(.+)"$';
                    $regexd = '.+LogonId="(\d+)"$';
                    $logon_users = @(Get-WmiObject win32_loggedonuser -ComputerName 'localhost');
                    if(($logon_users -ne "") -and ($null -ne $logon_users)){
                        $session_user = @{};
                        $logon_users |ForEach-Object {
                            $_.antecedent -match $regexa > $nul;
                            $username = $matches[1] + "\" + $matches[2];
                            $_.dependent -match $regexd > $nul;
                            $session = $matches[1];
                            $sessionHex = ('0x{0:X}' -f [long]$session);
                            $session_user[$sessionHex] += $username ;
                        };

                        $klistsarraylist = [System.Collections.ArrayList]@();

                        foreach($i in $session_user.keys){

                            $item = $session_user.item($i).split("\")[1]    

                            $klistoutput = klist -li $i

                            if(($null -ne $klistsarraylist) -and ($klistoutput.count -gt 7)){
            
                                $numofrecords = $klistoutput[4].split("(")[1]
                                $numofrecords = $numofrecords.Substring(0,$numofrecords.Length-1)        

                                for($j = 0; $j -lt ($numofrecords);$j++){
                                    $klistObject = [PSCustomObject]@{
                                                    Session = ""
                                                    Username = ""
                                                    Client = ""
                                                    Server = ""
                                                    KerbTicketEncryptionType = ""
                                                    StartTime = ""
                                                    EndTime = ""
                                                    RenewTime = ""
                                                    SessionKeyType = ""
                                                    CacheFlags = ""
                                                    KdcCalled = ""
                                                }

                                        $klistObject.session = $i
                                        $klistObject.username = $item
                                        $klistObject.client = $klistoutput[6 + ($j * 11)].substring(12)
                                        $klistobject.server = $klistoutput[7 + ($j * 11)].substring(9)
                                        $klistobject.KerbTicketEncryptionType = $klistoutput[8 + ($j * 11)].substring(29)
                                        $klistobject.StartTime = $klistoutput[10 + ($j * 11)].substring(13)
                                        $klistobject.EndTime = $klistoutput[11 + ($j * 11)].substring(13)
                                        $klistobject.Renewtime = $klistoutput[12 + ($j * 11)].substring(13)
                                        $klistobject.sessionkeytype = $klistoutput[13 + ($j * 11)].substring(13)
                                        $klistobject.cacheflags = $klistoutput[14 + ($j * 11)].substring(14)
                                        $klistobject.kdccalled = $klistoutput[15 + ($j * 11)].substring(13)

                                        $klistsarraylist.Add($klistObject) | out-null
                                }
                            }else{
                                continue
                            }
                        }
                    }
                    $klistsarraylist

                    }
    $datapoints.Add([DataPoint]::new("PassTheHash", $scriptblock, $true, "T1550.002", [TechniqueCategory]::CredentialAccess)) | Out-Null

    $scriptblock = {get-childitem \\.\pipe\ | Select-Object fullname}
    $datapoints.Add([DataPoint]::new("NamedPipes", $scriptblock, $true)) | Out-Null


    <#
        TODO: Dive into HKU:SID for run keys instead of just HKCU
        Im also being lazy here. i need to break these out into their separate datapoints.
    #>
    $scriptblock = {  
                    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
                    $HKCUS = (Get-Item HKU:\*).name
                    $registry = [PSCustomObject]@{
                        
                        HKLMRun = [String]($(if(Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\'){Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\'}))
                        HKLMRun32 = [String]($(if(Test-Path 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\'){  Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\'}))
                        HKLMRunOnce = [String]($(if(Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\'){  Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\'}))
                        HKLMRunOnce32 = [String]($(if(Test-Path 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\'){  Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\'}))
                        HKLMRunOnceEx = [String]($(if(Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\'){  Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\'}))
                        HKLMPolicyRun = [String]($(if(Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'){  Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'}))
                        HKLMBootExecute = [string]($(if(Test-Path "HKLM:\system\CurrentControlSet\Control\Session Manager\"){ Get-ItemProperty "HKLM:\system\CurrentControlSet\Control\Session Manager\"}))
                        HKLMRunServicesOnce = [string]($(if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\"){ Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\"}))
                        HKLMRunServices = [string]($(if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices\"){ Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices\"}))
                        HKLMShellFolders = [string]($(if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\"){ Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\"}))
                        HKLMUserShellFolders = [string]($(if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\"){ Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\"}))
                        <#
                        Manufacturer = [String](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation\' -ErrorAction SilentlyContinue).manufacturer
                        ShimCustom = [String](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom' -ErrorAction SilentlyContinue)
                        Powershellv2 = if((test-path HKLM:\SOFTWARE\Microsoft\PowerShell\1\powershellengine\)){$true}else{$false}
                        BootShell = [string](Get-ItemProperty "HKLM:\system\CurrentControlSet\Control\Session Manager\" -name bootshell).bootshell
                        
                        NetworkList = [String]((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\UnManaged\*' -ErrorAction SilentlyContinue).dnssuffix)
                        #>
                    }
                    foreach($sid in $hkcus){
                        $sidy = $sid.replace("HKEY_USERS","HKU:");
                        $path= $sidy+"\software\microsoft\windows\currentversion\run\";
                        if(test-path $path){
                            Add-Member -InputObject $registry -MemberType NoteProperty -Name $path -Value $(Get-ItemProperty -LiteralPath $path)
                        }
                        $path= $sidy+"\software\microsoft\windows\currentversion\runonce\";
                        if(test-path $path){
                            Add-Member -InputObject $registry -MemberType NoteProperty -Name $path -Value $(Get-ItemProperty -LiteralPath $path)
                        }
                        $path=$sidy+"\Software\Microsoft\Windows NT\CurrentVersion\Windows\"
                        if(test-path $path){
                            Add-Member -InputObject $registry -MemberType NoteProperty -Name $path -Value $(Get-ItemProperty -LiteralPath $path)
                        }
                        $path=$sidy+"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\"
                        if(test-path $path){
                            Add-Member -InputObject $registry -MemberType NoteProperty -Name $path -Value $(Get-ItemProperty -LiteralPath $path)
                        }
                        $path=$sidy+"\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\"
                        if(test-path $path){
                            Add-Member -InputObject $registry -MemberType NoteProperty -Name $path -Value $(Get-ItemProperty -LiteralPath $path)
                        }
                        $path=$sidy+"\Software\Microsoft\Windows\CurrentVersion\RunServices\"
                        if(test-path $path){
                            Add-Member -InputObject $registry -MemberType NoteProperty -Name $path -Value $(Get-ItemProperty -LiteralPath $path)
                        }
                        $path=$sidy+"\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\"
                        if(test-path $path){
                            Add-Member -InputObject $registry -MemberType NoteProperty -Name $path -Value $(Get-ItemProperty -LiteralPath $path)
                        }
                        $path=$sidy+"\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\"
                        if(test-path $path){
                            Add-Member -InputObject $registry -MemberType NoteProperty -Name $path -Value $(Get-ItemProperty -LiteralPath $path)
                        }
                    }
                
                    $registry
            
                }
    $datapoints.Add([DataPoint]::new("RegistryRunKeys", $scriptblock, $true, "T1547.001", [TechniqueCategory]::Persistence, $true)) | Out-Null

    $scriptblock = {try {Get-MpPreference | Select-Object -ExpandProperty ExclusionPath} catch {}}
    $datapoints.Add([DataPoint]::new("DefenderExclusionPath", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion, $true)) | Out-Null

    $scriptblock = {try {Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress} catch {}}
    $datapoints.Add([DataPoint]::new("DefenderExclusionIpAddress", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion, $true)) | Out-Null

    $scriptblock = {try {Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension} catch {}}
    $datapoints.Add([DataPoint]::new("DefenderExclusionExtension", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion, $true)) | Out-Null

    # ============================================================
    # Phase 1: Privilege Escalation Primitives (WinPEAS-inspired)
    # Surface attack-surface inventory for cross-host LFO stacking.
    # ============================================================

    <#
        AlwaysInstallElevated: when both HKLM and HKCU values are 1, any MSI
        installs as SYSTEM. Almost always 0/absent across a fleet; the rare
        host with it enabled is a giant priv-esc primitive.
        Emits one HKLM row + one per HKU SID.
    #>
    $scriptblock = {
        $rows = [System.Collections.ArrayList]@()
        try {
            $hklm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
            $rows.Add([PSCustomObject]@{
                Scope = 'HKLM'
                Sid = $null
                Username = $null
                AlwaysInstallElevated = if ($null -ne $hklm) { $hklm.AlwaysInstallElevated } else { $null }
            }) | Out-Null
        } catch {}

        try {
            if (-not (Test-Path HKU:)) {
                New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
            }
            $sids = Get-ChildItem -Path HKU: -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } |
                ForEach-Object { $_.PSChildName }
            foreach ($sid in $sids) {
                $username = $null
                try {
                    $username = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                } catch {}
                $val = $null
                try {
                    $reg = Get-ItemProperty -Path "HKU:\$sid\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
                    if ($null -ne $reg) { $val = $reg.AlwaysInstallElevated }
                } catch {}
                $rows.Add([PSCustomObject]@{
                    Scope = 'HKU'
                    Sid = $sid
                    Username = $username
                    AlwaysInstallElevated = $val
                }) | Out-Null
            }
        } catch {}
        $rows
    }
    $datapoints.Add([DataPoint]::new("AlwaysInstallElevated", $scriptblock, $true, "T1548", [TechniqueCategory]::PrivilegeEscalation, $true)) | Out-Null

    <#
        AutologonCredentials: emits booleans for the presence of plaintext
        credentials in Winlogon registry. NEVER emits the password values.
    #>
    $scriptblock = {
        try {
            $winlogon = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                AutoAdminLogon            = $winlogon.AutoAdminLogon
                DefaultUserName           = $winlogon.DefaultUserName
                DefaultDomainName         = $winlogon.DefaultDomainName
                DefaultPasswordPresent    = [bool]($winlogon.PSObject.Properties.Name -contains 'DefaultPassword' -and $winlogon.DefaultPassword)
                AltDefaultPasswordPresent = [bool]($winlogon.PSObject.Properties.Name -contains 'AltDefaultPassword' -and $winlogon.AltDefaultPassword)
                ForceAutoLogon            = $winlogon.ForceAutoLogon
            }
        } catch {}
    }
    $datapoints.Add([DataPoint]::new("AutologonCredentials", $scriptblock, $true, "T1078", [TechniqueCategory]::PrivilegeEscalation, $true)) | Out-Null

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

    <#
        UnquotedServicePaths: services whose ImagePath contains spaces and
        isn't quoted. Emits one row per service, with semicolon-joined list
        of parent directories writable by Users/Authenticated Users/Everyone.
        Empty WritableSegments is still emitted to support negative-LFO.
    #>
    $scriptblock = {
        $nonAdminPrincipals = @(
            'BUILTIN\Users',
            'NT AUTHORITY\Authenticated Users',
            'Everyone',
            'NT AUTHORITY\INTERACTIVE'
        )
        $rows = [System.Collections.ArrayList]@()
        try {
            $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue
            foreach ($svc in $services) {
                $path = $svc.PathName
                if ([string]::IsNullOrWhiteSpace($path)) { continue }
                # Strip trailing args by finding the executable; for unquoted-check we look at the raw PathName.
                if ($path.StartsWith('"')) { continue }
                # Trim leading whitespace
                $raw = $path.TrimStart()
                # Stop at the first .exe / .dll / .sys to isolate the binary portion (best-effort)
                $binary = $raw
                if ($raw -match '^(?<bin>[^"]+?\.(exe|dll|sys|com|bat|cmd))(\s|$)') {
                    $binary = $matches['bin']
                } else {
                    # No extension match; split on first space anyway
                    $binary = $raw.Split(' ')[0]
                }
                if ($binary -notmatch ' ') { continue }

                # Walk the unquoted binary path segment by segment
                $segments = $binary.Split(' ')
                $candidatePaths = @()
                $accum = ''
                for ($i = 0; $i -lt $segments.Length - 1; $i++) {
                    if ($i -eq 0) { $accum = $segments[$i] } else { $accum = $accum + ' ' + $segments[$i] }
                    # Parent dir of candidate exe
                    $candidate = Split-Path -Parent ($accum + '.exe') -ErrorAction SilentlyContinue
                    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
                        $candidatePaths += $candidate
                    }
                }
                $writable = [System.Collections.ArrayList]@()
                foreach ($cp in ($candidatePaths | Select-Object -Unique)) {
                    try {
                        $acl = Get-Acl -LiteralPath $cp -ErrorAction SilentlyContinue
                        if (-not $acl) { continue }
                        foreach ($ace in $acl.Access) {
                            if ($ace.AccessControlType -ne 'Allow') { continue }
                            if ($nonAdminPrincipals -contains $ace.IdentityReference.Value) {
                                if (($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -or
                                    ($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData) -or
                                    ($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -or
                                    ($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -or
                                    ($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::CreateFiles)) {
                                    if (-not $writable.Contains($cp)) { $writable.Add($cp) | Out-Null }
                                    break
                                }
                            }
                        }
                    } catch {}
                }
                $rows.Add([PSCustomObject]@{
                    ServiceName          = $svc.Name
                    DisplayName          = $svc.DisplayName
                    BinaryPath           = $svc.PathName
                    Account              = $svc.StartName
                    StartMode            = $svc.StartMode
                    FirstWritableSegment = if ($writable.Count -gt 0) { $writable[0] } else { $null }
                    AllWritableSegments  = if ($writable.Count -gt 0) { ($writable -join ';') } else { $null }
                }) | Out-Null
            }
        } catch {}
        $rows
    }
    $datapoints.Add([DataPoint]::new("UnquotedServicePaths", $scriptblock, $true, "T1574.009", [TechniqueCategory]::PrivilegeEscalation, $true)) | Out-Null

    <#
        WeakServiceACLs: per-service DACL flattened to one row per ACE.
        No filtering -- emit Admins/SYSTEM/TrustedInstaller too. LFO finds
        the host where a non-admin SID has SERVICE_CHANGE_CONFIG etc.
    #>
    $scriptblock = {
        $rows = [System.Collections.ArrayList]@()
        try {
            $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue
            foreach ($svc in $services) {
                $sddl = $null
                try {
                    $sdshow = & sc.exe sdshow $svc.Name 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        $sddl = ($sdshow | Where-Object { $_ -match '^[DOSGA]:' } | Select-Object -First 1)
                    }
                } catch {}
                if ([string]::IsNullOrWhiteSpace($sddl)) { continue }
                try {
                    $parsed = ConvertFrom-SddlString -Sddl $sddl -ErrorAction SilentlyContinue
                    if (-not $parsed) { continue }
                    for ($i = 0; $i -lt $parsed.DiscretionaryAcl.Count; $i++) {
                        $ace = $parsed.DiscretionaryAcl[$i]
                        # Format: "DOMAIN\Name: AccessType (Right1, Right2)"
                        if ($ace -match '^(?<principal>[^:]+):\s+(?<type>Access(?:Allowed|Denied))\s+\((?<rights>.+)\)\s*$') {
                            $principal = $matches['principal']
                            $aceType = $matches['type']
                            $rights = $matches['rights']
                            $sid = $null
                            try { $sid = (New-Object System.Security.Principal.NTAccount($principal)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
                            foreach ($r in ($rights -split ',\s*')) {
                                $rows.Add([PSCustomObject]@{
                                    ServiceName  = $svc.Name
                                    Principal    = $principal
                                    PrincipalSid = $sid
                                    AccessRight  = $r.Trim()
                                    AceType      = $aceType
                                    IsInherited  = $null
                                }) | Out-Null
                            }
                        }
                    }
                } catch {}
            }
        } catch {}
        $rows
    }
    $datapoints.Add([DataPoint]::new("WeakServiceACLs", $scriptblock, $true, "T1543.003", [TechniqueCategory]::PrivilegeEscalation)) | Out-Null

    <#
        WeakServiceBinaryACLs: ACL of each service-backing binary flattened
        to one row per {Service, ACE}. Duplicate binaries across services
        produce multiple rows by design (better per-service LFO).
    #>
    $scriptblock = {
        $rows = [System.Collections.ArrayList]@()
        try {
            $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue
            foreach ($svc in $services) {
                $path = $svc.PathName
                if ([string]::IsNullOrWhiteSpace($path)) { continue }
                # Extract binary
                $raw = $path.Trim()
                if ($raw.StartsWith('"')) {
                    $endQuote = $raw.IndexOf('"', 1)
                    if ($endQuote -gt 0) { $binary = $raw.Substring(1, $endQuote - 1) } else { continue }
                } else {
                    if ($raw -match '^(?<bin>[^"]+?\.(exe|dll|sys|com|bat|cmd))(\s|$)') {
                        $binary = $matches['bin']
                    } else {
                        $binary = $raw.Split(' ')[0]
                    }
                }
                # Expand env vars
                $binary = [Environment]::ExpandEnvironmentVariables($binary)
                if (-not (Test-Path -LiteralPath $binary -ErrorAction SilentlyContinue)) { continue }
                try {
                    $acl = Get-Acl -LiteralPath $binary -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }
                    foreach ($ace in $acl.Access) {
                        $sid = $null
                        try { $sid = (New-Object System.Security.Principal.NTAccount($ace.IdentityReference.Value)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
                        $rows.Add([PSCustomObject]@{
                            ServiceName       = $svc.Name
                            BinaryPath        = $binary
                            Principal         = $ace.IdentityReference.Value
                            PrincipalSid      = $sid
                            FileSystemRights  = [string]$ace.FileSystemRights
                            AccessControlType = [string]$ace.AccessControlType
                            IsInherited       = $ace.IsInherited
                        }) | Out-Null
                    }
                } catch {}
            }
        } catch {}
        $rows
    }
    $datapoints.Add([DataPoint]::new("WeakServiceBinaryACLs", $scriptblock, $true, "T1574", [TechniqueCategory]::PrivilegeEscalation)) | Out-Null

    <#
        WeakRegistryServiceACLs: ACL on each HKLM service registry subkey
        flattened to one row per ACE.
    #>
    $scriptblock = {
        $rows = [System.Collections.ArrayList]@()
        try {
            $svcKeys = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue
            foreach ($key in $svcKeys) {
                try {
                    # Note: Get-Acl on registry requires -Path (not -LiteralPath); -LiteralPath silently returns $null
                    $acl = Get-Acl -Path $key.PSPath -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }
                    foreach ($ace in $acl.Access) {
                        $sid = $null
                        try { $sid = (New-Object System.Security.Principal.NTAccount($ace.IdentityReference.Value)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
                        $rows.Add([PSCustomObject]@{
                            ServiceRegPath    = $key.Name
                            Principal         = $ace.IdentityReference.Value
                            PrincipalSid      = $sid
                            RegistryRights    = [string]$ace.RegistryRights
                            AccessControlType = [string]$ace.AccessControlType
                            IsInherited       = $ace.IsInherited
                        }) | Out-Null
                    }
                } catch {}
            }
        } catch {}
        $rows
    }
    $datapoints.Add([DataPoint]::new("WeakRegistryServiceACLs", $scriptblock, $true, "T1574", [TechniqueCategory]::PrivilegeEscalation)) | Out-Null

    <#
        WritablePathDirectories: ACL on each entry of System and per-user
        PATH, flattened to one row per ACE. Lets LFO surface the host with
        a non-admin-writable directory in PATH (DLL planting primitive).
    #>
    $scriptblock = {
        $rows = [System.Collections.ArrayList]@()

        function _EmitAclRows($dir, $scope, $sid, $username, $list) {
            try {
                $acl = Get-Acl -LiteralPath $dir -ErrorAction SilentlyContinue
                if (-not $acl) { return }
                foreach ($ace in $acl.Access) {
                    $aceSid = $null
                    try { $aceSid = (New-Object System.Security.Principal.NTAccount($ace.IdentityReference.Value)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
                    $list.Add([PSCustomObject]@{
                        Scope            = $scope
                        Sid              = $sid
                        Username         = $username
                        PathEntry        = $dir
                        Principal        = $ace.IdentityReference.Value
                        PrincipalSid     = $aceSid
                        FileSystemRights = [string]$ace.FileSystemRights
                        IsInherited      = $ace.IsInherited
                    }) | Out-Null
                }
            } catch {}
        }

        # System PATH
        try {
            $sysPath = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path -ErrorAction SilentlyContinue).Path
            if ($sysPath) {
                foreach ($entry in ($sysPath -split ';' | Where-Object { $_ })) {
                    $expanded = [Environment]::ExpandEnvironmentVariables($entry)
                    if (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue) {
                        _EmitAclRows $expanded 'System' $null $null $rows
                    }
                }
            }
        } catch {}

        # Per-user PATH
        try {
            if (-not (Test-Path HKU:)) {
                New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
            }
            $sids = Get-ChildItem -Path HKU: -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } |
                ForEach-Object { $_.PSChildName }
            foreach ($sid in $sids) {
                $username = $null
                try {
                    $username = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                } catch {}
                try {
                    $userPath = (Get-ItemProperty -Path "HKU:\$sid\Environment" -Name Path -ErrorAction SilentlyContinue).Path
                } catch { $userPath = $null }
                if ($userPath) {
                    foreach ($entry in ($userPath -split ';' | Where-Object { $_ })) {
                        $expanded = [Environment]::ExpandEnvironmentVariables($entry)
                        if (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue) {
                            _EmitAclRows $expanded 'User' $sid $username $rows
                        }
                    }
                }
            }
        } catch {}

        $rows
    }
    $datapoints.Add([DataPoint]::new("WritablePathDirectories", $scriptblock, $true, "T1574.007", [TechniqueCategory]::PrivilegeEscalation)) | Out-Null

    return $datapoints
}