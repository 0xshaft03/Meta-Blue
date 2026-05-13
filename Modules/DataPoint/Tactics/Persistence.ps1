# ============================================================
# Persistence data points
# Dot-sourced by Modules/DataPoint/DataPoint.psm1::New-DataPoints
# Relies on $datapoints (ArrayList), [DataPoint], [TechniqueCategory]
# being in scope from the caller.
# ============================================================

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


    # This lil guy needs to be straight rippin from the registry and manually parsing.
    $scriptblock = {Get-WmiObject win32_service | Select-Object -Property PSComputerName,caption,description,pathname,processid,startname,state}
    $datapoints.Add([DataPoint]::new("Services", $scriptblock, $true, "T1543.003", [TechniqueCategory]::Persistence, $true)) | Out-Null


    $scriptblock = {
                    Get-ChildItem -path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"<# -include *.lnk,*.url#> -ErrorAction SilentlyContinue| Select-Object -Property PSComputerName,Length,FullName,Extension,CreationTime,LastAccessTime;
                    Get-ChildItem -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" <#-include *.lnk,*.url#> -ErrorAction SilentlyContinue | Select-Object -Property PSComputerName,Length,FullName,Extension,CreationTime,LastAccessTime
                }
    $datapoints.Add([DataPoint]::new("StartupFolder", $scriptblock, $true, "T1547.001", [TechniqueCategory]::Persistence, $true)) | Out-Null



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


    $scriptblock = {Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'} -ErrorAction SilentlyContinue | Select-Object timecreated,message}
    $datapoints.Add([DataPoint]::new("NewlyRegisteredServices", $scriptblock, $true, "T1543.003", [TechniqueCategory]::Persistence)) | Out-Null


    $scriptblock = {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*' -Name *}
    $datapoints.Add([DataPoint]::new("AppPaths", $scriptblock, $true, "T1546.012", [TechniqueCategory]::Persistence)) | Out-Null


    $scriptblock = {
                    Select-String -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "exe";
                    Select-String -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "dll";
                    Select-String -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Pattern "dll";
                    Select-String -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Pattern "exe";
                    Get-ChildItem -path "C:\Users\" -recurse -include *.lnk -ea SilentlyContinue | Select-String -Pattern "exe";
                    Get-ChildItem -path "C:\Users\" -recurse -include *.lnk -ea SilentlyContinue | Select-String -Pattern "dll";
                }
    $datapoints.Add([DataPoint]::new("ShortcutModifications", $scriptblock, $true, "T1547.009", [TechniqueCategory]::Persistence)) | Out-Null


    # I need to go through the keys and pullout the actual dlls and stuff for the com objects.
    $scriptblock = {Get-ChildItem HKLM:\Software\Classes -ea 0| Where-Object {$_.PSChildName -match '^\w+\.\w+$' -and(Get-ItemProperty "$($_.PSPath)\CLSID" -ea 0)} | Select-Object Name}
    $datapoints.Add([DataPoint]::new("COMObjects", $scriptblock, $true, "T1546.015", [TechniqueCategory]::Persistence)) | Out-Null



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

