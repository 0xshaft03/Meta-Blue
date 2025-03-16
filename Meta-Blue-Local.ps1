<#
.SYNOPSIS  
    

.EXAMPLE
    .\Meta-Blue.ps1

.NOTES  
    File Name      : Meta-Blue-Local.ps1
    Version        : v.2
    Author         : newhandle
    Prerequisite   : PowerShell
    Created        : 26 Oct 24
#>
using module .\Modules\DataPoint.psm1
$timestamp = (get-date).Tostring("yyyy_MM_dd_hh_mm_ss")

<#
    Define the root directory for results. CHANGE THIS TO BE WHEREVER YOU WANT.
#>
$global:metaBlueFolder = "C:\Meta-Blue\"
$global:outFolder = "$metaBlueFolder\$timestamp"
$global:rawFolder = "$outFolder\raw"
$global:anomaliesFolder = "$outFolder\Anomalies"
$global:nodeList = [System.Collections.ArrayList]@()
$datapoints = [System.Collections.ArrayList]@()



function Load-UserHives{
    # Get a list of NTUSER.DATs to load
    $ntusers= Get-ChildItem c:\users | ForEach-Object{if(test-path "$($_.fullname)\NTUSER.DAT"){"$($_.fullname)\NTUSER.DAT"}}
    
    # Attempt to load NTUSER.DATs
    foreach($user in $ntusers){
        & reg load HKU\$($user.split('\')[2]) $user
    }
}

function Create-OutputFolders{
    if(!(test-path $outFolder)){
        new-item -itemtype directory -path $outFolder -Force
    }
    if(!(test-path $rawFolder)){
        new-item -itemtype directory -path $rawFolder -Force
    }
    if(!(test-path $anomaliesFolder)){
        new-item -itemtype directory -path $anomaliesFolder -Force
    }
}

<#
    Right now all of these are just out in the open.
    They need to be added to $datapoints or whatever based off of the commandline.
    so something like: Invoke-Collection -light --> that instantiates a lightweight
    collector class etc.
#>
$scriptblock = {Get-ItemProperty "HKLM:\System\CurrentControlSet\services\TermService\Parameters\"}
$datapoints.Add([DataPoint]::new("TerminalServicesDLL", $scriptblock, $true, "T1505.005", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {$(
    if(!(test-path HKU:)){
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
    }
    $UserInstalls += Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
    foreach($user in $UserInstalls){
        Get-ItemProperty "HKU:\$User\Control Panel\Desktop" -Name ScreenSaveActive;
        Get-ItemProperty "HKU:\$User\Control Panel\Desktop" -Name SCRNSAVE.exe;
        Get-ItemProperty "HKU:\$User\Control Panel\Desktop" -Name ScreenSaverIsSecure;
    }
)   
}
$datapoints.Add([DataPoint]::new("Screensaver", $scriptblock, $true, "T1546.002", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
    $(Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Select-Object -Property __SERVER, __CLASS, EventNamespace, Name, Query;
    Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object -Property __SERVER, __CLASS, Name;
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Select-Object -Property __server, __CLASS, consumer, filter) 
} 
$datapoints.Add([DataPoint]::new("WMIEventSubscription", $scriptblock, $true, "T1546.003", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Netsh')}
$datapoints.Add([DataPoint]::new("NetshHelperDLL", $scriptblock, $true, "T1546.007", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*' | Select-Object DisableExeptionChainValidation,MitigationOptions,PSPath,PSChildName,PSComputerName}
$datapoints.Add([DataPoint]::new("AccessibilityFeature", $scriptblock, $true, "T1546.008", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\appcertdlls\'}
$datapoints.Add([DataPoint]::new("AppCertDLLS", $scriptblock, $true, "T1546.009", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {$(
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\" -name AppInit_DLLs; 
    Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\" -name AppInit_DLLs;
    if(!(test-path HKU:)){
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
    }
    #This is a handy line that gets all the sids for users from the registry.
    $UserInstalls += Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
    $(foreach ($User in $UserInstalls){
        Get-ItemProperty "HKU:\$User\Software\Microsoft\Windows NT\CurrentVersion\Windows\" -name AppInit_DLLs;
        Get-ItemProperty "HKU:\$User\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\" -name AppInit_DLLs
    });
    $UserInstalls = $null;) | Where-Object {($_.DisplayName -ne $null) -and ($_.Publisher -ne $null)}}
$datapoints.Add([DataPoint]::new("AppInitDLLS", $scriptblock, $true, "T1546.010", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-ShimEngine/Operational';}  |Select-Object Message,TimeCreated,ProcessId,ThreadId}
$datapoints.Add([DataPoint]::new("ApplicationShimming", $scriptblock, $true, "T1546.011", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" -name Debugger -ErrorAction SilentlyContinue}
$datapoints.Add([DataPoint]::new("ImageFileExecutionOptions", $scriptblock, $true, "T1546.012", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
                test-path $pshome\profile.ps1
                test-path $pshome\microsoft.*.ps1
                test-path "c:\users\*\My Documents\powershell\Profile.ps1"
                test-path "C:\Users\*\My Documents\microsoft.*.ps1"
             
             }
$datapoints.Add([DataPoint]::new("PowershellProfile", $scriptblock, $true, "T1546.013", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {get-itemproperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -name "Authentication Packages"}
$datapoints.Add([DataPoint]::new("AuthenticationPackage", $scriptblock, $true, "T1547.002", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-ItemProperty HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\* | Select-Object dllname,pspath}
$datapoints.Add([DataPoint]::new("TimeProviders", $scriptblock, $true, "T1547.003", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
    $(
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -name UserInit, shell
        if(!(test-path HKU:)){
            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
        }
        #This is a handy line that gets all the sids for users from the registry.
        $UserInstalls = ""
        $UserInstalls += Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
        $(foreach ($User in $UserInstalls){
            Get-ItemProperty "HKU:\$User\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -name UserInit, shell -ErrorAction SilentlyContinue
        });
        $UserInstalls = $null;)

}
$datapoints.Add([DataPoint]::new("WinlogonHelperDLL", $scriptblock, $true, "T1547.004", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
    $(
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "Security Packages";
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\" -Name "Security Packages" -ErrorAction SilentlyContinue
    )
}
$datapoints.Add([DataPoint]::new("SecuritySupportProvider", $scriptblock, $true, "T1547.005", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
            Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4614';} -ErrorAction SilentlyContinue;
            Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='3033';} -ErrorAction SilentlyContinue;
            Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='3063';} -ErrorAction SilentlyContinue
            }
$datapoints.Add([DataPoint]::new("LSASSDriverWindowsEvents", $scriptblock, $true, "T1547.008", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\" -Name LsaDbExtPt -ErrorAction SilentlyContinue;
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\" -Name DirectoryServiceExtPt -ErrorAction SilentlyContinue;
    }
$datapoints.Add([DataPoint]::new("LSASSDriverRegistry", $scriptblock, $true, "T1547.008", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\*" -name driver}
$datapoints.Add([DataPoint]::new("PortMonitors", $scriptblock, $true, "T1547.010", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
    $(
        Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Control\Print\Environments\*\Print Processors\*";
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors\*"
    )    
}
$datapoints.Add([DataPoint]::new("PrintProcessors", $scriptblock, $true, "T1547.012", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {get-itemproperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*" | Select-Object "(default)",componentid,stubpath,pspath}
$datapoints.Add([DataPoint]::new("ActiveSetup", $scriptblock, $true, "T1547.014", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
    $processes = Get-WmiObject win32_process
    $processes | ForEach-Object{
        Add-Member -InputObject $_ -Name Hash -Value (Get-FileHash -Path $_.ExecutablePath -ea SilentlyContinue).hash -MemberType NoteProperty 
    } 
    $processes | Select-Object processname,handles,path.pscomputernamename,commandline,creationdate,executablepath,parentprocessid,processid, Hash
}
$datapoints.Add([DataPoint]::new("Process", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -Property TTL,pscomputername,data,entry,name}
$datapoints.Add([DataPoint]::new("DNSCache", $scriptblock, $true)) | Out-Null

# I don't know how to feel about this one. Seems trash.
$scriptblock = {Get-ChildItem -Recurse c:\ProgramData\ | Select-Object -Property Fullname,Pscomputername,creationtimeutc,lastaccesstimeutc,attributes} 
$datapoints.Add([DataPoint]::new("ProgramData", $scriptblock, $true)) | Out-Null

$scriptblock = {Set-Location C:\Users; (Get-ChildItem -Recurse).fullname | Get-Item -Stream * | Where-Object{$_.stream -ne ':$DATA'} | Select-Object -Property Filename,Pscomputername,stream}
$datapoints.Add([DataPoint]::new("AlternateDataStreams", $scriptblock, $true, "T1564.004", [TechniqueCategory]::Uncategorized)) | Out-Null

# This one is hot garbage as well. 
$scriptblock = {(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs\')}
$datapoints.Add([DataPoint]::new("KnownDLLs", $scriptblock, $true)) | Out-Null


$scriptblock = {
    (Get-ChildItem -path C:\Windows\System32\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid");
    (Get-ChildItem -path C:\Windows\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid")
}
$datapoints.Add([DataPoint]::new("DLLSearchOrderHijacking", $scriptblock, $true, "T1574.001", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Bits-Client/Operational'; Id='59'} | Select-Object -Property message,pscomputername,id,logname,processid,userid,timecreated}
$datapoints.Add([DataPoint]::new("BITSJobsLogs", $scriptblock, $true, "T1197", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-BitsTransfer -AllUsers}
$datapoints.Add([DataPoint]::new("BITSTransfer", $scriptblock, $true, "T1197", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-WmiObject win32_bios | Select-Object -Property pscomputername,biosversion,caption,currentlanguage,manufacturer,name,serialnumber}
$datapoints.Add([DataPoint]::new("SystemFirmware", $scriptblock, $true)) | Out-Null

$scriptblock = {
                 $logonScriptsArrayList = [System.Collections.ArrayList]@();
                 
                 New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null;
                 Set-Location HKU: | Out-Null;

                 $SIDS  += Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };

                 foreach($SID in $SIDS){
                    $logonscriptObject = [PSCustomObject]@{
                        SID =""
                        HasLogonScripts = ""
                 
                    };
                    $logonscriptObject.sid = $SID; 
                    $logonscriptObject.haslogonscripts = !((Get-ItemProperty HKU:\$SID\Environment\).userinitmprlogonscript -eq $null); 
                    $logonScriptsArrayList.add($logonscriptObject) | out-null
                    }
                    $logonScriptsArrayList
             }
$datapoints.Add([DataPoint]::new("UserInitMprLogonScript", $scriptblock, $true)) | Out-Null

$scriptblock = {
                $(
                    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*; 
                    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*;
                    if(!(test-path HKU:)){
                        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
                    }
                    #This is a handy line that gets all the sids for users from the registry.
                    $UserInstalls += Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
                    $(foreach ($User in $UserInstalls){
                        Get-ItemProperty HKU:\$User\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*;
                        Get-ItemProperty HKU:\$User\SOFTWARE\Wow6432Node\Windows\CurrentVersion\Uninstall\*
                    });
                    $UserInstalls = $null;) | Where-Object {($_.DisplayName -ne $null) -and ($_.Publisher -ne $null)}
            }
$datapoints.Add([DataPoint]::new("InstalledSoftare", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object PSComputerName,displayName,pathToSignedProductExe,pathToSignedReportingExe}
$datapoints.Add([DataPoint]::new("AVProduct", $scriptblock, $true)) | Out-Null

# This lil guy needs to be straight rippin from the registry and manually parsing.
$scriptblock = {Get-WmiObject win32_service | Select-Object -Property PSComputerName,caption,description,pathname,processid,startname,state}
$datapoints.Add([DataPoint]::new("Services", $scriptblock, $true, "T1543.003", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-WindowsOptionalFeature -Online -FeatureName microsoftwindowspowershellv2 | Select-Object -Property PSComputerName,FeatureName,State,LogPath}
$datapoints.Add([DataPoint]::new("PowerShellVersion", $scriptblock, $true)) | Out-Null

# I don't like this one either.
$scriptblock = {Get-CimInstance win32_startupcommand | Select-Object -Property PSComputerName,Caption,Command,Description,Location,User}
$datapoints.Add([DataPoint]::new("Startup", $scriptblock, $true)) | Out-Null

$scriptblock = {
                Get-ChildItem -path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"<# -include *.lnk,*.url#> -ErrorAction SilentlyContinue| Select-Object -Property PSComputerName,Length,FullName,Extension,CreationTime,LastAccessTime;
                Get-ChildItem -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" <#-include *.lnk,*.url#> -ErrorAction SilentlyContinue | Select-Object -Property PSComputerName,Length,FullName,Extension,CreationTime,LastAccessTime
            }
$datapoints.Add([DataPoint]::new("StartupFolder", $scriptblock, $true)) | Out-Null

# Can we get this from the registry with higher fidelity instead or no?
$scriptblock = {
    $drivers = Get-WmiObject win32_systemdriver
    $drivers | ForEach-Object {
        Add-Member -InputObject $_ -Name Hash -Value (Get-FileHash -Path $_.pathname -ea SilentlyContinue).hash -MemberType NoteProperty
    } | Select-Object -Property PSComputerName,caption,description,name,pathname,started,startmode,state,hash
    $drivers
}
$datapoints.Add([DataPoint]::new("Drivers", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WmiObject win32_environment |Where-Object{$_.name -ne "OneDrive"}}
$datapoints.Add([DataPoint]::new("EnvironmentVariables", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WmiObject win32_networkadapterconfiguration | Select-Object -Property PSComputerName,Description,IPAddress,IPSubnet,MACAddress,servicename,__server}
$datapoints.Add([DataPoint]::new("NetworkAdapters", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WmiObject win32_computersystem | Select-Object -Property PSComputerName,domain,manufacturer,model,primaryownername,totalphysicalmemory,username}
$datapoints.Add([DataPoint]::new("SystemInfo", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WmiObject win32_networkloginprofile}
$datapoints.Add([DataPoint]::new("Logon", $scriptblock, $true)) | Out-Null

$scriptblock = {get-NetTcpConnection}
$datapoints.Add([DataPoint]::new("NetworkConnections", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-SmbShare}
$datapoints.Add([DataPoint]::new("SMBShares", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-SmbConnection}
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
$datapoints.Add([DataPoint]::new("ScheduledTasks", $scriptblock, $true, "T1053.005", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-ChildItem "C:\Windows\Prefetch"}
$datapoints.Add([DataPoint]::new("PrefetchListing", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WmiObject win32_pnpentity}
$datapoints.Add([DataPoint]::new("PNPDevices", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WmiObject win32_logicaldisk} 
$datapoints.Add([DataPoint]::new("LogicalDisks", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WmiObject win32_diskdrive | Select-Object pscomputername,DeviceID,Capabilities,CapabilityDescriptions,Caption,FirmwareRevision,Model,PNPDeviceID,SerialNumber}
$datapoints.Add([DataPoint]::new("DiskDrives", $scriptblock, $true)) | Out-Null

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
$datapoints.Add([DataPoint]::new("UnsignedDrivers", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-HotFix -ErrorAction SilentlyContinue}
$datapoints.Add([DataPoint]::new("Hotfixes", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-NetNeighbor -ErrorAction SilentlyContinue}
$datapoints.Add([DataPoint]::new("ArpCache", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | Select-Object timecreated,message}
$datapoints.Add([DataPoint]::new("NewlyRegisteredServices", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*' -Name *}
$datapoints.Add([DataPoint]::new("AppPaths", $scriptblock, $true )) | Out-Null

$scriptblock = {
                if(!(test-path HKU:)){
                    New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;
                }
                $UserInstalls = ""
                $UserInstalls += Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };
                foreach($user in $UserInstalls){
                    if(test-path HKU\$user\Software\Classes\ms-settings\shell\open\command){
                        Get-ItemProperty HKU:\$User\SOFTWARE\classes\ms-settings-shell\open\command -ErrorAction SilentlyContinue
                    }
                }
             
             }
$datapoints.Add([DataPoint]::new("UACBypassFodHelper", $scriptblock, $true)) | Out-Null

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
$datapoints.Add([DataPoint]::new("VisibleWirelessNetworks", $scriptblock, $true)) | Out-Null

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
$datapoints.Add([DataPoint]::new("HistoricalWiFiConnections", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';} | Select-Object TimeCreated, Message}
$datapoints.Add([DataPoint]::new("HistoricalFirewallChanges", $scriptblock, $true)) | Out-Null

$scriptblock = {
                $portproxyResults = (netsh interface portproxy show all);
                $portproxyarraylist = [System.Collections.ArrayList]@();
                if((($portproxyResults.gettype()).basetype.name -eq "Array") -and ($portproxyResults.count -gt 0)){
                    for($i = 5; $i -lt ($portproxyResults.Length); $i++){
                        $portproxyObject = [PSCustomObject]@{
                            proxy = ""
                        }
                        $portproxyObject.proxy = $portproxyResults[$i]

                        $portproxyarraylist.Add($portproxyObject) | Out-Null
                    }
                    $portproxyarraylist
                }
                                 
            }
$datapoints.Add([DataPoint]::new("PortProxies", $scriptblock, $true, "T1090", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*\NonPackaged\*)}
$datapoints.Add([DataPoint]::new("CapabilityAccessManager", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-DnsClientServerAddress}
$datapoints.Add([DataPoint]::new("DnsClientServerAddress", $scriptblock, $true)) | Out-Null

$scriptblock = {
                Select-String -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "exe";
                Select-String -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Pattern "dll";
                Select-String -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Pattern "dll";
                Select-String -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Pattern "exe";
                Get-ChildItem -path "C:\Users\" -recurse -include *.lnk -ea SilentlyContinue | Select-String -Pattern "exe";
                Get-ChildItem -path "C:\Users\" -recurse -include *.lnk -ea SilentlyContinue | Select-String -Pattern "dll";
            }
$datapoints.Add([DataPoint]::new("ShortcutModifications", $scriptblock, $true)) | Out-Null

$scriptblock = {(Get-Process -Module -ea 0).FileName|Where-Object{$_ -notlike "*system32*"}|Select-String "Appdata","ProgramData","Temp","Users","public"|Get-unique|%{Get-FileHash -Path $_}}
$datapoints.Add([DataPoint]::new("DLLsInTempDirs", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-WinEvent -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | Select-Object -exp Properties | Where-Object {$_.Value -like '*.*.*.*' } | Sort-Object Value -u }
$datapoints.Add([DataPoint]::new("RDPHistoricallyConnectedIPs", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-MpComputerStatus}
$datapoints.Add([DataPoint]::new("MpComputerStatus", $scriptblock, $true)) | Out-Null

$scriptblock = {Get-MpPreference}
$datapoints.Add([DataPoint]::new("MpPreference", $scriptblock, $true)) | Out-Null

# I need to go through the keys and pullout the actual dlls and stuff for the com objects.
$scriptblock = {Get-ChildItem HKLM:\Software\Classes -ea 0| Where-Object {$_.PSChildName -match '^\w+\.\w+$' -and(Get-ItemProperty "$($_.PSPath)\CLSID" -ea 0)} | Select-Object Name}
$datapoints.Add([DataPoint]::new("COMObjects", $scriptblock, $true)) | Out-Null

$scriptblock = {get-winevent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';} | Where-Object{$_.leveldisplayname -eq 'Error'} | Select-Object Message, id, processid, timecreated}
$datapoints.Add([DataPoint]::new("CodeIntegrityLogs", $scriptblock, $true)) | Out-Null

$scriptblock = {get-winevent -FilterHashtable @{LogName='Security';} | Where-Object{$_.id -eq 1102} | Select-Object TimeCreated, Id, Message}
$datapoints.Add([DataPoint]::new("SecurityLogCleared", $scriptblock, $true, "T1070.001", [TechniqueCategory]::Uncategorized)) | Out-Null

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
$datapoints.Add([DataPoint]::new("SIPandTrustProviderHijacking", $scriptblock, $true, "T1553.003", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {
                $regexa = '.+Domain="(.+)",Name="(.+)"$';
                $regexd = '.+LogonId="(\d+)"$';
                $logon_users = @(Get-WmiObject win32_loggedonuser -ComputerName 'localhost');
                if(($logon_users -ne "") -and ($logon_users -ne $null)){
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

                        if(($klistsarraylist -ne $null) -and ($klistoutput.count -gt 7)){
        
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
$datapoints.Add([DataPoint]::new("PassTheHash", $scriptblock, $true)) | Out-Null

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
$datapoints.Add([DataPoint]::new("RegistryRunKeys", $scriptblock, $true, "T1547.001", [TechniqueCategory]::Uncategorized)) | Out-Null

$scriptblock = {Get-MpPreference | Select-Object -ExpandProperty ExclusionPath}
$datapoints.Add([DataPoint]::new("DefenderExclusionPath", $scriptblock, $true, "T1562.001", [TechniqueCategory]::ImpairDefenses)) | Out-Null

$scriptblock = {Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress}
$datapoints.Add([DataPoint]::new("DefenderExclusionIpAddress", $scriptblock, $true, "T1562.001", [TechniqueCategory]::ImpairDefenses)) | Out-Null

$scriptblock = {Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension}
$datapoints.Add([DataPoint]::new("DefenderExclusionExtension", $scriptblock, $true, "T1562.001", [TechniqueCategory]::ImpairDefenses)) | Out-Null

function WaitFor-Jobs{
    while((get-job | Where-Object state -eq "Running" |Measure).Count -ne 0){
            get-job | Format-Table -RepeatHeader
            Start-Sleep -Seconds 10
    }

}

function Invoke-Collect($dp){
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
    
    Register-ObjectEvent -MessageData $env:COMPUTERNAME -InputObject (Start-Job -Name $dp.jobname -ScriptBlock $dp.scriptblock) -EventName StateChanged -Action $action | out-null

}

function Invoke-MetaBlue {    
    
    Create-OutputFolders 
    
    foreach($datapoint in $datapoints){
        if($datapoint.isEnabled){
            Invoke-Collect $datapoint
        }
    }

    WaitFor-Jobs
         
}
Invoke-MetaBlue







