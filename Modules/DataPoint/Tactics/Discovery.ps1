# ============================================================
# Discovery data points
# Dot-sourced by Modules/DataPoint/DataPoint.psm1::New-DataPoints
# Relies on $datapoints (ArrayList), [DataPoint], [TechniqueCategory]
# being in scope from the caller.
# ============================================================


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


    $scriptblock = {try {Get-WindowsOptionalFeature -Online -FeatureName microsoftwindowspowershellv2 | Select-Object -Property PSComputerName,FeatureName,State,LogPath} catch {}}
    $datapoints.Add([DataPoint]::new("PowerShellVersion", $scriptblock, $true, "T1082", [TechniqueCategory]::Discovery)) | Out-Null


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


    $scriptblock = {try {Get-NetTcpConnection} catch {}}
    $datapoints.Add([DataPoint]::new("NetworkConnections", $scriptblock, $true, "T1049", [TechniqueCategory]::Discovery, $true)) | Out-Null


    $scriptblock = {try {Get-SmbShare} catch {}}
    $datapoints.Add([DataPoint]::new("SMBShares", $scriptblock, $true, "T1135", [TechniqueCategory]::Discovery)) | Out-Null


    $scriptblock = {Get-WmiObject win32_pnpentity}
    $datapoints.Add([DataPoint]::new("PNPDevices", $scriptblock, $true, "T1120", [TechniqueCategory]::Discovery)) | Out-Null


    $scriptblock = {Get-WmiObject win32_logicaldisk} 
    $datapoints.Add([DataPoint]::new("LogicalDisks", $scriptblock, $true, "T1083", [TechniqueCategory]::Discovery)) | Out-Null


    $scriptblock = {Get-WmiObject win32_diskdrive | Select-Object pscomputername,DeviceID,Capabilities,CapabilityDescriptions,Caption,FirmwareRevision,Model,PNPDeviceID,SerialNumber}
    $datapoints.Add([DataPoint]::new("DiskDrives", $scriptblock, $true, "T1083", [TechniqueCategory]::Discovery)) | Out-Null


    $scriptblock = {Get-HotFix -ErrorAction SilentlyContinue}
    $datapoints.Add([DataPoint]::new("Hotfixes", $scriptblock, $true, "T1082", [TechniqueCategory]::Discovery)) | Out-Null


    $scriptblock = {try {Get-NetNeighbor -ErrorAction SilentlyContinue} catch {}}
    $datapoints.Add([DataPoint]::new("ArpCache", $scriptblock, $true, "T1018", [TechniqueCategory]::Discovery)) | Out-Null


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


    $scriptblock = {try {Get-DnsClientServerAddress} catch {}}
    $datapoints.Add([DataPoint]::new("DnsClientServerAddress", $scriptblock, $true, "T1016", [TechniqueCategory]::Discovery)) | Out-Null

