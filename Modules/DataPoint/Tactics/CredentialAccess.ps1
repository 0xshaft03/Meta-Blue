# ============================================================
# CredentialAccess data points
# Dot-sourced by Modules/DataPoint/DataPoint.psm1::New-DataPoints
# Relies on $datapoints (ArrayList), [DataPoint], [TechniqueCategory]
# being in scope from the caller.
# ============================================================


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

