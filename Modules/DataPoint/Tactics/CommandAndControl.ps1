# ============================================================
# CommandAndControl data points
# Dot-sourced by Modules/DataPoint/DataPoint.psm1::New-DataPoints
# Relies on $datapoints (ArrayList), [DataPoint], [TechniqueCategory]
# being in scope from the caller.
# ============================================================


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

