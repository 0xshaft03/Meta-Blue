# ============================================================
# LateralMovement data points
# Dot-sourced by Modules/DataPoint/DataPoint.psm1::New-DataPoints
# Relies on $datapoints (ArrayList), [DataPoint], [TechniqueCategory]
# being in scope from the caller.
# ============================================================


    $scriptblock = {Get-WinEvent -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -ErrorAction SilentlyContinue | Select-Object -exp Properties | Where-Object {$_.Value -like '*.*.*.*' } | Sort-Object Value -u }
    $datapoints.Add([DataPoint]::new("RDPHistoricallyConnectedIPs", $scriptblock, $true, "T1021.001", [TechniqueCategory]::LateralMovement)) | Out-Null

