# ============================================================
# DefenseEvasion data points
# Dot-sourced by Modules/DataPoint/DataPoint.psm1::New-DataPoints
# Relies on $datapoints (ArrayList), [DataPoint], [TechniqueCategory]
# being in scope from the caller.
# ============================================================


    $scriptblock = {Get-ChildItem -Path C:\Users\* -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object FullName | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ':$DATA'} | Select-Object -Property Filename, PSComputerName, Stream}
    $datapoints.Add([DataPoint]::new("AlternateDataStreams", $scriptblock, $true, "T1564.004", [TechniqueCategory]::DefenseEvasion)) | Out-Null


    $scriptblock = {Get-ChildItem -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | Get-AuthenticodeSignature | Where-Object {$_.status -ne 'Valid'}}
    $datapoints.Add([DataPoint]::new("UnsignedDrivers", $scriptblock, $true, "T1553", [TechniqueCategory]::DefenseEvasion)) | Out-Null


    $scriptblock = {Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message}
    $datapoints.Add([DataPoint]::new("HistoricalFirewallChanges", $scriptblock, $true, "T1562.004", [TechniqueCategory]::DefenseEvasion)) | Out-Null


    $scriptblock = {try {Get-MpComputerStatus} catch {}}
    $datapoints.Add([DataPoint]::new("MpComputerStatus", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion)) | Out-Null


    $scriptblock = {try {Get-MpPreference} catch {}}
    $datapoints.Add([DataPoint]::new("MpPreference", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion)) | Out-Null


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


    $scriptblock = {try {Get-MpPreference | Select-Object -ExpandProperty ExclusionPath} catch {}}
    $datapoints.Add([DataPoint]::new("DefenderExclusionPath", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion, $true)) | Out-Null


    $scriptblock = {try {Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress} catch {}}
    $datapoints.Add([DataPoint]::new("DefenderExclusionIpAddress", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion, $true)) | Out-Null


    $scriptblock = {try {Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension} catch {}}
    $datapoints.Add([DataPoint]::new("DefenderExclusionExtension", $scriptblock, $true, "T1562.001", [TechniqueCategory]::DefenseEvasion, $true)) | Out-Null

