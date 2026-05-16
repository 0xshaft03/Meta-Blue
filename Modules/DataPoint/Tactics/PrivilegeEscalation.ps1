# ============================================================
# PrivilegeEscalation data points
# Dot-sourced by Modules/DataPoint/DataPoint.psm1::New-DataPoints
# Relies on $datapoints (ArrayList), [DataPoint], [TechniqueCategory]
# being in scope from the caller.
# ============================================================


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

