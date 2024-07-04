<#
.SYNOPSIS  
    

.EXAMPLE
    .\Meta-Blue.ps1

.NOTES  
    File Name      : Meta-Blue.ps1
    Version        : v.2
    Author         : newhandle
    Prerequisite   : PowerShell
    Created        : 1 Oct 18
    Change Date    : 29 May 23
    
#>

$timestamp = (get-date).Tostring("yyyy_MM_dd_hh_mm_ss")

<#
    Define the root directory for results. CHANGE THIS TO BE WHEREVER YOU WANT.
#>
$global:metaBlueFolder = "C:\Meta-Blue\"
$global:outFolder = "$metaBlueFolder\$timestamp"
#$outFolder = "$home\desktop\collection\$timestamp"
$global:rawFolder = "$outFolder\raw"
$global:anomaliesFolder = "$outFolder\Anomalies"
#$jsonFolder = "C:\MetaBlue Results"
$global:excludedHostsFile = "C:\Meta-Blue\ExcludedHosts.csv"

class DataPoint {
    [string]$jobname
    [scriptblock]$scriptblock
    [bool]$isEnabled
    [string]$mitreID

    DataPoint($jobname, $scriptblock, $isEnabled, $mitreID){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = $mitreID
    }

    DataPoint($jobname, $scriptblock, $isEnabled){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = "N/A"
    }

    enable(){
        $this.isEnabled = $true
    }

    disable(){
        $this.isEnabled = $false
    }
 }


 class ProcessCreateEventLog {
    [string]$SID
    [string]$accountName
    $pid
    [string]$processName
    $ppid
    [string]$parentName
 }

 class Node {
    [string]$Hostname
    [string]$IPAddress
    [string]$OperatingSystem
    [int]$TTL
  
    Node() {
      $this.Hostname = ""
      $this.IPAddress = ""
      $this.OperatingSystem = ""
      $this.TTL = 0
    }
  
  
}

$datapoints = [System.Collections.ArrayList]@()

function Build-Directories{
    if(!(test-path $outFolder)){
        new-item -itemtype directory -path $outFolder -Force
    }
    if(!(test-path $rawFolder)){
        new-item -itemtype directory -path $rawFolder -Force
    }if(!(test-path $anomaliesFolder)){
        new-item -itemtype directory -path $anomaliesFolder -Force
    }
    <#if(!(test-path $jsonFolder)){
        new-item -itemtype directory -path $jsonFolder -Force
    }#>
}

$adEnumeration = $false
$winrm = $true
$localBox = $false
$waitForJobs = ""
$runningJobThreshold = 5
$jobTimeOutThreshold = 20
$isRanAsSchedTask = $false
$nodeList = [System.Collections.ArrayList]@()

function Get-Exports {
<#
.SYNOPSIS
Get-Exports, fetches DLL exports and optionally provides
C++ wrapper output (idential to ExportsToC++ but without
needing VS and a compiled binary). To do this it reads DLL
bytes into memory and then parses them (no LoadLibraryEx).
Because of this you can parse x32/x64 DLL's regardless of
the bitness of PowerShell.

.DESCRIPTION
Author: Ruben Boonen (@FuzzySec)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.PARAMETER DllPath

Absolute path to DLL.

.PARAMETER CustomDll

Absolute path to output file.

.EXAMPLE
C:\PS> Get-Exports -DllPath C:\Some\Path\here.dll

.EXAMPLE
C:\PS> Get-Exports -DllPath C:\Some\Path\here.dll -ExportsToCpp C:\Some\Out\File.txt
#>
	param (
        [Parameter(Mandatory = $True)]
		[string]$DllPath,
		[Parameter(Mandatory = $False)]
		[string]$ExportsToCpp
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct IMAGE_EXPORT_DIRECTORY
	{
		public UInt32 Characteristics;
		public UInt32 TimeDateStamp;
		public UInt16 MajorVersion;
		public UInt16 MinorVersion;
		public UInt32 Name;
		public UInt32 Base;
		public UInt32 NumberOfFunctions;
		public UInt32 NumberOfNames;
		public UInt32 AddressOfFunctions;
		public UInt32 AddressOfNames;
		public UInt32 AddressOfNameOrdinals;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct IMAGE_SECTION_HEADER
	{
		public String Name;
		public UInt32 VirtualSize;
		public UInt32 VirtualAddress;
		public UInt32 SizeOfRawData;
		public UInt32 PtrToRawData;
		public UInt32 PtrToRelocations;
		public UInt32 PtrToLineNumbers;
		public UInt16 NumOfRelocations;
		public UInt16 NumOfLines;
		public UInt32 Characteristics;
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern IntPtr LoadLibraryEx(
			String lpFileName,
			IntPtr hReservedNull,
			UInt32 dwFlags);
	}
"@

	# Load the DLL into memory so we can refference it like LoadLibrary
	$FileBytes = [System.IO.File]::ReadAllBytes($DllPath)
	[IntPtr]$HModule = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FileBytes.Length)
	[System.Runtime.InteropServices.Marshal]::Copy($FileBytes, 0, $HModule, $FileBytes.Length)

	# Some Offsets..
	$PE_Header = [Runtime.InteropServices.Marshal]::ReadInt32($HModule.ToInt64() + 0x3C)
	$Section_Count = [Runtime.InteropServices.Marshal]::ReadInt16($HModule.ToInt64() + $PE_Header + 0x6)
	$Optional_Header_Size = [Runtime.InteropServices.Marshal]::ReadInt16($HModule.ToInt64() + $PE_Header + 0x14)
	$Optional_Header = $HModule.ToInt64() + $PE_Header + 0x18

	# We need some values from the Section table to calculate RVA's
	$Section_Table = $Optional_Header + $Optional_Header_Size
	$SectionArray = @()
	for ($i; $i -lt $Section_Count; $i++) {
		$HashTable = @{
			VirtualSize = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0x8)
			VirtualAddress = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0xC)
			PtrToRawData = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0x14)
		}
		$Object = New-Object PSObject -Property $HashTable
		$SectionArray += $Object
		
		# Increment $Section_Table offset by Section size
		$Section_Table = $Section_Table + 0x28
	}

	# Helper function for dealing with on-disk PE offsets.
	# Adapted from @mattifestation:
	# https://github.com/mattifestation/PowerShellArsenal/blob/master/Parsers/Get-PE.ps1#L218
	function Convert-RVAToFileOffset($Rva, $SectionHeaders) {
		foreach ($Section in $SectionHeaders) {
			if (($Rva -ge $Section.VirtualAddress) -and
				($Rva-lt ($Section.VirtualAddress + $Section.VirtualSize))) {
				return [IntPtr] ($Rva - ($Section.VirtualAddress - $Section.PtrToRawData))
			}
		}
		# Pointer did not fall in the address ranges of the section headers
		Write-Output "Mmm, pointer did not fall in the PE range.."
	}

	# Read Magic UShort to determin x32/x64
	if ([Runtime.InteropServices.Marshal]::ReadInt16($Optional_Header) -eq 0x010B) {
		Write-Output "`n[?] 32-bit Image!"
		# IMAGE_DATA_DIRECTORY[0] -> Export
		$Export = $Optional_Header + 0x60
	} else {
		Write-Output "`n[?] 64-bit Image!"
		# IMAGE_DATA_DIRECTORY[0] -> Export
		$Export = $Optional_Header + 0x70
	}

	# Convert IMAGE_EXPORT_DIRECTORY[0].VirtualAddress to file offset!
	$ExportRVA = Convert-RVAToFileOffset $([Runtime.InteropServices.Marshal]::ReadInt32($Export)) $SectionArray

	# Cast offset as IMAGE_EXPORT_DIRECTORY
	$OffsetPtr = New-Object System.Intptr -ArgumentList $($HModule.ToInt64() + $ExportRVA)
	$IMAGE_EXPORT_DIRECTORY = New-Object IMAGE_EXPORT_DIRECTORY
	$IMAGE_EXPORT_DIRECTORY = $IMAGE_EXPORT_DIRECTORY.GetType()
	$EXPORT_DIRECTORY_FLAGS = [system.runtime.interopservices.marshal]::PtrToStructure($OffsetPtr, [type]$IMAGE_EXPORT_DIRECTORY)

	# Print the in-memory offsets!
	Write-Output "`n[>] Time Stamp: $([timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($EXPORT_DIRECTORY_FLAGS.TimeDateStamp)))"
	Write-Output "[>] Function Count: $($EXPORT_DIRECTORY_FLAGS.NumberOfFunctions)"
	Write-Output "[>] Named Functions: $($EXPORT_DIRECTORY_FLAGS.NumberOfNames)"
	Write-Output "[>] Ordinal Base: $($EXPORT_DIRECTORY_FLAGS.Base)"
	Write-Output "[>] Function Array RVA: 0x$('{0:X}' -f $EXPORT_DIRECTORY_FLAGS.AddressOfFunctions)"
	Write-Output "[>] Name Array RVA: 0x$('{0:X}' -f $EXPORT_DIRECTORY_FLAGS.AddressOfNames)"
	Write-Output "[>] Ordinal Array RVA: 0x$('{0:X}' -f $EXPORT_DIRECTORY_FLAGS.AddressOfNameOrdinals)"

	# Get equivalent file offsets!
	$ExportFunctionsRVA = Convert-RVAToFileOffset $EXPORT_DIRECTORY_FLAGS.AddressOfFunctions $SectionArray
	$ExportNamesRVA = Convert-RVAToFileOffset $EXPORT_DIRECTORY_FLAGS.AddressOfNames $SectionArray
	$ExportOrdinalsRVA = Convert-RVAToFileOffset $EXPORT_DIRECTORY_FLAGS.AddressOfNameOrdinals $SectionArray

	# Loop exports
	$ExportArray = @()
	for ($i=0; $i -lt $EXPORT_DIRECTORY_FLAGS.NumberOfNames; $i++){
		# Calculate function name RVA
		$FunctionNameRVA = Convert-RVAToFileOffset $([Runtime.InteropServices.Marshal]::ReadInt32($HModule.ToInt64() + $ExportNamesRVA + ($i*4))) $SectionArray
		$HashTable = @{
			FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($HModule.ToInt64() + $FunctionNameRVA)
			ImageRVA = Write-Output "0x$("{0:X8}" -f $([Runtime.InteropServices.Marshal]::ReadInt32($HModule.ToInt64() + $ExportFunctionsRVA + ($i*4))))"
			Ordinal = [Runtime.InteropServices.Marshal]::ReadInt16($HModule.ToInt64() + $ExportOrdinalsRVA + ($i*2)) + $EXPORT_DIRECTORY_FLAGS.Base
		}
		$Object = New-Object PSObject -Property $HashTable
		$ExportArray += $Object
	}

	# Print export object
	$ExportArray |Sort-Object Ordinal

	# Optionally write ExportToC++ wrapper output
	if ($ExportsToCpp) {
		foreach ($Entry in $ExportArray) {
			Add-Content $ExportsToCpp "#pragma comment (linker, '/export:$($Entry.FunctionName)=[FORWARD_DLL_HERE].$($Entry.FunctionName),@$($Entry.Ordinal)')"
		}
	}

	# Free buffer
	[Runtime.InteropServices.Marshal]::FreeHGlobal($HModule)
}


function Get-FileName($initialDirectory){
<#
    This was taken from: 
    https://social.technet.microsoft.com/Forums/office/en-US/0890adff-43ea-4b4b-9759-5ac2649f5b0b/getcontent-with-open-file-dialog?forum=winserverpowershell
#>   
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

function Repair-PSSessions{
    $sessions = Get-PSSession
    $sessions | Where-Object {$_.state -eq "Disconnected"} | Connect-PSSession
    $sessions | Where-Object {$_.state -eq "Broken"} | New-PSSession -SessionOption (New-PSSessionOption -NoMachineProfile -MaxConnectionRetryCount 5)
    Get-PSSession | Where-Object {$_.state -eq "Broken"} | Remove-PSSession 
}

<#
    https://www.powershellgallery.com/packages/Binary-Search-WExample/1.0.1/Content/Binary-Search-WExample.ps1
#>
Function Binary-Search {
[CmdletBinding()]

Param (
    [Parameter(Mandatory=$True)
    ]

    $InputArray,
    $SearchVal,
    $Attribute)   #End Param

#==============Begin Main Function============================
#$InputArray = $InputArray |sort $Attribute #remove # if the input array was not sorted before calling the function
#write-host "SearchVal is: "$Searchval
#write-host "Attribute is: "$Attribute
$LowIndex = 0                              #Low side of array segment
$Counter = 0
$TempVal = ""                              #Used to determine end of search where $Found = $False
$HighIndex = $InputArray.count             #High Side of array segment
[int]$MidPoint = ($HighIndex-$LowIndex)/2  #Mid point of array segment
#write-host "Midpoint is: $midPoint Searchval is: $Searchval"
$Global:Found = $False


While($LowIndex -le $HighIndex){
    $MidVal = $InputArray[$MidPoint].$Attribute   
                                                
    If($TempVal -eq $MidVal){              #If identical, the search has completed and $Found = $False
        $Global:Found = $False
        Return
    }
    else{
        $TempVal = $MidVal                 #Update the TempVal. Search continues.
    }
    
#write-host "Midval is: $midval"
    #Write-host "Low is $lowindex, Mid is $midpoint, High is $HighIndex"
    #read-host
        If($SearchVal -lt $MidVal) {
            #write-host "SV < MV"
            $Counter++
            $HighIndex = $MidPoint 
            [int]$MidPoint = (($HighIndex-$LowIndex)/ 2 +$LowIndex)
            }
        If($SearchVal -gt $MidVal) {
            #write-host "SV > MV"
            $Counter++
            $LowIndex = $MidPoint 
            [int]$MidPoint = ($MidPoint+(($HighIndex - $MidPoint) / 2))         
            }
        If($SearchVal -eq $MidVal) {
            $Global:Found = $True 
            #write-host "User $Midval was found. It took $Counter passes"
            
            Return $midpoint
            }
}   #End While
}   #End Function


function Get-SubnetRange {
<#
    Thank you mr sparkly markley for this super awesome cool subnetrange generator.
#>
    [CmdletBinding(DefaultParameterSetName = "Set1")]
    Param(
        [Parameter(
        Mandatory          =$true,
        Position           = 0,
        ValueFromPipeLine  = $false,
        ParameterSetName   = "Set1"
        )]
        [ValidatePattern(@"
^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$
"@
        )]
            [string]$IPAddress,



        [Parameter(
        Mandatory          =$true,
        ValueFromPipeline  = $false,
        ParameterSetName   = "Set1"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern(@"
^([0-9]|[0-2][0-9]|3[0-2]|\/([0-9]|[0-2][0-9]|3[0-2]))$
"@
        )]
            [string]$CIDR

)
$IPSubnetList = [System.Collections.ArrayList]@()

#Ip Address in Binary #######################################
$Binary  = $IPAddress -split '\.' | ForEach-Object {
    [System.Convert]::ToString($_,2).Padleft(8,'0')}
$Binary = $Binary -join ""


#Host Bits from CIDR #######################################
if ($CIDR -like '/*') {
$CIDR = ($CIDR -split '/')[1] }
$HostBits = 32 - $CIDR



$NetworkIDinBinary = $Binary.Substring(0,$CIDR)
$FirstHost = $NetworkIDinBinary.Padright(32,'0')
$LastHost = $NetworkIDinBinary.padright(32,'1')

#Getting IP of Hosts #######################################
$x = 1


while ($FirstHost -lt $LastHost) {
   
    $Octet1 = $FirstHost[0..7] -join "" | ForEach-Object {[System.Convert]::ToByte($_,2)}
    $Octet2 = $FirstHost[8..15] -join "" | ForEach-Object {[System.Convert]::ToByte($_,2)}
    $Octet3 = $FirstHost[16..23] -join "" | ForEach-Object {[System.Convert]::ToByte($_,2)}
    $Octet4 = $FirstHost[24..31] -join "" | ForEach-Object {[System.Convert]::ToByte($_,2)}

    $NewIPAddress = $Octet1,$Octet2,$Octet3,$Octet4 -join "."

    if(!($NewIPAddress -like "*.0")){
        $IPSubnetList.add($NewIPAddress) | out-null
    }
    $NetworkBitsinBinary = $FirstHost.Substring(0,$FirstHost.Length-$HostBits)

    $xInBinary = [System.Convert]::ToString($x,2).padleft($HostBits,'0')

    $FirstHost = $NetworkBitsinBinary+$xInBinary

    ++$x

    }

# Adds Last IP because the while loop refuses to for whatever reason #
    $Octet1 = $LastHost[0..7] -join "" | ForEach-Object {[System.Convert]::ToByte($_,2)}
    $Octet2 = $LastHost[8..15] -join "" | ForEach-Object {[System.Convert]::ToByte($_,2)}
    $Octet3 = $LastHost[16..23] -join "" | ForEach-Object {[System.Convert]::ToByte($_,2)}
    $Octet4 = $LastHost[24..31] -join "" | ForEach-Object {[System.Convert]::ToByte($_,2)}

    
    $NewIPAddress = $Octet1,$Octet2,$Octet3,$Octet4 -join "."
    
    if(!($NewIPAddress -like "*.255")){
        $IPSubnetList.add( $NewIPAddress) | out-null
    }

# Calls on IP List #######################################
   return $IPSubnetList
}
function Enumerator([System.Collections.ArrayList]$iparray) {

<#
    Enumerator asynchronously pings and asynchronously performs DNS name resolution.
#>
    Build-Directories

    

    if($adEnumeration){
        Write-host -ForegroundColor Green "[+]Checking Windows OS Type"
   
        foreach($i in $iparray){
            $nodeObj = [PSCustomObject]@{
                HostName = ""
                IPAddress = ""
                OperatingSystem = ""
                TTL = 0
            }
            $nodeObj.Hostname = $i
            if($null -ne $i) {                
                    (Invoke-Command -ComputerName $i -ScriptBlock  {(Get-WmiObject win32_operatingsystem).caption} -AsJob -JobName $i) | out-null               
                    }
                }get-job | wait-job | out-null
    }
    else{
        <#
            Asynchronously Ping
        #>
        $task = foreach($ip in $iparray){
            ((New-Object System.Net.NetworkInformation.Ping).SendPingAsync($ip))
        }[threading.tasks.task]::WaitAll($task)

        
        $result = $task.Result
        
        $result = $result | Where-Object{($_.status -eq "Success") -and ($_.address -ne "0.0.0.0") -and ($iparray.Contains($_.Address.IPAddressToString))}
        
        $duplicateIp = [System.Collections.ArrayList]@()
        foreach($i in $result){
            if(!$duplicateIp.Contains($i.Address.IPAddressToString)){

                $duplicateIp.add($i.Address.IPAddressToString) | out-null

                $nodeObj = [Node]::new()
                
                $nodeObj.IPAddress = $i.Address.IPAddressToString
                
                $nodeObj.TTL = $i.Options.ttl
                
                $ttl = $nodeObj.TTL
                if($ttl -le 64 -and $ttl -ge 45){
                    $nodeObj.OperatingSystem = "*NIX"
                }elseif($ttl -le 128 -and $ttl -ge 115){
                    $nodeObj.OperatingSystem = "Windows"
                
                }elseif($ttl -le 255 -and $ttl -ge 230){
                    $nodeObj.OperatingSystem = "Cisco"
                }

            
                $global:nodeList.Add($nodeObj)
            }
        }

        write-host -ForegroundColor Green "[+]There are" ($nodeList | Measure).count "total live hosts."
        Write-Host -ForegroundColor Green "[+]Connection Testing Complete beep boop beep"
        Write-Host -ForegroundColor Green "[+]Starting Reverse DNS Resolution"

        <#
            Asynchronously Resolve DNS Names
        #>
        
        $dnsTask = foreach($i in $nodeList){
                    [system.net.dns]::GetHostEntryAsync($i.ipaddress)
                    
        }[threading.tasks.task]::WaitAll($dnsTask) | out-null

        $dnsTask = $dnsTask | Where-Object{$_.status -ne "Faulted"}

        $nodelist = $nodelist | Sort-Object ipaddress
        
        foreach($i in $dnsTask){
            $hostname = (($i.result.hostname).split('.')[0]).toUpper()
            $ip = ($i.result.addresslist.Ipaddresstostring)
            if(($null -ne $ip) -and ($Null -ne $hostname) -and ($ip -ne "") -and ($hostname -ne "")){
                $index = Binary-Search $nodeList $ip ipaddress
                if(($index -ne "") -and ($null -ne $index)){
                    $nodeList[$index].hostname = $hostname
                }
            }
            
        }
            
        Write-Host -ForegroundColor Green "[+]Reverse DNS Resolution Complete"   

        Write-host -ForegroundColor Green "[+]Checking Windows OS Type"

        foreach($i in $nodeList){
            if(($i.operatingsystem -eq "Windows")){
                $comp = $i.ipaddress
                Write-Host -ForegroundColor Green "Starting OS ID Job on:" $comp
                if(($i.hostname -ne "") -and ($null -ne $i.hostname)){
                    #Start-Job -Name $comp -ScriptBlock {gwmi win32_operatingsystem -ComputerName $using:comp -ErrorAction SilentlyContinue}|Out-Null
                    
                    Invoke-Command -ComputerName $i.hostname -ScriptBlock {Get-WmiObject win32_operatingsystem -ErrorAction SilentlyContinue} -AsJob -JobName $comp | out-null
                } else {
                    Write-Host "NO HOSTNAME FOR $comp"
                }
            }
        }
        
    }
    Write-Host -ForegroundColor Green "[+]All OS Jobs Started"
    
    $poll = $true
    
    $refTime = (Get-Date)
    while($poll){
        foreach($job in (get-job)){
            $time = (Get-Date)
            $elapsed = ($time - $job.PSBeginTime).minutes
            if($job.state -eq "completed"){

                 $osinfo = Receive-Job $job -ErrorAction SilentlyContinue
                 remove-job $job
                 if(($null -ne $osinfo) -and ($osinfo -ne "") -and ($osinfo.csname -ne "") -and ($null -ne $osinfo.csname)){

                    $hostname = (($osinfo.CSName).split('.')[0]).toUpper()
                    
                    foreach($i in $nodeList){
                        if($i.IPAddress -eq $job.name){
                            $i.hostname = $hostname
                            $i.operatingsystem =$osinfo.caption
                        }
                    }
                }
            }
            elseif($job.State -eq "failed"){
                Remove-Job $job.id -Force
            }
            elseif(($elapsed -ge $jobTimeOutThreshold) -and ($job.state -ne "Completed")){
                Write-Host "Stopping Job:" $job.Name
                $job | stop-job
            }
        }Start-Sleep -Seconds 8
        if((get-job | Where-Object state -eq "completed" |measure).Count -eq 0){
            if((get-job | Where-Object state -eq "failed" |measure).Count -eq 0){
                if((get-job | Where-Object state -eq "Running" |measure).Count -lt $runningJobThreshold){
                    $poll = $false
                    Write-Host "Total Elapsed:" ((get-date) - $refTime).Minutes
                }
            }
        }
    }
    <#
        Create the DnsMapper.csv
    #>
    $nodeList.getEnumerator() | Select-Object -Property @{N='HostName';E={$_.hostname}},@{N='IPAddress';E={$_.IPAddress}},@{N='OperatingSystem';E={$_.OperatingSystem}},@{N='TTL';E={$_.TTL}} | Export-Csv -path "$outfolder\NodeList.csv" -NoTypeInformation
    Write-Host -ForegroundColor Green "[+]NodeList.csv created"

    Get-Job
    write-host -ForegroundColor Green "Operating System identification jobs are done."    

    Get-Job | Where-Object{$_.state -ne "Stopped"} | Remove-Job -Force

}

function Memory-Dumper{
    #TODO:Adapt this for other memory dump solutions like dumpit
     <#
        Create individual folders and files under $home\desktop\Meta-Blue
     #>
    foreach($i in $dnsMappingTable.Values){
        if(!(test-path $outFolder\$i)){
            new-item -itemtype directory -path $outFolder\$i -force
        }
    }
    
    Write-host -ForegroundColor Green "Begin Memory Dumping"

    <#
        Create PSSessions
    #>
    foreach($i in $windowsHosts){
        Write-host "Starting PSSession on" $i
        New-pssession -computername $i -name $i | out-null
    }
    foreach($i in $windowsServers){
        Write-host "Starting PSSession on" $i
        New-pssession -computername $i -credential $socreds -name $i | out-null
    }

    if((Get-PSSession | Measure).count -eq 0){
        return
    }

    write-host -ForegroundColor Green "There are" ((Get-PSSession | Measure).count) "Sessions."

    foreach($i in (Get-PSSession)){
        if(!(invoke-command -session $i -ScriptBlock { Test-Path "c:\winpmem-2.1.post4.exe" })){
            Write-host -ForegroundColor Green "Select winpmem-2.1.post4.exe location:"
            Copy-Item -ToSession $i $(Get-FileName) -Destination "c:\"
        }        
        Invoke-Command -Session $i -ScriptBlock {Remove-Item "$home\documents\memory.aff4" -ErrorAction SilentlyContinue}
        Write-Host "Starting Memory Dump on" $i.computername       
        Invoke-Command -session $i -ScriptBlock  {"$(C:\winpmem-2.1.post4.exe -o memory.aff4)" } -asjob -jobname "Memory Dumps" | Out-Null 
        
    }get-job | wait-job

    Write-host "Collecting Memory Dumps"
    foreach($i in (Get-PSSession)){
        $name = $i.computername
        Write-Host "Collecting" $name "'s dump"
        Copy-Item -FromSession $i "$home\documents\memory.aff4" -Destination "$outFolder\$name memorydump"
    }

    Get-PSSession | Remove-PSSession
    get-job | remove-job -Force

}

<#
    Right now all of these are just out in the open.
    They need to be added to $datapoints or whatever based off of the commandline.
    so something like: Invoke-Collection -light --> that instantiates a lightweight
    collector class etc.
#>
$scriptblock = {Get-ItemProperty "HKLM:\System\CurrentControlSet\services\TermService\Parameters\*"}
$datapoints.Add([DataPoint]::new("TerminalServicesDLL", $scriptblock, $true, "T1505.005")) | Out-Null

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
$datapoints.Add([DataPoint]::new("Screensaver", $scriptblock, $true, "T1546.002")) | Out-Null

$scriptblock = {
    $(Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Select-Object -Property __SERVER, __CLASS, EventNamespace, Name, Query;
    Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object -Property __SERVER, __CLASS, Name;
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Select-Object -Property __server, __CLASS, consumer, filter) 
} 
$datapoints.Add([DataPoint]::new("WMIEventSubscription", $scriptblock, $true, "T1546.003")) | Out-Null

$scriptblock = {(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Netsh')}
$datapoints.Add([DataPoint]::new("NetshHelperDLL", $scriptblock, $true, "T1546.007")) | Out-Null

$scriptblock = {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*' | Select-Object DisableExeptionChainValidation,MitigationOptions,PSPath,PSChildName,PSComputerName}
$datapoints.Add([DataPoint]::new("AccessibilityFeature", $scriptblock, $true, "T1546.008")) | Out-Null

$scriptblock = {Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\appcertdlls\'}
$datapoints.Add([DataPoint]::new("AppCertDLLS", $scriptblock, $true, "T1546.009")) | Out-Null

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
$datapoints.Add([DataPoint]::new("AppInitDLLS", $scriptblock, $true, "T1546.010")) | Out-Null

$scriptblock = {Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-ShimEngine/Operational';}  |Select-Object Message,TimeCreated,ProcessId,ThreadId}
$datapoints.Add([DataPoint]::new("ApplicationShimming", $scriptblock, $true, "T1546.011")) | Out-Null

$scriptblock = {Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" -name Debugger -ErrorAction SilentlyContinue}
$datapoints.Add([DataPoint]::new("ImageFileExecutionOptions", $scriptblock, $true, "T1546.012")) | Out-Null

$scriptblock = {
                test-path $pshome\profile.ps1
                test-path $pshome\microsoft.*.ps1
                test-path "c:\users\*\My Documents\powershell\Profile.ps1"
                test-path "C:\Users\*\My Documents\microsoft.*.ps1"
             
             }
$datapoints.Add([DataPoint]::new("PowershellProfile", $scriptblock, $true, "T1546.013")) | Out-Null

$scriptblock = {get-itemproperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -name "Authentication Packages"}
$datapoints.Add([DataPoint]::new("AuthenticationPackage", $scriptblock, $true, "T1547.002")) | Out-Null

$scriptblock = {Get-ItemProperty HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\* | Select-Object dllname,pspath}
$datapoints.Add([DataPoint]::new("TimeProviders", $scriptblock, $true, "T1547.003")) | Out-Null

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
$datapoints.Add([DataPoint]::new("WinlogonHelperDLL", $scriptblock, $true, "T1547.004")) | Out-Null

$scriptblock = {
    $(
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "Security Packages";
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\" -Name "Security Packages" -ErrorAction SilentlyContinue
    )
}
$datapoints.Add([DataPoint]::new("SecuritySupportProvider", $scriptblock, $true, "T1547.005")) | Out-Null

$scriptblock = {
            Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4614';} -ErrorAction SilentlyContinue;
            Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='3033';} -ErrorAction SilentlyContinue;
            Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='3063';} -ErrorAction SilentlyContinue
            }
$datapoints.Add([DataPoint]::new("LSASSDriver", $scriptblock, $true, "T1547.008")) | Out-Null

$scriptblock = {Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\*" -name driver}
$datapoints.Add([DataPoint]::new("PortMonitors", $scriptblock, $true, "T1547.010")) | Out-Null

$scriptblock = {
    $(
        Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Control\Print\Environments\*\Print Processors\*";
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors\*"
    )    
}
$datapoints.Add([DataPoint]::new("PrintProcessors", $scriptblock, $true, "T1547.012")) | Out-Null

$scriptblock = {get-itemproperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*" | Select-Object componentid,stubpath,pspath}
$datapoints.Add([DataPoint]::new("ActiveSetup", $scriptblock, $true, "T1547.014")) | Out-Null

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
$datapoints.Add([DataPoint]::new("AlternateDataStreams", $scriptblock, $true, "T1564.004")) | Out-Null

# This one is hot garbage as well. 
$scriptblock = {(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs\')}
$datapoints.Add([DataPoint]::new("KnownDLLs", $scriptblock, $true)) | Out-Null


$scriptblock = {
    (Get-ChildItem -path C:\Windows\System32\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid");
    (Get-ChildItem -path C:\Windows\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid")
}
$datapoints.Add([DataPoint]::new("DLLSearchOrderHijacking", $scriptblock, $true, "T1574.001")) | Out-Null

$scriptblock = {Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Bits-Client/Operational'; Id='59'} | Select-Object -Property message,pscomputername,id,logname,processid,userid,timecreated}
$datapoints.Add([DataPoint]::new("BITSJobsLogs", $scriptblock, $true, "T1197")) | Out-Null

$scriptblock = {Get-BitsTransfer -AllUsers}
$datapoints.Add([DataPoint]::new("BITSTransfer", $scriptblock, $true, "T1197")) | Out-Null

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
$datapoints.Add([DataPoint]::new("Services", $scriptblock, $true, "T1543.003")) | Out-Null

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
$datapoints.Add([DataPoint]::new("ScheduledTasks", $scriptblock, $true, "T1053.005 ")) | Out-Null

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
$datapoints.Add([DataPoint]::new("PortProxies", $scriptblock, $true, "T1090")) | Out-Null

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
$datapoints.Add([DataPoint]::new("SecurityLogCleared", $scriptblock, $true, "T1070.001")) | Out-Null

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
$datapoints.Add([DataPoint]::new("SIPandTrustProviderHijacking", $scriptblock, $true, "T1553.003")) | Out-Null

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
                

                $registry = [PSCustomObject]@{
                    
                    BootShell = [string](Get-ItemProperty "HKLM:\system\CurrentControlSet\Control\Session Manager\" -name bootshell).bootshell

                    BootExecute = [string](Get-ItemProperty "HKLM:\system\CurrentControlSet\Control\Session Manager\" -name BootExecute).BootExecute

                    NetworkList = [String]((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\UnManaged\*' -ErrorAction SilentlyContinue).dnssuffix)

                    HKLMRun = [String](get-item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\' -ErrorAction SilentlyContinue).property
                    HKCURun = [String](get-item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\' -ErrorAction SilentlyContinue).property
                    HKLMRunOnce = [String](get-item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\' -ErrorAction SilentlyContinue).property
                    HKCURunOnce = [String](Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\' -ErrorAction SilentlyContinue).property
                    HKLMRunOnce32 = [String](Get-Item 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\' -ErrorAction SilentlyContinue).property
                    HKLMRun32 = [String](Get-Item 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\' -ErrorAction SilentlyContinue).property


                    Manufacturer = [String](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation\' -ErrorAction SilentlyContinue).manufacturer
                    ShimCustom = [String](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom' -ErrorAction SilentlyContinue)
                    Powershellv2 = if((test-path HKLM:\SOFTWARE\Microsoft\PowerShell\1\powershellengine\)){$true}else{$false}
                }
                $registry
        
            }
$datapoints.Add([DataPoint]::new("RegistryMisc", $scriptblock, $true, "T1547.001")) | Out-Null

function Find-File{
    if(!$localBox){
        do{
            $findfile = Read-Host "Do you want to find some files?(Y/N)"
            if($findfile -ieq 'y'){
                $fileNames = [system.collections.arraylist]@()
                $fileNameFile = Get-FileName
                $fileNameFileImport = import-csv $filenamefile
                foreach($file in $filenamefileimport){$filenames.Add($file.filename) | Out-Null}
                Write-host "Starting File Search Jobs"
                <#
                    OK how the fuck am i gonna do this 
                #> 
                foreach($i in (Get-PSSession)){
                     (Invoke-Command -session $i -ScriptBlock{
                        $files = $using:filenames;
                        Set-Location C:\Users;
                        Get-ChildItem -Recurse | Where-Object{$files.Contains($_.name)}         
                     }  -asjob -jobname "FindFile")| out-null         
                }Create-Artifact
                break
            }elseif($findfile -ieq 'n'){
                return $false
            }else{
                Write-host "Not a valid option"
            }
           }while($true)
       }
}

function TearDown-Sessions{
    if(!$localBox){
        if($isRanAsSchedTask -eq $true){
            Remove-PSSession * | out-null
            return $true
        }
        else{
            do{
                $sessions = Read-Host "Do you want to tear down the PSSessions?(y/n)"

                if($sessions -ieq 'y'){
                        Remove-PSSession * | out-null
                        return $true
                }
                elseif($sessions -ieq 'n'){
                    return $false
                }
                else{
                    Write-Host "Not a valid option"
                }
            }while($true)
        }
        
    }
}

function Build-Sessions{
    if(!$localBox){
        $excludedHosts = @()

        #Set-Item WSMan:\localhost\Shell\MaxShellsPerUser -Value 10000
        #Set-Item WSMan:\localhost\Plugin\microsoft.powershell\Quotas\MaxShellsPerUser -Value 10000
        #Set-Item WSMan:\localhost\Plugin\microsoft.powershell\Quotas\MaxShells -Value 10000
        <#
            Clean up and broken PSSessions.
        #>
        $brokenSessions = (Get-PSSession | Where-Object{$_.State -eq "Broken"}).Id
        if($null -ne $brokenSessions){
            Remove-PSSession -id $brokenSessions
        }
        $activeSessions = (Get-PSSession | Where-Object{$_.State -eq "Opened"}).ComputerName

        if(test-path $excludedHostsFile){
            $excludedHosts = import-csv $excludedHostsFile
        }

        <#
            Create PSSessions
        #>
        
        foreach($i in $global:nodeList){
            if($null -ne $activeSessions){
                if(!$activeSessions.Contains($i.hostname)){
                    if(($i.hostname -ne "") -and ($i.operatingsystem -like "*Windows*") -and (!$excludedHosts.hostname.Contains($i.hostname))){
                        Write-host "Starting PSSession on" $i.hostname
                        New-pssession -computername $i.hostname -name $i.hostname -SessionOption (New-PSSessionOption -NoMachineProfile -MaxConnectionRetryCount 5) -ThrottleLimit 100| out-null
                    }
                }else{
                    Write-host "PSSession already exists:" $i.hostname -ForegroundColor Red
                }
            }else{
                if(($i.hostname -ne "") -and ($i.operatingsystem -like "*windows*") -and (!$excludedHosts.hostname.Contains($i.hostname))){
                    Write-host "Starting PSSession on" $i.hostname
                    New-pssession -computername $i.hostname -name $i.hostname -SessionOption (New-PSSessionOption -NoMachineProfile -MaxConnectionRetryCount 5) -ThrottleLimit 100| out-null
                }
            }
        }
        
    
        if((Get-PSSession | Measure).count -eq 0){
            return
        }    

        write-host -ForegroundColor Green "There are" ((Get-PSSession | Measure).count) "Sessions."
    } 

}

function WaitFor-Jobs{
    while((get-job | Where-Object state -eq "Running" |Measure).Count -ne 0){
            get-job | Format-Table -RepeatHeader
            Start-Sleep -Seconds 10
    }

}

function Enable-PSRemoting{
    
    foreach($node in $global:nodeList){
        wmic /node:$($node.IpAddress) process call create "powershell enable-psremoting -force"
    }
}

function Collect($dp){
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
    
    write-host "[+]Starting" $dp.jobname "Jobs"

    if($localBox){
        #$s = New-PSSession -ComputerName $env:COMPUTERNAME
        #Register-ObjectEvent -InputObject ((Invoke-Command -Session $s -ScriptBlock $dp.scriptblock -AsJob -JobName $dp.jobname) | Out-Null) -EventName StateChanged -Action $action
        Register-ObjectEvent -MessageData $env:COMPUTERNAME -InputObject (Start-Job -Name $dp.jobname -ScriptBlock $dp.scriptblock) -EventName StateChanged -Action $action | out-null
        
    }else{
        foreach($i in (Get-PSSession)){
            Register-ObjectEvent -MessageData $i.ComputerName -InputObject ((Invoke-Command -session $i -ScriptBlock $dp.scriptblock -asjob -jobname $dp.jobname)) -EventName StateChanged -Action $action           
        }        
    }
}

function Meta-Blue {    
    
    Build-Directories
    Build-Sessions
        
    <#
        Begining the artifact collection. Will start one job per session and then wait for all jobs
        of that type to complete before moving on to the next set of jobs.
    #>
    Write-host -ForegroundColor Green "[+]Begin Artifact Gathering"  
    
    foreach($datapoint in $datapoints){
        if($datapoint.isEnabled){
            Collect $datapoint
        }
    }

    WaitFor-Jobs
    if(!$localBox){
        TearDown-Sessions
    }
    #Set-Location $outFolder
         
}

function Show-TitleMenu{
     Clear-Host 
     Write-Host "================META-BLUE================"
     Write-Host "Tabs over spaces. Ain't nothin but a G thang"
    
     Write-Host "1: Press '1' to run Meta-Blue as enumeration only."
     Write-Host "2: Press '2' to run Meta-Blue as both enumeration and artifact collection."
     Write-Host "3: Press '3' to audit snort rules."
     Write-Host "4: Press '4' to remotely perform dump."
     Write-Host "5: Press '5' to run Meta-Blue against the local box."
     Write-Host "6: Press '6' to generate an IP space text file."
     Write-Host "Q: Press 'Q' to quit."
    
     $selection = Read-Host "Please make a selection (title)"
     switch ($selection)
     {
           '1' {
                Clear-Host
                show-EnumMenu
                break
           } '2' {
                Clear-Host
                Show-CollectionMenu
                break
           } '3' {
                Clear-Host                
                Audit-Snort
                break    
           } '4'{
                Clear-Host
                Show-MemoryDumpMenu
                break
           
           }'5'{
                $localBox = $true
                Meta-Blue
                break
           
           }'6'{
                Generate-IPSpaceTextFile
                Write-Host -ForegroundColor Green "[+]File saved to $($outFolder)\ipspace.txt"
                Set-Location $outFolder
                break
           }

            'q' {
                break 
           } 

     }break
    
}

function Show-EnumMenu{
     
     Clear-Host
     Write-Host "================META-BLUE================"
     Write-Host "============Enumeration Only ================"
     Write-Host "      Do you have a list of hosts?"
     Write-Host "1: Yes"
     Write-Host "2: No"
     Write-Host "3: Return to previous menu."
     Write-Host "Q: Press 'Q' to quit."

                do{
                $selection = Read-Host "Please make a selection(enum)"
                switch ($selection)
                {
                    '1' {
                            $PTL = [System.Collections.arraylist]@()
                            $ptlFile = get-filename                        
                            if($ptlFile -eq ""){
                                Write-warning "Not a valid path!"
                                pause
                                show-enummenu
                            }
                            if($ptlFile -like "*.csv"){
                                $ptlimport = import-csv $ptlFile
                                foreach($ip in $ptlimport){$PTL.Add($ip.ipaddress) | out-null}
                                Enumerator($PTL)
                            }if($ptlFile -like "*.txt"){
                                $PTL = Get-Content $ptlFile
                                Enumerator($PTL)
                            }
                            break
                        }
                    '2'{
                            Write-Host "Running the default scan"
                            $subnets = Read-Host "How many seperate subnets do you want to scan?"

                            $ips = @()

                            for($i = 0; $i -lt $subnets; $i++){
                                $ipa = Read-Host "[$($i +1)]Please enter the network id to scan"
                                $cidr = Read-Host "[$($i +1)]Please enter the CIDR"
                                $ips += Get-SubnetRange -IPAddress $ipa -CIDR $cidr
                            }
                            Enumerator($ips)
                            break
                        }
                    '3'{
                            Show-TitleMenu
                            break
                    }
                    'q' {
                            break
                        }
                }
            }until ($selection -eq 'q')
}

function Show-CollectionMenu{
    Clear-Host
    Write-Host "================META-BLUE================"
    Write-Host "============Artifact Collection ================"
    Write-Host "          Please Make a Selection               "
    Write-Host "1: Collect from a list of hosts"
    Write-Host "2: Collect from a network enumeration"
    Write-Host "3: Collect from active directory list (RSAT required!!)"
    Write-Host "4: Return to Previous menu."
    Write-Host "Q: Press 'Q' to quit."

                do{
                $selection = Read-Host "Please make a selection(collection)"
                switch ($selection)
                {
                    '1' {
                            $PTL = [System.Collections.arraylist]@()
                            $ptlFile = get-filename                        
                            if($ptlFile -eq ""){
                                Write-warning "Not a valid path!"
                                pause
                                show-enummenu
                            }
                            if($ptlFile -like "*.csv"){
                                $ptlimport = import-csv $ptlFile
                                foreach($node in $ptlimport){
                                    if($node.OperatingSystem -like "*windows*"){
                                        $nodeObj = [PSCustomObject]@{
                                            HostName = ""
                                            IPAddress = ""
                                            OperatingSystem = ""
                                            TTL = 0
                                        }
                                        $nodeObj.Hostname = $node.hostname
                                        $nodeObj.IPaddress = $node.IPAddress
                                        $nodeObj.OperatingSystem = $node.OperatingSystem
                                        $nodeObj.TTL = $node.TTL
                                        $global:nodeList.Add($nodeObj) | out-null
                                    }
                                }
                                
                                Build-Sessions
                            }if($ptlFile -like "*.txt"){
                                $PTL = Get-Content $ptlFile
                                Enumerator($PTL)
                            }
                            Meta-Blue
                            break
                        }
                    '2'{
                            Write-Host "Running the default scan"
                            $subnets = Read-Host "How many seperate subnets do you want to scan?"

                            $ips = @()

                            for($i = 0; $i -lt $subnets; $i++){
                                $ipa = Read-Host "[$($i +1)]Please enter the network id to scan"
                                $cidr = Read-Host "[$($i +1)]Please enter the CIDR"
                                $ips += Get-SubnetRange -IPAddress $ipa -CIDR $cidr
                            }
                            Enumerator($ips)
                            Build-Sessions
                            Meta-Blue
                            break
                        }
                    '3'{
                            $adEnumeration = $true
                            $iparray = (Get-ADComputer -filter *).dnshostname
                            Enumerator($iparray)
                            Meta-Blue
                            break                           
                    
                        }
                    '4'{
                            Show-TitleMenu
                            break
                    }
                    'q' {
                  
                            break
                        }
                }
            }until ($seleciton -eq 'q')
}

function Show-MemoryDumpMenu{   
    do{
        Clear-Host
        Write-Host "================META-BLUE================"
        Write-Host "============Memory Dump ================"
        Write-Host "      Do you have a list of hosts?"
        Write-Host "1: Yes"
        Write-Host "2: Return to previous menu."
        Write-Host "Q: Press 'Q' to quit."
        $selection = Read-Host "Please make a selection(dump)"
        switch ($selection)
        {
            '1' {
                    $hostsToDump = [System.Collections.arraylist]@()
                    $hostsToDumpFile = get-filename                        
                    if($hostsToDumpFile -eq ""){
                        Write-warning "Not a valid path!"
                        pause
                        }else{
                        $dumpImport = import-csv $hostsToDumpFile
                        foreach($ip in $dumpImport){$hostsToDump.Add($ip.ipaddress) | out-null}
                        Enumerator($hostsToDump)
                        Memory-Dumper
                        break
                    }
                }
            '2'{
                    Show-TitleMenu
                    break
                }
            'q' {
                    break
                }
        }
    }until ($selection -eq 'q')
}

show-titlemenu 