function Invoke-MetaBlue {
<#
.SYNOPSIS
    MetaBlue is a mass survey tool that facilitates the rapid collection 
    of curated data points from Microsoft Windows hosts.

.DESCRIPTION
    There are many PowerShell data collection scripts out there for blue
    teams but MetaBlue is the only one that does it at scale and very quickly.

    MetaBlue opens a PSSession on every specified host and runs its queries as
    background jobs which are reaped with PowerShell's powerful event engine.
.PARAMETER ComputerName
.EXAMPLE
.EXAMPLE
.INPUTS
.OUTPUTS
    An ungodly amount of CSVs in your specified directory.
.NOTES
    Author: 0xshaft03
#>

    [CmdletBinding(DefaultParameterSetName = 'LocalCollect')]
    param(

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [Parameter(ParameterSetName = 'LocalCollect')]
        [ValidateSet('Light', 'Medium', 'Heavy', 'Dreadnought', 'Custom')]
        [string]$CollecterSize = 'Light',

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [switch]$Enumerate,

        [Parameter(ParameterSetName = 'Enumeration')]
        [ValidateNotNullOrEmpty()]
        [string]$Subnet,

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ActiveDirectoryComputers', 'TextFile', 'CSVFile')]
        [string]$ComputerSet,

        [Parameter(Mandatory)]
        [string]$OutFolder
    )
    BEGIN {
        if($Null == $ComputerSet){
            
        }
        if($LightCollecter){

        }
        elseif($MediumCollecter){

        }
        elseif($HeavyCollecter){

        }
        elseif($DreadnoughtCollecter){

        }
    
    }
    PROCESS {
        Write-Host "[+] Collecting from $Computername"
        Write-Verbose "its super neat"
    }
    END {

    }
}