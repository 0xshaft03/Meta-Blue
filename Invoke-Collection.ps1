using module .\Modules\DataPoint.psm1
function Invoke-Collection {
<#
.SYNOPSIS
    Invoke-Collection is a mass survey tool that facilitates the rapid collection 
    of curated data points from Microsoft Windows hosts.

.DESCRIPTION
    
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
        [ValidateSet('Light', 'Medium', 'Heavy', 'Dreadnought', 'Custom')]
        [string]$CollecterSize = 'Light',

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [switch]$Enumerate,

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [ValidateNotNullOrEmpty()]
        [string]$Subnet,

        [Parameter(ParameterSetName = 'RemoteCollect')]
        [Parameter(ParameterSetName = 'Enumeration')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ActiveDirectoryComputers', 'TextFile', 'CSVFile')]
        [string]$ComputerSet,
        
        [Parameter(Mandatory)]
        [string]$OutFolder = "C:\Meta-Blue"
    )
    BEGIN {
        $timestamp = (get-date).Tostring("yyyy_MM_dd_hh_mm_ss")
        if($Null -eq $ComputerSet){
        }
        if(!(Test-Path -Path "$OutFolder\$timestamp")){
            Write-Verbose "Creating $OutFolder\$timestamp"
            new-item -itemtype directory -path "$outFolder\$timestamp" -Force | Out-Null
            Write-Verbose "Creating $OutFolder\$timestamp\Raw"
            new-item -itemtype directory -path "$outFolder\$timestamp\Raw" -Force | out-null
            Write-Verbose "Creating $OutFolder\$timestamp\Anomalies"
            new-item -itemtype directory -path "$outFolder\$timestamp\Anomalies" -Force | out-null  
        }
        if($CollecterSize -eq "Light"){
            Write-Verbose "Starting Light Collector"
        }
        elseif($CollecterSize -eq "Medium"){
            Write-Verbose "Starting Medium Collector"
        }
        elseif($CollecterSize -eq "Heavy"){
            Write-Verbose "Starting Heavy Collector"
        }
        elseif($CollecterSize -eq "Dreadnought"){
            Write-Verbose "Starting Dreadnought Collector"
        }
    
    }
    PROCESS {
        if($PSCmdlet.ParameterSetName -eq "LocalCollect"){
            Write-Verbose "Starting the Local Collecter"
        }
        
    }
    END {

    }
}