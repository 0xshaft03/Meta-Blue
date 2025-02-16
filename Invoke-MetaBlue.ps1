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
        
    )
    BEGIN {
        
    
    }
    PROCESS {
        
    }
    END {

    }
}