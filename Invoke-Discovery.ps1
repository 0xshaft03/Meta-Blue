function Invoke-Discovery {
    <#
    .SYNOPSIS
        
    
    .DESCRIPTION
        
    .PARAMETER DomainName
        The target domain name in which to pull computer objects from 
        for enumeration.

    .PARAMETER IPAddress
        The IP address or addresses to enumerate.

    .PARAMETER CIDR
        The subnet mask in CIDR notation for the addresses to scan.

    .PARAMETER InputFile
        The file with the hostnames or IP addresses to enumerate.

    .EXAMPLE
    .EXAMPLE
    .INPUTS
    .OUTPUTS
        nodelist.csv
    .NOTES
        Author: 0xshaft03
    #>
    [CmdletBinding(HelpUri="https://github.com/0xshaft03/Meta-Blue")]
    param (
        [Parameter(ParameterSetName = 'ActiveDirectory')]
        [string]$DomainName,

        [Parameter(ParameterSetName = 'IPAddresses')]
        [string[]]$IPAddress,

        [Parameter(ParameterSetName = 'IPAddresses')]
        [int]$CIDR,

        [Parameter(ParameterSetName = 'InputFile')]
        [string]$InputFile,

        [Parameter()]
        [string]$OutputFile

    )

    BEGIN {

    }

    PROCESS{

    }

    END{

    }

}