function Write-CMTraceLog
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        $Message,
        [Parameter(Mandatory=$false)]
        $ErrorMessage,
        [Parameter(Mandatory=$false)]
        $Component = "Office365",
        [Parameter(Mandatory=$false)]
        [int]$Type,
        [Parameter(Mandatory=$false)]
        $LogFile = "$env:ProgramData\Logs\$Component.log",
        $EnableLogWriteVerbose = $true
        #$LogFile = "$env:ProgramData\Logs\$Component.log"
    )

    # Write-Verbose "Called by: $((Get-PSCallStack)[1].Command)"

    $WhatIfPreference = $false

    Write-Debug "Log file: $LogFile"
    Write-Debug "Component: $Component"

<#     If ($Global:DMLogFile)
    {
        $LogFile = $Global:DMLogFile
        Write-Debug "Log file changed to: $LogFile"
    } #>

    <#
        Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    #>
	    $Time = Get-Date -Format "HH:mm:ss.ffffff"
	    $Date = Get-Date -Format "MM-dd-yyyy"
 
	    if ($ErrorMessage -ne $null) {$Type = 3}
	    if ($Component -eq $null) {$Component = " "}
	    if ($Type -eq $null) {$Type = 1}

        If ($EnableLogWriteVerbose -eq $false)
        {
            Write-Debug "Verbose log messages disabled."
        }
        else
        {
            Write-Verbose -Message "[$((Get-PSCallStack)[1].Command)] $Message"
        }

        $LogPath = Split-Path -path $LogFile

        If (!(Test-Path $LogPath))
        {
            Write-Verbose -Message "Directory $LogPath does not exist and will be created."
            # New-Item -Path $LogPath -ItemType Directory -Force
            [void][System.IO.Directory]::CreateDirectory($LogPath)
        }

	    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
        Write-Debug $LogMessage
	    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile -Confirm:$false
}