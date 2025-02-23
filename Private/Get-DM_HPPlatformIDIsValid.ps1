Function Get-DM_HPPlatformIDIsValid
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [alias('Platform')]
    [string]$PlatformID,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )
    # Get-HPDeviceDetails -Platform $PlatformID -oslist | Where-Object {$_.OperatingSystemRelease -eq $OSBuild -and $_.OperatingSystem -eq "$FullOS"}

    $Component = $($myinvocation.mycommand)

    Write-CMTraceLog -Message "Checking PlatformID $PlatformID to make sure its valid." -Component $Component -type 1 -Logfile $LogFile

    try
    {
        Write-CMTraceLog -Message "Making sure the HPCMSL module is loaded." -Component $Component -type 1 -Logfile $LogFile
        Import-Module -Name HPCMSL -Force -ErrorAction Stop

        If (Get-Module -Name HPCMSL)
        {
            Write-CMTraceLog -Message "HPCMSL is loaded." -Component $Component -type 1 -Logfile $LogFile
            If (Get-HPDeviceDetails -Platform $PlatformID)
            {
                Write-CMTraceLog -Message "PlatformID $PlatformID is valid." -Component $Component -type 1 -Logfile $LogFile
                Write-CMTraceLog -Message "Returning True." -Component $Component -type 1 -Logfile $LogFile
                return $true
            }
            else
            {
                Write-CMTraceLog -Message "PlatformID $PlatformID is not valid." -Component $Component -type 1 -Logfile $LogFile
                Write-CMTraceLog -Message "Returning False." -Component $Component -type 1 -Logfile $LogFile
                return $false
            }
        }
        else
        {
            Write-CMTraceLog -Message "HPCMSL is not loaded." -Component $Component -type 1 -Logfile $LogFile
            Write-Warning "HPCMSL is not loaded. Unable to continue"
            Write-CMTraceLog -Message "Returning False." -Component $Component -type 1 -Logfile $LogFile
            return $false
        }
    }
    catch
    {
        Write-Warning "Something went wrong with checking the PlatformID."
        Write-CMTraceLog -Message "Something went wrong with checking the PlatformID." -Component $Component -type 3 -Logfile $LogFile 
        Write-Warning -Message "An error has occured during script execution."
        Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile 
        Get-ErrorInformation -incomingError $_
    }

    Write-CMTraceLog -Message "Exiting." -Component $Component -type 1 -Logfile $LogFile
}