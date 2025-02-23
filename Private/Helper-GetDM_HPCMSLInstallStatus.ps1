Function Helper-GetDM_HPCMSLInstallStatus ()
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    $Component = $($myinvocation.mycommand)

    $PSDefaultParameterValues = $Global:PSDefaultParameterValues

    If (!(Get-InstalledModule HPCMSL -ErrorAction SilentlyContinue))
    {
        Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
        return $false
    }

    if (!(Get-Module HPCMSL))
    {
        Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile

        if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-CMTraceLog -Message "User is an Admin, importing HPCMSL module with global scope." -Component $Component -type 1 -Logfile $LogFile
            Import-Module HPCMSL
        }
        else
        {
            Write-CMTraceLog -Message "User is not an Admin, importing HPCMSL module with local scope." -Component $Component -type 1 -Logfile $LogFile
            Import-Module HPCMSL -Scope Local
        }

        If (!(Get-Module HPCMSL))
        {
            Write-CMTraceLog -Message "HPCMSL was not imported." -Component $Component -type 1 -Logfile $LogFile 
            return $false
        }
        else
        {   
            Write-CMTraceLog -Message "HPCMSL is imported and loaded." -Component $Component -type 1 -Logfile $LogFile 
            return $true
        }
    }
}