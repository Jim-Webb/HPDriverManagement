Function Get-DM_HPRepository ()
{
        <#
        .SYNOPSIS
        Retreives the HP driver repository information for a PlatformID, OS, and OS Build.

        .DESCRIPTION
        Retreives the HP driver repository information for a PlatformID, OS, and OS Build.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

        .PARAMETER HPRepoPath
        The path where the repository will be created.

        Use can set the following to provide a default value, or just pass the value on the command line.

        $PSDefaultParameterValues["*-DM*:HPRepoPath"] = "\\path\you\wish\to\use"

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        Outpus a custom object that contains the details of the new repository.

        'PlatformID'
        'OS'
        'OSBuild'
        'RootPath'
        'Path'
        'Status'

        Example:
        PlatformID : DDDD
        OS         : Win10
        OSBuild    : 22H2
        RootPath   : \\corp.viamonstra.com\CMSource\WorkstationDriverRepository
        Path       : \\corp.viamonstra.com\CMSource\WorkstationDriverRepository\Test\Win10\22H2\DDDD
        Status     : Test

        .EXAMPLE
        Get-DM_HPRepository -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test

        .EXAMPLE
        Get-DM_HPRepository -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Test

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [string[]]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Prod", "Test")]
    [string]$Status,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin{
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }

        # [bool]$Global:EnableLogWriteVerbose = $false

        If ((Helper-GetDM_HPCMSLInstallStatus) -eq $false)
        {
            Write-Warning "HPCMSL is not installed. Please install and try again."
            Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
            break
        }
        elseif (!(Get-Module HPCMSL))
        {
            Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
            Import-Module HPCMSL

            If (!(Get-Module HPCMSL))
            {
                Write-Warning "HPCMSL was not imported."
                Write-CMTraceLog -Message "HPCMSL was not imported." -Component $Component -type 1 -Logfile $LogFile 
                break
            }
        }
    }

    Process{

        foreach ($ID in $PlatformID)
        {
            Write-CMTraceLog -Message "------ $ID ------" -Component $Component -type 1 -Logfile $LogFile 

            $RepoPath = join-path $HPRepoPath $Status\$OS\$OSBuild\$ID

            Write-CMTraceLog -Message "PlatformID: $ID" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "OS: $OS" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "OSBuild: $OSBuild" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "RootPath: $HPRepoPath" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "Path: $RepoPath" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "Status: $Status" -Component $Component -type 1 -Logfile $LogFile 
            
            If (Test-Path $RepoPath)
            {
                If (Test-Path (Join-Path $RepoPath LastSync.txt))
                {
                    $RepoLastSync = Get-Content (Join-Path $RepoPath LastSync.txt)
                    [datetime]$RepoLastSyncDate = $RepoLastSync | Where-Object {$_ -match "Last Sync:"} | ForEach-Object {$_.substring(11)}

                    $RepoLastSyncMonthYear = $($RepoLastSyncDate).ToString("yyyy-MM")
                }

                $props = [pscustomobject]@{
                    'PlatformID'=$ID
                    'OS'=$OS
                    'OSBuild'=$OSBuild
                    'RootPath'=$HPRepoPath
                    'Path'=$RepoPath
                    'Status'=$((Get-Culture).TextInfo.ToTitleCase($Status))
                    'LastUpdated' = $RepoLastSyncMonthYear
                }
    
                Write-Output $props
            }
            else
            {
                Write-CMTraceLog -Message "Repository path $RepoPath does not exist." -Component $Component -type 2 -Logfile $LogFile 
                Write-Warning "Repository path $RepoPath does not exist."
            }
        }
    }
}