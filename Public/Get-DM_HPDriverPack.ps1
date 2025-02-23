Function Get-DM_HPDriverPack ()
{
        <#
        .SYNOPSIS
        Retreives the HP driver pack information for a PlatformID, OS, and OS Build.

        .DESCRIPTION
        Retreives the HP driver pack information for a PlatformID, OS, and OS Build.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies of the driver pack is Test or Prod. This allows two separate drive packs for each Platform, OS and Build.

        .PARAMETER PackageContentPath
        The path where the driver pack will be created.

        Use can set the following to provide a default value, or just pass the value on the command line.

        $PSDefaultParameterValues["*-DM*:PackageContentPath"] = "\\path\you\wish\to\use"

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
        RootPath   : \\corp.viamonstra.com\CMSource\OSD\Drivers\DriverPacks\HP
        Path       : \\corp.viamonstra.com\CMSource\OSD\Drivers\DriverPacks\HP\Test\Win10\22H2\DDDD
        Status     : Test

        .EXAMPLE
        Get-DM_HPDriverPack -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test

        .EXAMPLE
        Get-DM_HPDriverPack -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Test

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [string]$PlatformID,
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
    [string]$PackageContentPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin{
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $DPDestination = Join-Path $PackageContentPath "HP"

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ((Invoke-PathPermissionsCheck -Path $PackageContentPath) -eq $false) { break }

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
        $DPPath = join-path $DPDestination $Status\$OS\$OSBuild\$PlatformID

        Write-CMTraceLog -Message "PlatformID: $PlatformID" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "OS: $OS" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "OSBuild: $OSBuild" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "RootPath: $DPDestination" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "Path: $DPPath" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "Status: $Status" -Component $Component -type 1 -Logfile $LogFile 
        
        If (Test-Path $DPPath)
        {
            If (Test-Path (Join-Path $DPPath DriverInfo.txt))
            {
                $DriverPackCreatedInfo = Get-Content (Join-Path $DPPath DriverInfo.txt)
                [datetime]$DriverPackCreatedDate = $DriverPackCreatedInfo | Where-Object {$_ -match "Date Created:"} | ForEach-Object {$_.substring(14)}

                $DriverPackCreatedMonthYear = $($DriverPackCreatedDate).ToString("yyyy-MM")
            }
            
            $props = [pscustomobject]@{
                'PlatformID'=$PlatformID
                'OS'=$OS
                'OSBuild'=$OSBuild
                'RootPath'=$DPDestination
                'Path'=$DPPath
                'Status'=$((Get-Culture).TextInfo.ToTitleCase($Status))
                'LastUpdated' = $DriverPackCreatedMonthYear         
            }

            return, $props;
        }
        else
        {
            Write-CMTraceLog -Message "DriverPack path $DPPath does not exist." -Component $Component -type 2 -Logfile $LogFile 
            Write-Warning "DriverPack path $DPPath does not exist."
        }
    }
}