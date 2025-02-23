Function Invoke-DM_HPRepositorySyncToProd ()
{
        <#
        .SYNOPSIS
        Copies a test HP driver repository to the prod location.

        .DESCRIPTION
        Copies a well tested test repository to the prod location.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        If you need to copy multiple repositories at a time, you can pass multiple Platform IDs at a time.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies that status of the repository to be copied. This parameter is optional.
        
        .PARAMETER PackageContentPath
        Path of the driver repository to copy. This is an optional parameter.

        .PARAMETER OverrideVPNCheck
        The repository copy can take a long time over a VPN connection. If the -OverrideVPNCheck parameter is passed, the built-in VPN check will be bypassed.

        .PARAMETER Force
        If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        Outputs a custom object that contains the details of the copied prod repository.

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
        RootPath   : \\corp.viamonstra.com\shared\WorkstationDriverRepository
        Path       : \\corp.viamonstra.com\shared\WorkstationDriverRepository\Test\Win10\22H2\DDDD
        Status     : Test

        .EXAMPLE
        Invoke-DM_HPRepositorySyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test

        .EXAMPLE
        Invoke-DM_HPRepositorySyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test -Force

        .EXAMPLE
        Invoke-DM_HPRepositorySyncToProd -PlatformID AAAA,BBBB -OS Win11 -OSBuild 24H2 -Status Test -Force

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [string[]]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [Parameter(Mandatory=$True,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [switch]$OverrideVPNCheck,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-Warning "The Invoke-DM_HPRepositorySyncToProd function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again."
            Write-CMTraceLog -Message "The Invoke-DM_HPRepositorySyncToProd function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again." -Component $Component -Type 3

            break
        }
    }

    Process
    {
        try{
            $Component = $($myinvocation.mycommand)

            if ($Force -and -not $Confirm)
            {
                $ConfirmPreference = 'None'
            }

            Foreach ($ID in $PlatformID)
            {
                $IDUpper = $ID.ToUpper()
                $SourcePath = $(Join-Path -Path "$HPRepoPath" "Test\$OS\$OSBuild\$IDUpper")
                Write-CMTraceLog -Message "Source path: $SourcePath" -Component $Component -type 1 -Logfile $LogFile 

                $DestPath = $(Join-Path -Path "$HPRepoPath" "Prod\$OS\$OSBuild\$IDUpper")
                Write-CMTraceLog -Message "Dest path: $DestPath." -Component $Component -type 1 -Logfile $LogFile 

                Write-CMTraceLog -Message "Checking for write permission to `"$HPRepoPath`"." -Component $Component -type 1 -Logfile $LogFile
                If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $true)
                {
                    Write-CMTraceLog -Message "Path `"$HPRepoPath`" exists. Script can continue." -Component $Component -type 1 -Logfile $LogFile
                    Write-CMTraceLog -Message "Permissions check to $HPRepoPath path passed." -Component $Component -type 1 -Logfile $LogFile 
                    If (Test-path $SourcePath)
                    {
                        Write-CMTraceLog -Message "Source path exists." -Component $Component -type 1 -Logfile $LogFile 
                        if($PSCmdlet.ShouldProcess($ID,"Sync Test repository for $ID, OS $OS, and OSBuild $OSBuild to Prod" + "?"))
                        {
                            If (-Not (Test-Path $DestPath))
                            {
                                Write-CMTraceLog -Message "Path `"$DestPath`" does not exist. Creating path." -Component $Component -type 1 -Logfile $LogFile 
                                [void][System.IO.Directory]::CreateDirectory($DestPath)
                            }

                            Write-CMTraceLog -Message "Syncing `"Test`" repository for $ID to `"Prod`" for $OS $OSBuild." -Component $Component -type 1 -Logfile $LogFile 
                            Sync-DirWithProgress -SourceDir $(Join-Path -Path "$HPRepoPath" "Test\$OS\$OSBuild\$ID") -DestDir $(Join-Path -Path "$HPRepoPath" "Prod\$OS\$OSBuild\$ID")
                            Write-CMTraceLog -Message "Sync complete." -Component $Component -type 1 -Logfile $LogFile

                            # Write file to show when the repo was last synced from test.
                            "Platform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nDate copied: $((get-date).tostring())`nPerpetrator: $env:USERNAME`nSource Path: $SourcePath`nDest Path: $DestPath" | out-file -FilePath "$(Join-Path -Path "$HPRepoPath" "Prod\$OS\$OSBuild\$IDUpper")\LastSyncFromTest.txt"

                            # Get repo info so we can output the object so the results of this cmdlet can be piped to other cmdlets.
                            $Return = Get-DM_HPRepository -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status Prod

                            If ($Return)
                            {
                                return $Return
                            }
                        }
                    }
                    else
                    {
                        Write-Warning -Message "The path `"$SourcePath`" does not exist."
                        Write-CMTraceLog -Message "The path `"$SourcePath`" does not exist." -Component $Component -type 3 -Logfile $LogFile 
                        break
                    }
                }
                else
                {
                    # Write-CMTraceLog -Message "Path `"$HPRepoPath`" does not exist. Script cannot continue." -Component $Component -type 3 -Logfile $LogFile 
                    Write-Warning "Permissions check failed. Unable to continue. Exiting script."
                    Write-CMTraceLog -Message "Permissions check failed. Unable to continue. Exiting script." -Component $Component -type 3 -Logfile $LogFile 
                    break
                }
            }
        }
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution. $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            # Set-Location $CurrentLocation
        }
    }

    End
    {
        # End
    }
}