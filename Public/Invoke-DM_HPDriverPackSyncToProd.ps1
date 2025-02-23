Function Invoke-DM_HPDriverPackSyncToProd ()
{
            <#
        .SYNOPSIS
        Syncs an HP driver pack from test to prod.

        .DESCRIPTION
        Takes a the tested driver pack and copies it to the prod driver pack location.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        If you need to create multiple driver packs at a time, you can pass multiple Platform IDs at a time.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies that status of the repository to be copied. This parameter is optional.

        .PARAMETER PackageContentPath
        Path of the driver pack to copy. This is an optional parameter.

        .PARAMETER OverrideVPNCheck
        The driver pack copy can take a long time over a VPN connection. If the -OverrideVPNCheck parameter is passed, the built-in VPN check will be bypassed.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        None

        .EXAMPLE
        Invoke-DM_HPDriverPackSyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test

        Start a sync for the test platform AAAA and OS Windows 11 24H2.

        .EXAMPLE
        Invoke-DM_HPDriverPackSyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test -Force

        Start a sync for the test platform AAAA and OS Windows 11 24H2 bypassing all confirmation prompts.

        .EXAMPLE
        Copy a test driver pack to proc, then pipe the output to New-DM_CMDriverManagementPackage to either create or update the CM package.

        Invoke-DM_HPDriverPackSyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test -Force | New-DM_CMDriverManagementPackage -PackageType DriverPack -Force -UpdateExistingPackage
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
    [string]$PackageContentPath,
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
            Write-Warning "The Invoke-DM_HPDriverPackSyncToProd function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again."
            Write-CMTraceLog -Message "The Invoke-DM_HPDriverPackSyncToProd function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again." -Component $Component -Type 3

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

            $DPDestination = Join-Path $PackageContentPath "HP"

            Foreach ($ID in $PlatformID)
            {
                $IDUpper = $ID.ToUpper()
                $SourcePath = $(Join-Path -Path "$DPDestination" "Test\$OS\$OSBuild\$IDUpper")
                Write-CMTraceLog -Message "Source path: $SourcePath" -Component $Component -type 1 -Logfile $LogFile 

                $DestPath = $(Join-Path -Path "$DPDestination" "Prod\$OS\$OSBuild\$IDUpper")
                Write-CMTraceLog -Message "Dest path: $DestPath." -Component $Component -type 1 -Logfile $LogFile 

                Write-CMTraceLog -Message "Checking for write permission to `"$DPDestination`"." -Component $Component -type 1 -Logfile $LogFile
                If ((Invoke-PathPermissionsCheck -Path $DPDestination) -eq $true)
                {
                    Write-CMTraceLog -Message "Path `"$DPDestination`" exists. Script can continue." -Component $Component -type 1 -Logfile $LogFile 
                    Write-CMTraceLog -Message "Permissions check to $DPDestination path passed." -Component $Component -type 1 -Logfile $LogFile 
                    If (Test-path $SourcePath)
                    {
                        Write-CMTraceLog -Message "Source path exists." -Component $Component -type 1 -Logfile $LogFile
                        if($PSCmdlet.ShouldProcess($ID,"Sync Test DriverPack for $ID, OS $OS, and OSBuild $OSBuild to Prod" + "?"))
                        {
                            If (-Not (Test-Path $DestPath))
                            {
                                Write-CMTraceLog -Message "Path `"$DestPath`" does not exist. Creating path." -Component $Component -type 1 -Logfile $LogFile 
                                [void][System.IO.Directory]::CreateDirectory($DestPath)
                            }

                            Write-CMTraceLog -Message "Syncing `"Test`" DriverPack for $ID to `"Prod`" for $OS $OSBuild." -Component $Component -type 1 -Logfile $LogFile 
                            Sync-DirWithProgress -SourceDir $SourcePath -DestDir $DestPath
                            Write-CMTraceLog -Message "Sync complete." -Component $Component -type 1 -Logfile $LogFile 

                            # Write file to show when the repo was last synced from test.
                            "Platform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nDate copied: $((get-date).tostring())`nPerpetrator: $env:USERNAME`nSource Path: $SourcePath`nDest Path: $DestPath" | out-file -FilePath "$DestPath\LastSyncFromTest.txt"

                            # Get repo info so we can output the object so the results of this cmdlet can be piped to other cmdlets.
                            $Return = Get-DM_HPDriverPack -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status Prod

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