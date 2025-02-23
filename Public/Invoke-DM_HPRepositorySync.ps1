function Invoke-DM_HPRepositorySync ()
{
        <#
        .SYNOPSIS
        Syncs an HP driver repository with HP to download updates.

        .DESCRIPTION
        Syncs an HP driver repository with HP to download updates.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        If you need to create multiple repositories at a time, you can pass multiple Platform IDs at a time.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies if the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

        .PARAMETER HPRepoPath
        Root path when the HP repositories are stored.

        .PARAMETER Cleanup
        Indicates that Invoke-DM_HPRepositorySync should be ran after the sync is complete to remove superseded updates.

        .PARAMETER ProcessRepoExcludes
        By default the repository sync runs Invoke-DM_HPRepositoryExcludeCleanup to remove excluded SP files. Setting this paramter to $false disables that step.

        .PARAMETER ProcessRefImageExcludes
        By default the repository sync runs Invoke-DM_HPIARefFileExclude to remove excluded SP files from the reference image XML file. 
        Setting this paramter to $false disables that step.

        .PARAMETER OverrideVPNCheck
        The repository sync can take a long time over a VPN connection. If the -OverrideVPNCheck parameter is passed, the built-in VPN check will be bypassed.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        None

        .EXAMPLE
        Invoke-DM_HPRepositorySync -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Test

        Start a sync for the test platform 8711 and OS Windows 10 22H2.

        .EXAMPLE
        Invoke-DM_HPRepositorySync -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Prod

        Start a sync for the Prod platform 8711 and OS Windows 10 22H2.

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [string[]]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [switch]$Cleanup,
    [bool]$ProcessRepoExcludes = $true,
    [bool]$ProcessRefImageExcludes = $true,
    [switch]$OverrideVPNCheck,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin {

        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $InformationPreference = 'Continue'

        Helper-GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        Invoke-ModuleVersionCheck -Module "DriverManagement"

        # [bool]$Global:EnableLogWriteVerbose = $false

        $PulseAdapterStatus = (Get-NetAdapter -InterfaceDescription "Juniper Networks Virtual Adapter" -ErrorAction SilentlyContinue).Status

        # If OverrideVPNCheck is passed, set PulseAdapterStatus to False to bypass the prompt.
        if ($PSBoundParameters.ContainsKey('OverrideVPNCheck'))
        {
            $PulseAdapterStatus = 'Down'
            Write-CMTraceLog -Message "Parameter OverrideVPNCheck passed. Bypassing VPN check." -Component $Component -type 1 -Logfile $LogFile 
        }

        if ($PulseAdapterStatus -eq 'Up')
        {
            Write-CMTraceLog -Message "Script running over VPN, prompt to continue." -Component $Component -type 1 -Logfile $LogFile 

            $title    = 'Continue?'
            $question = "Looks like you're connected over the VPN. What your about to do will take a while to complete.`nDo you want to continue?"
            $choices  = '&Yes', '&No'

            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                # Write-Host 'confirmed'
                $Runscript = $True
                Write-CMTraceLog -Message "User decided to continue over VPN." -Component $Component -type 1 -Logfile $LogFile 
            } else {
                # Write-Host 'cancelled'
                $Runscript = $false
                Write-CMTraceLog -Message "User decided not to continue over VPN." -Component $Component -type 1 -Logfile $LogFile 
            }

            <# Write-Host "Looks like you're connected over the VPN. What your about to do will take a while to complete. `nDo you want to continue? (Y/N)"
            $response = read-host
            if ( $response -ne "Y" ) { $VPNConnected = $True }#>
        }
        else
        {
            $Runscript = $True
        }
    }

    process
    {
        If ($Runscript -eq $True)
        {
            # If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.
            if ($Force -and -not $Confirm)
            {
                $ConfirmPreference = 'None'
            }

            $CurrentLocation = Get-Location

           <#  If (!(Get-Module HPCMSL))
            {
                # Write-Verbose "Importing HPCMSL module."
                Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
                Import-Module HPCMSL
            } #>

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

            # If (Test-Path $HPRepoPath)
            If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $true)
            {
                Write-CMTraceLog -Message "Path $HPRepoPath exists." -Component $Component -type 1 -Logfile $LogFile 

                Foreach ($ID in $PlatformID)
                {
                    Write-CMTraceLog -Message "------ $ID ------" -Component $Component -type 1 -Logfile $LogFile 
                    # Write-Verbose "PlatformID: $ID."
                    Write-CMTraceLog -Message "PlatformID: $ID." -Component $Component -type 1 -Logfile $LogFile 
                    $PlatformPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID\Repository"
                    $PlatformRootPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID"

                    If (!(Test-Path $PlatformPath))
                    {
                        Write-Warning "The path $HPRepoPath\$Status\$os\$OSBuild\$ID does not exist. Please use New-NCHHPRepository to create repository."
                        Write-CMTraceLog -Message "The path $HPRepoPath\$Status\$os\$OSBuild\$ID does not exist. Please use New-NCHHPRepository to create repository." -Component $Component -type 1 -Logfile $LogFile 
                        Break
                    }

                    If (Get-Module HPCMSL -Verbose:$false)
                    {
                        Set-Location $PlatformPath
                        Write-Verbose "Location set to $PlatformPath."
                        Write-CMTraceLog -Message "Location set to $PlatformPath." -Component $Component -type 1 -Logfile $LogFile 
                        If ((Test-Path "$PlatformPath\.repository") -and (Test-Path "$PlatformPath\.repository\repository.json"))
                        {
                            #Write-Verbose "Repository exists and has been initilized."
                            Write-CMTraceLog -Message "Repository exists and has been initilized." -Component $Component -type 1 -Logfile $LogFile 

                            try
                            {
                                if($PSCmdlet.ShouldProcess($ID,"Sync repository for platformID $ID, OS $OS, and OSBuild $OSBuild" + "?"))
                                {
                                    # Write-Verbose "Starting sync..."
                                    Write-CMTraceLog -Message "Starting repository sync for platform $ID..." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Starting repository sync for platform $ID..." -InformationAction Continue
                                    if ($PSBoundParameters.ContainsKey('Verbose'))
                                    {
                                        Write-CMTraceLog -Message "Running a verbose repository sync." -Component $Component -type 1 -Logfile $LogFile 
                                        Invoke-RepositorySync
                                    }
                                    else
                                    {
                                        Write-CMTraceLog -Message "Running a quiet repository sync." -Component $Component -type 1 -Logfile $LogFile 
                                        #Invoke-RepositorySync -Quiet
                                        # Removing the Quiet switch for now so that you can see what's happening without the need to use the Verbose option.
                                        Invoke-RepositorySync
                                    }
                                    "Last Sync: $((get-date).tostring())`nPlatform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nPerpetrator: $env:USERNAME" | out-file -FilePath "$PlatformRootPath\LastSync.txt"
                                    # Write-Verbose "Sync complete."
                                    Write-CMTraceLog -Message "Sync complete." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Sync completed." -InformationAction Continue
                                }
                                If ($Cleanup)
                                {
                                    if($PSCmdlet.ShouldProcess($ID,"Perform repository cleanup for platform $ID, OS $OS, and OSBuild $OSBuild" + "?"))
                                    {
                                        Write-CMTraceLog -Message "Cleanup parameter passed." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-CMTraceLog -Message "Starting cleanup." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Starting cleanup." -InformationAction Continue
                                        Invoke-RepositoryCleanup
                                        Write-CMTraceLog -Message "Cleanup complete." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Cleanup complete." -InformationAction Continue
                                    }
                                }

                                Get-HPDeviceDetails -Platform $ID | Out-File "$PlatformRootPath\PlatformInfo.txt"
                                Get-HPDeviceDetails -Platform $ID -OSList | Out-File "$PlatformRootPath\OSSupport.txt"
                                "Platform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nDate created: $((get-date).tostring())`nPerpetrator: $env:USERNAME" | out-file -FilePath "$PlatformRootPath\RepositoryInfo.txt"

                                # Update reference image xml file
                                Write-CMTraceLog -Message "Create new reference image xml file." -Component $Component -type 1 -Logfile $LogFile
                                Write-Information -MessageData "Create new reference image xml file." -InformationAction Continue
                                $Results = Invoke-DM_CreateHPIARefFile -Platform $ID -OS $OS -OSBuild $OSBuild -status $Status -HPRepoPath $HPRepoPath
                                Write-CMTraceLog -Message "Reference image xml file has been created." -Component $Component -type 1 -Logfile $LogFile
                                Write-Information -MessageData "Reference image xml file has been created." -InformationAction Continue

                                If ($ProcessRefImageExcludes -eq $true)
                                {
                                    if($PSCmdlet.ShouldProcess($ID,"Process repository file exclude for platform $ID, OS $OS, and OSBuild $OSBuild" + "?"))
                                    {
                                        Write-CMTraceLog -Message "Start: Reference file exclude update." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Start: Reference file exclude update." -InformationAction Continue

                                        Invoke-DM_HPIARefFileExclude -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -HPRepoPath $HPRepoPath -confirm:$false

                                        Write-CMTraceLog -Message "End: Reference file exclude update." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "End: Reference file exclude update." -InformationAction Continue
                                    }
                                }
                                else
                                {
                                    Write-CMTraceLog -Message "Processing of reference file excludes skipped." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Processing of reference file excludes skipped." -InformationAction Continue
                                }

                                If ($ProcessRepoExcludes -eq $true)
                                {
                                    if($PSCmdlet.ShouldProcess($ID,"Start repository exclude cleanup for platform $ID, OS $OS, and OSBuild $OSBuild" + "?"))
                                    {
                                        # Begin removal of excluded files from repository
                                        Write-CMTraceLog -Message "Start: Excluded file Removal." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Start: Excluded file Removal." -InformationAction Continue

                                        Invoke-DM_HPRepositoryExcludeCleanup -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -HPRepoPath $HPRepoPath -confirm:$false

                                        Write-CMTraceLog -Message "End: Excluded file Removal." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "End: Excluded file Removal." -InformationAction Continue
                                        # End removal of excluded files from repository
                                    }
                                }
                                else
                                {
                                    Write-CMTraceLog -Message "Processing of repository file excludes skipped." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Processing of repository file excludes skipped." -InformationAction Continue
                                }

                                $props = [pscustomobject]@{
                                    #'Model'= $Model
                                    'PlatformID'=$ID
                                    'OS'=$OS
                                    'OSBuild'=$OsBuild
                                    'Status'=$Status            
                                    'Path'=$PlatformRootPath
                                }

                                If ($props)
                                {
                                    return, $props;
                                }
                            }
                            catch
                            {
                                Write-Warning "Some went wrong with the sync."
                                Write-CMTraceLog -Message "Some went wrong with the sync." -Component $Component -type 1 -Logfile $LogFile 

                                Write-Warning -Message "An error has occured during script execution."
                                Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 1 -Logfile $LogFile 
                                # Write-Log -Message "An error has occured during script execution." -Component "Catch" -Type 3
                                Get-ErrorInformation -incomingError $_
                            }
                            
                        }
                        else
                        {
                            Write-Warning "The repository has not been initilized. Nothing to do."
                            Write-CMTraceLog -Message "The repository has not been initilized. Nothing to do." -Component $Component -type 1 -Logfile $LogFile 
                        }
                    }

                }

            <#  #Mark the last time the script ran if not ran with WhatIf
                If (!$WhatIfPreference){Get-Date | Out-File $lastRanPath -Force} #>
                Set-Location $CurrentLocation
            }
            else
            {
                Write-Warning "Unable to continue. Exiting script."
                Write-CMTraceLog -Message "Unable to continue. Exiting script." -Component $Component -type 3 -Logfile $LogFile 
            }
        }
        else {
            # Write-Verbose "User elected not to continue with script because of VPN connection."
            Write-CMTraceLog -Message "User elected not to continue with script because of VPN connection." -Component $Component -type 1 -Logfile $LogFile 
        }
    }

    end
    {   
        # Write-Verbose "End of script."
        # End
        Set-Location $CurrentLocation
    }
}