Function New-DM_CMDriverManagementPackage ()
{
    <#
    .SYNOPSIS
    Creates a new ConfigMgr package for either a HP driver package or HP repository package.

    .DESCRIPTION
    Creates a new ConfigMgr package for either a HP driver package or HP repository package.

    .PARAMETER PlatformID
    The platform ID from a HP computer.

    .PARAMETER OS
    Specifies the OS. Windows 10 or Windows 11.

    .PARAMETER OSBuild
    The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

    .PARAMETER Status
    Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

    .PARAMETER Packagetype
    Indicates what type of package needs to be created.
    
    DriverPack = ConfigMgr package containing drivers
    
    DriverRepository = ConfigMgr package containing an HP driver repository.

    .PARAMETER PackageDate
    Used to set the date to be used in the verions field of the ConfigMgr package. If nothing is passed, today's month and year will be used.
    Example: 2025-02

    .PARAMETER Manufacturer
    Specifies the manufacturer that will be used to set the manufacturer field on the ConfigMgr package

    .PARAMETER Path
    The path that will be used as the source of the new ConfigMgr package.

    .PARAMETER UpdateExistingPackage
    If an existing ConfigMgr package is found, update it instead of creating a new package. If this parameter is not
    specified and the package already exists, the existing package will NOT be updated and you will need
    to update the version and distribute the content manually.

    .PARAMETER SiteServer
    ConfigMgr site server name.

    .PARAMETER SiteCode
    ConfigMgr site code.

    .PARAMETER CMFolder
    The folder where the new ConfigMgr package will be moved to in ConfigMgr.

    "[SiteCode]:\Package\OSD\HP"

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    Outputs the object from the creation of the ConfigMgr package.

    .EXAMPLE
    New-DM_CMDriverManagementPackage -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverPack -Path \\corp.viamonstra.com\CMSource\OSD\Drivers\DriverPacks\HP_DP_880D_Win10-22H2-202212

    .EXAMPLE
    New-DM_CMDriverManagementPackage -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverRepository -Path \\corp.viamonstra.com\CMSource\WorkstationDriverRepository\Test\Win10\22H2\880D

    .EXAMPLE
    Get-DM_HPRepository -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test | New-DM_CMDriverManagementPackage -PackageType DriverRepository

    Use output from the Get-DM_HPRepository as input for New-DM_CMDriverManagementPackage. You still need to use the -PackageType parameter since that's not passed from the previous command.

    .NOTES
    Requires the ConfigMgr console to be installed on the system running the command.
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
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("Prod", "Test")]
        [string]$Status,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("DriverPack", "DriverRepository")]
        [string]$PackageType,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [alias('LastUpdated')]
        $PackageDate,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [string]$Manufacturer = 'HP',
        #[string]$Language,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$Path,
        [alias('SyncExistingPackage')]
        [switch]$UpdateExistingPackage,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteServer,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteCode,
        [string]$CMFolder,
        [Switch]$Force,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin
    {
        $Component = $($myinvocation.mycommand)

        if ($Force -and -not $Confirm)
        {
            $ConfirmPreference = 'None'
        }

        $InformationPreference = 'Continue'

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false)
        {
            Write-CMTraceLog -Message "Failed SCCM repreq check." -Component $Component -type 1 -Logfile $LogFile 
            break
        }

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues
    }
    Process
    {
        Write-CMTraceLog -Message "Checking for write permission to `"$Path`"." -Component $Component -type 1 -Logfile $LogFile 
        If ((Invoke-PathPermissionsCheck -Path $Path) -eq $false)
        {
            Write-CMTraceLog -Message "Unable to write to `"$Path`"." -Component $Component -type 3 -Logfile $LogFile 
            break
        }
        try
        {
            Foreach ($ID in $PlatformID)
            {
                if ($PSBoundParameters.ContainsKey('PackageType'))
                {
                    # Write-Verbose "PackageType passed."
                    Write-CMTraceLog -Message "PackageType passed." -Component $Component -type 1 -Logfile $LogFile 
                    switch ($PackageType)
                    {
                        'DriverPack' { 
                            # Write-Verbose "Package type = 'DriverPack'."
                            Write-CMTraceLog -Message "Package type = 'DriverPack'." -Component $Component -type 1 -Logfile $LogFile 
                            $PackageName = "DriverPack: $Manufacturer $($ID.ToUpper()) $OS $OSBuild - $Status"
                            }
                        'DriverRepository' {
                            # Write-Verbose "Package type = 'DriverRepository'."
                            Write-CMTraceLog -Message "Package type = 'DriverRepository'." -Component $Component -type 1 -Logfile $LogFile 
                            $PackageName = "DriverRepository: $Manufacturer $($ID.ToUpper()) $OS $OSBuild - $Status"
                            }
                    }
                }
        
                # Write-Verbose "Importing SCCM PS Module"
                Write-CMTraceLog -Message "Importing SCCM PS Module" -Component $Component -type 1 -Logfile $LogFile 
        
                # Load CM PowerShell Module
                Import-CMPSModule
            
                $CurrentLocation = Get-Location
        
                # Write-Verbose "SiteCode: $SiteCode"
                Write-CMTraceLog -Message "SiteCode: $SiteCode" -Component $Component -type 1 -Logfile $LogFile 
            
                Set-Location "$($SiteCode):\" -Verbose:$false
        
                # Write-Verbose "Checking to see if package already exists."
                Write-CMTraceLog -Message "Find package." -Component $Component -type 1 -Logfile $LogFile
                Write-CMTraceLog -Message "Checking to see if package `"$PackageName`" exists." -Component $Component -type 1 -Logfile $LogFile 
                $PackageObj = Get-CMPackage -Name $PackageName -Fast -Verbose:$false
        
                If (!($PackageObj))
                {
                    # Write-Verbose "Package `"$PackageName`" does not exist."
                    Write-CMTraceLog -Message "Package `"$PackageName`" does not exist." -Component $Component -type 1 -Logfile $LogFile 
        
                    if($PSCmdlet.ShouldProcess($PackageName,"Create package with type `"$PackageType`" and name `"$PackageName`""))
                    {
                        #Create the package first
                        # Write-Verbose "Creating new package."
                        Write-CMTraceLog -Message "Creating new package." -Component $Component -type 1 -Logfile $LogFile

                        If ($PackageDate)
                        {
                            Write-CMTraceLog -Message "Using date passed from command line." -Component $Component -type 1 -Logfile $LogFile
                            $NewPackage = New-CMPackage -Name $PackageName -Manufacturer $Manufacturer -Path $Path -Language "$Manufacturer $($ID.ToUpper()) $OS $OSBuild" -Version $PackageDate -Verbose:$false
                        }
                        else
                        {
                            Write-CMTraceLog -Message "Using today's date for package." -Component $Component -type 1 -Logfile $LogFile
                            $NewPackage = New-CMPackage -Name $PackageName -Manufacturer $Manufacturer -Path $Path -Language "$Manufacturer $($ID.ToUpper()) $OS $OSBuild" -Version $(get-date).ToString("yyyy-MM") -Verbose:$false
                        }
      
                        Write-CMTraceLog -Message "New package Name: $($NewPackage.Name)" -Component $Component -type 1 -Logfile $LogFile 
                        Write-CMTraceLog -Message "New package ID: $($NewPackage.PackageID)" -Component $Component -type 1 -Logfile $LogFile 
                        
                        Write-Verbose "Updating settings on new package."
                        Write-CMTraceLog -Message "Updating settings on new package." -Component $Component -type 1 -Logfile $LogFile 
                        # Set-CMPackage -InputObject $NewPackage -EnableBinaryDeltaReplication $true -CopyToPackageShareOnDistributionPoint $true -SendToPreferredDistributionPoint $true -Verbose:$false
                        [void](Set-CMPackage -InputObject $NewPackage -EnableBinaryDeltaReplication $true -SendToPreferredDistributionPoint $true -Verbose:$false)
        
                        # If ($PackageType -eq "DriverRepository")
                        # {
                        Write-CMTraceLog -Message "Creating `"Download`" program in package $($NewPackage.Name)." -Component $Component -type 1 -Logfile $LogFile 
                        [void](New-CMProgram -PackageName $($NewPackage.Name) -CommandLine "cmd.exe /c" -StandardProgramName "Download" -ProgramRunType WhetherOrNotUserIsLoggedOn -RunMode RunWithAdministrativeRights -RunType Hidden -Verbose:$false)
                        [void](Get-CMProgram -PackageName $($NewPackage.Name) -ProgramName "Download" -Verbose:$false | Set-CMProgram -StandardProgram -EnableTaskSequence $true -AfterRunningType NoActionRequired -Verbose:$false)
                        # }
        
                        # Move package to correct folder
                        # Write-Verbose "Moving new packge to correct folder."
                        If (Test-path $CMFolder)
                        {
                            Write-CMTraceLog -Message "Moving new packge to folder: $CMFolder." -Component $Component -type 1 -Logfile $LogFile 
                            [void](Move-CMObject -InputObject $NewPackage -FolderPath $CMFolder -Verbose:$false)
                        }
                        else
                        {
                            Write-CMTraceLog -Message "ConfigMgr folder $CMFolder does not exist. New package cannot be moved to non existant folder." -Component $Component -type 1 -Logfile $LogFile 
                            Write-CMTraceLog -Message "New package $($NewPackage.Name) will need to be moved manually once folder path has been created." -Component $Component -type 1 -Logfile $LogFile 
                            Write-Warning "ConfigMgr folder $CMFolder does not exist. New package cannot be moved to non existant folder."
                            Write-Warning "New package $($NewPackage.Name) will need to be moved manually once folder path has been created."
                        }

        
                        # Write-Verbose "Distributing contents of new package."
                        Write-CMTraceLog -Message "Distributing contents of new package." -Component $Component -type 1 -Logfile $LogFile 
                        [void](Invoke-DM_CMPackageDistribution -PackageID $($NewPackage.PackageID))
        
                        <# If (Get-CMDistributionPointGroup -Name $DistributionPointGroupName)
                        {
                            Write-Verbose "Distribution point group `"$DistributionPointGroupName`" is vaild."
                            # Distribute package content
                            Write-Verbose "Distributing contents of new package."
                            Start-CMContentDistribution -InputObject $NewPackage -DistributionPointGroupName $DistributionPointGroupName
                        } #>
                        Write-CMTraceLog -Message "Returning object for package: $($NewPackage.PackageID)." -Component $Component -type 1 -Logfile $LogFile 
                        $PackageOut = Get-CMPackage -Id $($NewPackage.PackageID) -Fast -Verbose:$false
                    }
        
                    Set-Location $CurrentLocation
        
                    return, $PackageOut;
                }   
                else
                {
                    Write-CMTraceLog -Message "Package `"$PackageName`" exists." -Component $Component -type 2 -Logfile $LogFile
                    Write-Warning "Package `"$PackageName`" exists."

                    if ($UpdateExistingPackage)
                    {
                        Write-CMTraceLog -Message "UpdateExistingPackage parameter passed. Updating version and redistrbuting existing package." -Component $Component -type 1 -Logfile $LogFile
                        Write-Information -MessageData "UpdateExistingPackage parameter passed. Updating version and redistrbuting existing package." -InformationAction Continue
                        #Update date of existing driver package.
                        Write-CMTraceLog -Message "Updating version date for package `"$PackageName`"." -Component $Component -type 2 -Logfile $LogFile
                        Write-Information -MessageData "Updating version date for package `"$PackageName`"." -InformationAction Continue
                        Set-DM_CMDriverManagementPackage -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -PackageType $PackageType -UpdateVersion $($(get-date).ToString("yyyy-MM"))

                        Get-DM_CMDriverManagementPackage -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -PackageType $PackageType | Invoke-DM_CMPackageDistribution
                        Write-CMTraceLog -Message "Redistribution of existing package started." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Redistribution of existing package started." -InformationAction Continue
                    }
                    else
                    {
                        # Write-Verbose "Package already exists."
                        Write-Warning "Use the -UpdateExistingPackage parameter with New-DM_CMDriverManagementPackage to redistribute content when the package already exists."
                    }
        
                    Set-Location $CurrentLocation
                    return $PackageObj
                }
            }

        }
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-CMTraceLog -Message "Something went wrong." -Component $Component -type 2 -Logfile $LogFile 
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution. $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            Set-Location $CurrentLocation
        }
    }
}