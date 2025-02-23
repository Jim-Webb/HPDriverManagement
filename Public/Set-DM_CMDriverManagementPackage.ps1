Function Set-DM_CMDriverManagementPackage ()
{
    <#
    .SYNOPSIS
    Used to update some settings on a ConfigMgr package for either a HP driver package or HP repository package.

    .DESCRIPTION
    Used to update some settings on a ConfigMgr package for either a HP driver package or HP repository package.

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

    .PARAMETER Manufacturer
    Specifies the manufacturer that will be used to set the manufacturer field on the ConfigMgr package

    .PARAMETER UpdateVersion
    New version that will be used as the version of the ConfigMgr package.

    .PARAMETER UpdateLanguage
    New language that will be used as the language of the ConfigMgr package.  

    .PARAMETER UpdatePath
    New path that will be used as the source of the ConfigMgr package.

    .PARAMETER SendToPreferredDistributionPoint
    Used to check the On-Demand box for the ConfigMgr package.

    .PARAMETER CopyToPackageShareOnDistributionPoint
    Used to update the 'Copy the content in this package to a package share on distribution points' box on the 'Data Access' tab for the ConfigMgr package.
    
    .PARAMETER SiteServer
    ConfigMgr site server name.

    .PARAMETER SiteCode
    ConfigMgr site code.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    Outputs the object of the ConfigMgr package found.

    .EXAMPLE
    Set-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverRepository -UpdateStatus Prod

    Changes the status of a DriverManagement package from Test to Prod.

    .EXAMPLE
    Set-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverPack -UpdateVersion '2203-03'

    Updates the version field of the DriverManagement package to the value passed.

    .EXAMPLE
    Set-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverPack -UpdatePath \\corp.viamonstra.com\shared\CMsource\OSD\Drivers\DriverPacks\HP\HP_DP_880D_Win10-22H2-20232

    Updates the path field of the DriverManagement package to the value passed.

    .NOTES
    Requires the ConfigMgr console to be installed on the system running the command.

    Version: 1.0.0.0 - Initial Build
        # Added ShouldProcess to script.

    #>

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
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
        [string]$Manufacturer = 'HP',
        [string]$UpdateVersion = $($(get-date).ToString("yyyy-MM")),
        [string]$UpdateLanguage,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [alias('PkgSourcePath')]
        [string]$UpdatePath,
        [bool]$SendToPreferredDistributionPoint,
        [bool]$CopyToPackageShareOnDistributionPoint,
        <#
        [ValidateSet("Prod", "Test")]
        [ValidateNotNullOrEmpty()]
        [string]$UpdateStatus,
        #>
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteServer,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteCode,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    try
    {
        $Component = $($myinvocation.mycommand)

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "DriverManagement"

        If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false) { break }

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $CurrentLocation = Get-Location

        Foreach ($ID in $PlatformID)
        {
            Write-CMTraceLog -Message "Processing PlatformID: $ID." -Component $Component -type 1 -Logfile $LogFile 
            Write-Information -MessageData "Processing PlatformID: $ID." -InformationAction Continue

            Write-CMTraceLog -Message "Getting package info." -Component $Component -type 1 -Logfile $LogFile 
            Write-Information -MessageData "Getting package info." -InformationAction Continue
            $CMDriverManagementPackage = Get-DM_CMDriverManagementPackage -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -PackageType $PackageType -OutputCMObject

            If ($CMDriverManagementPackage)
            {
                # Write-Verbose "Importing SCCM PS Module"
                Write-CMTraceLog -Message "Importing SCCM PS Module" -Component $Component -type 1 -Logfile $LogFile 

                # Load CM PowerShell Module
                Import-CMPSModule
            
                # Write-Verbose "SiteCode: $SiteCode"
                Write-CMTraceLog -Message "SiteCode: $SiteCode" -Component $Component -type 1 -Logfile $LogFile 
            
                Set-Location "$($SiteCode):\" -Verbose:$false

                Write-CMTraceLog -Message "Package exists." -Component $Component -type 1 -Logfile $LogFile

                if ($PSBoundParameters.ContainsKey('UpdateVersion'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update version to $UpdateVersion on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating version to $UpdateVersion." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating version to $UpdateVersion." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage -Version $UpdateVersion -Verbose:$false)
                    }
                }

                if ($PSBoundParameters.ContainsKey('UpdatePath'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update path to $Path on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating path to $Path." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating path to $Path." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage -Path $Path -Verbose:$false)
                    }
                }

                if ($PSBoundParameters.ContainsKey('UpdateLanguage'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update language to ($Manufacturer $($ID.ToUpper()) $OS $OSBuild) on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating language to ($Manufacturer $($ID.ToUpper()) $OS $OSBuild)." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating language to ($Manufacturer $($ID.ToUpper()) $OS $OSBuild)." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage "$Manufacturer $($ID.ToUpper()) $OS $OSBuild" -Verbose:$false)
                    }
                }

                if ($PSBoundParameters.ContainsKey('SendToPreferredDistributionPoint'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update On-Demand setting to `"$SendToPreferredDistributionPoint`" on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating On-Demand setting to True." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating On-Demand setting to True." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage -SendToPreferredDistributionPoint $SendToPreferredDistributionPoint -Verbose:$false)
                    }
                }

                if ($PSBoundParameters.ContainsKey('CopyToPackageShareOnDistributionPoint'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update `"Copy to share`" setting to `"$CopyToPackageShareOnDistributionPoint`" on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating `"Copy to share`" setting to $CopyToPackageShareOnDistributionPoint." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating `"Copy to share`" setting to $CopyToPackageShareOnDistributionPoint." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage -CopyToPackageShareOnDistributionPoint $CopyToPackageShareOnDistributionPoint -Verbose:$false)
                    }
                }

<#                 if ($PSBoundParameters.ContainsKey('UpdateStatus'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update status from `"$status`" to `"$UpdateStatus`" on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Processing a $PackageType package." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Processing a $PackageType package." -InformationAction Continue

                        if ($PackageType -eq "DriverPack")
                        {
                            Write-CMTraceLog -Message "Update package status from $Status to $UpdateStatus." -Component $Component -type 1 -Logfile $LogFile 
                            Write-Information -MessageData "Update package status from $Status to $UpdateStatus." -InformationAction Continue

                            $NewName = $CMDriverManagementPackage.Name -replace "$Status","$UpdateStatus"

                            Write-CMTraceLog -Message "Old name: $($CMDriverManagementPackage.Name) - New Name: $NewName" -Component $Component -type 1 -Logfile $LogFile 

                            If ($NewName)
                            {
                                If ($($CMDriverManagementPackage.Name) -eq $NewName)
                                {
                                    Write-CMTraceLog -Message "Package name already equals `"$NewName`"." -Component $Component -type 2 -Logfile $LogFile 
                                    Write-Information -MessageData "Package name already equals `"$NewName`"." -InformationAction Continue
                                    Write-Warning "Package name already equals `"$NewName`"."
                                }
                                else
                                {
                                    Write-CMTraceLog -Message "Updating package name." -Component $Component -type 1 -Logfile $LogFile 
                                    Set-CMPackage -InputObject $CMDriverManagementPackage -NewName $NewName -Verbose:$false
                                }

                            }
                        }
                        elseif ($PackageType -eq "DriverRepository")
                        {
                            Write-CMTraceLog -Message "The the `"UpdateStatus`" parameter is not supported for DriverRepository packages." -Component $Component -type 2 -Logfile $LogFile 
                            Write-Information -MessageData "The the `"UpdateStatus`" parameter is not supported for DriverRepository packages." -InformationAction Continue
                            Write-Warning "The the `"UpdateStatus`" parameter is not supported for DriverRepository packages."
                        }
                    }
                }
                 #>
            }
        }

        Set-Location $CurrentLocation
    }
    catch
    {
        Write-Warning "Something went wrong: $_"
        Write-CMTraceLog -Message "Something went wrong: $_" -Component $Component -type 2
        Write-Warning -Message "An error has occured during script execution."
        Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile 
        Get-ErrorInformation -incomingError $_
        Set-Location $CurrentLocation
    }

}