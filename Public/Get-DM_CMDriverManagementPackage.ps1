Function Get-DM_CMDriverManagementPackage ()
{
    <#
    .SYNOPSIS
    Retreives a ConfigMgr package for either a HP driver package or HP repository package.

    .DESCRIPTION
    Retreives a ConfigMgr package for either a HP driver package or HP repository package.

    .PARAMETER PlatformID
    The platform ID from a HP computer.

    .PARAMETER OS
    Specifies the OS. Windows 10 or Windows 11.

    .PARAMETER OSBuild
    The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

    .PARAMETER Status
    Specifies of the repository or DriverPack is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

    .PARAMETER Packagetype
    Indicates what type of package needs to be created.
    
    DriverPack = ConfigMgr package containing drivers
    
    DriverRepository = ConfigMgr package containing an HP driver repository.

    .PARAMETER Manufacturer
    Specifies the manufacturer that will be used to set the manufacturer field on the ConfigMgr package

    .PARAMETER SiteServer
    ConfigMgr site server name.

    .PARAMETER SiteCode
    ConfigMgr site code.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    Outputs the object of the ConfigMgr package found.

    .EXAMPLE
    Get-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverRepository

    Find a DriverRepository package.

    .EXAMPLE
    Get-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverPack

    Find a DriverPack package.

    .NOTES
    Requires the ConfigMgr console to be installed on the system running the command.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
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
        [switch]$OutputCMObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteServer,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteCode,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false) { throw "SCCM Console is not available. Unable to continue." }

        <## Connect to the site's drive if it is not already present
        if($null -eq (Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
            $null = New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteServer -Scope Global
        } #>
    }

    Process
    {
        try
        {
            Foreach ($ID in $PlatformID)
            {
                Write-CMTraceLog -Message "Processing PlatformID: $ID" -Component $Component -type 1 -Logfile $LogFile 

                #Write-Verbose "[$($myinvocation.mycommand)] Importing SCCM PS Module"
                Write-CMTraceLog -Message "Importing SCCM PS Module" -Component $Component -type 1 -Logfile $LogFile 

                # Load CM PowerShell Module
                Import-DM_CMPSModule

                $CurrentLocation = Get-Location

                Set-Location "$($SiteCode):\" -Verbose:$false

                # Write-verbose "Called by: $((Get-PSCallStack)[1].Command)"
                # Write-CMTraceLog -Message "Called by: $((Get-PSCallStack)[1].Command)" -Component $Component -type 1 -Logfile $LogFile

                if ($PSBoundParameters.ContainsKey('PackageType'))
                {
                    # Write-Verbose "[$($myinvocation.mycommand)] PackageType passed."
                    Write-CMTraceLog -Message "PackageType passed." -Component $Component -type 1 -Logfile $LogFile 
                    #Create the package first
                    # Write-Verbose "[$($myinvocation.mycommand)] Find package."
                    Write-CMTraceLog -Message "Find package." -Component $Component -type 1 -Logfile $LogFile 
                    switch ($PackageType)
                    {
                        'DriverPack' { 
                            # Write-Verbose "[$($myinvocation.mycommand)] Package type = 'DriverPack'."
                            Write-CMTraceLog -Message "Package type = 'DriverPack'." -Component $Component -type 1 -Logfile $LogFile 
                            $PackageName = "DriverPack: $Manufacturer $ID $OS $OSBuild - $Status"
                            }
                        'DriverRepository' {
                            # Write-Verbose "[$($myinvocation.mycommand)] Package type = 'DriverRepository'."
                            Write-CMTraceLog -Message "Package type = 'DriverRepository'." -Component $Component -type 1 -Logfile $LogFile 
                            $PackageName = "DriverRepository: $Manufacturer $ID $OS $OSBuild - $Status"
                            }
                    }
                }

                #Create the package first
                # $PackageName = "DriverPack: HP $PlatformID $OS $OSBuild - $Status"
                # Write-Verbose "[$($myinvocation.mycommand)] Looking for package: $PackageName."
                Write-CMTraceLog -Message "Looking for package: $PackageName." -Component $Component -type 1 -Logfile $LogFile 

                $PackageObj = Get-CMPackage -Name $PackageName -Fast -Verbose:$false

                # $PackageObj

                Set-Location $CurrentLocation

                If ($PackageObj)
                {
                    Write-CMTraceLog -Message "Package found." -Component $Component -type 1 -Logfile $LogFile 
                    Write-CMTraceLog -Message "Package name: $($PackageObj.name) `nPackage ID: $($PackageObj.PackageID)." -Component $Component -type 1 -Logfile $LogFile 
                    
                    if ($PSBoundParameters.ContainsKey('OutputCMObject'))
                    {
                        return $PackageObj
                    }
                    else
                    {
                        $object1 = New-Object PSObject

                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PlatformID -Value $ID
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name OS -Value $OS
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name OSBuild -Value $OSBuild
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name Status -Value $((Get-Culture).TextInfo.ToTitleCase($Status))
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PackageType -Value $PackageType
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name ID -Value $PackageObj.PackageID
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name Name -Value $PackageObj.Name
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PackageSourcePath -Value $PackageObj.PkgSourcePath
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PackageVersion -Value $PackageObj.Version
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PackageLastRefreshTime -Value $PackageObj.LastRefreshTime
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name CMObjectPath -Value $PackageObj.ObjectPath

                        Write-Output $object1
                    }
                }
                else
                {
                    # Write-Verbose "[$($myinvocation.mycommand)] Package `"$PackageName`" not found."
                    Write-CMTraceLog -Message "Package `"$PackageName`" not found." -Component $Component -type 1 -Logfile $LogFile

                    Write-Information -MessageData "Package `"$PackageName`" not found." -InformationAction Continue

                    #Write-Output $false
                }
            }
        }
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "Something went wrong: $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            Set-Location $CurrentLocation
        }

    }
}