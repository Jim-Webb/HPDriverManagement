Function Invoke-DM_CMPackageDistribution ()
{
    <#
    .SYNOPSIS
    Distributes a package to the specified distribution point.

    .DESCRIPTION
    Distributes a package to the specified distribution point.

    .PARAMETER Name
    Name of ConfigMgr packge.

    .PARAMETER PackageID
    PackageID for ConfigMgr package.

    .PARAMETER DistributionPointGroupName
    DistributionPoint group name to use for distribution.

    .PARAMETER SiteServer
    ConfigMgr site server name.

    .PARAMETER SiteCode
    ConfigMgr site code.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    If succesfull, will output $true.

    .EXAMPLE
    Invoke-DM_CMPackageDistribution -PackageID PS100FE7

    .EXAMPLE
    Invoke-DM_CMPackageDistribution -Name 'DriverRepository: HP 880D Win10 22H2 - Test'

    .NOTES
    Requires the ConfigMgr console to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName='packageid')]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName, ParameterSetName='name')]
    [string]$Name,
    [Parameter(Mandatory=$True,ValueFromPipeline,ValueFromPipelineByPropertyName, ParameterSetName='packageid')]
    [string]$PackageID,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
    [string]$DistributionPointGroupName = 'All Content except Microsoft Patches (All DPs)',
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    [string]$SiteServer,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [string]$SiteCode,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        Write-Verbose "Called by: $((Get-PSCallStack)[1].Command)"

        $Component = $($myinvocation.mycommand)
    
        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"
    
        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false) { break }

        #Write-Verbose "Importing SCCM PS Module"
        Write-CMTraceLog -Message "Importing SCCM PS Module" -Component $Component -type 1 -Logfile $LogFile 

        # Load CM PowerShell Module
        Import-CMPSModule
    }

    Process
    {
        $CurrentLocation = Get-Location

        Set-Location "$($SiteCode):\" -Verbose:$false

        try
        {
            #Create the package first
            # Write-Verbose "Find package."
            Write-CMTraceLog -Message "Find package." -Component $Component -type 1 -Logfile $LogFile 
            switch ($PSBoundParameters.Keys)
            {
                'name' { 
                    # Write-Verbose "-name parameter passed."
                    Write-CMTraceLog -Message "-name parameter passed." -Component $Component -type 1 -Logfile $LogFile 
                    Write-CMTraceLog -Message "Looking for package name `"$name`"." -Component $Component -type 1 -Logfile $LogFile 
                    $Package = Get-CMPackage -Name $name -Fast -Verbose:$false
                    }
                'packageid' {
                    # Write-Verbose "-packageID parameter passed."
                    Write-CMTraceLog -Message "-packageID parameter passed." -Component $Component -type 1 -Logfile $LogFile 
                    Write-CMTraceLog -Message "Looking for packageID `"$PackageID`"." -Component $Component -type 1 -Logfile $LogFile 
                    $Package = Get-CMPackage -Id $PackageID -Fast -Verbose:$false
                    }
            }

            If ($Package)
            {
                # Check current distribution status.
                If ((Get-CMDistributionStatus -Id ($Package.PackageID) -Verbose:$false).targeted -ne 0)
                {
                    if($PSCmdlet.ShouldProcess(($Package.PackageID),"Update distribution for package on `"$DistributionPointGroupName`""))
                    {
                        $Output = Get-CMDistributionStatus -Id ($Package.PackageID) -Verbose:$false
                        # Write-Verbose "The package has been distributed, updating."
                        Write-CMTraceLog -Message "The package $($Package.PackageID) has been distributed, updating." -Component $Component -type 1 -Logfile $LogFile 
                        Update-CMDistributionPoint -PackageId ($Package.PackageID) -Verbose:$false
                        $Result = $True
                    }
                }
                else
                {
                    # Write-Verbose "The package has not been distributed."
                    Write-CMTraceLog -Message "The package $($Package.PackageID) has not been distributed." -Component $Component -type 1 -Logfile $LogFile 
                    # Write-Output "Starting distribution now."
                    Write-CMTraceLog -Message "Starting distribution now." -Component $Component -type 1 -Logfile $LogFile 
                    If (Get-CMDistributionPointGroup -Name $DistributionPointGroupName -Verbose:$false)
                    {
                        if($PSCmdlet.ShouldProcess(($Package.PackageID),"Distributing package to `"$DistributionPointGroupName`""))
                        {
                            # Write-Verbose "Distribution point group `"$DistributionPointGroupName`" is vaild."
                            Write-CMTraceLog -Message "Distribution point group `"$DistributionPointGroupName`" is vaild." -Component $Component -type 1 -Logfile $LogFile 
                            # Distribute package content
                            # Write-Verbose "Distributing contents of new package."
                            Write-CMTraceLog -Message "Distributing contents of new package." -Component $Component -type 1 -Logfile $LogFile 
                            [void](Start-CMContentDistribution -InputObject $Package -DistributionPointGroupName $DistributionPointGroupName -Verbose:$false)
                            $Result= $True
                        }
                    }
                    else
                    {
                        Set-Location $CurrentLocation
                        Write-Warning "DistributionPoint group name: `"$DistributionPointGroupName`" is not valid"
                        Write-CMTraceLog -Message "DistributionPoint group name: `"$DistributionPointGroupName`" is not valid" -Component $Component -type 1 -Logfile $LogFile 
                        $Result = $false
                        # throw "DistributionPoint group name: `"$DistributionPointGroupName`" is not valid"
                    }
                }
            }
            else
            {
                # Write-Verbose "Package `"$name`" not found."
                Write-CMTraceLog -Message "Package `"$name`" not found." -Component $Component -type 1 -Logfile $LogFile 
                $Result = $false
            }

            Set-Location $CurrentLocation

            return $Result
        }
        catch
        {
            Write-Warning "Something went wrong, $_."
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile
            Write-CMTraceLog -Message "$_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            Set-Location $CurrentLocation
        }
    }

}