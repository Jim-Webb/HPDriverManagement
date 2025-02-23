Function Set-DM_HPRepositoryCategory ()
{
    <#
    .SYNOPSIS
    Updates an HP driver repository for a PlatformID, OS, and OS Build with additional category support.

    .DESCRIPTION
    Updates an HP driver repository for a PlatformID, OS, and OS Build with additional category support.

    .PARAMETER PlatformID
    The platform ID from a HP computer.

    If you need to update the categories for multiple repositories, you can pass multiple Platform IDs at a time.

    .PARAMETER OS
    Specifies the OS. Windows 10 or Windows 11.

    .PARAMETER OSBuild
    The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

    .PARAMETER Status
    Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

    .PARAMETER Category
    Sets the different categories supported by the repository. Multiple values can be passed by separating them with commas.

    "All", "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility"

    If "All" is specified, the all supported categories will be added to the repository. This saves you from having to specify them seperately.

    .PARAMETER HPRepoPath
    Root path when the HP repositories are stored.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    No output.

    .EXAMPLE
    Set-DM_HPRepositoryCategory -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS,Driver,Firmware,Software

    .EXAMPLE
    Set-DM_HPRepositoryCategory -PlatformID aaaa -OS Win10 -OSBuild 22H2 -Status Test -Category Driver

    .EXAMPLE
    Set-DM_HPRepositoryCategory -PlatformID AAAA,BBBB,CCCC,DDDD -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS,Driver,Firmware,Software

    When passing multiple PlatformIDs, the OS, OSBuild, and Status must be the same.

    .NOTES
    Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [alias('Platform')]
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
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("All", "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility")]
    [string[]]$Category,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin{
        $Categories = "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility"
        $Component = $($myinvocation.mycommand)

        Write-CMTraceLog -Message "------ $Component ------" -Component $Component -type 1 -Logfile $LogFile 

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "DriverManagement"
    
        # [bool]$Global:EnableLogWriteVerbose = $false
        
        $CurrentLocation = Get-Location

        <# If (!(Get-Module HPCMSL))
        {
            #Write-Verbose "Importing HPCMSL module."
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
    }

    Process
    {
        # If (Test-Path $HPRepoPath)
        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $true)
        {
            #Write-Verbose "Path $Path exists."
            Write-CMTraceLog -Message "Path $HPRepoPath exists." -Component $Component -type 1 -Logfile $LogFile 

            Foreach ($ID in $PlatformID)
            {

                # Write-Verbose "PlatformID: $ID."
                Write-CMTraceLog -Message "PlatformID: $ID." -Component $Component -type 1 -Logfile $LogFile 
                Write-Information -MessageData "PlatformID: $ID." -InformationAction Continue

                $PlatformPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID\Repository"

                If (Get-Module HPCMSL)
                {
                    Set-Location $PlatformPath
                    If ((Test-Path "$PlatformPath\.repository") -and (Test-Path "$PlatformPath\.repository\repository.json"))
                    {
                        # Write-Verbose "Updating $ID repository settings."
                        Write-CMTraceLog -Message "Updating $ID repository settings." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating $ID repository settings." -InformationAction Continue
                        try
                        {
                            if($PSCmdlet.ShouldProcess($ID,"Update category on repository $PlatformPath"))
                            {
                                # Write-Verbose "Configuring required repository settings."
                                Write-CMTraceLog -Message "Configuring required repository settings." -Component $Component -type 1 -Logfile $LogFile 
                                Write-Information -MessageData "Configuring required repository settings." -InformationAction Continue
                                Set-RepositoryConfiguration -setting OfflineCacheMode -Cachevalue Enable -ErrorAction Stop

                                If ($Category -eq 'All'){$Category = $Categories}
                                Foreach ($Cat in $Category)
                                {
                                    #Write-Verbose "Adding category $Cat to repository."
                                    Write-CMTraceLog -Message "Adding category `"$Cat`" to repository." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Adding category `"$Cat`" to repository." -InformationAction Continue
                                    Add-RepositoryFilter -Platform $ID -Os $OS -OsVer $OSBuild -Category $Cat -ErrorAction Stop
                                    Write-CMTraceLog -Message "Category `"$Cat`" has been added." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Category `"$Cat`" has been added." -InformationAction Continue
                                }
                            }
                        }
                        catch
                        {
                            Write-Warning "Something went wrong with repository update."
                            Write-CMTraceLog -Message "Something went wrong with repository update." -Component $Component -type 2 -Logfile $LogFile 
                        }
                    }
                    else
                    {
                        Write-Warning "Repository does not exist. Please Initialize the repository."
                        Write-CMTraceLog -Message "Repository does not exist. Please Initialize the repository." -Component $Component -type 3 -Logfile $LogFile 
                    }
                }

                Set-Location $CurrentLocation
            }
        }
    }
}