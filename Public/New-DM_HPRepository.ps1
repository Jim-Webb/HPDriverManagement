function New-DM_HPRepository ()
{
        <#
        .SYNOPSIS
        Creates a new HP driver repository for a PlatformID, OS, and OS Build.

        .DESCRIPTION
        Creates a new HP driver repository for a PlatformID, OS, and OS Build.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        If you need to create multiple repositories at a time, you can pass multiple Platform IDs at a time.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies if the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

        *** Updated to only allow the creation of "Test" repositories.

        .PARAMETER Category
        Sets the different categories supported by the repository. Multiple values can be passed by separating them with commas.

        "All", "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility"

        If "All" is specified, the all supported categories will be added to the repository. This saves you from having to specify them seperately.

        .PARAMETER HPRepoPath
        Root path when the HP repositories are stored.

        .PARAMETER Force
        If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.

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
        New-DM_HPRepository -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS,Driver,Firmware,Software

        .EXAMPLE
        New-DM_HPRepository -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS

        .EXAMPLE
        New-DM_HPRepository -PlatformID AAAA,BBBB,CCCC,DDDD -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS,Driver,Firmware,Software

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [alias('Platform')]
    [string[]]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
    #[ValidateSet("Prod", "Test")]
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("All", "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility")]
    [string[]]$Category,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin
    {
        $Categories = "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility"
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        # If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.
        if ($Force -and -not $Confirm){
            $ConfirmPreference = 'None'
        }

        # [bool]$Global:EnableLogWriteVerbose = $false

        $CurrentLocation = Get-Location

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
        # If ((Check-DM_PreReqFilePath -Path $PackageContentPath -TestFile '!README!.txt') -eq $false) { break }
        # If (Test-Path $HPRepoPath)
        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $true)
        {
            # Write-Verbose "Path $RootPath exists."
            Write-CMTraceLog -Message "Path $HPRepoPath exists." -Component $Component -type 1 -Logfile $LogFile

            switch ($OS)
            {
                Win10 {$FullOS = "Microsoft Windows 10"}
                Win11 {$FullOS = "Microsoft Windows 11"}
            }

            $RepositoryObject = @()

            Foreach ($ID in $PlatformID)
            {
                If ((Get-DM_HPPlatformIDIsValid -PlatformID $ID) -eq $true)
                {
                    If (Get-HPDeviceDetails -Platform $ID -oslist | Where-Object {$_.OperatingSystemRelease -eq $OSBuild -and $_.OperatingSystem -eq "$FullOS"})
                    {
                        if($PSCmdlet.ShouldProcess($HPRepoPath,"Create new repository $Status\$os\$OSBuild\$ID at $HPRepoPath"))
                        {
                            # Write-Verbose "PlatformID: $ID."
                            Write-CMTraceLog -Message "PlatformID: $ID." -Component $Component -type 1 -Logfile $LogFile 
                            $PlatformPath = "$HPRepoPath\$Status\$os\$OSBuild\$($ID.ToUpper())\Repository"

                            If (!(Test-Path $PlatformPath))
                            {
                                # Write-Verbose "The path $RootPath\$Status\$os\$OSBuild\$ID does not exist."
                                Write-CMTraceLog -Message "The path $HPRepoPath\$Status\$os\$OSBuild\$($ID.ToUpper()) does not exist." -Component $Component -type 1 -Logfile $LogFile 

                                try
                                {
                                    # Write-Verbose "Creating path $PlatformPath"
                                    Write-CMTraceLog -Message "Creating path $PlatformPath" -Component $Component -type 1 -Logfile $LogFile 
                                    # New-Item -Path $PlatformPath -ItemType Directory -Force -ErrorAction Stop
                                    [void][System.IO.Directory]::CreateDirectory($PlatformPath)
                                }
                                catch
                                {
                                    Write-Warning "Something went wrong creating the path $PlatformPath."
                                    Write-CMTraceLog -Message "Something went wrong creating the path $PlatformPath." -Component $Component -type 1 -Logfile $LogFile 
                                    exit
                                }
                            }

                            If (Get-Module HPCMSL)
                            {
                                Set-Location $PlatformPath
                                If (!((Test-Path "$PlatformPath\.repository") -and (Test-Path "$PlatformPath\.repository\repository.json")))
                                {
                                    # Write-Verbose "Repository does not exist."
                                    Write-CMTraceLog -Message "Repository does not exist." -Component $Component -type 1 -Logfile $LogFile 

                                    try
                                    {
                                        # Write-Verbose "Creating repository for $ID."
                                        Write-CMTraceLog -Message "Creating repository for $($ID.ToUpper())." -Component $Component -type 1 -Logfile $LogFile 
                                        Initialize-Repository -ErrorAction Stop

                                        # Write-Verbose "Configuring repository settings."
                                        Write-CMTraceLog -Message "Configuring repository settings." -Component $Component -type 1 -Logfile $LogFile 
                                        
                                        # When using HP Image Assistant and offline mode, OfflineCacheMode must be set to Enable.
                                        Set-RepositoryConfiguration -setting OfflineCacheMode -Cachevalue Enable -ErrorAction Stop
                                        
                                        # The default setting is to Fail, setting to LogAndContinue allows the sync process to continue.
                                        Set-RepositoryConfiguration -setting OnRemoteFileNotFound -Value LogAndContinue -ErrorAction Stop

                                        # Handle the use of the ALL parameter to update the categories
                                        If ($Category -eq 'All'){$Category = $Categories}
                                        Foreach ($Cat in $Category)
                                        {
                                            Add-RepositoryFilter -Platform $ID -Os $OS -OsVer $OSBuild -Category $Cat -ErrorAction Stop
                                        }
                                        
                                        # Write-Verbose "Copying repository info."
                                        Write-CMTraceLog -Message "Copying repository info." -Component $Component -type 1 -Logfile $LogFile 
                                        Get-HPDeviceDetails -Platform $ID | Out-File "$HPRepoPath\$Status\$os\$OSBuild\$ID\PlatformInfo.txt"
                                        Get-HPDeviceDetails -Platform $ID -OSList | Out-File "$HPRepoPath\$Status\$os\$OSBuild\$ID\OSSupport.txt"
                                        "Platform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nDate created: $((get-date).tostring())`nPerpetrator: $env:USERNAME" | out-file -FilePath "$HPRepoPath\$Status\$os\$OSBuild\$ID\RepositoryInfo.txt"

                                        # Write-Verbose "Repository setup complete."
                                        Write-CMTraceLog -Message "Repository setup complete." -Component $Component -type 1 -Logfile $LogFile 

                                        $RepoPath = join-path $HPRepoPath $Status\$OS\$OSBuild\$ID

                                        $props = [pscustomobject]@{
                                            'PlatformID'=$ID
                                            'OS'=$OS
                                            'OSBuild'=$OSBuild
                                            'RootPath'=$HPRepoPath
                                            'Path'=$RepoPath
                                            'Status'=$Status            
                                        }

                                        $RepositoryObject += $props
                                    }
                                    catch
                                    {
                                        Write-Warning "Something went wrong with repository creation."
                                        Write-CMTraceLog -Message "Something went wrong with repository creation." -Component $Component -type 3 -Logfile $LogFile 
                                        Write-Warning -Message "An error has occured during script execution."
                                        Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile 
                                        # Write-Log -Message "An error has occured during script execution." -Component "Catch" -Type 3
                                        Get-ErrorInformation -incomingError $_
                                    }
                                }
                                else
                                {
                                    Write-Warning "The repository has already been initilized. Nothing to do."
                                    Write-CMTraceLog -Message "The repository has already been initilized. Nothing to do." -Component $Component -type 2 -Logfile $LogFile

                                    $RepositoryObject = Get-DM_HPRepository -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status
                                }
                            }
                        }#should

                        Set-Location $CurrentLocation

                        Write-Output $RepositoryObject
                    }
                    else
                    {
                        Write-Warning "Platform $ID on OS $OS Version $OSBuild not supported. Check yo self fool."
                        Write-CMTraceLog -Message "Platform $ID on OS $OS Version $OSBuild not supported. Check yo self fool." -Component $Component -Type 3 -Logfile $LogFile 
                        Write-Error "Platform $ID on OS $OS Version $OSBuild not supported. Check yo self fool."
                    }
                }
                else
                {
                    Write-CMTraceLog -Message "PlatformID: $ID, is not valid." -Component $Component -type 1 -Logfile $LogFile
                    Write-Warning "The PlatformID: $ID, is not valid. Unable to continue. Exiting."
                    Write-Error "The PlatformID: $ID, is not valid. Unable to continue. Exiting." -ErrorAction Stop
                }
            }
        }
        else
        {
            Write-Warning "Unable to continue. Exiting script."
            Write-CMTraceLog -Message "Unable to continue. Exiting script." -Component $Component -type 3 -Logfile $LogFile 
        }
    }
}