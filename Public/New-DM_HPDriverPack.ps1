function New-DM_HPDriverPack ()
{
    <#
        .SYNOPSIS
        Creates an HP driver pack for the PlatformID, OS, and OS Build.

        .DESCRIPTION
        Creates an HP driver pack for the PlatformID, OS, and OS Build.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

        *** Updated to only allow the creation of "Test" DriverPacks.

        .Parameter UnselectList
        Aligns with the same parameter in New-HPDriverPack, which this function uses.

        Specifies a list of SoftPaq numbers and SoftPaq names to not be included in the Driver Pack. A partial name can be specified. Examples include 'Docks', 'USB', 'sp123456'.

        .PARAMETER DriverRoot
        Working path where the drivers will be download to and extracted.

        .PARAMETER Compress
        Compress the driver pack with 7-Zip.

        .PARAMETER Overwite
        Overwite and existing drivers. Needed when the command has already been ran.

        .PARAMETER CreatePackage
        Create an ConfigMgr package for the driver pack. Uses New-DM_CMDriverManagementPackage to create the package.

        .PARAMETER Cleanup
        Removes files in the temp directory used to download, extrace, and compress the driver pack.

        .PARAMETER CopyDP

        Copies the driver pack and supporting files to the ConfigMgr sourcefiles share.

        "\\corp.viamonstra.com\CMSource\OSD\Drivers\DriverPacks"

        .PARAMETER UpdateExistingPackage
        If an existing ConfigMgr package is found, update it instead of creating a new package. If this parameter is not
        specified and the package already exists, the existing package will NOT be updated and you will need
        to update the version and distribute the content manually.
        
        .PARAMETER PackageContentPath
        Path to copy the source files for the SCCM package.

        .PARAMETER OverrideVPNCheck
        The driver pack download can take a long time over a VPN connection. If the -OverrideVPNCheck parameter is passed, the built-in VPN check will be bypassed.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        Outpus a custom object that contains the details of the new driver pack.

        'PlatformID'
        'OS'
        'OSBuild'
        'DriverRoot'
        'Path'
        'Status'

        .EXAMPLE
        New-DM_HPDriverPack -PlatformID 8711 -OS Win10 -OsVer 22H2 -Status Test -Compress -Overwite -CreatePackage -CopyDP

        Create a new driver pack for platform 8711, OS Win10, build 22H2, that will be compressed and copied to the CMSource file share and a package created.

        .EXAMPLE
        Import-Csv C:\Temp\DrivePackTest.csv | New-DM_HPDriverPack -Status Test -Compress -Overwite -CreatePackage -CopyDP

        Pipe a CSV with different models to the script to download each one.

        Example CSV file

        Model,Platform,OS,OsVer
        HP EliteDesk 800 G5 Desktop Mini,8595,Win10,22H2
        HP ZBook Firefly 14 inch G8 Mobile Workstation PC,8AB3,Win11,22H2

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(DefaultParameterSetName='default', SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
        #Define a configuration file.
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [alias('Platform')]
        [string]$PlatformID,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("Win10", "Win11")]
        [string]$OS,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("22H2", "23H2", "24H2")]
        [alias('OsVer')]
        [string]$OSBuild,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        #[ValidateSet("Prod", "Test")]
        [ValidateSet("Test")]
        [string]$Status = 'Test',
        # HP parameter to: Specifies a list of SoftPaq numbers and SoftPaq names to not be included in the Driver Pack. A partial name can be specified. Examples include 'Docks', 'USB', 'sp123456'.
        [string]$UnselectList,
        [string]$DriverRoot = "C:\Temp\Drivers",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        # [Parameter(ParameterSetName = 'Compress')]
        [Parameter(ParameterSetName = 'Default')]
        [switch]$Compress,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("7Zip")]
        # [ValidateSet("7Zip", "Zip", "WIM")]
        [string]$CompressionMethod = '7Zip',
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [switch]$Overwite,
        <#
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='package',Mandatory=$True)]
        [Parameter(ParameterSetName = 'Default')]
        [switch]$CopyDP,
        #>
        #[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        #[Parameter(ParameterSetName='package')]
        #[Parameter(ParameterSetName = 'Default')]
        #[switch]$CreatePackage,
        #[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        #[Parameter(ParameterSetName='package')]
        #[Parameter(ParameterSetName = 'Default')]
        #[alias('SyncExistingPackage')]
        #[switch]$UpdateExistingPackage,
        [bool]$Cleanup = $True,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
        [string]$PackageContentPath,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [switch]$OverrideVPNCheck,
        [Switch]$Force,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        #region Functions

        #endregion

        #region #################################### START GLOBAL VARIABLES ####################################>

        Write-Verbose "Called by: $((Get-PSCallStack)[1].Command)"
        # Get-PSCallStack | Select-Object -Property *

        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $Date = Get-Date -Format ("MM-dd-yyyy")

        Write-CMTraceLog -Message "Date: $Date" -Component $Component -type 1 -Logfile $LogFile 

        $DPDestination = Join-Path $PackageContentPath "HP"

        $CopyDP = $true

        if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-Warning "When creating a HP Driver pack you must run Powershell with admin privileges. Please open an elevated Powershell prompt and try again."
            Write-CMTraceLog -Message "When creating a HP Driver pack you must run Powershell with admin privileges. Please open an elevated Powershell prompt and try again." -Component $Component -Type 3

            break
        }

        If ((Helper-GetDM_HPCMSLInstallStatus) -eq $false)
        {
            Write-Warning "HPCMSL is not installed. Please install and try again."
            Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
            break
        }

        If ($Compress)
        {
            Write-CMTraceLog -Message "Compress parameter passed, compression method selected: $CompressionMethod." -Component $Component -type 1 -Logfile $LogFile
            Write-CMTraceLog -Message "Compress parameter passed, checking for 7-Zip." -Component $Component -type 1 -Logfile $LogFile 
            If ((Check-DM_PreReqSoftware -PreReq 7Zip) -eq $false) { break }
            Write-CMTraceLog -Message "7-Zip EXE to use: $Global:EXE." -Component $Component -type 1 -Logfile $LogFile 
        }

        If ($CreatePackage)
        {
            Write-CMTraceLog -Message "Create package parameter passed, checking for SCCM Console." -Component $Component -type 1 -Logfile $LogFile 
            If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false) { break }
        }

        If ($CopyDP)
        {
            Write-CMTraceLog -Message "CopyDP parameter passed, checking for write access to $PackageContentPath." -Component $Component -type 1 -Logfile $LogFile 
            If ((Invoke-PathPermissionsCheck -Path $PackageContentPath) -eq $false) { break }
        }

        #endregion #################################### END GLOBAL VARIABLES ####################################>
    }

    Process
    {
        #region #################################### START MAIN LOGIC ####################################>
        try {
            # $DiskInfo = Get-CimInstance -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "C:" } | Select-Object -Property DeviceID, VolumeName, @{Label='FreeSpace (Gb)'; expression={($_.FreeSpace/1GB).ToString('F2')}},@{Label='Total (Gb)'; expression={($_.Size/1GB).ToString('F2')}},@{label='FreePercent'; expression={[Math]::Round(($_.freespace / $_.size) * 100, 2)}}
            $DiskInfo = Get-CimInstance -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "C:" } | Select-Object -Property DeviceID, VolumeName, @{Label='FreeSpace (Gb)'; expression={($_.FreeSpace/1GB)}},@{Label='Total (Gb)'; expression={($_.Size/1GB)}},@{label='FreePercent'; expression={[Math]::Round(($_.freespace / $_.size) * 100, 2)}}

            If ($DiskInfo.FreePercent -lt 20)
            {
                Write-CMTraceLog -Message "Low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available." -Component $Component -Type 2
                Write-Warning "Low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available."
                # throw "Low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available."
            }

            If ($DiskInfo.'FreeSpace (Gb)' -lt 5)
            {
                Write-CMTraceLog -Message "Really low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available." -Component $Component -Type 3
                Write-Warning "Really low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available."
                throw "Low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available."
            }

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
                    $Runscript = $True
                    Write-CMTraceLog -Message "User decided to continue over VPN." -Component $Component -type 1 -Logfile $LogFile 
                } else {
                    $Runscript = $false
                    Write-CMTraceLog -Message "User decided not to continue over VPN." -Component $Component -type 1 -Logfile $LogFile 
                }
            }
            else
            {
                $Runscript = $True
            }

            If ($Runscript -eq $True)
            {
                # If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.
                if ($Force -and -not $Confirm)
                {
                    $ConfirmPreference = 'None'
                }

                Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
                # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

                $PlatformID = $($PlatformID.ToUpper())

                Write-CMTraceLog -Message "------ Start $PlatformID Start------" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Driver pack destination: $DPDestination" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Platform: $PlatformID" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "OS: $OS" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "OS version: $OSBuild" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Driver root: $DriverRoot" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Driver pack destination: $DPDestination" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "CopyDP: $CopyDP" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Compress: $Compress" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Overwrite: $Overwite" -Component $Component -type 1 -Logfile $LogFile 

                switch ($OS)
                {
                    Win10 {$FullOS = "Microsoft Windows 10"}
                    Win11 {$FullOS = "Microsoft Windows 11"}
                }

                Write-CMTraceLog -Message "Full OS: $FullOS" -Component $Component -type 1 -Logfile $LogFile 

                if (!(Get-InstalledModule HPCMSL))
                {
                    # Write-Verbose "HPCMSL is not installed."
                    Write-CMTraceLog -Message "HPCMSL is not installed." -Component $Component -Type 3 -Logfile $LogFile 
                    break
                }
                Else
                {
                    # Write-Verbose "HPCMSL is installed. Let's work."
                    Write-CMTraceLog -Message "HPCMSL is installed. Let's work." -Component $Component -type 1 -Logfile $LogFile 

                    If ((Get-DM_HPPlatformIDIsValid -PlatformID $PlatformID) -eq $true)
                    {
                        If (Get-HPDeviceDetails -Platform $PlatformID -oslist | Where-Object {$_.OperatingSystemRelease -eq $OSBuild -and $_.OperatingSystem -eq "$FullOS"})
                        {
                            $PlatformDriverPath = Join-Path $DriverRoot "$PlatformID\$os\$OSBuild\$Date"
                            $PlatformRoot = Join-Path $DriverRoot "$PlatformID"

                            if (-Not(Test-Path -Path $PlatformDriverPath))  {
                                # New-Item -ItemType Directory $PlatformDriverPath -Force
                                [void][System.IO.Directory]::CreateDirectory($PlatformDriverPath)
                            }

                            # Write-Verbose "Driver platform path: $PlatformDriverPath"
                            Write-CMTraceLog -Message "Driver platform path: $PlatformDriverPath" -Component $Component -type 1 -Logfile $LogFile 
                            
                            Try{
                                If (!(Test-Path "$PlatformDriverPath\DP$PlatformID") -or $Overwite)
                                {
                                    if($PSCmdlet.ShouldProcess($PlatformID,"Create driver pack for platform $PlatformID, OS $OS, and OSBuild $OSBuild" + "?"))
                                    {
                                        Write-CMTraceLog -Message "Folder $PlatformDriverPath\DP$PlatformID does not exist or -Overwrite was passed." -Component $Component -type 1 -Logfile $LogFile 
                                        If ($Overwite)
                                        {
                                            Write-CMTraceLog -Message "Overwrite parameter passed." -Component $Component -type 1 -Logfile $LogFile 
                                            If (test-path "$PlatformDriverPath\DP$PlatformID")
                                            {
                                                Write-CMTraceLog -Message "Removing $PlatformDriverPath\DP$PlatformID." -Component $Component -type 1 -Logfile $LogFile 
                                                remove-item -Path "$PlatformDriverPath\DP$PlatformID" -Force -Recurse
                                            }
                                        }
                                        # [void][System.IO.Directory]::CreateDirectory("$PlatformDriverPath\DP$Platform")
                                        Write-CMTraceLog -Message "Downloading driver pack." -Component $Component -type 1 -Logfile $LogFile 

                                        if ($UnselectList)
                                        {
                                            Write-CMTraceLog -Message "UnSelectList: $UnselectList." -Component $Component -type 1 -Logfile $LogFile
                                            Write-CMTraceLog -Message "UnSelectList: $UnselectList." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"

                                            $ExcludeList = @()
                                            foreach ($Item in $UnselectList)
                                            {
                                                Clear-Variable SPFile -ErrorAction SilentlyContinue
                                                If ($Item -match "^sp\d+$")
                                                {
                                                    Write-CMTraceLog -Message "Item appears to already be in SP format. Adding to array. $Item" -Component $Component -type 1 -Logfile $LogFile
                                                    Write-CMTraceLog -Message "Item appears to already be in SP format. Adding to array. $Item" -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"
                                                    $ExcludeList += $Item
                                                }
                                                else
                                                {
                                                    Write-CMTraceLog -Message "Item appears to not be in SP format. $Item" -Component $Component -type 1 -Logfile $LogFile
                                                    Write-CMTraceLog -Message "Item appears to not be in SP format. $Item" -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"

                                                    Write-CMTraceLog -Message "Looking up $Item." -Component $Component -type 1 -Logfile $LogFile
                                                    Write-CMTraceLog -Message "Looking up $Item." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"
                                                    $SPFile = Get-SoftpaqList -Platform $PlatformID -Bitness 64 -Os $OS -OsVer $OSBuild | Where-Object {$_.name -eq "$Item"} | Select-Object -ExpandProperty id
                                                    If ($SPFile)
                                                    {
                                                        Write-CMTraceLog -Message "$Item was found." -Component $Component -type 1 -Logfile $LogFile
                                                        Write-CMTraceLog -Message "$Item was found." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"

                                                        Write-CMTraceLog -Message "SPFile: $SPFile." -Component $Component -type 1 -Logfile $LogFile
                                                        Write-CMTraceLog -Message "SPFile: $SPFile." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"
        
                                                        $ExcludeList += $SPFile
                                                    }
                                                }

                                            }
                                            If ($Excludelist)
                                            {
                                                $ExcludeList = $ExcludeList -join "," | Select-Object -Unique
                                                Write-CMTraceLog -Message "UnselectList was passed, excluding $Excludelist." -Component $Component -type 1 -Logfile $LogFile
                                                Write-CMTraceLog -Message "UnselectList was passed, excluding $Excludelist." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"

                                                "The following has been excluded from this DriverPack: $Excludelist" | Out-File "$PlatformRoot\Excluded.txt"
                                                $HPDriverPackResult = New-HPDriverPack -Platform $PlatformID -OS $os -OSVer $OSBuild -Path $PlatformDriverPath -RemoveOlder -UnselectList $ExcludeList

                                                $ExcludeSupportFiles = 'Exclude.log','Excluded.txt'
                                            }
                                        }
                                        Else
                                        {
                                            $HPDriverPackResult = New-HPDriverPack -Platform $PlatformID -OS $os -OSVer $OSBuild -Path $PlatformDriverPath -RemoveOlder
                                        }
                                        Write-CMTraceLog -Message "Driver pack result: $HPDriverPackResult." -Component $Component -type 1 -Logfile $LogFile 
                                        "Platform: $PlatformID`nFull OS: $FullOS`nOS Version: $OSBuild`nDate created: $((get-date).tostring())`nCreated by: $env:USERNAME" | out-file -FilePath "$PlatformDriverPath\DP$PlatformID\DriverInfo.txt"

                                        # Write-Output $DP

                                        If ($Compress)
                                        {
                                            # Write-Verbose "Compress drivers is enabled."
                                            Write-CMTraceLog -Message "Compress drivers is enabled." -Component $Component -type 1 -Logfile $LogFile

                                            Write-CMTraceLog -Message "Compression method selected: $CompressionMethod." -Component $Component -type 1 -Logfile $LogFile

                                            If ($CompressionMethod -eq '7Zip')
                                            {
                                                Write-CMTraceLog -Message "7Zip compression method selected." -Component $Component -type 1 -Logfile $LogFile

                                                # Check for the z-zip exe.
                                                if (Test-Path $EXE)
                                                {
                                                    # Check for the existance if the 7z file.
                                                    if (!(Test-Path "$PlatformDriverPath\DriverPack.7z") -or $Overwite)
                                                    {
                                                        if($PSCmdlet.ShouldProcess($PlatformID,"Create 7-Zip of driver pack for platform $PlatformID, OS $OS, and OSVer $OSBuild" + "?"))
                                                        {
                                                            If ($Overwite)
                                                            {
                                                                If (Test-Path "$PlatformDriverPath\DriverPack.7z")
                                                                {
                                                                    remove-item -Path "$PlatformDriverPath\DriverPack.7z" -Force
                                                                }
                                                            }
                                                            Write-CMTraceLog -Message "Using 7-Zip to compress driver pack." -Component $Component -type 1 -Logfile $LogFile 
                                                            Write-Information -MessageData "Using 7-Zip to compress driver pack." -InformationAction Continue
                                                            $Result = & $EXE -mx=9 a "$PlatformDriverPath\DriverPack.7z" "$PlatformDriverPath\DP$PlatformID\*"

                                                            If ((Get-Item "$PlatformDriverPath\DriverPack.7z").Length -eq 0)
                                                            {
                                                                Write-CMTraceLog -Message "DriverPack.7z is 0 bytes. Something went wrong." -Component $Component -Type 3 -Logfile $LogFile 
                                                                Write-Warning "DriverPack.7z is 0 bytes. Something went wrong."
                                                                throw "DriverPack.7z is 0 bytes. Something went wrong."
                                                            }

                                                            Write-CMTraceLog -Message "Result of 7-Zip operation: $Result." -Component $Component -type 1 -Logfile $LogFile 
                                                            Write-Information -MessageData "Result of 7-Zip operation: $Result." -InformationAction Continue
                                                            
                                                            If (!(Test-Path "$PlatformDriverPath\DriverPack.7z"))
                                                            {
                                                                # Write-Verbose "The 7-Zip file failed to get created."
                                                                Write-CMTraceLog -Message "The 7-Zip file failed to get created." -Component $Component -Type 3 -Logfile $LogFile 
                                                                Write-Warning "The 7-Zip file failed to get created."
                                                                throw "The 7-Zip file failed to get created."
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        # Write-Verbose "File $PlatformDriverPath\DriverPack.7z already exists."
                                                        Write-CMTraceLog -Message "File $PlatformDriverPath\DriverPack.7z already exists." -Component $Component -Type 3 -Logfile $LogFile 
                                                    }
                                                }
                                            }
                                            elseif ($CompressionMethod -eq 'Zip')
                                            {
                                                Write-CMTraceLog -Message "Zip compression method selected." -Component $Component -type 1 -Logfile $LogFile
                                            }
                                            elseif ($CompressionMethod -eq 'WIM')
                                            {
                                                Write-CMTraceLog -Message "WIM compression method selected." -Component $Component -type 1 -Logfile $LogFile
                                            }

                                        } # if compress
                                        
                                        # Generate supporting files
                                        Get-HPDeviceDetails -Platform $PlatformID | Out-File "$PlatformRoot\PlatformInfo.txt"
                                        Get-HPDeviceDetails -Platform $PlatformID -OSList | Out-File "$PlatformRoot\OSSupport.txt"

                                        if ($CopyDP)
                                        {
                                            # $DestPath = "$DPDestination\HP_DP_$($PlatformID)_$OS-$OSBuild-$($(get-date).ToString("yyyyMM"))"
                                            $DestPath = "$DPDestination\$((Get-Culture).TextInfo.ToTitleCase($Status))\$OS\$OSBuild\$PlatformID"
                                            if($PSCmdlet.ShouldProcess($PlatformID,"Copy files for driver pack to $DestPath and create package" + "?"))
                                            {
                                                If ($Compress)
                                                {
                                                    # Write-Verbose "Copy driver pack to $DPDestination\HP_DP_$($Platform)_$OS-$OSBuild-$((Get-date).year)$((Get-date).month)."
                                                    Write-CMTraceLog -Message "Copy driver pack to $DestPath." -Component $Component -type 1 -Logfile $LogFile 
                                                    Write-Information -MessageData "Copy driver pack to $DestPath." -InformationAction Continue

                                                    If (!(Test-Path $DestPath))
                                                    {
                                                        # New-Item -ItemType Directory -Path "$DPDestination\HP_DP_$($Platform)_$OS-$OSBuild-$((Get-date).year)$((Get-date).month)" -Force
                                                        [void][System.IO.Directory]::CreateDirectory($DestPath)
                                                    }

                                                    Copy-FileWithProgress -SourceDir $PlatformDriverPath -DestDir $DestPath -FileName "DriverPack.7z"
                                                    
                                                    # Write-Verbose "Copying 7-Zip files needed to decompress file."
                                                    Write-CMTraceLog -Message "Copying 7-Zip files needed to decompress file to $DestPath." -Component $Component -type 1 -Logfile $LogFile 
                                                    Write-Information -MessageData "Copying 7-Zip files needed to decompress file to $DestPath." -InformationAction Continue
                                                    Copy-7ZipFiles -Path $DestPath

                                                    <#If ($CreatePackage)
                                                    {
                                                        Write-CMTraceLog -Message "Creating new ConfigMgr package: `"DriverPack: HP $($PlatformID) $OS $OSBuild - $((Get-Culture).TextInfo.ToTitleCase($Status))`" at $DestPath." -Component $Component -type 1 -Logfile $LogFile 
                                                        Write-Information -MessageData "Creating new ConfigMgr package: `"DriverPack: HP $($PlatformID) $OS $OSBuild - $((Get-Culture).TextInfo.ToTitleCase($Status))`" at $DestPath." -InformationAction Continue

                                                        If ($UpdateExistingPackage)
                                                        {
                                                            Write-CMTraceLog -Message "UpdateExistingPackage paramater passed. Updating existing package if it exists." -Component $Component -type 1 -Logfile $LogFile 
                                                            Write-Information -MessageData "UpdateExistingPackage paramater passed. Updating existing package if it exists." -InformationAction Continue
                                                            $NewPackageInfo = New-DM_CMDriverManagementPackage -PlatformID $PlatformID -OS $OS -OSBuild $OSBuild -Status $((Get-Culture).TextInfo.ToTitleCase($Status)) -PackageType DriverPack -Manufacturer 'HP' -Path $DestPath -UpdateExistingPackage
                                                        }
                                                        else
                                                        {
                                                            $NewPackageInfo = New-DM_CMDriverManagementPackage -PlatformID $PlatformID -OS $OS -OSBuild $OSBuild -Status $((Get-Culture).TextInfo.ToTitleCase($Status)) -PackageType DriverPack -Manufacturer 'HP' -Path $DestPath
                                                        }

                                                        # Write-CMTraceLog -Message "NewPackageInfo $NewPackageInfo" -Component $Component -type 1 -Logfile $LogFile
                                                    } #>
                                                }

                                                # Write-Verbose "Copy driver pack support files..."
                                                Write-CMTraceLog -Message "Copy driver pack support files from $PlatformRoot to $DestPath..." -Component $Component -type 1 -Logfile $LogFile
                                                Copy-FileWithProgress -SourceDir $PlatformRoot -DestDir $DestPath -FileName 'PlatformInfo.txt'
                                                # Copy-Item -Path "$PlatformRoot\PlatformInfo.txt" -Destination "$DestPath\PlatformInfo.txt"
                                                Copy-FileWithProgress -SourceDir $PlatformRoot -DestDir $DestPath -FileName 'OSSupport.txt'
                                                # Copy-Item -Path "$PlatformRoot\OSSupport.txt" -Destination "$DestPath\OSSupport.txt"

                                                Copy-FileWithProgress -SourceDir "$PlatformDriverPath\DP$PlatformID" -DestDir $DestPath -FileName 'DriverInfo.txt'

                                                if ($ExcludeSupportFiles)
                                                {
                                                    Foreach ($ESF in $ExcludeSupportFiles)
                                                    {
                                                        If (test-path "$PlatformRoot\$ESF")
                                                        {
                                                            Write-CMTraceLog -Message "Copying exclude support file(s): $ESF" -Component $Component -type 1 -Logfile $LogFile 
                                                            Copy-FileWithProgress -SourceDir $PlatformRoot -DestDir $DestPath -FileName $ESF
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        $props = [pscustomobject]@{
                                            'PlatformID'=$PlatformID
                                            'OS'=$OS
                                            'OSBuild'=$OSBuild
                                            'DriverRoot'=$DriverRoot
                                            'Path'="$DestPath"
                                            'Status'=$((Get-Culture).TextInfo.ToTitleCase($Status))           
                                        }

                                        <#If ($NewPackageInfo)
                                        {
                                            # If $CreatePackage is true add needed values to the custom object before output.
                                            $props | Add-Member -MemberType NoteProperty -Name 'PackageID' -Value $NewPackageInfo.PackageID
                                            $props | Add-Member -MemberType NoteProperty -Name 'Name' -Value $NewPackageInfo.Name
                                            $props | Add-Member -MemberType NoteProperty -Name 'ObjectPath' -Value $NewPackageInfo.ObjectPath
                                            $props | Add-Member -MemberType NoteProperty -Name 'Version' -Value $NewPackageInfo.Version
                                        } #>

                                        # Write-Verbose "Process complete."
                                        Write-CMTraceLog -Message "Process complete." -Component $Component -type 1 -Logfile $LogFile 

                                        If ($Cleanup -eq $true)
                                        {
                                            Write-CMTraceLog -Message "Cleanup enabled." -Component $Component -type 1 -Logfile $LogFile 
                                            Write-CMTraceLog -Message "Removing `"$PlatformDriverPath\DP$PlatformID`"." -Component $Component -type 1 -Logfile $LogFile 
                                            remove-item -Path "$PlatformDriverPath\DP$PlatformID" -Force -Recurse

                                            Write-CMTraceLog -Message "Removing `"$PlatformDriverPath\DriverPack.7z`"." -Component $Component -type 1 -Logfile $LogFile 
                                            remove-item -Path "$PlatformDriverPath\DriverPack.7z" -Force

                                            Write-CMTraceLog -Message "Cleanup complete." -Component $Component -type 1 -Logfile $LogFile 
                                        }

                                        Write-CMTraceLog -Message "------ End $Component End ------" -Component $Component -type 1 -Logfile $LogFile 

                                        return, $props;
                                    }
                                }
                                else
                                {
                                    # Write-Verbose "The drivers for PlatformID have already been downloaded today."
                                    Write-CMTraceLog -Message "The drivers for $PlatformID have already been downloaded today." -Component $Component -type 1 -Logfile $LogFile 
                                }
                            }
                            catch
                            {
                                Write-Warning "Oh snap! An error as occured. $_"
                                $Error[0]
                                Write-CMTraceLog -Message "Oh snap! An error as occured. $_" -Component $Component -Type 3 -Logfile $LogFile 
                                Get-ErrorInformation -incomingError $_
                            }
                        }
                        else
                        {
                            Write-Warning "Platform $PlatformID on OS $OS Version $OSBuild not supported. Check yo self fool."
                            Write-CMTraceLog -Message "Platform $PlatformID on OS $OS Version $OSBuild not supported. Check yo self fool." -Component $Component -Type 3 -Logfile $LogFile 
                            "Platform $PlatformID on OS $OS Version $OSBuild not supported. Check yo self fool."
                        }
                    }
                    else
                    {
                        Write-CMTraceLog -Message "PlatformID: $PlatformID, is not valid." -Component $Component -type 1 -Logfile $LogFile
                        Write-Warning "The PlatformID: $PlatformID, is not valid. Unable to continue. Exiting."
                        Write-Error "The PlatformID: $PlatformID, is not valid. Unable to continue. Exiting." -ErrorAction Stop
                    }

                }

                #endregion #################################### END MAIN LOGIC ####################################>
            }
            else {
                # Write-Verbose "User elected not to continue with script because of VPN connection."
                Write-CMTraceLog -Message "User elected not to continue with script because of VPN connection." -Component $Component -type 1 -Logfile $LogFile 
            }
        } # End of Try
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution. $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            if ($CurrentLocation)
            {
                Set-Location $CurrentLocation
            }
        }
    } # End of Process

    End
    {
        # End
    }

}