function Invoke-DM_CreateHPIARefFile ()
{
        <#
    .SYNOPSIS
    Creates a reference image xml file for the Platform, OS, and OS version.

    .DESCRIPTION
    Creates a reference image xml file for the Platform, OS, and OS version.

    .PARAMETER Platform
    The platform ID from a HP computer.

    .PARAMETER OS
    Specifies the OS. Windows 10 or Windows 11.

    .PARAMETER OsVer
    The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

    .PARAMETER Status
    Specifies if the reference files should be considered Test or Prod. This allows two separate sets of reference files for each Platform, OS and Build.

    .PARAMETER HPRepoPath

    Root path when the HP repositories are stored.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    No output.

    .EXAMPLE
    Invoke-DM_CreateHPIARefFile -Platform 8711 -OS Win10 -OsVer 22H2

    Generate a reference image XML file for platform 8711 running Windows 10 version 22H2.

    .EXAMPLE
    Import-Csv -Path 'C:\temp\NewHPModels.csv' | Invoke-DM_CreateHPIARefFile -Platform 8711 -OS Win10 -OsVer 22H2

    Invoke-DM_CreateHPIARefFile supports piping a csv file with the needed information to the command. It will then process each entry one at a time.

    The format of the CSV is below:

    Model,Platform,OS,OsVer
    HP EliteDesk 800 G6 Desktop Mini PC,8711,Win10,22H2
    HP ZBook Firefly 14 inch G8 Mobile Workstation PC,880D,Win11,21H2

    .NOTES
    Requires the HPCMSL to be installed on the system running the command.
    #>
    # [CmdletBinding(SupportsShouldProcess=$True)]
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
    [string]$Model,
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
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
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [bool]$ProcessRefImageExcludes = $false,
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    $HPRepoPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin
    {
        $Component = $($myinvocation.mycommand)

        # Helper-GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        $ConfirmPreference = 'None'
    }

    Process
    {
        Try
        {
            Write-CMTraceLog -Message "-----" -Component $Component -type 1 -Logfile $LogFile 
            # Write-CMTraceLog -Message "Model: $Model" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "Model: $Model" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "Platform: $PlatformID" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "OS: $OS" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "OSBuild: $OsBuild" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "-----" -Component $Component -type 1 -Logfile $LogFile 

            #Location to create Reference files
            # $ReferenceFileLocation = "C:\HP ImageAssistant\ReferenceFiles"

            #Temp Cache where files are being built before moved.
            $CacheDir = "$env:temp\HPRefFiles\Cache"
            Write-CMTraceLog -Message "Cache directory: $CacheDir" -Component $Component -type 1 -Logfile $LogFile 

            # $PlatformRootPath = "$HPRepoPath\$Status\$os\$OsVer\$PlatformID"
            $ReferenceFileLocation = "$HPRepoPath\$Status\$os\$OsBuild\$PlatformID"

            If (Test-Path $CacheDir)
            {
                Remove-Item $CacheDir -Force -Recurse -ErrorAction SilentlyContinue -Confirm:$false
            }

            try {
                Write-CMTraceLog -Message "Create $CacheDir" -Component $Component -type 1 -Logfile $LogFile 
                [void][System.IO.Directory]::CreateDirectory($CacheDir)

                Write-CMTraceLog -Message "Create $ReferenceFileLocation" -Component $Component -type 1 -Logfile $LogFile 
                [void][System.IO.Directory]::CreateDirectory($ReferenceFileLocation)
            }
            catch {throw}

            ###

            Function Set-ReferenceFileSoftpaq
            {
                <#
                    Set-ReferenceFileSoftpaq
                    by Dan Felman/HP Inc
            
                    Script will parse an HPIA reference file and replace a Softpaq solution 
                    with a superseded version (anywhere it's referenced)
            
                    If changes are made, a backup is made of the original with extension '.orig'
            
                    8/2/2022 Version 1.01.00 - obtain Ref File with CMSL command
                            add -platform -OS and -OSVer in command line
                    8/3/2022 Version 1.01.01 Better management of cache folder
                            Using current folder for updated reference file
                    8/9/2022 Version 1.01.02 fixed -ToReplace search error
                    8/9/2022 Version 1.01.03 Added source reference file option
                    8/15/2022 Version 1.01.05 created functions
                            Fixed issue where superseded entry was ALSO in main /Solutions
                    8/16/2022 Version 1.01.06 Added -ListNoSupersedes switch
                            Added -ListByCategory <category array> (e.g. bios, or 'bios,driver')
                    8/17/2022 Version 1.01.10 added -ListSuperseded <SoftpaqID>, fixed bugs
                    8/29/2022 Version 1.10.11 made function out of -ListSuperseded option
                    10/27/2022 Version 1.10.12 Fix bug when $ToSoftpaq has no Supersedes entry (last element in chain)
                    10/28/2022 Version 1.10.13 Fix bug with -ReferenceFile code
                    10/28/2022 Version 1.10.14 ...
            
                    Notes:
                        -ReplaceSoftpaq AND -ToSoftpaq <Softpaq_IDs> MUST exist in Reference File
                    
                        Find Softpaqs: Ex Find Nvidia driver Softpaq with CMSL
                            get-softpaqlist | ? { $_.name -match 'nvidia' }
                            get-softpaqlist | ? { $_.Category -match 'network' -and ($_.name -match 'Intel') }
            
                    Options: 
                        -Platform <SysID>               # REQUIRED - also positional
                        -OS Win10|win11                 # REQUIRED - also positional
                        -OSVer <as per Get-SoftpaqList> # REQUIRED - also positional
                        -ReplaceSoftpaq <Softpaq_ID>    # REQUIRED
                                                        # a .bak file is created, but ONLY ONCE, then it is overwritten
                        [-ToSoftpaq <Softpaq_ID>]       # will use 'Previous' SOfptaq if omitted from command line
                        [-CacheDir <path>]              # where Reference file will be downloaded
                                                        If omitted, will use current folder
                        [-ReferenceFile <path>]         # location of reference XML file to modify
                                                        instead of d/l latest from HP
                                                        (-CacheDir option not used in this case)
                        [-ListNoSupersedes]             # Lists Softpaq with no Superseded entry
                        [-ListByCategory]               # lists Softpaqs by Category
                        [-ListSuperseded <Softpaq_ID>]  # Softpaq_ID must be latest recommendation
            
                        All output can be routed to text file: ' > out.txt'
            
                    Examples:
                        // download and update a reference file
                        Set-ReferenceFileSoftpaq -Platform 842a -OS win10 -OSVer 2009 -ReplaceSoftpaq sp139952 [-ToSoftpaq sp139166] [CacheDir <path>]
            
                        // update already downloaded reference file, make a backup of existing file (ONCE)
                        Set-ReferenceFileSoftpaq 842a win10 21H2 -ReplaceSoftpaq sp139952 -ReferenceFile .\842a_64_10.0.2009.xml
            
                        // show Softpaqs that do not supersede any version
                        Set-ReferenceFileSoftpaq 842a win10 21H2 -ListNoSupersedes | ListByCategory <bios,firmware,driver,dock,etc>
            
                        // find the "intel wlan" driver in reference file
                        Set-ReferenceFileSoftpaq1.01.06.ps1 842a win10 2009 -ListByCategory 'driver' | 
                            where { $_ -match 'intel wlan'} 
            
                        // list the superseded chain for a Softpaq
                        Set-ReferenceFileSoftpaq1.01.06.ps1 842a win10 2009 -ListSuperseded sp139952
            
                #>
                param(
                    [Parameter( Mandatory = $True, Position = 0 )] 
                    [string]$Platform,
                    [Parameter( Mandatory = $True, Position = 1 )] [ValidateSet('win10', 'win11')]
                    [string]$OS,
                    [Parameter( Mandatory = $True, Position = 2 )] 
                    [string]$OSVer,
                    [Parameter( Mandatory = $false )] 
                    $CacheDir,
                    [Parameter( Mandatory = $false )] 
                    $ReplaceSoftpaq,
                    [Parameter( Mandatory = $false )] 
                    $ToSoftpaq,
                    [Parameter( Mandatory = $false )] 
                    $ReferenceFile,
                    [Parameter( Mandatory = $false )] 
                    [switch]$ListNoSupersedes,
                    [Parameter( Mandatory = $false )] 
                    $ListByCategory,
                    [Parameter( Mandatory = $false )] 
                    $ListSuperseded
                ) # param
            
                $ReFileVersion = '1.02.00 Oct-28-2022'
                write-verbose "Set-ReferenceFileSoftpaq - version $ReFileVersion"
            
                #################################################################
                # Function Get_ReferenceFileArg
                #
                #   1) copy reference file argument to the caching folde
                #   2) if file with same reference file name exists in 
                #      current folder, renames it as .bak (only once)
                #   3) copies file from cache folder to current folder
                #
                #   Returns: path of reference file in current folder
                #################################################################
            
                Function Get_ReferenceFileArg {
                    [CmdletBinding()]
                    param( $pReferenceFile, $pCacheDir ) 
            
                    if ( Test-Path $pReferenceFile ) {
                        $f_CurrentFolder = Get-Location
                        $f_ReferenceFileFolder = Split-Path -Path $pReferenceFile -Parent
                        $pReferenceFileName = Split-Path -Path $pReferenceFile -Leaf
                        $f_DestinationXmlFile = $f_CurrentFolder.Path+'\'+$pReferenceFileName       # Destination path
                        $pReferenceFile = (Resolve-Path -Path $pReferenceFile).Path
            
                        # if Reference File Argument is already in Current Folder, nothing to do (e.g., paths match)
                        if ( (Join-Path $f_DestinationXmlFile '') -eq (Join-Path $pReferenceFile '') ) {
                            #'-- Use existing Reference File' | out-host
                            write-verbose '-- Use existing Reference File'
                            $f_DestinationXmlFile = $pReferenceFile
                        } else {
                            Try {
                                $Error.Clear()
                                if ( Test-Path $f_DestinationXmlFile) {
                                    Move-Item -Path $f_DestinationXmlFile -Destination $f_DestinationXmlFile'.bak' -Force -EA Stop
                                }
                                Copy-Item $pReferenceFile -Destination $f_DestinationXmlFile -Force -EA Stop
                            } catch {
                                $error[0].exception          # $error[0].exception.gettype().fullname 
                                exit 2
                            }
                        } # else if ( (Join-Path $f_DestinationXmlFile '') -eq (Join-Path $pReferenceFile '') )
                    } else {
                        write-verbose '-- Reference File does not exist'
                        exit 1
                    } # else if ( Test-Path $pReferenceFile )
            
                    return $f_DestinationXmlFile
            
                } # Function Get_ReferenceFileArg
                #################################################################
            
                #################################################################
                # Function Get_ReferenceFileFromHP
                #
                #   1) retrieves latest reference file from HP to cache folder
                #      (with CMSL Get-SofptaqList)
                #   2) finds downloaded reference (xml) file
                #   3) copies file from cache folder to current folder
                #      replacing file if same file name exists in folder
                #
                #   Returns: path of reference file in current folder
                #################################################################
            
                Function Get_ReferenceFileFromHP {
                    [CmdletBinding()]
                    param( $pPlatform, $pOS, $pOSVer, $pCacheDir ) 
            
                    Try {
                        $Error.Clear()
                        get-softpaqList -platform $pPlatform -OS $pOS -OSVer $pOSVer -Overwrite 'Yes' -CacheDir $pCacheDir -EA Stop | Out-Null
                    } Catch {
                        $error[0].exception          # $error[0].exception.gettype().fullname 
                        return
                    }
                    # find the downloaded Reference_File.xml file
                    $f_XmlFile = Get-Childitem -Path $pCacheDir'\cache' -Include "*.xml" -Recurse -File |
                        where { ($_.Directory -match '.dir') -and ($_.Name -match $pPlatform) `
                            -and ($_.Name -match $pOS.Substring(3)) -and ($_.Name -match $pOSVer) }
            
                    Copy-Item $f_XmlFile -Destination $Pwd.Path -Force
            
                    return "$($Pwd.Path)\$($f_XmlFile.Name)"   # final destination in current folder
            
                } # Function Get_ReferenceFileFromHP
                #################################################################
            
                #################################################################
                # Function ListSupersededChain
                #
                #   1) retrieves latest reference file from HP to cache folder
                #      (with CMSL Get-SofptaqList)
                #   2) scans the supersede chaing for the argument
                #
                #################################################################
            
                Function ListSupersededChain { 
                    [CmdletBinding()]
                    param( $pSolutionsNodes, $pssNodes, [string]$pListSuperseded ) 
            
                    $f_ssNode = $pSolutionsNodes | where { $_.id -eq $pListSuperseded }
                    if ( $f_ssNode ) {
                        write-verbose "// List of Superseded Softpaqs for $pListSuperseded $($f_ssNode.name)"
                        "   $($f_ssNode.id) / $($f_ssNode.version)"
                        # check if superseded is in /Solutions by mistake first (assume only possible once)
                        $f_ssNodeNext = $pSolutionsNodes | where { $_.id -eq $f_ssNode.supersedes }
                        if ( $f_ssNodeNext ) {
                            ".... $($f_ssNodeNext.id) / $($f_ssNodeNext.version)"
                            $f_ssNode = $pSolutionsNodes | where { $_.id -eq $f_ssNode.supersedes }
                        }
                        # ... find and list the superseded chain of Softpaqs
                        do {
                            if ( $f_ssNode = $pssNodes | where { $_.id -eq $f_ssNode.supersedes } ) {
                                "   $($f_ssNode.id) / $($f_ssNode.version)"
                            } else {
                                break
                            }
                        } while ( $f_ssNode -ne $null )
                    } else {
                        write-verbose 'Softpaq not found'
                    } # if ( $f_ssNode )
            
                } # Function ListSupersededChain
            
                #################################################################
                # Step 1. make sure Reference File is available
                #################################################################
            
                # Set up the Cache folder path that hosts the TEMP reference file
            
                if ( $CacheDir -eq $null ) { 
                    $CacheDir = $Pwd.Path 
                }
                $CacheDir = (Convert-Path $CacheDir)
            
                # check for -ReferenceFile argument, in case we should use it
            
                if ( $ReferenceFile -eq $null ) {
                    $ReferenceFile = Get_ReferenceFileFromHP $Platform $OS $OSVer $CacheDir
                    write-verbose "-- Caching folder: $CacheDir\cache"
                } else {
                    $ReferenceFile = Get_ReferenceFileArg $ReferenceFile $CacheDir
                    write-verbose "-- Caching folder: $CacheDir"
                    } # else if ( $ReferenceFile -ne $null )
            
                Try {
                    write-verbose "-- Working Reference file: '$ReferenceFile'"
                    $Error.Clear()
                    $xmlContent = [xml](Get-Content -Path $ReferenceFile)
                } Catch {
                    $error[0].exception          # $error[0].exception.gettype().fullname 
                    return 3
                }
            
                # get each section of the XML file
                $SystemNode = $xmlContent.SelectNodes("ImagePal/SystemInfo")
                $SolutionsNodes = $xmlContent.SelectNodes("ImagePal/Solutions/UpdateInfo")
                $ssNodes = $xmlContent.SelectNodes("ImagePal/Solutions-Superseded/UpdateInfo")
                $swInstalledNodes = $xmlContent.SelectNodes("ImagePal/SystemInfo/SoftwareInstalled/Software")
                $deviceNodes = $xmlContent.SelectNodes("ImagePal/Devices/Device")
            
                ###################################################
                # List all Softpaqs that do not supersede any other
                ###################################################
                # find all Softpaqs that do not Superseded any other
                if ( $ListNoSupersedes ) {
                    write-verbose "// Liting Softpaqs with no Superseded version"
                    foreach ( $entry in $SolutionsNodes ) {
                        if ( $entry.Supersedes -eq $null ) {
                            "   $($entry.id) $($entry.name) / $($entry.version)"
                        }
                    } # foreach ( $entry in $SolutionsNodes )
                    return
                } # if ( $ListNoSupersedes )
            
                ###################################################
                # List Softpaqs by each category (as per cmd line)
                ###################################################
                if ( $ListByCategory ) {
                    [array]$CatArray = $ListByCategory.split(',')
                    write-verbose "// Listing by Category $ListByCategory"
            
                    foreach ( $i in $CatArray ) {
                        write-verbose "// Category: $($i)"
                        $SoftpaqByCategoryNodes = $SolutionsNodes | Where-Object { $_.category -match $i }
                        foreach ( $sol in $SoftpaqByCategoryNodes ) {
                            if ( $sol.category -match $i ) {
                                "   $($sol.id) $($sol.name) / $($sol.version)"
                            }
                        } # foreach ( $sol in $SoftpaqByCategoryNodes )
                    } # foreach ( $i in $CatArray )
                    return
                } # if ( $ListCategory )
            
                ###################################################
                # List the Superseded chain for a specific Softpaq
                ###################################################
                if ( $ListSuperseded ) {
                    ListSupersededChain $SolutionsNodes $ssNodes $ListSuperseded
                    return # nothing else to do, so exit
                } # if ( $ListSuperseded -ne $null )
            
                #################################################################
                # Step 2. Find the Softpaq to replace and its replacement in file
                #################################################################
            
                ###################################################
                # Find -ReplaceSoftpaq to replace in /Solutions
                ###################################################
                $SoftpaqNode = $SolutionsNodes | where { $_.id -eq $ReplaceSoftpaq }
            
                write-verbose "-- Begin XML reference file modification"
                if ( $SoftpaqNode -eq $null ) {
                    # return "Softpaq $ReplaceSoftpaq not found in Reference File"
                    Write-Verbose "Softpaq $ReplaceSoftpaq not found in Reference File"
                    return
                    
                }
                write-verbose "-- /Solutions: ReplaceSoftpaq Found - $ReplaceSoftpaq/$($SoftpaqNode.Version) - $($SoftpaqNode.Category)"
            
                ###################################################
                # Find -ToSoftpaq in /Solutions-Superseded
                ###################################################
            
                if ( $ToSoftpaq -eq $null ) { $ToSoftpaq = $SoftpaqNode.Supersedes }
                if ( $ToSoftpaq -eq $null ) { 
                    # return '-- Error: No superseded Softpaq listed'
                    Write-Verbose '-- Error: No superseded Softpaq listed'
                    return
                }
            
                # ... first check for the node in /Solutions (can be a file ERROR - SHOULD BE REPORTED)
                $ssNode = $SolutionsNodes | where { $_.id -eq $ToSoftpaq }
            
                if ( $ssNode.id -eq $null ) {
            
                    # ... next, search the supersede chain for the Softpaq node
                    do {
                        #$ssNode = $ssNodes | where { $_.id -eq $SSSoftpaqID }
                        $ssNode = $ssNodes | where { $_.id -eq $ToSoftpaq }
                        if ( ($SSSoftpaqID = $ssNode.Supersedes) -eq $null) { break }
                    } while ( ($ssNode.id -ne $ToSoftpaq) -and ($SSSoftpaqID -ne $null) )
            
                    if ( $ssNode.id -ne $ToSoftpaq ) {
                        if ( $ssNode -eq $null ) {
                            # return "-- ToSoftpaq not found - $($ToSoftpaq) must be a superseded Softpaq for $($SoftpaqNode.id)"
                            Write-Verbose "-- ToSoftpaq not found - $($ToSoftpaq) must be a superseded Softpaq for $($SoftpaqNode.id)"
                            return
                        } else {
                            write-verbose "-- /Solutions: ToSoftpaq found - $($ssNode.id)/$($ssNode.Version)"
                        } # else if ( $ssNode -eq $null )
                    } else {
                        write-verbose "-- /Solutions-Superseded: ToSoftpaq found - $($ssNode.id)/$($ssNode.Version)"
                    } # else if ( $ssNode.id -ne $ToSoftpaq )
            
                } # if ( $ssNode.id -eq $null )
            
                #################################################################
                # Step 3. Replace content with superseded Softpaq node
                #################################################################
            
                ###################################################
                # Handle the case this is a BIOS
                ###################################################
                #if BIOS Softpaq, check /System node area (top of file)
            
                if ( ($SoftpaqNode.Category -eq 'BIOS') -and ($SystemNode.System.Solutions.UpdateInfo.IdRef -eq $ReplaceSoftpaq) ) {
                    $SystemNode.System.Solutions.UpdateInfo.IdRef = $ssNode.Id 
                    write-verbose "-- /System: (/Category:BIOS) updated /UpdateInfo IdRef= entry"
                }
            
                ###################################################
                # Solutions: Replace contents of Softpaq node w/replacement
                ###################################################
            
                if ( $null -ne $ssNode.Supersedes ) {
                    $SoftpaqNode.Supersedes = [string]$ssNode.Supersedes
                } else {
                    $SoftpaqNode.RemoveAttribute("Supersedes")
                }
                $SoftpaqNode.ColId = $ssNode.ColId
                $SoftpaqNode.ItemId = $ssNode.ItemId
                $SoftpaqNode.Id = $ssNode.Id
                $SoftpaqNode.Name = $ssNode.Name
                $SoftpaqNode.Category = $ssNode.Category
                $SoftpaqNode.Version = $ssNode.Version
                $SoftpaqNode.Vendor = $ssNode.Vendor
                $SoftpaqNode.ReleaseType = $ssNode.ReleaseType
                $SoftpaqNode.SSMCompliant = $ssNode.SSMCompliant
                $SoftpaqNode.DPBCompliant = $ssNode.DPBCompliant
                $SoftpaqNode.SilentInstall = $ssNode.SilentInstall
                $SoftpaqNode.Url = $ssNode.Url
                $SoftpaqNode.ReleaseNotesUrl = $ssNode.ReleaseNotesUrl
                $SoftpaqNode.CvaUrl = $ssNode.CvaUrl
                $SoftpaqNode.MD5 = $ssNode.MD5
                $SoftpaqNode.SHA256 = $ssNode.SHA256
                $SoftpaqNode.Size = $ssNode.Size
                $SoftpaqNode.DateReleased = $ssNode.DateReleased
                $SoftpaqNode.SupportedLanguages = $ssNode.SupportedLanguages
                $SoftpaqNode.SupportedOS = $ssNode.SupportedOS
                $SoftpaqNode.Description = $ssNode.Description
                write-verbose "-- /solutions: ReplaceSoftpaq node Updated [$($ReplaceSoftpaq) with $($ssNode.id)]"
            
                ###################################################
                # SoftwareInstalled: Upate contents of node w/replacement
                ###################################################
                $swInstalledFound = $false
                foreach ( $sw in $swInstalledNodes ) {
                    if ( $sw.Solutions.UpdateInfo.IdRef -eq $ReplaceSoftpaq ) {
                        $sw.Version = [string]$ssNode.Version
                        $sw.Vendor = [string]$ssNode.Vendor
                        $sw.Solutions.UpdateInfo.IdRef = $SoftpaqNode.Id
                        $swInstalledFound = $true
                    }
                } # foreach ( $sw in $swInstalledNodes )
            
                if ( $swInstalledFound ) {
                    write-verbose "-- /SoftwareInstalled: Replaced values for ReplaceSoftpaq $($ReplaceSoftpaq)"
                } else {
                    write-verbose "-- /SoftwareInstalled: No matches found for ReplaceSoftpaq $($ReplaceSoftpaq)"
                }
            
                $DeviceCount = 0
                foreach ( $dev in $deviceNodes ) {
                    if ( $dev.Solutions.UpdateInfo.IdRef -eq $ReplaceSoftpaq ) {
                        $DeviceCount += 1
                        $dev.DriverDate = [string]$ssNode.DateReleased
                        $Dev.DriverProvider = [string]$ssNode.Vendor
                        $Dev.DriverVersion = [string]$ssNode.Version   # $Dev.DriverVersion comes from Device Manager
                        $dev.Solutions.UpdateInfo.IdRef = $ssNode.Id
                    }
                } # foreach ( $dev in $deviceNodes )
            
                if ( $DeviceCount -gt 0 ) {
                    write-verbose "-- /Devices: Found $DeviceCount matches - Replaced info with new Softpaq $([string]$ssNode.Id)"
                } else {
                    write-verbose "-- /Devices: No matches found for ReplaceSoftpaq $($ReplaceSoftpaq)"
                } # else if ( $DeviceCount -gt 0 )
            
                $xmlContent.Save((Convert-Path $ReferenceFile))
                write-verbose "-- Reference File Updated: '$ReferenceFile'"
            }

            ###
            Write-CMTraceLog -Message "Saving current location." -Component $Component -type 1 -Logfile $LogFile 
            $CurrentLocation = Get-Location
            Write-CMTraceLog -Message "Saved location: $CurrentLocation." -Component $Component -type 1 -Logfile $LogFile 

            Write-CMTraceLog -Message "Setting location to $ReferenceFileLocation." -Component $Component -type 1 -Logfile $LogFile 
            Set-Location -Path $ReferenceFileLocation
                
            <#foreach ($Platform in $ModelsTable.Platform){
                $Model = ($ModelsTable | Where-Object {$_.Platform -eq $Platform}).Model
            foreach ($OS in $OSTable.OS){
                    $OSVer = ($OSTable | Where-Object {$_.OS -eq $OS}).osver
                Write-Host "-- $Model | $OS | $OSVer --" -ForegroundColor Cyan
                    Set-ReferenceFileSoftpaq -Platform $Platform -OS $OS -OSVer $OSVer -CacheDir $CacheDir 
            }
            
            }#>

            if($PSCmdlet.ShouldProcess($PlatformID, "Create XML reference file for $PlatformID running $OS ($OsBuild)"))
            {
                Write-CMTraceLog -Message "Running set-ReferenceFileSoftpaq function." -Component $Component -type 1 -Logfile $LogFile 
                Set-ReferenceFileSoftpaq -Platform $PlatformID -OS $OS -OSVer $OSBuild -CacheDir $CacheDir
                Write-CMTraceLog -Message "Function set-ReferenceFileSoftpaq complete." -Component $Component -type 1 -Logfile $LogFile 

                If ($ProcessRefImageExcludes -eq $true)
                {
                    # XML file cleanup
                    Write-CMTraceLog -Message "Starting XML file processing." -Component $Component -type 1 -Logfile $LogFile 

                    Invoke-DM_HPIARefFileExclude -PlatformID $PlatformID -OS $OS -OSBuild $OSBuild -Status $Status -HPRepoPath $HPRepoPath

                    Write-CMTraceLog -Message "XML file processing complete." -Component $Component -type 1 -Logfile $LogFile 

                    # End XML file cleanup
                }
                else
                {
                    Write-CMTraceLog -Message "Reference Image XML cleanup not enabled.." -Component $Component -type 1 -Logfile $LogFile 
                }

                $props = [pscustomobject]@{
                    #'Model'= $Model
                    'PlatformID'=$PlatformID
                    'OS'=$OS
                    'OSBuild'=$OsBuild
                    'Status'=$Status            
                    'Path'=$ReferenceFileLocation
                }

            }
            Write-CMTraceLog -Message "Setting location back to $CurrentLocation" -Component $Component -type 1 -Logfile $LogFile 
            Set-Location $CurrentLocation

            If ($props)
            {
                return, $props;
            }
        }
        catch
        {
            Write-Warning "Something went wrong."
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile
            Get-ErrorInformation -incomingError $_

            Write-CMTraceLog -Message "Setting location back to $CurrentLocation" -Component $Component -type 1 -Logfile $LogFile 
            Set-Location $CurrentLocation
        }
    }
    End
    {
        # End
    }
}