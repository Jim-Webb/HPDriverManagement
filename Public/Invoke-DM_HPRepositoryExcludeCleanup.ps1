Function Invoke-DM_HPRepositoryExcludeCleanup ()
{

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
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        $Component = $($myinvocation.mycommand)

        Helper-GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }
    }

    Process
    {
        try
        {
            Foreach ($ID in $PlatformID)
            {
                $PlatformPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID\Repository"
                $PlatformExcludeLogPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID"

                If (!(Get-Module HPCMSL))
                {
                    # Write-Verbose "Importing HPCMSL module."
                    Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
                    Import-Module HPCMSL -ErrorAction SilentlyContinue
                }
            
                $CurrentLocation = Get-Location
            
                If (-Not (Test-Path $PlatformPath))
                {
                    Write-Warning "The path $HPRepoPath\$Status\$OS\$OSBuild\$ID does not exist. Please use New-DM_HPRepository to create repository."
                    Write-CMTraceLog -Message "The path $HPRepoPath\$Status\$OS\$OSBuild\$ID does not exist. Please use New-DM_HPRepository to create repository." -Component $Component -type 1 -Logfile $LogFile 
                    Break
                }
            
                If (Get-Module HPCMSL)
                {
                    Set-Location $PlatformPath
                    Write-Verbose "Location set to $PlatformPath."
                    Write-CMTraceLog -Message "Location set to $PlatformPath." -Component $Component -type 1 -Logfile $LogFile 
                    If ((Test-Path "$PlatformPath\.repository") -and (Test-Path "$PlatformPath\.repository\repository.json"))
                    {
                        #Write-Verbose "Repository exists and has been initilized."
                        Write-CMTraceLog -Message "Repository exists and has been initilized." -Component $Component -type 1 -Logfile $LogFile 
            
                        # Begin removal of excluded files from repository
                        $Apps = @()
                        $Apps = Get-DM_HPRepositoryIncludeExclude -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -HPRepoPath $HPRepoPath

                        # Get apps that are marked to be included on a platform.
                        # Once we have the included applications, we remove those from the excluded applications, leaving the final list of excluded applications.
                        $IncludeApps = $Apps | Where-Object {$_.action -eq "Include"}
                        
                        $ExcludedApps = @()
                        
                        If ($IncludeApps)
                        {
                            # Gets the names of the included applications.
                            $IncludeAppNames = $IncludeApps | Select-Object -ExpandProperty Application

                            Write-CMTraceLog -Message "Not excluding these apps: $IncludeAppNames." -Component $Component -type 1 -Logfile $LogFile
    
                            # Simply removes the included applications from the original array and creates a new array of only excluded applications.
                            $ExcludeApps = $Apps | Where-Object {$_.action -eq "Exclude"}
    
                            # Interate through the excluded applications and remove and applications that were in the included applications list.
                            foreach ($x in $ExcludeApps)
                            {
                                $ExcludedApps = $ExcludeApps | Where-Object {$_.Application -notin $IncludeAppNames}
                            }
                        }
                        else
                        {
                            # If there are no included applications simply pass the excluded applications to the $ExcludedApps variable and everything continues.
                            $ExcludedApps = $Apps | Where-Object {$_.action -eq "Exclude"}
                        }

                        Write-CMTraceLog -Message "Excluded apps: $($ExcludedApps | Select-Object Application | Out-String)." -Component $Component -type 1 -Logfile $LogFile 

                        # Write-Information -MessageData "Begining cleanup." -InformationAction Continue
    
                        $i = 0

                        # $TotalExcludedApps = $ExcludedApps.Count
                        # $CurrentItem = 0
                        # $PercentComplete = 0
                        Write-CMTraceLog -Message "------ Start $(Get-Date -Format MM/dd/yyyy) ------" -Component $Component -type 1 -Logfile "$PlatformExcludeLogPath\Exclude.log"
                        Foreach ($EA in $ExcludedApps)
                        {
                            # Write-Progress -Activity "[$($EA.'exclusion type')] Processing $($EA.exclusion)" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete

                            #Progress parameter
                            [int]$percentage = ($i / $ExcludedApps.Count)*100

                            $Progress = @{
                                Activity = 'Removing excluded applications:'
                                CurrentOperation = "[$($EA.'type')] Processing $($EA.Application)"
                                Status = 'Processing application: '
                                PercentComplete = $percentage
                            }

                            $i++
                        
                            Write-Progress @Progress -Id 1

                            Write-CMTraceLog -Message "[$($EA.'type')] Processing $($EA.Application)." -Component $Component -type 1 -Logfile $LogFile
                            Write-CMTraceLog -Message "[$($EA.'type')] Processing $($EA.Application)." -Component $Component -type 1 -Logfile "$PlatformExcludeLogPath\Exclude.log"
                            # Write-Information -MessageData "[$($EA.'exclusion type')] Processing $($EA.exclusion)." -InformationAction Continue
                            # $SPFile = New-RepositoryReport | Where-Object {$_.Title -eq $($EA.exclusion)} | Select-Object -ExpandProperty Softpaq
                            $SPFile = Get-SoftpaqList -Platform $ID -Bitness 64 -Os $OS -OsVer $OSBuild | Where-Object {$_.name -eq $($EA.Application)} | Select-Object -ExpandProperty id

                            If ($SPFile)
                            {
                                Write-CMTraceLog -Message "SP to remove: $SPFile." -Component $Component -type 1 -Logfile $LogFile 
                                Write-Information -MessageData "SP to remove: $SPFile." -InformationAction Continue
                                $Files = Get-Item "$SPFile.*"

                                If ($Files)
                                {
                                    $f = 0
                                    foreach ($File in $files)
                                    {   
                                        $FileProgress = @{
                                            Activity = 'Removing excluded files:'
                                            Status = 'Processing files: '
                                            PercentComplete = ($f / $Files.Count)*100
                                        }
                                    
                                        Write-Progress @FileProgress -CurrentOperation "Removing $($File.Name)" -id 2

                                        $f++

                                        If (Test-Path $File)
                                        {
                                            if($PSCmdlet.ShouldProcess($File,"Delete file $file from $PlatformPath?"))
                                            {
                                                Write-CMTraceLog -Message "[$($EA.'type')] Removing file $($File.Name)." -Component $Component -type 1 -Logfile $LogFile 
                                                Write-Information -MessageData "[$($EA.'type')] Removing file $($File.Name)." -InformationAction Continue
                                                Write-CMTraceLog -Message "[$($EA.'type')] Removing file $($File.Name)." -Component $Component -type 1 -Logfile "$PlatformExcludeLogPath\Exclude.log"
                                                Remove-Item $($File.Name) -ErrorAction SilentlyContinue -Confirm:$false
                                                Start-Sleep 1
                                                Write-CMTraceLog -Message "[$($EA.'type')] File $($File.Name) has been removed." -Component $Component -type 1 -Logfile $LogFile 
                                                Write-Information -MessageData "[$($EA.'type')] File $($File.Name) has been removed." -InformationAction Continue
                                                Write-CMTraceLog -Message "[$($EA.'type')] File $($File.Name) has been removed." -Component $Component -type 1 -Logfile "$PlatformExcludeLogPath\Exclude.log"
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                Write-CMTraceLog -Message "Nothing to remove for $($EA.exclusion)." -Component $Component -type 1 -Logfile $LogFile 
                            }

                            #$CurrentItem++
                            #$PercentComplete = [int](($CurrentItem / $TotalExcludedApps) * 100)
                        }
                        Write-CMTraceLog -Message "------ End $(Get-Date -Format MM/dd/yyyy) ------" -Component $Component -type 1 -Logfile "$PlatformExcludeLogPath\Exclude.log"
                    }
                    else
                    {
                        Write-CMTraceLog -Message "Either `"$PlatformPath\.repository`" or `"$PlatformPath\.repository\repository.json`" not available." -Component $Component -type 1 -Logfile $LogFile       
                    }
                    
                    Write-Progress -Activity 'Removing excluded files:' -Status "Ready" -Completed -Id 2

                    Write-Progress -Activity 'Removing excluded applications:' -Status "Ready" -Completed -Id 1
                    Write-CMTraceLog -Message "End." -Component $Component -type 1 -Logfile $LogFile 
                }
                else
                {
                    Write-Warning "HPCMSL not available. Unable to continue."
                    Write-CMTraceLog -Message "HPCMSL not available. Unable to continue." -Component $Component -type 3 -Logfile $LogFile 
                }
            
                Set-Location $CurrentLocation
            }
        }
        Catch
        {
            Write-Warning "Something went wrong."
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile
            Get-ErrorInformation -incomingError $_
            Set-Location $CurrentLocation
        }
    }
}