Function Invoke-DM_HPIARefFileExclude ()
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

        Function Get-DM_XMLContent ($File)
        {
            [xml]$XML = Get-Content -Path $File

            If ($File)
            {
                return $XML
            }
        }

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }
    }

    Process
    {
        Try
        {
            Foreach ($ID in $PlatformID)
            {
                $PlatformRepoPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID\Repository"
                $PlatformPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID"

                $CurrentLocation = Get-Location
            
                If (-Not (Test-Path $PlatformRepoPath))
                {
                    Write-Warning "The path $HPRepoPath\$Status\$OS\$OSBuild\$ID does not exist. Please use New-DM_HPRepository to create repository."
                    Write-CMTraceLog -Message "The path $HPRepoPath\$Status\$OS\$OSBuild\$ID does not exist. Please use New-DM_HPRepository to create repository." -Component $Component -type 1 -Logfile $LogFile 
                    Break
                }
            
                    Set-Location $PlatformPath
                    Write-Verbose "Location set to $PlatformPath."
                    Write-CMTraceLog -Message "Location set to $PlatformPath." -Component $Component -type 1 -Logfile $LogFile 

                    $HPRefFIle = Get-Item *.xml

                    If (-Not ($HPRefFile))
                    {
                        Write-CMTraceLog -Message "Reference file doesn't exit. Script can't continue." -Component $Component -type 1 -Logfile $LogFile 
                        break
                    }
            
                    If (Test-Path $HPRefFile.FullName)
                    {
                        [xml]$XML = Get-DM_XMLContent -File $HPRefFile.FullName

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
                            foreach ($A in $ExcludeApps)
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
            
                        Foreach ($EA in $ExcludedApps)
                        {
                            If ($XML)
                            {
                                #Progress parameter
                                $i++

                                [int]$percentage = ($i / $ExcludedApps.Count)*100

                                $Progress = @{
                                    Activity = 'Removing excluded applications:'
                                    CurrentOperation = "[$($EA.'type')] Processing $($EA.Application)"
                                    Status = 'Processing application: '
                                    PercentComplete = $percentage
                                }
                            
                                Write-Progress @Progress -Id 1

                                Write-CMTraceLog -Message "[$($EA.'type')] Searching for `"$($EA.Application)`"." -Component $Component -type 1 -Logfile $LogFile 
                                Write-Information -MessageData "[$($EA.'type')] Searching for `"$($EA.Application)`"." -InformationAction Continue
                                Write-CMTraceLog -Message "[$($EA.'type')] Searching for `"$($EA.Application)`"." -Component $Component -type 1 -Logfile "$PlatformPath\XMLExclude.log"

                                $UpdateNodes = $xml.SelectNodes("//UpdateInfo[Name=`"$($EA.Application)`"]")

                                If (-Not ([string]::IsNullOrEmpty($UpdateNodes)))
                                {
                                    Foreach($Node in $UpdateNodes)
                                    {
                                        Write-CMTraceLog -Message "Application $($Node.Name) has been found." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Application $($Node.Name) has been found." -InformationAction Continue
                                        Write-CMTraceLog -Message "Application $($Node.Name) has been found." -Component $Component -type 1 -Logfile "$PlatformPath\XMLExclude.log"

                                        Write-CMTraceLog -Message "Processing update node: $($Node.Name)." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Processing update node: $($Node.Name)." -InformationAction Continue
                                        Write-CMTraceLog -Message "Processing update node: $($Node.Name)." -Component $Component -type 1 -Logfile "$PlatformPath\XMLExclude.log"
                                        $node.parentnode.removechild($Node) | Out-Null
                                        
                                        Start-Sleep 1
                                    }

                                    $XMLUpdate = $true
                                }
                                else
                                {
                                    # Write-Information -MessageData "[UpdateInfo] Application `"$($EA.exclusion)`" not found in XML file." -InformationAction Continue
                                    Write-CMTraceLog -Message "[UpdateInfo] Application `"$($EA.Application)`" not found in XML file." -Component $Component -type 1 -Logfile $LogFile
                                    Write-CMTraceLog -Message "[UpdateInfo] Application `"$($EA.Application)`" not found in XML file." -Component $Component -type 1 -Logfile "$PlatformPath\XMLExclude.log"
                                }

                                $UWAPAppNodes = $xml.SelectNodes("//UWPApps/UWPApp[DisplayName=`"$($EA.Application)`"]")

                                If (-Not ([string]::IsNullOrEmpty($UWAPAppNodes)))
                                {
                                    Foreach($Node in $UWAPAppNodes)
                                    {
                                        Write-CMTraceLog -Message "UWAPApp application $($Node.Name) has been found." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "UWAPApp application $($Node.Name) has been found." -InformationAction Continue
                                        Write-CMTraceLog -Message "UWAPApp application $($Node.Name) has been found." -Component $Component -type 1 -Logfile "$PlatformPath\XMLExclude.log"

                                        Write-CMTraceLog -Message "Processing UWAPApp node: $($Node.Name)." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Processing UWAPApp node: $($Node.Name)." -InformationAction Continue
                                        Write-CMTraceLog -Message "Processing UWAPApp node: $($Node.Name)." -Component $Component -type 1 -Logfile "$PlatformPath\XMLExclude.log"
                                        $node.parentnode.removechild($Node) | Out-Null
                                            
                                        Start-Sleep 1
                                    }

                                    $XMLUpdate = $true
                                }
                                else
                                {
                                    # Write-Information -MessageData "[UWPApps] Application `"$($EA.exclusion)`" not found in XML file." -InformationAction Continue
                                    Write-CMTraceLog -Message "[UWPApps] Application `"$($EA.Application)`" not found in XML file." -Component $Component -type 1 -Logfile $LogFile
                                    Write-CMTraceLog -Message "[UWPApps] Application `"$($EA.Application)`" not found in XML file." -Component $Component -type 1 -Logfile "$PlatformPath\XMLExclude.log"
                                }
                            }
                        }
                    }
                    
                    If ($XMLUpdate -eq $True)
                    {
                        Write-Progress -Activity "Saving updated XML file." -Status "Completing" -CurrentOperation "Saving XML `"$($HPRefFIle.Name)`"" -Id 2

                        Write-CMTraceLog -Message "Saving update XML file to $($HPRefFIle.FullName)." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Saving update XML file to $($HPRefFIle.FullName)." -InformationAction Continue

                        $xml.Save("$($HPRefFIle.FullName)")

                        Write-Progress -Activity "Saving updated XML file." -Status "Complete" -Completed

                        Write-Information -MessageData "Process complete." -InformationAction Continue
                        Write-CMTraceLog -Message "Process complete." -Component $Component -type 1 -Logfile "$PlatformPath\XMLExclude.log"
                        Write-CMTraceLog -Message "End." -Component $Component -type 1 -Logfile $LogFile 
                    }
                    else
                    {
                        Write-Information -MessageData "No excluded applications found. No changes made to XML file." -InformationAction Continue
                        Write-CMTraceLog -Message "No excluded applications found. No changes made to XML file." -Component $Component -type 1 -Logfile $LogFile 
                    }
            
                Set-Location $CurrentLocation
            }
        }
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution. $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            Set-Location $CurrentLocation
        }
    }
}