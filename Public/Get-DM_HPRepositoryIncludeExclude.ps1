Function Get-DM_HPRepositoryIncludeExclude ()
{

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [alias('Platform')]
    [string]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("Prod", "Test")]
    [string]$Status,
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    try
    {
        $Component = $($myinvocation.mycommand)

        $InformationPreference = 'Continue'

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "------ Start ------" -Component $Component -type 1 -Logfile $LogFile 

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }

        $ExcludedApps = @()
        $Object = @()

        # Start global config
        $GlobalExclude = "$Status\GlobalIncludeExclude.json"

        $GlobalExcludePath = Join-Path $HPRepoPath -childpath $GlobalExclude

        Write-CMTraceLog -Message "Checking to see if $GlobalExcludePath exists." -Component $Component -type 1 -Logfile $LogFile
        If (-Not (test-path $GlobalExcludePath))
        {
            Write-Warning "Global Include/Exclude file `"$GlobalExcludePath`" does not exist. Unable to continue."
            break
            # Write-CMTraceLog -Message "Creating default $GlobalExcludePath file." -Component $Component -type 1 -Logfile $LogFile
            # New-DM_HPRepositoryGlobalIncludeExcludeConfig -Status $Status
        }

        Write-CMTraceLog -Message "Global path: $GlobalExcludePath" -Component $Component -type 1 -Logfile $LogFile 

        $GlobalExcludeJson = Get-JsonContent -File $GlobalExcludePath
        
        If ($GlobalExcludeJson)
        {
            Write-CMTraceLog -Message "Getting current global excluded apps." -Component $Component -type 1 -Logfile $LogFile 

            If (($GlobalExcludeJson.$OS).Exclude -eq "")
            {
                return $false
            }
            else
            {
                $ExcludedApps = (($GlobalExcludeJson.$OS).Exclude).Split(",")

                Write-CMTraceLog -Message "Global excluded apps: $ExcludedApps." -Component $Component -type 1 -Logfile $LogFile 

                Foreach ($App in $ExcludedApps)
                {
                    $GlobalObj = New-Object System.Management.Automation.PSObject
                    Add-Member -InputObject $GlobalObj -MemberType NoteProperty -Name "Type" -Value "Global"
                    Add-Member -InputObject $GlobalObj -MemberType NoteProperty -Name "Action" -Value "Exclude"
                    Add-Member -InputObject $GlobalObj -MemberType NoteProperty -Name "Platform" -Value "N/A"
                    Add-Member -InputObject $GlobalObj -MemberType NoteProperty -Name "OS" -Value "$OS"
                    Add-Member -InputObject $GlobalObj -MemberType NoteProperty -Name "Application" -Value $App

                    $Object += $Globalobj
                }
            }
        }
        #End global config

        # Read Platform specific excludes
        $ChildPath = "$Status\$OS\$OSBuild\$PlatformID\Repository\.repository\Exclude.json"

        Write-CMTraceLog -Message "Child path: $ChildPath" -Component $Component -type 1 -Logfile $LogFile 

        # Use Join-Path since $RootPath can be passed and may or may not contain a trailing \.
        $FullFilePath = Join-Path $HPRepoPath -childpath $ChildPath

        Write-CMTraceLog -Message "Full path: $FullFilePath" -Component $Component -type 1 -Logfile $LogFile 

        $ConfigFile = $FullFilePath

        Write-CMTraceLog -Message "Config file: $ConfigFile" -Component $Component -type 1 -Logfile $LogFile 

        $Json = Get-JsonContent -File $ConfigFile

        If ($Json)
        {
            Write-CMTraceLog -Message "Getting current platform included and excluded apps." -Component $Component -type 1 -Logfile $LogFile 

            # Handle excluded apps
            If ((($Json.$PlatformID).$OS.$OSBuild.Exclude -eq "") -or ($null -eq ($Json.$PlatformID).$OS.$OSBuild.Include))
            {
                Write-CMTraceLog -Message "No platform excluded apps found." -Component $Component -type 1 -Logfile $LogFile
                Write-Information -MessageData "No platform excluded apps found." -InformationAction Continue
            }
            else
            {
                Write-Information -MessageData "Platform excluded apps found." -InformationAction Continue
                Write-CMTraceLog -Message "Platform excluded apps: $PlatformExcludedApps." -Component $Component -type 1 -Logfile $LogFile 

                $PlatformExcludedApps += (($Json.$PlatformID).$OS.$OSBuild.Exclude).Split(",")

                Foreach ($App in $PlatformExcludedApps)
                {
                    $PlatformObj = New-Object System.Management.Automation.PSObject
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "Type" -Value "Platform"
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "Action" -Value "Exclude"
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "Platform" -Value "$PlatformID"
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "OS" -Value "$OS"
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "Application" -Value $App

                    $Object += $Platformobj
                }
            }

            # Handle included apps
            If ((($Json.$PlatformID).$OS.$OSBuild.Include -eq "") -or ($null -eq ($Json.$PlatformID).$OS.$OSBuild.Include))
            {
                Write-CMTraceLog -Message "No platform include apps found." -Component $Component -type 1 -Logfile $LogFile
                Write-Information -MessageData "No platform include apps found." -InformationAction Continue
            }
            else
            {
                $PlatformIncludedApps += (($Json.$PlatformID).$OS.$OSBuild.Include).Split(",")

                Write-CMTraceLog -Message "Platform included apps: $PlatformIncludedApps." -Component $Component -type 1 -Logfile $LogFile 

                Foreach ($App in $PlatformIncludedApps)
                {
                    $PlatformObj = New-Object System.Management.Automation.PSObject
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "Type" -Value "Platform"
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "Action" -Value "Include"
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "Platform" -Value "$PlatformID"
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "OS" -Value "$OS"
                    Add-Member -InputObject $PlatformObj -MemberType NoteProperty -Name "Application" -Value $App

                    $Object += $Platformobj
                }
            }

        }

        If ($Object)
        {
            # Remove duplicates before returning.
            # $ExcludedApps = $ExcludedApps | Select-Object -Unique

            # return $ExcludedApps
            Write-CMTraceLog -Message "------ End ------" -Component $Component -type 1 -Logfile $LogFile 
            return $Object
        }
        else
        {
            Write-CMTraceLog -Message "------ End ------" -Component $Component -type 1 -Logfile $LogFile 
        }
    }
    catch
    {
        Write-Warning "Something went wrong."
        Write-Warning -Message "An error has occured during script execution."
        # Write-Log -Message "An error has occured during script execution." -Component "Catch" -Type 3
        Get-ErrorInformation -incomingError $_
        # Set-Location $CurrentLocation
        Write-CMTraceLog -Message "------ End ------" -Component $Component -type 1 -Logfile $LogFile 

    }
}