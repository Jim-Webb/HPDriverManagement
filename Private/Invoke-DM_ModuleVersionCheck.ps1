Function Invoke-DM_ModuleVersionCheck
{
    [CmdletBinding()]
    [Alias('Invoke-ModuleVersionCheck')]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Module,
        [string]$Repository = "PSRepo",
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    try
    {
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "Repository: $Repository" -Component $Component -type 1 -Logfile $LogFile 

        Write-CMTraceLog -Message "Module: $Module" -Component $Component -type 1 -Logfile $LogFile 

        $Installed = Get-InstalledModule -Name $Module -ErrorAction SilentlyContinue

        If ($Installed)
        {
            Write-CMTraceLog -Message "Module $Module is installed." -Component $Component -type 1 -Logfile $LogFile 

            $Repo = Get-PSRepository -Name $Repository -ErrorAction SilentlyContinue

            if ($Repo)
            {
                Write-CMTraceLog -Message "Repository $Repository is configured." -Component $Component -type 1 -Logfile $LogFile 

                $Available = Find-Module -Name $Module -Repository $Repository -ErrorAction SilentlyContinue

                If ($Available)
                {
                    Write-CMTraceLog -Message "Module $Module is available in repository $Repository." -Component $Component -type 1 -Logfile $LogFile 

                    if ($Installed.Version -lt $Available.Version)
                    {
                        Write-CMTraceLog -Message "The version of module $Module installed is older than the version available on $Repository." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "The version of module $Module installed is older than the version available on $Repository." -InformationAction Continue

                        Write-CMTraceLog -Message "Version $($Installed.Version) of the $Module is installed." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Version $($Installed.Version) of the $Module is installed." -InformationAction Continue

                        Write-CMTraceLog -Message "Version $($Available.Version) of the $Module is available." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Version $($Available.Version) of the $Module is available." -InformationAction Continue

                        if ($Installed.InstalledLocation -like 'C:\Program Files\WindowsPowerShell\Modules*')
                        {
                            Write-CMTraceLog -Message "A new version of the module `"$Module`" is available and can be installed by running `"Update-Module`" from and elevated PowerShell prompt." -Component $Component -type 1 -Logfile $LogFile 
                            Write-Information -MessageData "A new version of the module `"$Module`" is available and can be installed by running `"Update-Module`" from and elevated PowerShell prompt." -InformationAction Continue

                            Write-CMTraceLog -Message "The module `"$Module`" has been installed in the global location and can only be updated by running `"Update-Module`"." -Component $Component -type 2 -Logfile $LogFile 
                            Write-Warning "The module `"$Module`" has been installed in the global location and can only be updated by running `"Update-Module`" from an elevated PowerShell prompt."
                        }
                        else
                        {
                            Write-CMTraceLog -Message "A new version of the module `"$Module`" is available and can be installed by running `"Update-Module`"." -Component $Component -type 1 -Logfile $LogFile 
                            Write-Information -MessageData "A new version of the module `"$Module`" is available and can be installed by running `"Update-Module`"." -InformationAction Continue
                        }
                    }
                }
                else
                {
                    Write-Warning "Module `"$Module`" is not available from the repository `"$Repository`"."
                    Write-CMTraceLog -Message "Module `"$Module`" is not available from the repository `"$Repository`"." -Component $Component -type 2 -Logfile $LogFile 
                }
            }
            else
            {
                Write-Warning "Repository `"$Repository`" is not installed on this computer."
                Write-CMTraceLog -Message "Repository `"$Repository`" is not installed on this computer." -Component $Component -type 2 -Logfile $LogFile 
            }

        }
        else
        {
            Write-Warning "Module $Module is not installed."
            Write-CMTraceLog -Message "Module $Module is not installed." -Component $Component -type 2 -Logfile $LogFile
            break
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