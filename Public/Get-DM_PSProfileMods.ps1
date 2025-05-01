Function Get-DM_PSProfileMods ()
{
    Write-host "In order to prevent being prompted for required variables when running the cmdlets, you can add the following to your powershell profile."

    Write-Host  "You can add the following to `"$($PROFILE.CurrentUserAllHosts)`" to only effect your profile or"
    Write-host  "add it to `"$PSHOME\Profile.ps1`" to make them available for all users on this system. This option requires Administrative permissions. :-("
    Write-Host  ""
    Write-Host  "###################################################################################"
    Write-host  '$PSDefaultParameterValues["*-DM*:SiteServer"] = "smsprov.corp.viamonstra.com"'
    Write-host  '$PSDefaultParameterValues["*-DM*:SiteCode"] = "HOS"'
    write-host  '$PSDefaultParameterValues["*-DM*:CMDBServer"] = "sccmdb.corp.viamonstra.com"'
    write-host  '$PSDefaultParameterValues["*-DM*:HPRepoPath"] = "\\corp.viamonstra.com\SourceFiles$\WorkstationDriverRepository"'
    write-host  '$PSDefaultParameterValues["*-DM*:PackageContentPath"] = "\\corp.viamonstra.com\SourceFiles$\OSD\Drivers\DriverPacks"'
	Write-Host  '$PSDefaultParameterValues["*-DM*:DistributionPointGroupName"] = "All DPs"'
	Write-Host  '$PSDefaultParameterValues["*-DM*:CMFolder"] = "PS1:\Package\OSD\HP"'
    Write-Host  ""
    Write-Host  "# This command creates a central log file for the driver management process. If this is not set, each function will have it's own log."
    write-host  '$PSDefaultParameterValues["*-DM*:LogFile"] = "C:\ProgramData\Logs\DriverManagement.log"'
    Write-Host  "###################################################################################"

}