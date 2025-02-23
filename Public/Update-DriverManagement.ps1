<#
.SYNOPSIS
Updates the HPDriverManagement PowerShell Module to the latest version

.DESCRIPTION
Updates the HPDriverManagement PowerShell Module to the latest version from the *repository name* repository.

.LINK
Insert link to repository.

.Example
Update-HPDriverManagement
#>

function Update-DriverManagement {
    [CmdletBinding()]
    PARAM ()
    try {
        Write-Warning "Uninstall-Module -Name HPDriverManagement -AllVersions -Force"
        Uninstall-Module -Name HPDriverManagement -AllVersions -Force
    }
    catch {}

    try {
        Write-Warning "Install-Module -Name HPDriverManagement -Force"
        Install-Module -Name HPDriverManagement -Force
    }
    catch {}

    try {
        Write-Warning "Import-Module -Name HPDriverManagement -Force"
        Import-Module -Name HPDriverManagement -Force
    }
    catch {}
}