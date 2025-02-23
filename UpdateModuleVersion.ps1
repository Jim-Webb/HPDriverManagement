$manifest = Import-PowerShellDataFile .\HPDriverManagement.psd1
[version]$version = $Manifest.ModuleVersion
# Add one to the build of the version number
[version]$NewVersion = "{0}.{1}.{2}.{3}" -f $Version.Major, $Version.Minor, $Version.Build, ($Version.Revision + 1) 
# Update the manifest file
# Update-ModuleManifest -Path .\DriverManagement.psd1 -ModuleVersion $NewVersion
Update-Metadata -Path .\HPDriverManagement.psd1 -PropertyName ModuleVersion -Value $NewVersion