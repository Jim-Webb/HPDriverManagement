The HPDriverManagement module is a wrapper for the HPCMSL module from HP. The goal is to make the HPCMSL easier to use and the output more standardized. In order to build the module you will need to have ModuleBuilder from the PowerShell Gallery install. At the time of writing this,
the latest verion of ModuleBuilder did not work for me. I recommend version 3.1.0.

The code in this module is a sanitized version of what was developed for use at work. There are still some parts of the code that aren't needed in the public version and will be removed as time permits. Once I'm satisfied with the progress, I will publish the module to the PowerShell gallery for easier installation.

[ModuleBuilder - Powershell Gallery](https://www.powershellgallery.com/packages/ModuleBuilder)

[ModuleBuilder - GitHub](https://github.com/PoshCode/ModuleBuilder)

## Folder structure layout and support files

- Public - All functions (files) in this directory will be exported when the module is loaded as public funtions.
- Private - All functions (files) in this directory will be exported when the module is loaded as private funtions. Private functions are only available for use by functions of the module. They are not exported.
- Output - This is where the complete module is stored once built. There will be a directory for each version.
- HPDriverManagement.psd1 - Is the template used to create the complete module. The values in this file are update/replace when the module is built.
- UpdateModuleVersion.ps1 - This is the result of being lazy. When this file is ran, it updates the fourth part of the version number by one. Version 25.2.22.1 would become 25.2.22.2.
- BuildModule.ps1 - This takes some custom paramters and uses them to pass the the ModuleBuilder process. This file makes the build easier by enabling passing the changelog file, building the module only, or building and published to a custom repository. This file will likely need updated once I begin publishing to the PowerShell Gallery.
- CHANGELOG - Used to keep track of changes made to each of the functions.

## How to build

1. Install ModuleBuilder
```powershell
find-module modulebuilder -MaximumVersion 3.1.0 | Install-Module
```
2. Clone the repo
3. Open a PowerShell window and change into the repo directory.
4. Run 'BuildModule.ps1'
```powershell
.\BuildModule.ps1 -BuildModule
```
If you want to incorporate the CHANGELOG file you would run this command:
```powershell
.\BuildModule.ps1 -BuildModule -ChangeLog .\CHANGELOG
```
5. The newly created module should be located in the .\Output\HPDriverManagement\currentversion\ directory
6. Test importing the driver
```powershell
Import-Module .\HPDriverManagement.psd1
```

For information on how to use the module, see the documentation file.
[Documentation](DOCS.md)