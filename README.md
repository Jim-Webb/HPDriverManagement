The HPDriverManagement module is a wrapper for the HPCMSL module from HP. The goal is to make the HPCMSL easier to use and the output more standardized. In order to build the module you will need to have ModuleBuilder from the PowerShell Gallery install. At the time of writing this,
the latest verion of ModuleBuilder did not work for me. I recommend version 3.1.0.

[ModuleBuilder - Powershell Gallery](https://www.powershellgallery.com/packages/ModuleBuilder)

[ModuleBuilder - GitHub](https://github.com/PoshCode/ModuleBuilder)

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
5. The newly created module should be located in the .\Output\HPDriverManagement\currentversion\ directory
6. Test importing the driver
```powershell
Import-Module .\HPDriverManagement.psd1
```

For information on how to use the module, see the documentation file.
[Documentation](DOCS.md)