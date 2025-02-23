#Region '.\Private\Check-DM_PreReqSoftware.ps1' -1

function Check-DM_PreReqSoftware
{
	[CmdletBinding()]
	param (
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
        [ValidateSet("7Zip", "SCCM")]
		[string]$PreReq,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
	)

    $Component = $($myinvocation.mycommand)
    
    $PSDefaultParameterValues = $Global:PSDefaultParameterValues

    Write-CMTraceLog -Message "Parameter passed: $PreReq." -Component $Component -type 1 -Logfile $LogFile 

    If ($PreReq -eq '7Zip')
    {
        Write-CMTraceLog -Message "Checking for 7-Zip." -Component $Component -type 1 -Logfile $LogFile 
        If (Get-InstalledSoftware -Name '7-zip')
        {
            $7ZipExe = "7z.exe"

            If (test-path HKLM:\SOFTWARE\7-Zip)
            {
                $Path = (Get-ItemProperty HKLM:\SOFTWARE\7-Zip).path

                $7ZipExePath = Join-Path $Path $7ZipExe

                If (Test-Path $7ZipExePath)
                {
                    $Global:EXE = $7ZipExePath

                    Write-CMTraceLog -Message "7-Zip exe to use: $exe" -Component $Component -type 1 -Logfile $LogFile 
                    Write-Host "7-Zip exe to use: $exe"

                    return $true
                }
            }
        }
        else
        {
            Write-Warning "7-Zip.exe not present on this computer. Please install 7-Zip and try again."
            Write-CMTraceLog -Message "7-Zip.exe not present on this computer. Please install 7-Zip and try again." -Component $Component -type 3 -Logfile $LogFile
            # break
            return $false
        }
    }

    If ($PreReq -eq 'SCCM')
    {
        Write-CMTraceLog -Message "Checking for SCCM Console." -Component $Component -type 1 -Logfile $LogFile 
        If (Get-InstalledSoftware -Name 'Configuration Manager Console')
        {
            $CMExe = "Microsoft.ConfigurationManagement.exe"

            If (test-path "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1")
            {
                Write-CMTraceLog -Message "SCCM console is installed." -Component $Component -type 1 -Logfile $LogFile 
                # Write-Host "SCCM console is installed."
                If ($null -eq $env:SMS_ADMIN_UI_PATH)
                {
                    Write-CMTraceLog -Message "CM Console is not in Path Variable. Please close the PowerShell console and reopen." -Component $Component -type 2 -Logfile $LogFile 
                    Write-Warning -Message "CM Console is not in Path Variable. Please close the PowerShell console and reopen."
                    return $false
                }
                else
                {
                    Write-CMTraceLog -Message "CM Console is in Path Variable." -Component $Component -type 1 -Logfile $LogFile 
                    return $true
                }
            }
        }
        else
        {
            Write-Warning "Configuration Manager Console not present on this computer. Please install the Configuration Manager Console and try again."
            Write-CMTraceLog -Message "Configuration Manager Console not present on this computer. Please install the Configuration Manager Console and try again." -Component $Component -type 3 -Logfile $LogFile 
            # break
            return $false
        }
    }
}
#EndRegion '.\Private\Check-DM_PreReqSoftware.ps1' 86
#Region '.\Private\Copy-7ZipFiles.ps1' -1

    Function Copy-7ZipFiles ()
    {
        [CmdletBinding()]
        Param(
            [string]$Path,
            [Parameter(Mandatory=$false)]
            [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
        )

        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        If ((Check-DM_PreReqSoftware -PreReq 7Zip) -eq $false) { break }

        $7ZipPath = "$env:ProgramFiles\7-Zip"
        $7ZipFiles = '7z.exe','7z.dll'
        foreach ($File in $7ZipFiles)
        {
            # Write-Verbose "Processing $file"
            Write-CMTraceLog -Message "Processing $file" -Component $Component -type 1
            If (-Not (Test-Path "$7ZipPath\$file"))
            {
                Write-Warning "7-Zip files not found."
                Write-CMTraceLog -Message "7-Zip files not found." -Component $Component -type 3
                break
            }

            try
            {
                $DestPath = Join-Path -Path $Path -ChildPath "\"

                Write-CMTraceLog -Message "Copying $file to $DestPath" -Component $Component -type 1

                copy-item -Path "$7ZipPath\$file" -Destination "$DestPath$file" -Force -ErrorAction Stop
            }
            Catch
            {
                Write-Warning "Could not copy the 7-Zip files. $_"
                Write-CMTraceLog -Message "Could not copy the 7-Zip files. $_" -Component $Component -type 1
                $Error[0]
            }
        }
    }
#EndRegion '.\Private\Copy-7ZipFiles.ps1' 45
#Region '.\Private\Copy-FileWithProgress.ps1' -1

    Function Copy-FileWithProgress ($SourceDir, $DestDir, $FileName)
    {
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-Warning "The Copy-FileWithProgress function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again."
            Write-CMTraceLog -Message "The Copy-FileWithProgress function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again." -Component $Component -Type 3

            break
        }

        Write-CMTraceLog -Message "Copying $FileName from $SourceDir to $DestDir." -Component $Component -type 1

        # Robocopy notes.
        # /J - Copy using unbuffered I/O. Recommended for large files
        # /NJH - Hide job header
        # /NJS - Hide job summary
        # /NDL - Hides output of the directory listing. Full file pathnames are output to more easily track down problematic files.
        # /NC - Hides output the file class â€œText Tagsâ€ (Go here for more information: https://www.uvm.edu/~gcd/2015/04/robocopy-file-classes/)
        # /BYTES - Print sizes as bytes	

        Robocopy $SourceDir $DestDir $FileName /J /NJH /NJS /NDL /NC /BYTES | ForEach-Object{
        
        $Script:data = $_ -split '\x09'
        
        If(![String]::IsNullOrEmpty("$($data[4])")){
            $Script:file = $data[4] -replace '.+\\(?=(?:.(?!\\))+$)'
        }
        If(![String]::IsNullOrEmpty("$($data[0])")){
            $Script:percent = ($data[0] -replace '%') -replace '\s'
        }
        If(![String]::IsNullOrEmpty("$($data[3])")){
            [double]$Script:size = $data[3]
        
            switch ($size) {
                {$_ -gt 1TB -and $_ -lt 1024TB} {
                    [String]$size = ($size / 1TB).ToString("n2") + " TB"
                }
                {$_ -gt 1GB -and $_ -lt 1024GB} {
                    [String]$size = ($size / 1GB).ToString("n2") + " GB"
                }
                {$_ -gt 1MB -and $_ -lt 1024MB} {
                    [String]$size = ($size / 1MB).ToString("n2") + " MB"
                }
                {$_ -ge 1KB -and $_ -lt 1024KB} {
                    [String]$size = ($size / 1KB).ToString("n2") + " KB"
                }
                {$_ -lt 1KB} {
                    [String]$size = "$size B"
                }
        
            }
        }
        
        Write-Progress -Activity "   Copying: " -CurrentOperation "Size: $size      Complete: $percent%"  -Status "   ...\$file"  -PercentComplete "$percent"
    }

        Write-Progress -Activity " " -Completed

        Write-CMTraceLog -Message "Copy completed." -Component $Component -type 1
    }
#EndRegion '.\Private\Copy-FileWithProgress.ps1' 65
#Region '.\Private\Get-DM_HPPlatformIDIsValid.ps1' -1

Function Get-DM_HPPlatformIDIsValid
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [alias('Platform')]
    [string]$PlatformID,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )
    # Get-HPDeviceDetails -Platform $PlatformID -oslist | Where-Object {$_.OperatingSystemRelease -eq $OSBuild -and $_.OperatingSystem -eq "$FullOS"}

    $Component = $($myinvocation.mycommand)

    Write-CMTraceLog -Message "Checking PlatformID $PlatformID to make sure its valid." -Component $Component -type 1 -Logfile $LogFile

    try
    {
        Write-CMTraceLog -Message "Making sure the HPCMSL module is loaded." -Component $Component -type 1 -Logfile $LogFile
        Import-Module -Name HPCMSL -Force -ErrorAction Stop

        If (Get-Module -Name HPCMSL)
        {
            Write-CMTraceLog -Message "HPCMSL is loaded." -Component $Component -type 1 -Logfile $LogFile
            If (Get-HPDeviceDetails -Platform $PlatformID)
            {
                Write-CMTraceLog -Message "PlatformID $PlatformID is valid." -Component $Component -type 1 -Logfile $LogFile
                Write-CMTraceLog -Message "Returning True." -Component $Component -type 1 -Logfile $LogFile
                return $true
            }
            else
            {
                Write-CMTraceLog -Message "PlatformID $PlatformID is not valid." -Component $Component -type 1 -Logfile $LogFile
                Write-CMTraceLog -Message "Returning False." -Component $Component -type 1 -Logfile $LogFile
                return $false
            }
        }
        else
        {
            Write-CMTraceLog -Message "HPCMSL is not loaded." -Component $Component -type 1 -Logfile $LogFile
            Write-Warning "HPCMSL is not loaded. Unable to continue"
            Write-CMTraceLog -Message "Returning False." -Component $Component -type 1 -Logfile $LogFile
            return $false
        }
    }
    catch
    {
        Write-Warning "Something went wrong with checking the PlatformID."
        Write-CMTraceLog -Message "Something went wrong with checking the PlatformID." -Component $Component -type 3 -Logfile $LogFile 
        Write-Warning -Message "An error has occured during script execution."
        Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile 
        Get-ErrorInformation -incomingError $_
    }

    Write-CMTraceLog -Message "Exiting." -Component $Component -type 1 -Logfile $LogFile
}
#EndRegion '.\Private\Get-DM_HPPlatformIDIsValid.ps1' 57
#Region '.\Private\Get-ErrorInformation.ps1' -1

function Get-ErrorInformation() {
    [cmdletbinding()]
    param (
        $incomingError,
        $Component
    )
    
    if (!($Component))
    {
        $Component = 'Get-ErrorInformation'
    }

    if ($incomingError -and (($incomingError | Get-Member | Select-Object -ExpandProperty TypeName -Unique) -eq 'System.Management.Automation.ErrorRecord')) {
        Write-Host `n"Error information:"`n
        Write-CMTraceLog -Message "Error information:" -Component $Component -Type 1
        Write-Host `t"Exception type for catch: [$($IncomingError.Exception | Get-Member | Select-Object -ExpandProperty TypeName -Unique)]"`n
        Write-CMTraceLog -Message "Exception type for catch: [$($IncomingError.Exception | Get-Member | Select-Object -ExpandProperty TypeName -Unique)]" -Component $Component -Type 1
        
        if ($incomingError.InvocationInfo.Line) {
            Write-Host `t"Command                 : [$($incomingError.InvocationInfo.Line.Trim())]"
            Write-CMTraceLog -Message "Command: [$($incomingError.InvocationInfo.Line.Trim())]" -Component $Component -Type 1
        }
        else {
            Write-Host `t"Unable to get command information! Multiple catch blocks can do this :("`n
            Write-CMTraceLog -Message "Unable to get command information! Multiple catch blocks can do this :(" -Component $Component -Type 1
        }
        
        Write-Host `t"Exception               : [$($incomingError.Exception.Message)]"`n
        Write-CMTraceLog -Message "Exception: [$($incomingError.Exception.Message)]" -Component $Component -Type 1
        Write-Host `t"Target Object           : [$($incomingError.TargetObject)]"`n
        Write-CMTraceLog -Message "Target Object: [$($incomingError.TargetObject)]" -Component $Component -Type 1
    }
    Else {
        Write-Host "Please include a valid error record when using this function!" -ForegroundColor Red -BackgroundColor DarkBlue
        Write-CMTraceLog -Message "Please include a valid error record when using this function!" -Component $Component -Type 1
    }
}
#EndRegion '.\Private\Get-ErrorInformation.ps1' 38
#Region '.\Private\Get-InstalledSoftware.ps1' -1

function Get-InstalledSoftware
{
    <#
	.SYNOPSIS
		Retrieves a list of all software installed on a Windows computer.
	.EXAMPLE
		PS> Get-InstalledSoftware
		
		This example retrieves all software installed on the local computer.
	.PARAMETER ComputerName
		If querying a remote computer, use the computer name here.
	
	.PARAMETER Name
		The software title you'd like to limit the query to.
	
	.PARAMETER Guid
		The software GUID you'e like to limit the query to
	#>
	[CmdletBinding()]
	param (
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName = $env:COMPUTERNAME,
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[Parameter()]
		[guid]$Guid,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
	)
	process
	{
        $Component = $($myinvocation.mycommand)

		$PSDefaultParameterValues = $Global:PSDefaultParameterValues

		try
		{
			Write-CMTraceLog -Message "Software to seach for: $Name." -Component $Component -type 1 -Logfile $LogFile

			$scriptBlock = {
				$args[0].GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value }
				
				$UninstallKeys = @(
					"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
					"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
				)

				if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
				{
					Write-CMTraceLog -Message "User is an Administrator, also searching HKCU." -Component $Component -type 1 -Logfile $LogFile
					New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
					$UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"}
				}

				if (-not $UninstallKeys)
				{
					Write-Warning -Message 'No software registry keys found'
					Write-CMTraceLog -Message 'No software registry keys found' -Component $Component -type 3 -Logfile $LogFile
				}
				else
				{
					foreach ($UninstallKey in $UninstallKeys)
					{
						$friendlyNames = @{
							'DisplayName'    = 'Name'
							'DisplayVersion' = 'Version'
						}
						Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
						Write-CMTraceLog -Message "Checking uninstall key [$($UninstallKey)]" -Component $Component -type 1 -Logfile $LogFile
						if ($Name)
						{
							$WhereBlock = { $_.GetValue('DisplayName') -like "*$Name*" }
						}
						elseif ($GUID)
						{
							$WhereBlock = { $_.PsChildName -eq $Guid.Guid }
						}
						else
						{
							$WhereBlock = { $_.GetValue('DisplayName') }
						}
						$SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
						if (-not $SwKeys)
						{
							Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
							Write-CMTraceLog -Message "No software keys in uninstall key $UninstallKey" -Component $Component -type 1 -Logfile $LogFile
						}
						else
						{
							Write-CMTraceLog -Message "Software `"$Name`" found." -Component $Component -type 1 -Logfile $LogFile
							foreach ($SwKey in $SwKeys)
							{
								$output = @{ }
								foreach ($ValName in $SwKey.GetValueNames())
								{
									if ($ValName -ne 'Version')
									{
										$output.InstallLocation = ''
										if ($ValName -eq 'InstallLocation' -and
											($SwKey.GetValue($ValName)) -and
											(@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\')))
										{
											$output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
										}
										[string]$ValData = $SwKey.GetValue($ValName)
										if ($friendlyNames[$ValName])
										{
											$output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
										}
										else
										{
											$output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
										}
									}
								}
								$output.GUID = ''
								if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')
								{
									$output.GUID = $SwKey.PSChildName
								}
								New-Object -TypeName PSObject -Prop $output
							}
						}
					}
				}
			}
			
			if ($ComputerName -eq $env:COMPUTERNAME)
			{
				$Result = & $scriptBlock $PSBoundParameters

				Write-CMTraceLog -Message "$($Result | out-string)" -Component $Component -type 1 -Logfile $LogFile

				return $Result
			}
			else
			{
				Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $PSBoundParameters
			}
		}
		catch
		{
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
			Write-CMTraceLog -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -Component $Component -type 3 -Logfile $LogFile
		}
	}
}
#EndRegion '.\Private\Get-InstalledSoftware.ps1' 151
#Region '.\Private\Helper-GetCallerPreference.ps1' -1

function Helper-GetCallerPreference
{
	    <#
	    .Synopsis
	       Fetches "Preference" variable values from the caller's scope.
	    .DESCRIPTION
	       Script module functions do not automatically inherit their caller's variables, but they can be
	       obtained through the $PSCmdlet variable in Advanced Functions.  This function is a helper function
	       for any script module Advanced Function; by passing in the values of $ExecutionContext.SessionState
	       and $PSCmdlet, Get-CallerPreference will set the caller's preference variables locally.
	    .PARAMETER Cmdlet
	       The $PSCmdlet object from a script module Advanced Function.
	    .PARAMETER SessionState
	       The $ExecutionContext.SessionState object from a script module Advanced Function.  This is how the
	       Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
	       script module.
	    .PARAMETER Name
	       Optional array of parameter names to retrieve from the caller's scope.  Default is to retrieve all
	       Preference variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0)
	       This parameter may also specify names of variables that are not in the about_Preference_Variables
	       help file, and the function will retrieve and set those as well.
	    .EXAMPLE
	       Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
	
	       Imports the default PowerShell preference variables from the caller into the local scope.
	    .EXAMPLE
	       Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference','SomeOtherVariable'
	
	       Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
	    .EXAMPLE
	       'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
	
	       Same as Example 2, but sends variable names to the Name parameter via pipeline input.
	    .INPUTS
	       String
	    .OUTPUTS
	       None.  This function does not produce pipeline output.
	    .LINK
	       about_Preference_Variables
	    #>
	
	[CmdletBinding(DefaultParameterSetName = 'AllVariables')]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ $_.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
		$Cmdlet,
		[Parameter(Mandatory = $true)]
		[System.Management.Automation.SessionState]$SessionState,
		[Parameter(ParameterSetName = 'Filtered', ValueFromPipeline = $true)]
		[string[]]$Name
	)
	
	begin
	{
		$filterHash = @{ }
	}
	
	process
	{
		if ($null -ne $Name)
		{
			foreach ($string in $Name)
			{
				$filterHash[$string] = $true
			}
		}
	}
	
	end
	{
		# List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0
		
		$vars = @{
			'ErrorView'					    = $null
			'FormatEnumerationLimit'	    = $null
			'LogCommandHealthEvent'		    = $null
			'LogCommandLifecycleEvent'	    = $null
			'LogEngineHealthEvent'		    = $null
			'LogEngineLifecycleEvent'	    = $null
			'LogProviderHealthEvent'	    = $null
			'LogProviderLifecycleEvent'	    = $null
			'MaximumAliasCount'			    = $null
			'MaximumDriveCount'			    = $null
			'MaximumErrorCount'			    = $null
			'MaximumFunctionCount'		    = $null
			'MaximumHistoryCount'		    = $null
			'MaximumVariableCount'		    = $null
			'OFS'						    = $null
			'OutputEncoding'			    = $null
			'ProgressPreference'		    = $null
			'PSDefaultParameterValues'	    = $null
			'PSEmailServer'				    = $null
			'PSModuleAutoLoadingPreference' = $null
			'PSSessionApplicationName'	    = $null
			'PSSessionConfigurationName'    = $null
			'PSSessionOption'			    = $null
			
			'ErrorActionPreference'		    = 'ErrorAction'
			'DebugPreference'			    = 'Debug'
			'ConfirmPreference'			    = 'Confirm'
			'WhatIfPreference'			    = 'WhatIf'
			'VerbosePreference'			    = 'Verbose'
			'WarningPreference'			    = 'WarningAction'
		}
		
		
		foreach ($entry in $vars.GetEnumerator())
		{
			if (([string]::IsNullOrEmpty($entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($entry.Value)) -and
				($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $filterHash.ContainsKey($entry.Name)))
			{
				$variable = $Cmdlet.SessionState.PSVariable.Get($entry.Key)
				
				if ($null -ne $variable)
				{
					if ($SessionState -eq $ExecutionContext.SessionState)
					{
						Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
					}
					else
					{
						$SessionState.PSVariable.Set($variable.Name, $variable.Value)
					}
				}
			}
		}
		
		if ($PSCmdlet.ParameterSetName -eq 'Filtered')
		{
			foreach ($varName in $filterHash.Keys)
			{
				if (-not $vars.ContainsKey($varName))
				{
					$variable = $Cmdlet.SessionState.PSVariable.Get($varName)
					
					if ($null -ne $variable)
					{
						if ($SessionState -eq $ExecutionContext.SessionState)
						{
							Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
						}
						else
						{
							$SessionState.PSVariable.Set($variable.Name, $variable.Value)
						}
					}
				}
			}
		}
		
	} # end
	
}
#EndRegion '.\Private\Helper-GetCallerPreference.ps1' 154
#Region '.\Private\Helper-GetDM_HPCMSLInstallStatus.ps1' -1

Function Helper-GetDM_HPCMSLInstallStatus ()
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    $Component = $($myinvocation.mycommand)

    $PSDefaultParameterValues = $Global:PSDefaultParameterValues

    If (!(Get-InstalledModule HPCMSL -ErrorAction SilentlyContinue))
    {
        Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
        return $false
    }

    if (!(Get-Module HPCMSL))
    {
        Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile

        if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-CMTraceLog -Message "User is an Admin, importing HPCMSL module with global scope." -Component $Component -type 1 -Logfile $LogFile
            Import-Module HPCMSL
        }
        else
        {
            Write-CMTraceLog -Message "User is not an Admin, importing HPCMSL module with local scope." -Component $Component -type 1 -Logfile $LogFile
            Import-Module HPCMSL -Scope Local
        }

        If (!(Get-Module HPCMSL))
        {
            Write-CMTraceLog -Message "HPCMSL was not imported." -Component $Component -type 1 -Logfile $LogFile 
            return $false
        }
        else
        {   
            Write-CMTraceLog -Message "HPCMSL is imported and loaded." -Component $Component -type 1 -Logfile $LogFile 
            return $true
        }
    }
}
#EndRegion '.\Private\Helper-GetDM_HPCMSLInstallStatus.ps1' 46
#Region '.\Private\Import-DM_CMPSModule.ps1' -1

function Import-DM_CMPSModule()
{
    [CmdletBinding()]
    [Alias('Import-CMPSModule')]
    Param(
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [string]$SiteServer,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [string]$SiteCode,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    $Component = $($myinvocation.mycommand)

    # Write-Verbose "Welcome to the Load-CMPSModule function."
    if ($null -ne $env:SMS_ADMIN_UI_PATH)
    {
        If (!(Get-Module -Name ConfigurationManager))
        {
            # Write-Verbose "Found CM Console in Path, trying to import module."
            Write-CMTraceLog -Message "Found CM Console in Path, trying to import module." -Component $Component -type 1 -Logfile $LogFile 
            Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1) -Verbose:$false -Force
            if (Get-Module -Name ConfigurationManager)
            {
                # Write-Verbose "$env:SMS_ADMIN_UI_PATH"
                Write-CMTraceLog -Message "$env:SMS_ADMIN_UI_PATH" -Component $Component -type 1 -Logfile $LogFile 
                # Write-Verbose "Successfully loaded CM Module from Installed Console"
                Write-CMTraceLog -Message "Successfully loaded CM Module from Installed Console" -Component $Component -type 1 -Logfile $LogFile
        
                # Connect to the site's drive if it is not already present
                if($null -eq (Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue))
                {
                    Write-CMTraceLog -Message "PS Drive for CM not available. Creating now." -Component $Component -type 1 -Logfile $LogFile 
                    $null = New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteServer -Scope Global
                }

                $Global:PSModulePath = $true
            }
        }
        Else
        {
            Write-Verbose "CM Module is already loaded, no need to import module."
            Write-CMTraceLog -Message "CM Module is already loaded, no need to import module." -Component $Component -type 1 -Logfile $LogFile

            # Connect to the site's drive if it is not already present
            if($null -eq (Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue))
            {
                Write-CMTraceLog -Message "PS Drive for CM not available. Creating now." -Component $Component -type 1 -Logfile $LogFile 
                $null = New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteServer -Scope Global
            }

            $Global:PSModulePath = $true
        }
    }
    else {
        $Message = "CM Console is not in Path Variable. Unable to continue."
        Write-CMTraceLog -Message "CM Console is not in Path Variable. Unable to continue." -Component $Component -type 2 -Logfile $LogFile 
        # Write-host $Message
        Write-Warning -Message $Message
        
        # Set-Location $CurrentLocation
        
        # exit 55378008
        break
    }
}
#EndRegion '.\Private\Import-DM_CMPSModule.ps1' 68
#Region '.\Private\Invoke-DM_ModuleVersionCheck.ps1' -1

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
#EndRegion '.\Private\Invoke-DM_ModuleVersionCheck.ps1' 96
#Region '.\Private\Invoke-PathPermissionsCheck.ps1' -1

function Invoke-PathPermissionsCheck ()
{
    [CmdletBinding()]
	    Param (
		    [Parameter(Mandatory = $true)]
		    [String]$Path,
            [Parameter(Mandatory=$false)]
            [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
	    )

    $Component = $($myinvocation.mycommand)

    $PSDefaultParameterValues = $Global:PSDefaultParameterValues

    Write-CMTraceLog -Message "Begin $Component." -Component $Component -type 1 -Logfile $LogFile 
    
    Write-CMTraceLog -Message "Path to check: `"$path`"." -Component $Component -type 1 -Logfile $LogFile 

    $File = 'PermissionsTest.txt'

    If (Test-Path $path)
    {
        try
        {
            $TestFile = Join-Path $Path $File

            Write-CMTraceLog -Message "Checking for write access to $Path." -Component $Component -type 1 -Logfile $LogFile
            New-Item $TestFile -ItemType "file" -ErrorAction Stop -Confirm:$false | Out-Null

            If (Test-Path $TestFile)
            {
                Write-CMTraceLog -Message "Write access to $TestFile confirmed." -Component $Component -type 1 -Logfile $LogFile
                Remove-Item $TestFile -Force -ErrorAction Stop -Confirm:$false
                return $true
            }
        }
        catch [System.UnauthorizedAccessException]
        {
            Write-Warning "$_"
            Write-Warning "Please check permissions for user $env:USERDOMAIN\$env:USERNAME."
            Write-CMTraceLog -Message "$_" -Component $Component -type 3 -Logfile $LogFile
            Write-CMTraceLog -Message "Please check permissions for user $env:USERDOMAIN\$env:USERNAME." -Component $Component -type 3 -Logfile $LogFile
            return $false
        }
        catch [System.ArgumentException]
        {
            Write-Warning "$_"
            Write-CMTraceLog -Message "$_" -Component $Component -type 1 -Logfile $LogFile
            return $false
        }
        catch [System.IO.IOException]
        {
            Write-Warning "$_"
            Write-CMTraceLog -Message "$_" -Component $Component -type 1 -Logfile $LogFile
            return $false
        }
        catch
        {
            Write-CMTraceLog -Message "$_" -Component $Component -type 1 -Logfile $LogFile
            Write-Warning "$_"
        }
    }
    else
    {
        Write-CMTraceLog -Message "Can't access $Path." -Component $Component -type 3 -Logfile $LogFile
        Write-Warning "Can't access $Path."
        return $false
    }
}
#EndRegion '.\Private\Invoke-PathPermissionsCheck.ps1' 70
#Region '.\Private\Sync-DirWithProgress.ps1' -1

    Function Sync-DirWithProgress ()
    {
        [CmdletBinding()]
        Param(
        [string]$SourceDir,
        [string]$DestDir,
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
        )

        $Component = $($myinvocation.mycommand)

        if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-Warning "The Copy-FileWithProgress function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again."
            Write-CMTraceLog -Message "The Copy-FileWithProgress function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again." -Component $Component -Type 3

            break
        }

        If (Test-path $SourceDir)
        {
            If (-Not (Test-Path $DestDir))
            {
                Write-CMTraceLog -Message "Path `"$DestDir`" does not exist. Creating path." -Component $Component -type 1 -Logfile $LogFile 
                [void][System.IO.Directory]::CreateDirectory($DestDir)
            }

            If (Test-Path $DestDir)
            {
                Write-CMTraceLog -Message "Syncing directory $SourceDir to $DestDir." -Component $Component -type 1

                # Robocopy notes.
                # /J - Copy using unbuffered I/O. Recommended for large files
                # /NJH - Hide job header
                # /NJS - Hide job summary
                # /NDL - Hides output of the directory listing. Full file pathnames are output to more easily track down problematic files.
                # /NC - Hides output the file class â€œText Tagsâ€ (Go here for more information: https://www.uvm.edu/~gcd/2015/04/robocopy-file-classes/)
                # /BYTES - Print sizes as bytes	

                # robocopy \\columbuschildrens.net\isapps\WorkstationDriverRepository\Test\Win10\22H2\8711 \\columbuschildrens.net\isapps\WorkstationDriverRepository\Prod\Win10\22H2\8711 /NJH /NJS /NDL /e /mt /zb

                # Robocopy $SourceDir $DestDir $FileName /J /NJH /NJS /NDL /NC /BYTES | ForEach-Object{
                Robocopy $SourceDir $DestDir /NJH /NJS /NDL /NC /BYTES /MIR /E /MT /ZB /copy:DAT | ForEach-Object{
                
                    $Script:data = $_ -split '\x09'
                    
                    If(![String]::IsNullOrEmpty("$($data[4])")){
                        $Script:file = $data[4] -replace '.+\\(?=(?:.(?!\\))+$)'
                    }
                    If(![String]::IsNullOrEmpty("$($data[0])")){
                        $Script:percent = ($data[0] -replace '%') -replace '\s'
                    }
                    If(![String]::IsNullOrEmpty("$($data[3])")){
                        [double]$Script:size = $data[3]
                    
                        switch ($size) {
                            {$_ -gt 1TB -and $_ -lt 1024TB} {
                                [String]$size = ($size / 1TB).ToString("n2") + " TB"
                            }
                            {$_ -gt 1GB -and $_ -lt 1024GB} {
                                [String]$size = ($size / 1GB).ToString("n2") + " GB"
                            }
                            {$_ -gt 1MB -and $_ -lt 1024MB} {
                                [String]$size = ($size / 1MB).ToString("n2") + " MB"
                            }
                            {$_ -ge 1KB -and $_ -lt 1024KB} {
                                [String]$size = ($size / 1KB).ToString("n2") + " KB"
                            }
                            {$_ -lt 1KB} {
                                [String]$size = "$size B"
                            }
                    
                        }
                    }
                    
                    Write-Progress -Activity "   Copying: " -CurrentOperation "Size: $size      Complete: $percent%"  -Status "   ...\$file"  -PercentComplete "$percent"
                }

                Write-Progress -Activity " " -Completed

                Write-CMTraceLog -Message "Copy completed." -Component $Component -type 1
            }
            else
            {
                Write-Warning -Message "Unable to connect to the destination path.`nDest Dir: $DestDir."
            }
        }
        else
        {
            Write-Warning -Message "Unable to connect to either the source path.`nSource path: $SourceDir."
        }
    }
#EndRegion '.\Private\Sync-DirWithProgress.ps1' 93
#Region '.\Private\Test-DM_ComputerConnection.ps1' -1

function Test-DM_ComputerConnection ()
{
<#
.SYNOPSIS
  Tests to see if a computer is available and can be connected to.
.DESCRIPTION
  Tests to see if a computer is available and can be connected to. Does a basci ping and tests WSManagemnt.
.PARAMETER ComputerName
    Computer to gather the information from. If this is not specified the local computer will be used.
.INPUTS
  ComputerName as a String.
.OUTPUTS
  True or False.
.NOTES
  Version:        1.0
  Author:         Jim Webb
  Creation Date:  7/28/2018
  Purpose/Change: Initial script development
.EXAMPLE
	Helper-Test-Computer -ComputerName computer1
	
	Will return $true or $false depending on if computer is available.
#>	
	
	
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[String]$ComputerName,
		[string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
	)
	
	$Component = $($myinvocation.mycommand)

	Helper-GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
	
	#Checking to see if the computername passed is the local computer or a remote computer. If local, we don't need to do the remaining tests.	
	if ($ComputerName.ToUpper() -eq $env:COMPUTERNAME.ToUpper())
	{
		Write-CMTraceLog -Message "Computer $ComputerName is not a remote computer. Nothing to test." -Component $Component -type 1 -Logfile $LogFile
		Return $true
	}
	else
	{
		if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)
		{
			Write-CMTraceLog -Message "Test-Connection: $ComputerName OK" -Component $Component -type 1 -Logfile $LogFile
			
			if ([bool](Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue))
			{
				Write-CMTraceLog -Message "Test-WSMan: $ComputerName OK" -Component $Component -type 1 -Logfile $LogFile
				
				if ([bool](Invoke-Command -ComputerName $ComputerName -ScriptBlock { "hello from $env:COMPUTERNAME" } -ErrorAction SilentlyContinue))
				{
					Write-CMTraceLog -Message "Invoke-Command: $ComputerName OK" -Component $Component -type 1 -Logfile $LogFile
					return $true
				}
				else
				{
					Write-CMTraceLog -Message "Invoke-Command: $ComputerName FAILED." -Component $Component -type 1 -Logfile $LogFile
				}
			}
			Else
			{
				Write-CMTraceLog -Message "Test-WSMan: $ComputerName FAILED." -Component $Component -type 1 -Logfile $LogFile
			}
		}
		else
		{
			Write-CMTraceLog -Message "Test-Connection: $ComputerName FAILED." -Component $Component -type 1 -Logfile $LogFile
			return $false
		}
	}
}
#EndRegion '.\Private\Test-DM_ComputerConnection.ps1' 75
#Region '.\Private\Write-CMTraceLog.ps1' -1

function Write-CMTraceLog
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        $Message,
        [Parameter(Mandatory=$false)]
        $ErrorMessage,
        [Parameter(Mandatory=$false)]
        $Component = "Office365",
        [Parameter(Mandatory=$false)]
        [int]$Type,
        [Parameter(Mandatory=$false)]
        $LogFile = "$env:ProgramData\Logs\$Component.log",
        $EnableLogWriteVerbose = $true
        #$LogFile = "$env:ProgramData\Logs\$Component.log"
    )

    # Write-Verbose "Called by: $((Get-PSCallStack)[1].Command)"

    $WhatIfPreference = $false

    Write-Debug "Log file: $LogFile"
    Write-Debug "Component: $Component"

<#     If ($Global:DMLogFile)
    {
        $LogFile = $Global:DMLogFile
        Write-Debug "Log file changed to: $LogFile"
    } #>

    <#
        Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    #>
	    $Time = Get-Date -Format "HH:mm:ss.ffffff"
	    $Date = Get-Date -Format "MM-dd-yyyy"
 
	    if ($ErrorMessage -ne $null) {$Type = 3}
	    if ($Component -eq $null) {$Component = " "}
	    if ($Type -eq $null) {$Type = 1}

        If ($EnableLogWriteVerbose -eq $false)
        {
            Write-Debug "Verbose log messages disabled."
        }
        else
        {
            Write-Verbose -Message "[$((Get-PSCallStack)[1].Command)] $Message"
        }

        $LogPath = Split-Path -path $LogFile

        If (!(Test-Path $LogPath))
        {
            Write-Verbose -Message "Directory $LogPath does not exist and will be created."
            # New-Item -Path $LogPath -ItemType Directory -Force
            [void][System.IO.Directory]::CreateDirectory($LogPath)
        }

	    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
        Write-Debug $LogMessage
	    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile -Confirm:$false
}
#EndRegion '.\Private\Write-CMTraceLog.ps1' 64
#Region '.\Public\Add-DM_HPRepositoryIncludeExclude.ps1' -1

Function Add-DM_HPRepositoryIncludeExclude ()
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
    [ValidateSet("Include", "Exclude")]
    [string[]]$Action,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [string[]]$App,
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $ReturnValue = $false

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }
    }

    Process
    {
        foreach ($ID in $PlatformID)
        {
            $ChildPath = "$Status\$OS\$OSBuild\$ID\Repository\.repository\Exclude.json"
    
            Write-CMTraceLog -Message "Child path: $ChildPath" -Component $Component -type 1 -Logfile $LogFile 
        
            # Use Join-Path since $RootPath can be passed and may or may not contain a trailing \.
            $FullFilePath = Join-Path $HPRepoPath -childpath $ChildPath
        
            Write-CMTraceLog -Message "Full path: $FullFilePath" -Component $Component -type 1 -Logfile $LogFile 
        
            $ConfigFile = $FullFilePath
        
            Write-CMTraceLog -Message "Config file: $ConfigFile" -Component $Component -type 1 -Logfile $LogFile 
        
            Write-CMTraceLog -Message "App(s) to exclude: $App" -Component $Component -type 1 -Logfile $LogFile 

            # The config file needs to exist before we can continue.
            If (Test-Path $ConfigFile)
            {
                if($PSCmdlet.ShouldProcess("Platform $ID, OS: $OS, and OSBuild: $OSBuild.", "Update HP repository include/exclude file"))
                {
                    $Json = Get-Content $ConfigFile | ConvertFrom-Json
            
                    If ($Json)
                    {
                        $Exclude = @()
                        $Apps = @()
                        If ($App)
                        {
                            foreach ($A in $App)
                            {
                                Write-CMTraceLog -Message "Adding app $A to list." -Component $Component -type 1 -Logfile $LogFile 
                                $Apps += $A
                            }
            
                            Write-CMTraceLog -Message "Current list: $Apps." -Component $Component -type 1 -Logfile $LogFile

                            # The $Action variable represents either to Include or Exclude an application from the driver repository.
            
                            If (($Json.$ID).$OS.$OSBuild.$Action -eq "")
                            {
                                Write-CMTraceLog -Message "$Action empty, adding first entry." -Component $Component -type 1 -Logfile $LogFile 
                                
                                Write-CMTraceLog -Message "Current ($Action): $(($Json.$ID).$OS.$OSBuild.$Action)." -Component $Component -type 1 -Logfile $LogFile 
            
                                if ($Apps.count -eq 1)
                                {
                                    ($Json.$ID).$OS.$OSBuild.$Action = $Apps
                                }
                                else
                                {
                                    ($Json.$ID).$OS.$OSBuild.$Action = $Apps -join ","
                                }
                                Write-CMTraceLog -Message "New ($Action): $(($Json.$ID).$OS.$OSBuild.$Action)." -Component $Component -type 1 -Logfile $LogFile 
            
                            }
                            Else
                            {
                                Write-CMTraceLog -Message "$Action has entries." -Component $Component -type 1 -Logfile $LogFile 
                                $Exclude = (($Json.$ID).$OS.$OSBuild.$Action).Split(",")
                    
                                If ($Exclude -contains $Apps)
                                {
                                    Write-Warning "Application $Apps is already in the $action section.."
                                    $ReturnValue = $false
                                }
                                else
                                {
                                    $Exclude = $Exclude += $Apps
                                    ($Json.$ID).$OS.$OSBuild.$Action = $Exclude -join ","
                                }
                            }
                            
                            Write-CMTraceLog -Message "Saving changes to config file." -Component $Component -type 1 -Logfile $LogFile 
                            
                            Write-CMTraceLog -Message "Updating date modified to $(Get-Date -Format MM/dd/yyyy)." -Component $Component -type 1 -Logfile $LogFile 
                            ($Json.$ID).$OS.$OSBuild.Modified = Get-Date -Format MM/dd/yyyy
            
                            Write-CMTraceLog -Message "Updating author to $(whoami)." -Component $Component -type 1 -Logfile $LogFile 
                            ($Json.$ID).$OS.$OSBuild.Author =  $(whoami)
            
                            Write-CMTraceLog -Message "Exporting json file." -Component $Component -type 1 -Logfile $LogFile 
                            $Json | ConvertTo-Json -Depth 3 | Format-Json | Set-Content $ConfigFile
                            
                            #Save-JsonContent -PlatformID $PlatformID -OS $OS -OSBuild $OSBuild -Status $Status -Json $Json -File $ConfigFile
            
                            $ReturnValue = $true
                        }
                    }
                }
            }
            else
            {
                Write-Warning "Config file `"$ConfigFile`" doesn't exist."
                Write-CMTraceLog -Message "Config file `"$ConfigFile`" doesn't exist." -Component $Component -type 1 -Logfile $LogFile 
                return $false
            }
        }
        return $ReturnValue
    }
}
#EndRegion '.\Public\Add-DM_HPRepositoryIncludeExclude.ps1' 145
#Region '.\Public\Get-DM_CMDriverManagementPackage.ps1' -1

Function Get-DM_CMDriverManagementPackage ()
{
    <#
    .SYNOPSIS
    Retreives a ConfigMgr package for either a HP driver package or HP repository package.

    .DESCRIPTION
    Retreives a ConfigMgr package for either a HP driver package or HP repository package.

    .PARAMETER PlatformID
    The platform ID from a HP computer.

    .PARAMETER OS
    Specifies the OS. Windows 10 or Windows 11.

    .PARAMETER OSBuild
    The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

    .PARAMETER Status
    Specifies of the repository or DriverPack is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

    .PARAMETER Packagetype
    Indicates what type of package needs to be created.
    
    DriverPack = ConfigMgr package containing drivers
    
    DriverRepository = ConfigMgr package containing an HP driver repository.

    .PARAMETER Manufacturer
    Specifies the manufacturer that will be used to set the manufacturer field on the ConfigMgr package

    .PARAMETER SiteServer
    ConfigMgr site server name.

    .PARAMETER SiteCode
    ConfigMgr site code.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    Outputs the object of the ConfigMgr package found.

    .EXAMPLE
    Get-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverRepository

    Find a DriverRepository package.

    .EXAMPLE
    Get-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverPack

    Find a DriverPack package.

    .NOTES
    Requires the ConfigMgr console to be installed on the system running the command.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string[]]$PlatformID,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("Win10", "Win11")]
        [string]$OS,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("22H2", "23H2", "24H2")]
        [string]$OSBuild,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("Prod", "Test")]
        [string]$Status,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("DriverPack", "DriverRepository")]
        [string]$PackageType,
        [string]$Manufacturer = 'HP',
        [switch]$OutputCMObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteServer,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteCode,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false) { throw "SCCM Console is not available. Unable to continue." }

        <## Connect to the site's drive if it is not already present
        if($null -eq (Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
            $null = New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteServer -Scope Global
        } #>
    }

    Process
    {
        try
        {
            Foreach ($ID in $PlatformID)
            {
                Write-CMTraceLog -Message "Processing PlatformID: $ID" -Component $Component -type 1 -Logfile $LogFile 

                #Write-Verbose "[$($myinvocation.mycommand)] Importing SCCM PS Module"
                Write-CMTraceLog -Message "Importing SCCM PS Module" -Component $Component -type 1 -Logfile $LogFile 

                # Load CM PowerShell Module
                Import-DM_CMPSModule

                $CurrentLocation = Get-Location

                Set-Location "$($SiteCode):\" -Verbose:$false

                # Write-verbose "Called by: $((Get-PSCallStack)[1].Command)"
                # Write-CMTraceLog -Message "Called by: $((Get-PSCallStack)[1].Command)" -Component $Component -type 1 -Logfile $LogFile

                if ($PSBoundParameters.ContainsKey('PackageType'))
                {
                    # Write-Verbose "[$($myinvocation.mycommand)] PackageType passed."
                    Write-CMTraceLog -Message "PackageType passed." -Component $Component -type 1 -Logfile $LogFile 
                    #Create the package first
                    # Write-Verbose "[$($myinvocation.mycommand)] Find package."
                    Write-CMTraceLog -Message "Find package." -Component $Component -type 1 -Logfile $LogFile 
                    switch ($PackageType)
                    {
                        'DriverPack' { 
                            # Write-Verbose "[$($myinvocation.mycommand)] Package type = 'DriverPack'."
                            Write-CMTraceLog -Message "Package type = 'DriverPack'." -Component $Component -type 1 -Logfile $LogFile 
                            $PackageName = "DriverPack: $Manufacturer $ID $OS $OSBuild - $Status"
                            }
                        'DriverRepository' {
                            # Write-Verbose "[$($myinvocation.mycommand)] Package type = 'DriverRepository'."
                            Write-CMTraceLog -Message "Package type = 'DriverRepository'." -Component $Component -type 1 -Logfile $LogFile 
                            $PackageName = "DriverRepository: $Manufacturer $ID $OS $OSBuild - $Status"
                            }
                    }
                }

                #Create the package first
                # $PackageName = "DriverPack: HP $PlatformID $OS $OSBuild - $Status"
                # Write-Verbose "[$($myinvocation.mycommand)] Looking for package: $PackageName."
                Write-CMTraceLog -Message "Looking for package: $PackageName." -Component $Component -type 1 -Logfile $LogFile 

                $PackageObj = Get-CMPackage -Name $PackageName -Fast -Verbose:$false

                # $PackageObj

                Set-Location $CurrentLocation

                If ($PackageObj)
                {
                    Write-CMTraceLog -Message "Package found." -Component $Component -type 1 -Logfile $LogFile 
                    Write-CMTraceLog -Message "Package name: $($PackageObj.name) `nPackage ID: $($PackageObj.PackageID)." -Component $Component -type 1 -Logfile $LogFile 
                    
                    if ($PSBoundParameters.ContainsKey('OutputCMObject'))
                    {
                        return $PackageObj
                    }
                    else
                    {
                        $object1 = New-Object PSObject

                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PlatformID -Value $ID
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name OS -Value $OS
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name OSBuild -Value $OSBuild
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name Status -Value $((Get-Culture).TextInfo.ToTitleCase($Status))
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PackageType -Value $PackageType
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name ID -Value $PackageObj.PackageID
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name Name -Value $PackageObj.Name
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PackageSourcePath -Value $PackageObj.PkgSourcePath
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PackageVersion -Value $PackageObj.Version
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name PackageLastRefreshTime -Value $PackageObj.LastRefreshTime
                        Add-Member -InputObject $object1 -MemberType NoteProperty -Name CMObjectPath -Value $PackageObj.ObjectPath

                        Write-Output $object1
                    }
                }
                else
                {
                    # Write-Verbose "[$($myinvocation.mycommand)] Package `"$PackageName`" not found."
                    Write-CMTraceLog -Message "Package `"$PackageName`" not found." -Component $Component -type 1 -Logfile $LogFile

                    Write-Information -MessageData "Package `"$PackageName`" not found." -InformationAction Continue

                    #Write-Output $false
                }
            }
        }
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "Something went wrong: $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            Set-Location $CurrentLocation
        }

    }
}
#EndRegion '.\Public\Get-DM_CMDriverManagementPackage.ps1' 204
#Region '.\Public\Get-DM_HPDriverPack.ps1' -1

Function Get-DM_HPDriverPack ()
{
        <#
        .SYNOPSIS
        Retreives the HP driver pack information for a PlatformID, OS, and OS Build.

        .DESCRIPTION
        Retreives the HP driver pack information for a PlatformID, OS, and OS Build.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies of the driver pack is Test or Prod. This allows two separate drive packs for each Platform, OS and Build.

        .PARAMETER PackageContentPath
        The path where the driver pack will be created.

        Use can set the following to provide a default value, or just pass the value on the command line.

        $PSDefaultParameterValues["*-DM*:PackageContentPath"] = "\\path\you\wish\to\use"

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        Outpus a custom object that contains the details of the new repository.

        'PlatformID'
        'OS'
        'OSBuild'
        'RootPath'
        'Path'
        'Status'

        Example:
        PlatformID : DDDD
        OS         : Win10
        OSBuild    : 22H2
        RootPath   : \\corp.viamonstra.com\CMSource\OSD\Drivers\DriverPacks\HP
        Path       : \\corp.viamonstra.com\CMSource\OSD\Drivers\DriverPacks\HP\Test\Win10\22H2\DDDD
        Status     : Test

        .EXAMPLE
        Get-DM_HPDriverPack -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test

        .EXAMPLE
        Get-DM_HPDriverPack -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Test

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [string]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Prod", "Test")]
    [string]$Status,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$PackageContentPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin{
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $DPDestination = Join-Path $PackageContentPath "HP"

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ((Invoke-PathPermissionsCheck -Path $PackageContentPath) -eq $false) { break }

        # [bool]$Global:EnableLogWriteVerbose = $false

        If ((Helper-GetDM_HPCMSLInstallStatus) -eq $false)
        {
            Write-Warning "HPCMSL is not installed. Please install and try again."
            Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
            break
        }
        elseif (!(Get-Module HPCMSL))
        {
            Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
            Import-Module HPCMSL

            If (!(Get-Module HPCMSL))
            {
                Write-Warning "HPCMSL was not imported."
                Write-CMTraceLog -Message "HPCMSL was not imported." -Component $Component -type 1 -Logfile $LogFile 
                break
            }
        }
    }

    Process{
        $DPPath = join-path $DPDestination $Status\$OS\$OSBuild\$PlatformID

        Write-CMTraceLog -Message "PlatformID: $PlatformID" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "OS: $OS" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "OSBuild: $OSBuild" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "RootPath: $DPDestination" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "Path: $DPPath" -Component $Component -type 1 -Logfile $LogFile 
        Write-CMTraceLog -Message "Status: $Status" -Component $Component -type 1 -Logfile $LogFile 
        
        If (Test-Path $DPPath)
        {
            If (Test-Path (Join-Path $DPPath DriverInfo.txt))
            {
                $DriverPackCreatedInfo = Get-Content (Join-Path $DPPath DriverInfo.txt)
                [datetime]$DriverPackCreatedDate = $DriverPackCreatedInfo | Where-Object {$_ -match "Date Created:"} | ForEach-Object {$_.substring(14)}

                $DriverPackCreatedMonthYear = $($DriverPackCreatedDate).ToString("yyyy-MM")
            }
            
            $props = [pscustomobject]@{
                'PlatformID'=$PlatformID
                'OS'=$OS
                'OSBuild'=$OSBuild
                'RootPath'=$DPDestination
                'Path'=$DPPath
                'Status'=$((Get-Culture).TextInfo.ToTitleCase($Status))
                'LastUpdated' = $DriverPackCreatedMonthYear         
            }

            return, $props;
        }
        else
        {
            Write-CMTraceLog -Message "DriverPack path $DPPath does not exist." -Component $Component -type 2 -Logfile $LogFile 
            Write-Warning "DriverPack path $DPPath does not exist."
        }
    }
}
#EndRegion '.\Public\Get-DM_HPDriverPack.ps1' 152
#Region '.\Public\Get-DM_HPRepository.ps1' -1

Function Get-DM_HPRepository ()
{
        <#
        .SYNOPSIS
        Retreives the HP driver repository information for a PlatformID, OS, and OS Build.

        .DESCRIPTION
        Retreives the HP driver repository information for a PlatformID, OS, and OS Build.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

        .PARAMETER HPRepoPath
        The path where the repository will be created.

        Use can set the following to provide a default value, or just pass the value on the command line.

        $PSDefaultParameterValues["*-DM*:HPRepoPath"] = "\\path\you\wish\to\use"

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        Outpus a custom object that contains the details of the new repository.

        'PlatformID'
        'OS'
        'OSBuild'
        'RootPath'
        'Path'
        'Status'

        Example:
        PlatformID : DDDD
        OS         : Win10
        OSBuild    : 22H2
        RootPath   : \\corp.viamonstra.com\CMSource\WorkstationDriverRepository
        Path       : \\corp.viamonstra.com\CMSource\WorkstationDriverRepository\Test\Win10\22H2\DDDD
        Status     : Test

        .EXAMPLE
        Get-DM_HPRepository -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test

        .EXAMPLE
        Get-DM_HPRepository -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Test

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [string[]]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Prod", "Test")]
    [string]$Status,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin{
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }

        # [bool]$Global:EnableLogWriteVerbose = $false

        If ((Helper-GetDM_HPCMSLInstallStatus) -eq $false)
        {
            Write-Warning "HPCMSL is not installed. Please install and try again."
            Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
            break
        }
        elseif (!(Get-Module HPCMSL))
        {
            Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
            Import-Module HPCMSL

            If (!(Get-Module HPCMSL))
            {
                Write-Warning "HPCMSL was not imported."
                Write-CMTraceLog -Message "HPCMSL was not imported." -Component $Component -type 1 -Logfile $LogFile 
                break
            }
        }
    }

    Process{

        foreach ($ID in $PlatformID)
        {
            Write-CMTraceLog -Message "------ $ID ------" -Component $Component -type 1 -Logfile $LogFile 

            $RepoPath = join-path $HPRepoPath $Status\$OS\$OSBuild\$ID

            Write-CMTraceLog -Message "PlatformID: $ID" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "OS: $OS" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "OSBuild: $OSBuild" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "RootPath: $HPRepoPath" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "Path: $RepoPath" -Component $Component -type 1 -Logfile $LogFile 
            Write-CMTraceLog -Message "Status: $Status" -Component $Component -type 1 -Logfile $LogFile 
            
            If (Test-Path $RepoPath)
            {
                If (Test-Path (Join-Path $RepoPath LastSync.txt))
                {
                    $RepoLastSync = Get-Content (Join-Path $RepoPath LastSync.txt)
                    [datetime]$RepoLastSyncDate = $RepoLastSync | Where-Object {$_ -match "Last Sync:"} | ForEach-Object {$_.substring(11)}

                    $RepoLastSyncMonthYear = $($RepoLastSyncDate).ToString("yyyy-MM")
                }

                $props = [pscustomobject]@{
                    'PlatformID'=$ID
                    'OS'=$OS
                    'OSBuild'=$OSBuild
                    'RootPath'=$HPRepoPath
                    'Path'=$RepoPath
                    'Status'=$((Get-Culture).TextInfo.ToTitleCase($Status))
                    'LastUpdated' = $RepoLastSyncMonthYear
                }
    
                Write-Output $props
            }
            else
            {
                Write-CMTraceLog -Message "Repository path $RepoPath does not exist." -Component $Component -type 2 -Logfile $LogFile 
                Write-Warning "Repository path $RepoPath does not exist."
            }
        }
    }
}
#EndRegion '.\Public\Get-DM_HPRepository.ps1' 156
#Region '.\Public\Get-DM_HPRepositoryIncludeExclude.ps1' -1

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

        Write-CMTraceLog -Message "------ Start ------" -Component $Component -type 1 -Logfile $LogFile 

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }

        $ExcludedApps = @()
        $Object = @()

        # Start global config
        $GlobalExclude = "$Status\GlobalIncludeExclude.json"

        $GlobalExcludePath = Join-Path $HPRepoPath -childpath $GlobalExclude

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
#EndRegion '.\Public\Get-DM_HPRepositoryIncludeExclude.ps1' 173
#Region '.\Public\Get-DM_PSProfileMods.ps1' -1

Function Get-DM_PSProfileMods ()
{
    Write-host "In order to prevent being prompted for required variables when running the cmdlets, you can add the following to your powershell profile."

    Write-Host "You can add the following to `"$($PROFILE.CurrentUserAllHosts)`" to only effect your profile or"
    Write-host "add it to `"$PSHOME\Profile.ps1`" to make them available for all users on this system. This option requires Administrative permissions. :-("
    Write-Host ""
    Write-Host "###################################################################################"
    Write-host '$PSDefaultParameterValues["*-DM*:SiteServer"] = "smsprov.corp.viamonstra.com"'
    Write-host '$PSDefaultParameterValues["*-DM*:SiteCode"] = "HOS"'
    write-host '$PSDefaultParameterValues["*-DM*:CMDBServer"] = "sccmdb.corp.viamonstra.com"'
    write-host '$PSDefaultParameterValues["*-DM*:HPRepoPath"] = "\\corp.viamonstra.com\SourceFiles$\WorkstationDriverRepository"'
    write-host '$PSDefaultParameterValues["*-DM*:PackageContentPath"] = "\\corp.viamonstra.com\SourceFiles$\OSD\Drivers\DriverPacks"'
    Write-Host ""
    Write-Host "# This command creates a central log file for the driver management process. If this is not set, each function will have it's own log."
    write-host '$PSDefaultParameterValues["*-DM*:LogFile"] = "C:\ProgramData\Logs\DriverManagement.log"'
    Write-Host "###################################################################################"

}
#EndRegion '.\Public\Get-DM_PSProfileMods.ps1' 20
#Region '.\Public\Get-DM_SystemInformation.ps1' -1

function Get-DM_SystemInformation ()
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$Computer = $env:COMPUTERNAME,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    # Collection system info

    $Component = $($myinvocation.mycommand)

    $PSDefaultParameterValues = $Global:PSDefaultParameterValues

    $InformationPreference = 'Continue'

    $Result = Test-DM_ComputerConnection -ComputerName $Computer

    If ($Result)
    {
        # Write-Output "Computer connection succedded."
        Write-CMTraceLog -Message "Computer connection succedded." -Component $Component -type 1 -Logfile $LogFile
        Write-Information -MessageData "Computer connection succedded." -InformationAction Continue

        # Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Write-Information -MessageData "Checking module version." -InformationAction Continue
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ($env:COMPUTERNAME -ne $Computer)
        {
            Write-CMTraceLog -Message "Opening session on $Computer." -Component $Component -type 1 -Logfile $LogFile
            Write-Information -MessageData "Opening session on $Computer." -InformationAction Continue
            $Session = New-PSSession -ComputerName $Computer
    
            $SCriptBlock = {
        
                $PlatformID = Get-WmiObject win32_baseboard | Select-Object -ExpandProperty Product
                $Manufacturer = Get-wmiobject win32_computersystem | Select-Object -ExpandProperty Manufacturer
                $Model = Get-wmiobject win32_computersystem | Select-Object -ExpandProperty Model
                $Serial = Get-wmiobject win32_bios | Select-Object -ExpandProperty SerialNumber
                $Caption = Get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Caption
                $OSVersion = Get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Version
                
                $props = [pscustomobject]@{
                    'PlatformID'=$PlatformID
                    'Manufacturer'=$Manufacturer
                    'Model'=$Model
                    'SerialNumber'=$Serial
                    'OS'=$Caption
                    'OS Version'=$OSVersion           
                }
            }
            
            return, $props;
        }
        else
        {
            Write-CMTraceLog -Message "Connecting to local computer: $Computer." -Component $Component -type 1 -Logfile $LogFile
            Write-Information -MessageData "Connecting to local computer: $Computer." -InformationAction Continue
        
            $PlatformID = Get-WmiObject win32_baseboard | Select-Object -ExpandProperty Product
            $Manufacturer = Get-wmiobject win32_computersystem | Select-Object -ExpandProperty Manufacturer
            $Model = Get-wmiobject win32_computersystem | Select-Object -ExpandProperty Model
            $Serial = Get-wmiobject win32_bios | Select-Object -ExpandProperty SerialNumber
            $Caption = Get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Caption
            $OSVersion = Get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Version
            
            $props = [pscustomobject]@{
                'PlatformID'=$PlatformID
                'Manufacturer'=$Manufacturer
                'Model'=$Model
                'SerialNumber'=$Serial
                'OS'=$Caption
                'OS Version'=$OSVersion           
            }
        
            # Add-Member -InputObject $obj -MemberType NoteProperty -Name "Session" -Value "Current"
            # $Output = $obj
    
            return, $props;
        }
    
        Write-CMTraceLog -Message "Running scriptblock on $Computer." -Component $Component -type 1 -Logfile $LogFile
        Write-Information -MessageData "Running scriptblock on $Computer." -InformationAction Continue
        $Result = Invoke-Command -Session $Session -ScriptBlock $SCriptBlock

        Write-CMTraceLog -Message "$Result." -Component $Component -type 1 -Logfile $LogFile 

        Write-CMTraceLog -Message "Removing session on $Computer." -Component $Component -type 1 -Logfile $LogFile
        Write-Information -MessageData "Removing session on $Computer." -InformationAction Continue
        Remove-PSSession -Session $Session

        return, $Result;
    }
    else
    {
        Write-Warning "Computer connection did not succedded."
        Write-CMTraceLog -Message "Computer connection did not succedded." -Component $Component -type 1 -Logfile $LogFile 
    }
}
#EndRegion '.\Public\Get-DM_SystemInformation.ps1' 103
#Region '.\Public\Invoke-DM_CMPackageDistribution.ps1' -1

Function Invoke-DM_CMPackageDistribution ()
{
    <#
    .SYNOPSIS
    Distributes a package to the specified distribution point.

    .DESCRIPTION
    Distributes a package to the specified distribution point.

    .PARAMETER Name
    Name of ConfigMgr packge.

    .PARAMETER PackageID
    PackageID for ConfigMgr package.

    .PARAMETER DistributionPointGroupName
    DistributionPoint group name to use for distribution.

    .PARAMETER SiteServer
    ConfigMgr site server name.

    .PARAMETER SiteCode
    ConfigMgr site code.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    If succesfull, will output $true.

    .EXAMPLE
    Invoke-DM_CMPackageDistribution -PackageID PS100FE7

    .EXAMPLE
    Invoke-DM_CMPackageDistribution -Name 'DriverRepository: HP 880D Win10 22H2 - Test'

    .NOTES
    Requires the ConfigMgr console to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName='packageid')]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName, ParameterSetName='name')]
    [string]$Name,
    [Parameter(Mandatory=$True,ValueFromPipeline,ValueFromPipelineByPropertyName, ParameterSetName='packageid')]
    [string]$PackageID,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
    [string]$DistributionPointGroupName = 'All Content except Microsoft Patches (All DPs)',
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    [string]$SiteServer,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [string]$SiteCode,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        Write-Verbose "Called by: $((Get-PSCallStack)[1].Command)"

        $Component = $($myinvocation.mycommand)
    
        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"
    
        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false) { break }

        #Write-Verbose "Importing SCCM PS Module"
        Write-CMTraceLog -Message "Importing SCCM PS Module" -Component $Component -type 1 -Logfile $LogFile 

        # Load CM PowerShell Module
        Import-CMPSModule
    }

    Process
    {
        $CurrentLocation = Get-Location

        Set-Location "$($SiteCode):\" -Verbose:$false

        try
        {
            #Create the package first
            # Write-Verbose "Find package."
            Write-CMTraceLog -Message "Find package." -Component $Component -type 1 -Logfile $LogFile 
            switch ($PSBoundParameters.Keys)
            {
                'name' { 
                    # Write-Verbose "-name parameter passed."
                    Write-CMTraceLog -Message "-name parameter passed." -Component $Component -type 1 -Logfile $LogFile 
                    Write-CMTraceLog -Message "Looking for package name `"$name`"." -Component $Component -type 1 -Logfile $LogFile 
                    $Package = Get-CMPackage -Name $name -Fast -Verbose:$false
                    }
                'packageid' {
                    # Write-Verbose "-packageID parameter passed."
                    Write-CMTraceLog -Message "-packageID parameter passed." -Component $Component -type 1 -Logfile $LogFile 
                    Write-CMTraceLog -Message "Looking for packageID `"$PackageID`"." -Component $Component -type 1 -Logfile $LogFile 
                    $Package = Get-CMPackage -Id $PackageID -Fast -Verbose:$false
                    }
            }

            If ($Package)
            {
                # Check current distribution status.
                If ((Get-CMDistributionStatus -Id ($Package.PackageID) -Verbose:$false).targeted -ne 0)
                {
                    if($PSCmdlet.ShouldProcess(($Package.PackageID),"Update distribution for package on `"$DistributionPointGroupName`""))
                    {
                        $Output = Get-CMDistributionStatus -Id ($Package.PackageID) -Verbose:$false
                        # Write-Verbose "The package has been distributed, updating."
                        Write-CMTraceLog -Message "The package $($Package.PackageID) has been distributed, updating." -Component $Component -type 1 -Logfile $LogFile 
                        Update-CMDistributionPoint -PackageId ($Package.PackageID) -Verbose:$false
                        $Result = $True
                    }
                }
                else
                {
                    # Write-Verbose "The package has not been distributed."
                    Write-CMTraceLog -Message "The package $($Package.PackageID) has not been distributed." -Component $Component -type 1 -Logfile $LogFile 
                    # Write-Output "Starting distribution now."
                    Write-CMTraceLog -Message "Starting distribution now." -Component $Component -type 1 -Logfile $LogFile 
                    If (Get-CMDistributionPointGroup -Name $DistributionPointGroupName -Verbose:$false)
                    {
                        if($PSCmdlet.ShouldProcess(($Package.PackageID),"Distributing package to `"$DistributionPointGroupName`""))
                        {
                            # Write-Verbose "Distribution point group `"$DistributionPointGroupName`" is vaild."
                            Write-CMTraceLog -Message "Distribution point group `"$DistributionPointGroupName`" is vaild." -Component $Component -type 1 -Logfile $LogFile 
                            # Distribute package content
                            # Write-Verbose "Distributing contents of new package."
                            Write-CMTraceLog -Message "Distributing contents of new package." -Component $Component -type 1 -Logfile $LogFile 
                            [void](Start-CMContentDistribution -InputObject $Package -DistributionPointGroupName $DistributionPointGroupName -Verbose:$false)
                            $Result= $True
                        }
                    }
                    else
                    {
                        Set-Location $CurrentLocation
                        Write-Warning "DistributionPoint group name: `"$DistributionPointGroupName`" is not valid"
                        Write-CMTraceLog -Message "DistributionPoint group name: `"$DistributionPointGroupName`" is not valid" -Component $Component -type 1 -Logfile $LogFile 
                        $Result = $false
                        # throw "DistributionPoint group name: `"$DistributionPointGroupName`" is not valid"
                    }
                }
            }
            else
            {
                # Write-Verbose "Package `"$name`" not found."
                Write-CMTraceLog -Message "Package `"$name`" not found." -Component $Component -type 1 -Logfile $LogFile 
                $Result = $false
            }

            Set-Location $CurrentLocation

            return $Result
        }
        catch
        {
            Write-Warning "Something went wrong, $_."
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile
            Write-CMTraceLog -Message "$_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            Set-Location $CurrentLocation
        }
    }

}
#EndRegion '.\Public\Invoke-DM_CMPackageDistribution.ps1' 169
#Region '.\Public\Invoke-DM_CreateHPIARefFile.ps1' -1

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
#EndRegion '.\Public\Invoke-DM_CreateHPIARefFile.ps1' 634
#Region '.\Public\Invoke-DM_HPDriverPackSyncToProd.ps1' -1

Function Invoke-DM_HPDriverPackSyncToProd ()
{
            <#
        .SYNOPSIS
        Syncs an HP driver pack from test to prod.

        .DESCRIPTION
        Takes a the tested driver pack and copies it to the prod driver pack location.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        If you need to create multiple driver packs at a time, you can pass multiple Platform IDs at a time.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies that status of the repository to be copied. This parameter is optional.

        .PARAMETER PackageContentPath
        Path of the driver pack to copy. This is an optional parameter.

        .PARAMETER OverrideVPNCheck
        The driver pack copy can take a long time over a VPN connection. If the -OverrideVPNCheck parameter is passed, the built-in VPN check will be bypassed.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        None

        .EXAMPLE
        Invoke-DM_HPDriverPackSyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test

        Start a sync for the test platform AAAA and OS Windows 11 24H2.

        .EXAMPLE
        Invoke-DM_HPDriverPackSyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test -Force

        Start a sync for the test platform AAAA and OS Windows 11 24H2 bypassing all confirmation prompts.

        .EXAMPLE
        Copy a test driver pack to proc, then pipe the output to New-DM_CMDriverManagementPackage to either create or update the CM package.

        Invoke-DM_HPDriverPackSyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test -Force | New-DM_CMDriverManagementPackage -PackageType DriverPack -Force -UpdateExistingPackage
    #>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [string[]]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [Parameter(Mandatory=$True,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$PackageContentPath,
    [switch]$OverrideVPNCheck,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-Warning "The Invoke-DM_HPDriverPackSyncToProd function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again."
            Write-CMTraceLog -Message "The Invoke-DM_HPDriverPackSyncToProd function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again." -Component $Component -Type 3

            break
        }
    }

    Process
    {
        try{
            $Component = $($myinvocation.mycommand)

            if ($Force -and -not $Confirm)
            {
                $ConfirmPreference = 'None'
            }

            $DPDestination = Join-Path $PackageContentPath "HP"

            Foreach ($ID in $PlatformID)
            {
                $IDUpper = $ID.ToUpper()
                $SourcePath = $(Join-Path -Path "$DPDestination" "Test\$OS\$OSBuild\$IDUpper")
                Write-CMTraceLog -Message "Source path: $SourcePath" -Component $Component -type 1 -Logfile $LogFile 

                $DestPath = $(Join-Path -Path "$DPDestination" "Prod\$OS\$OSBuild\$IDUpper")
                Write-CMTraceLog -Message "Dest path: $DestPath." -Component $Component -type 1 -Logfile $LogFile 

                Write-CMTraceLog -Message "Checking for write permission to `"$DPDestination`"." -Component $Component -type 1 -Logfile $LogFile
                If ((Invoke-PathPermissionsCheck -Path $DPDestination) -eq $true)
                {
                    Write-CMTraceLog -Message "Path `"$DPDestination`" exists. Script can continue." -Component $Component -type 1 -Logfile $LogFile 
                    Write-CMTraceLog -Message "Permissions check to $DPDestination path passed." -Component $Component -type 1 -Logfile $LogFile 
                    If (Test-path $SourcePath)
                    {
                        Write-CMTraceLog -Message "Source path exists." -Component $Component -type 1 -Logfile $LogFile
                        if($PSCmdlet.ShouldProcess($ID,"Sync Test DriverPack for $ID, OS $OS, and OSBuild $OSBuild to Prod" + "?"))
                        {
                            If (-Not (Test-Path $DestPath))
                            {
                                Write-CMTraceLog -Message "Path `"$DestPath`" does not exist. Creating path." -Component $Component -type 1 -Logfile $LogFile 
                                [void][System.IO.Directory]::CreateDirectory($DestPath)
                            }

                            Write-CMTraceLog -Message "Syncing `"Test`" DriverPack for $ID to `"Prod`" for $OS $OSBuild." -Component $Component -type 1 -Logfile $LogFile 
                            Sync-DirWithProgress -SourceDir $SourcePath -DestDir $DestPath
                            Write-CMTraceLog -Message "Sync complete." -Component $Component -type 1 -Logfile $LogFile 

                            # Write file to show when the repo was last synced from test.
                            "Platform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nDate copied: $((get-date).tostring())`nPerpetrator: $env:USERNAME`nSource Path: $SourcePath`nDest Path: $DestPath" | out-file -FilePath "$DestPath\LastSyncFromTest.txt"

                            # Get repo info so we can output the object so the results of this cmdlet can be piped to other cmdlets.
                            $Return = Get-DM_HPDriverPack -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status Prod

                            If ($Return)
                            {
                                return $Return
                            }
                        }
                    }
                    else
                    {
                        Write-Warning -Message "The path `"$SourcePath`" does not exist."
                        Write-CMTraceLog -Message "The path `"$SourcePath`" does not exist." -Component $Component -type 3 -Logfile $LogFile 
                        break
                    }
                }
                else
                {
                    Write-Warning "Permissions check failed. Unable to continue. Exiting script."
                    Write-CMTraceLog -Message "Permissions check failed. Unable to continue. Exiting script." -Component $Component -type 3 -Logfile $LogFile 
                    break
                }
            }
        }
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution. $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            # Set-Location $CurrentLocation
        }
    }

    End
    {
        # End
    }
}
#EndRegion '.\Public\Invoke-DM_HPDriverPackSyncToProd.ps1' 169
#Region '.\Public\Invoke-DM_HPIARefFileExclude.ps1' -1

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
#EndRegion '.\Public\Invoke-DM_HPIARefFileExclude.ps1' 231
#Region '.\Public\Invoke-DM_HPRepositoryExcludeCleanup.ps1' -1

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
#EndRegion '.\Public\Invoke-DM_HPRepositoryExcludeCleanup.ps1' 213
#Region '.\Public\Invoke-DM_HPRepositorySync.ps1' -1

function Invoke-DM_HPRepositorySync ()
{
        <#
        .SYNOPSIS
        Syncs an HP driver repository with HP to download updates.

        .DESCRIPTION
        Syncs an HP driver repository with HP to download updates.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        If you need to create multiple repositories at a time, you can pass multiple Platform IDs at a time.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies if the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

        .PARAMETER HPRepoPath
        Root path when the HP repositories are stored.

        .PARAMETER Cleanup
        Indicates that Invoke-DM_HPRepositorySync should be ran after the sync is complete to remove superseded updates.

        .PARAMETER ProcessRepoExcludes
        By default the repository sync runs Invoke-DM_HPRepositoryExcludeCleanup to remove excluded SP files. Setting this paramter to $false disables that step.

        .PARAMETER ProcessRefImageExcludes
        By default the repository sync runs Invoke-DM_HPIARefFileExclude to remove excluded SP files from the reference image XML file. 
        Setting this paramter to $false disables that step.

        .PARAMETER OverrideVPNCheck
        The repository sync can take a long time over a VPN connection. If the -OverrideVPNCheck parameter is passed, the built-in VPN check will be bypassed.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        None

        .EXAMPLE
        Invoke-DM_HPRepositorySync -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Test

        Start a sync for the test platform 8711 and OS Windows 10 22H2.

        .EXAMPLE
        Invoke-DM_HPRepositorySync -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Prod

        Start a sync for the Prod platform 8711 and OS Windows 10 22H2.

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
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
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [switch]$Cleanup,
    [bool]$ProcessRepoExcludes = $true,
    [bool]$ProcessRefImageExcludes = $true,
    [switch]$OverrideVPNCheck,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin {

        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $InformationPreference = 'Continue'

        Helper-GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        Invoke-ModuleVersionCheck -Module "DriverManagement"

        # [bool]$Global:EnableLogWriteVerbose = $false

        $PulseAdapterStatus = (Get-NetAdapter -InterfaceDescription "Juniper Networks Virtual Adapter" -ErrorAction SilentlyContinue).Status

        # If OverrideVPNCheck is passed, set PulseAdapterStatus to False to bypass the prompt.
        if ($PSBoundParameters.ContainsKey('OverrideVPNCheck'))
        {
            $PulseAdapterStatus = 'Down'
            Write-CMTraceLog -Message "Parameter OverrideVPNCheck passed. Bypassing VPN check." -Component $Component -type 1 -Logfile $LogFile 
        }

        if ($PulseAdapterStatus -eq 'Up')
        {
            Write-CMTraceLog -Message "Script running over VPN, prompt to continue." -Component $Component -type 1 -Logfile $LogFile 

            $title    = 'Continue?'
            $question = "Looks like you're connected over the VPN. What your about to do will take a while to complete.`nDo you want to continue?"
            $choices  = '&Yes', '&No'

            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                # Write-Host 'confirmed'
                $Runscript = $True
                Write-CMTraceLog -Message "User decided to continue over VPN." -Component $Component -type 1 -Logfile $LogFile 
            } else {
                # Write-Host 'cancelled'
                $Runscript = $false
                Write-CMTraceLog -Message "User decided not to continue over VPN." -Component $Component -type 1 -Logfile $LogFile 
            }

            <# Write-Host "Looks like you're connected over the VPN. What your about to do will take a while to complete. `nDo you want to continue? (Y/N)"
            $response = read-host
            if ( $response -ne "Y" ) { $VPNConnected = $True }#>
        }
        else
        {
            $Runscript = $True
        }
    }

    process
    {
        If ($Runscript -eq $True)
        {
            # If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.
            if ($Force -and -not $Confirm)
            {
                $ConfirmPreference = 'None'
            }

            $CurrentLocation = Get-Location

           <#  If (!(Get-Module HPCMSL))
            {
                # Write-Verbose "Importing HPCMSL module."
                Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
                Import-Module HPCMSL
            } #>

            If ((Helper-GetDM_HPCMSLInstallStatus) -eq $false)
            {
                Write-Warning "HPCMSL is not installed. Please install and try again."
                Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
                break
            }
            elseif (!(Get-Module HPCMSL))
            {
                Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
                Import-Module HPCMSL
    
                If (!(Get-Module HPCMSL))
                {
                    Write-Warning "HPCMSL was not imported."
                    Write-CMTraceLog -Message "HPCMSL was not imported." -Component $Component -type 1 -Logfile $LogFile 
                    break
                }
            }

            # If (Test-Path $HPRepoPath)
            If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $true)
            {
                Write-CMTraceLog -Message "Path $HPRepoPath exists." -Component $Component -type 1 -Logfile $LogFile 

                Foreach ($ID in $PlatformID)
                {
                    Write-CMTraceLog -Message "------ $ID ------" -Component $Component -type 1 -Logfile $LogFile 
                    # Write-Verbose "PlatformID: $ID."
                    Write-CMTraceLog -Message "PlatformID: $ID." -Component $Component -type 1 -Logfile $LogFile 
                    $PlatformPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID\Repository"
                    $PlatformRootPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID"

                    If (!(Test-Path $PlatformPath))
                    {
                        Write-Warning "The path $HPRepoPath\$Status\$os\$OSBuild\$ID does not exist. Please use New-NCHHPRepository to create repository."
                        Write-CMTraceLog -Message "The path $HPRepoPath\$Status\$os\$OSBuild\$ID does not exist. Please use New-NCHHPRepository to create repository." -Component $Component -type 1 -Logfile $LogFile 
                        Break
                    }

                    If (Get-Module HPCMSL -Verbose:$false)
                    {
                        Set-Location $PlatformPath
                        Write-Verbose "Location set to $PlatformPath."
                        Write-CMTraceLog -Message "Location set to $PlatformPath." -Component $Component -type 1 -Logfile $LogFile 
                        If ((Test-Path "$PlatformPath\.repository") -and (Test-Path "$PlatformPath\.repository\repository.json"))
                        {
                            #Write-Verbose "Repository exists and has been initilized."
                            Write-CMTraceLog -Message "Repository exists and has been initilized." -Component $Component -type 1 -Logfile $LogFile 

                            try
                            {
                                if($PSCmdlet.ShouldProcess($ID,"Sync repository for platformID $ID, OS $OS, and OSBuild $OSBuild" + "?"))
                                {
                                    # Write-Verbose "Starting sync..."
                                    Write-CMTraceLog -Message "Starting repository sync for platform $ID..." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Starting repository sync for platform $ID..." -InformationAction Continue
                                    if ($PSBoundParameters.ContainsKey('Verbose'))
                                    {
                                        Write-CMTraceLog -Message "Running a verbose repository sync." -Component $Component -type 1 -Logfile $LogFile 
                                        Invoke-RepositorySync
                                    }
                                    else
                                    {
                                        Write-CMTraceLog -Message "Running a quiet repository sync." -Component $Component -type 1 -Logfile $LogFile 
                                        #Invoke-RepositorySync -Quiet
                                        # Removing the Quiet switch for now so that you can see what's happening without the need to use the Verbose option.
                                        Invoke-RepositorySync
                                    }
                                    "Last Sync: $((get-date).tostring())`nPlatform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nPerpetrator: $env:USERNAME" | out-file -FilePath "$PlatformRootPath\LastSync.txt"
                                    # Write-Verbose "Sync complete."
                                    Write-CMTraceLog -Message "Sync complete." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Sync completed." -InformationAction Continue
                                }
                                If ($Cleanup)
                                {
                                    if($PSCmdlet.ShouldProcess($ID,"Perform repository cleanup for platform $ID, OS $OS, and OSBuild $OSBuild" + "?"))
                                    {
                                        Write-CMTraceLog -Message "Cleanup parameter passed." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-CMTraceLog -Message "Starting cleanup." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Starting cleanup." -InformationAction Continue
                                        Invoke-RepositoryCleanup
                                        Write-CMTraceLog -Message "Cleanup complete." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Cleanup complete." -InformationAction Continue
                                    }
                                }

                                Get-HPDeviceDetails -Platform $ID | Out-File "$PlatformRootPath\PlatformInfo.txt"
                                Get-HPDeviceDetails -Platform $ID -OSList | Out-File "$PlatformRootPath\OSSupport.txt"
                                "Platform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nDate created: $((get-date).tostring())`nPerpetrator: $env:USERNAME" | out-file -FilePath "$PlatformRootPath\RepositoryInfo.txt"

                                # Update reference image xml file
                                Write-CMTraceLog -Message "Create new reference image xml file." -Component $Component -type 1 -Logfile $LogFile
                                Write-Information -MessageData "Create new reference image xml file." -InformationAction Continue
                                $Results = Invoke-DM_CreateHPIARefFile -Platform $ID -OS $OS -OSBuild $OSBuild -status $Status -HPRepoPath $HPRepoPath
                                Write-CMTraceLog -Message "Reference image xml file has been created." -Component $Component -type 1 -Logfile $LogFile
                                Write-Information -MessageData "Reference image xml file has been created." -InformationAction Continue

                                If ($ProcessRefImageExcludes -eq $true)
                                {
                                    if($PSCmdlet.ShouldProcess($ID,"Process repository file exclude for platform $ID, OS $OS, and OSBuild $OSBuild" + "?"))
                                    {
                                        Write-CMTraceLog -Message "Start: Reference file exclude update." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Start: Reference file exclude update." -InformationAction Continue

                                        Invoke-DM_HPIARefFileExclude -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -HPRepoPath $HPRepoPath -confirm:$false

                                        Write-CMTraceLog -Message "End: Reference file exclude update." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "End: Reference file exclude update." -InformationAction Continue
                                    }
                                }
                                else
                                {
                                    Write-CMTraceLog -Message "Processing of reference file excludes skipped." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Processing of reference file excludes skipped." -InformationAction Continue
                                }

                                If ($ProcessRepoExcludes -eq $true)
                                {
                                    if($PSCmdlet.ShouldProcess($ID,"Start repository exclude cleanup for platform $ID, OS $OS, and OSBuild $OSBuild" + "?"))
                                    {
                                        # Begin removal of excluded files from repository
                                        Write-CMTraceLog -Message "Start: Excluded file Removal." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "Start: Excluded file Removal." -InformationAction Continue

                                        Invoke-DM_HPRepositoryExcludeCleanup -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -HPRepoPath $HPRepoPath -confirm:$false

                                        Write-CMTraceLog -Message "End: Excluded file Removal." -Component $Component -type 1 -Logfile $LogFile 
                                        Write-Information -MessageData "End: Excluded file Removal." -InformationAction Continue
                                        # End removal of excluded files from repository
                                    }
                                }
                                else
                                {
                                    Write-CMTraceLog -Message "Processing of repository file excludes skipped." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Processing of repository file excludes skipped." -InformationAction Continue
                                }

                                $props = [pscustomobject]@{
                                    #'Model'= $Model
                                    'PlatformID'=$ID
                                    'OS'=$OS
                                    'OSBuild'=$OsBuild
                                    'Status'=$Status            
                                    'Path'=$PlatformRootPath
                                }

                                If ($props)
                                {
                                    return, $props;
                                }
                            }
                            catch
                            {
                                Write-Warning "Some went wrong with the sync."
                                Write-CMTraceLog -Message "Some went wrong with the sync." -Component $Component -type 1 -Logfile $LogFile 

                                Write-Warning -Message "An error has occured during script execution."
                                Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 1 -Logfile $LogFile 
                                # Write-Log -Message "An error has occured during script execution." -Component "Catch" -Type 3
                                Get-ErrorInformation -incomingError $_
                            }
                            
                        }
                        else
                        {
                            Write-Warning "The repository has not been initilized. Nothing to do."
                            Write-CMTraceLog -Message "The repository has not been initilized. Nothing to do." -Component $Component -type 1 -Logfile $LogFile 
                        }
                    }

                }

            <#  #Mark the last time the script ran if not ran with WhatIf
                If (!$WhatIfPreference){Get-Date | Out-File $lastRanPath -Force} #>
                Set-Location $CurrentLocation
            }
            else
            {
                Write-Warning "Unable to continue. Exiting script."
                Write-CMTraceLog -Message "Unable to continue. Exiting script." -Component $Component -type 3 -Logfile $LogFile 
            }
        }
        else {
            # Write-Verbose "User elected not to continue with script because of VPN connection."
            Write-CMTraceLog -Message "User elected not to continue with script because of VPN connection." -Component $Component -type 1 -Logfile $LogFile 
        }
    }

    end
    {   
        # Write-Verbose "End of script."
        # End
        Set-Location $CurrentLocation
    }
}
#EndRegion '.\Public\Invoke-DM_HPRepositorySync.ps1' 351
#Region '.\Public\Invoke-DM_HPRepositorySyncToProd.ps1' -1

Function Invoke-DM_HPRepositorySyncToProd ()
{
        <#
        .SYNOPSIS
        Copies a test HP driver repository to the prod location.

        .DESCRIPTION
        Copies a well tested test repository to the prod location.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        If you need to copy multiple repositories at a time, you can pass multiple Platform IDs at a time.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies that status of the repository to be copied. This parameter is optional.
        
        .PARAMETER PackageContentPath
        Path of the driver repository to copy. This is an optional parameter.

        .PARAMETER OverrideVPNCheck
        The repository copy can take a long time over a VPN connection. If the -OverrideVPNCheck parameter is passed, the built-in VPN check will be bypassed.

        .PARAMETER Force
        If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        Outputs a custom object that contains the details of the copied prod repository.

        'PlatformID'
        'OS'
        'OSBuild'
        'RootPath'
        'Path'
        'Status'

        Example:
        PlatformID : DDDD
        OS         : Win10
        OSBuild    : 22H2
        RootPath   : \\corp.viamonstra.com\shared\WorkstationDriverRepository
        Path       : \\corp.viamonstra.com\shared\WorkstationDriverRepository\Test\Win10\22H2\DDDD
        Status     : Test

        .EXAMPLE
        Invoke-DM_HPRepositorySyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test

        .EXAMPLE
        Invoke-DM_HPRepositorySyncToProd -PlatformID AAAA -OS Win11 -OSBuild 24H2 -Status Test -Force

        .EXAMPLE
        Invoke-DM_HPRepositorySyncToProd -PlatformID AAAA,BBBB -OS Win11 -OSBuild 24H2 -Status Test -Force

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [string[]]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [Parameter(Mandatory=$True,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [switch]$OverrideVPNCheck,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-Warning "The Invoke-DM_HPRepositorySyncToProd function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again."
            Write-CMTraceLog -Message "The Invoke-DM_HPRepositorySyncToProd function requires you run Powershell with admin privileges. Please open an elevated Powershell prompt and try again." -Component $Component -Type 3

            break
        }
    }

    Process
    {
        try{
            $Component = $($myinvocation.mycommand)

            if ($Force -and -not $Confirm)
            {
                $ConfirmPreference = 'None'
            }

            Foreach ($ID in $PlatformID)
            {
                $IDUpper = $ID.ToUpper()
                $SourcePath = $(Join-Path -Path "$HPRepoPath" "Test\$OS\$OSBuild\$IDUpper")
                Write-CMTraceLog -Message "Source path: $SourcePath" -Component $Component -type 1 -Logfile $LogFile 

                $DestPath = $(Join-Path -Path "$HPRepoPath" "Prod\$OS\$OSBuild\$IDUpper")
                Write-CMTraceLog -Message "Dest path: $DestPath." -Component $Component -type 1 -Logfile $LogFile 

                Write-CMTraceLog -Message "Checking for write permission to `"$HPRepoPath`"." -Component $Component -type 1 -Logfile $LogFile
                If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $true)
                {
                    Write-CMTraceLog -Message "Path `"$HPRepoPath`" exists. Script can continue." -Component $Component -type 1 -Logfile $LogFile
                    Write-CMTraceLog -Message "Permissions check to $HPRepoPath path passed." -Component $Component -type 1 -Logfile $LogFile 
                    If (Test-path $SourcePath)
                    {
                        Write-CMTraceLog -Message "Source path exists." -Component $Component -type 1 -Logfile $LogFile 
                        if($PSCmdlet.ShouldProcess($ID,"Sync Test repository for $ID, OS $OS, and OSBuild $OSBuild to Prod" + "?"))
                        {
                            If (-Not (Test-Path $DestPath))
                            {
                                Write-CMTraceLog -Message "Path `"$DestPath`" does not exist. Creating path." -Component $Component -type 1 -Logfile $LogFile 
                                [void][System.IO.Directory]::CreateDirectory($DestPath)
                            }

                            Write-CMTraceLog -Message "Syncing `"Test`" repository for $ID to `"Prod`" for $OS $OSBuild." -Component $Component -type 1 -Logfile $LogFile 
                            Sync-DirWithProgress -SourceDir $(Join-Path -Path "$HPRepoPath" "Test\$OS\$OSBuild\$ID") -DestDir $(Join-Path -Path "$HPRepoPath" "Prod\$OS\$OSBuild\$ID")
                            Write-CMTraceLog -Message "Sync complete." -Component $Component -type 1 -Logfile $LogFile

                            # Write file to show when the repo was last synced from test.
                            "Platform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nDate copied: $((get-date).tostring())`nPerpetrator: $env:USERNAME`nSource Path: $SourcePath`nDest Path: $DestPath" | out-file -FilePath "$(Join-Path -Path "$HPRepoPath" "Prod\$OS\$OSBuild\$IDUpper")\LastSyncFromTest.txt"

                            # Get repo info so we can output the object so the results of this cmdlet can be piped to other cmdlets.
                            $Return = Get-DM_HPRepository -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status Prod

                            If ($Return)
                            {
                                return $Return
                            }
                        }
                    }
                    else
                    {
                        Write-Warning -Message "The path `"$SourcePath`" does not exist."
                        Write-CMTraceLog -Message "The path `"$SourcePath`" does not exist." -Component $Component -type 3 -Logfile $LogFile 
                        break
                    }
                }
                else
                {
                    # Write-CMTraceLog -Message "Path `"$HPRepoPath`" does not exist. Script cannot continue." -Component $Component -type 3 -Logfile $LogFile 
                    Write-Warning "Permissions check failed. Unable to continue. Exiting script."
                    Write-CMTraceLog -Message "Permissions check failed. Unable to continue. Exiting script." -Component $Component -type 3 -Logfile $LogFile 
                    break
                }
            }
        }
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution. $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            # Set-Location $CurrentLocation
        }
    }

    End
    {
        # End
    }
}
#EndRegion '.\Public\Invoke-DM_HPRepositorySyncToProd.ps1' 183
#Region '.\Public\New-DM_CMDriverManagementPackage.ps1' -1

Function New-DM_CMDriverManagementPackage ()
{
    <#
    .SYNOPSIS
    Creates a new ConfigMgr package for either a HP driver package or HP repository package.

    .DESCRIPTION
    Creates a new ConfigMgr package for either a HP driver package or HP repository package.

    .PARAMETER PlatformID
    The platform ID from a HP computer.

    .PARAMETER OS
    Specifies the OS. Windows 10 or Windows 11.

    .PARAMETER OSBuild
    The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

    .PARAMETER Status
    Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

    .PARAMETER Packagetype
    Indicates what type of package needs to be created.
    
    DriverPack = ConfigMgr package containing drivers
    
    DriverRepository = ConfigMgr package containing an HP driver repository.

    .PARAMETER PackageDate
    Used to set the date to be used in the verions field of the ConfigMgr package. If nothing is passed, today's month and year will be used.
    Example: 2025-02

    .PARAMETER Manufacturer
    Specifies the manufacturer that will be used to set the manufacturer field on the ConfigMgr package

    .PARAMETER Path
    The path that will be used as the source of the new ConfigMgr package.

    .PARAMETER UpdateExistingPackage
    If an existing ConfigMgr package is found, update it instead of creating a new package. If this parameter is not
    specified and the package already exists, the existing package will NOT be updated and you will need
    to update the version and distribute the content manually.

    .PARAMETER SiteServer
    ConfigMgr site server name.

    .PARAMETER SiteCode
    ConfigMgr site code.

    .PARAMETER CMFolder
    The folder where the new ConfigMgr package will be moved to in ConfigMgr.

    "[SiteCode]:\Package\OSD\HP"

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    Outputs the object from the creation of the ConfigMgr package.

    .EXAMPLE
    New-DM_CMDriverManagementPackage -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverPack -Path \\corp.viamonstra.com\CMSource\OSD\Drivers\DriverPacks\HP_DP_880D_Win10-22H2-202212

    .EXAMPLE
    New-DM_CMDriverManagementPackage -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverRepository -Path \\corp.viamonstra.com\CMSource\WorkstationDriverRepository\Test\Win10\22H2\880D

    .EXAMPLE
    Get-DM_HPRepository -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test | New-DM_CMDriverManagementPackage -PackageType DriverRepository

    Use output from the Get-DM_HPRepository as input for New-DM_CMDriverManagementPackage. You still need to use the -PackageType parameter since that's not passed from the previous command.

    .NOTES
    Requires the ConfigMgr console to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidatePattern("^[a-fA-F0-9]{4}$")]
        [string[]]$PlatformID,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("Win10", "Win11")]
        [string]$OS,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("22H2", "23H2", "24H2")]
        [string]$OSBuild,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("Prod", "Test")]
        [string]$Status,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("DriverPack", "DriverRepository")]
        [string]$PackageType,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [alias('LastUpdated')]
        $PackageDate,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [string]$Manufacturer = 'HP',
        #[string]$Language,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$Path,
        [alias('SyncExistingPackage')]
        [switch]$UpdateExistingPackage,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteServer,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteCode,
        [string]$CMFolder = "$($SiteCode):\Package\OSD\HP\Testing",
        [Switch]$Force,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin
    {
        $Component = $($myinvocation.mycommand)

        if ($Force -and -not $Confirm)
        {
            $ConfirmPreference = 'None'
        }

        $InformationPreference = 'Continue'

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false)
        {
            Write-CMTraceLog -Message "Failed SCCM repreq check." -Component $Component -type 1 -Logfile $LogFile 
            break
        }

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues
    }
    Process
    {
        Write-CMTraceLog -Message "Checking for write permission to `"$Path`"." -Component $Component -type 1 -Logfile $LogFile 
        If ((Invoke-PathPermissionsCheck -Path $Path) -eq $false)
        {
            Write-CMTraceLog -Message "Unable to write to `"$Path`"." -Component $Component -type 3 -Logfile $LogFile 
            break
        }
        try
        {
            Foreach ($ID in $PlatformID)
            {
                if ($PSBoundParameters.ContainsKey('PackageType'))
                {
                    # Write-Verbose "PackageType passed."
                    Write-CMTraceLog -Message "PackageType passed." -Component $Component -type 1 -Logfile $LogFile 
                    switch ($PackageType)
                    {
                        'DriverPack' { 
                            # Write-Verbose "Package type = 'DriverPack'."
                            Write-CMTraceLog -Message "Package type = 'DriverPack'." -Component $Component -type 1 -Logfile $LogFile 
                            $PackageName = "DriverPack: $Manufacturer $($ID.ToUpper()) $OS $OSBuild - $Status"
                            }
                        'DriverRepository' {
                            # Write-Verbose "Package type = 'DriverRepository'."
                            Write-CMTraceLog -Message "Package type = 'DriverRepository'." -Component $Component -type 1 -Logfile $LogFile 
                            $PackageName = "DriverRepository: $Manufacturer $($ID.ToUpper()) $OS $OSBuild - $Status"
                            }
                    }
                }
        
                # Write-Verbose "Importing SCCM PS Module"
                Write-CMTraceLog -Message "Importing SCCM PS Module" -Component $Component -type 1 -Logfile $LogFile 
        
                # Load CM PowerShell Module
                Import-CMPSModule
            
                $CurrentLocation = Get-Location
        
                # Write-Verbose "SiteCode: $SiteCode"
                Write-CMTraceLog -Message "SiteCode: $SiteCode" -Component $Component -type 1 -Logfile $LogFile 
            
                Set-Location "$($SiteCode):\" -Verbose:$false
        
                # Write-Verbose "Checking to see if package already exists."
                Write-CMTraceLog -Message "Find package." -Component $Component -type 1 -Logfile $LogFile
                Write-CMTraceLog -Message "Checking to see if package `"$PackageName`" exists." -Component $Component -type 1 -Logfile $LogFile 
                $PackageObj = Get-CMPackage -Name $PackageName -Fast -Verbose:$false
        
                If (!($PackageObj))
                {
                    # Write-Verbose "Package `"$PackageName`" does not exist."
                    Write-CMTraceLog -Message "Package `"$PackageName`" does not exist." -Component $Component -type 1 -Logfile $LogFile 
        
                    if($PSCmdlet.ShouldProcess($PackageName,"Create package with type `"$PackageType`" and name `"$PackageName`""))
                    {
                        #Create the package first
                        # Write-Verbose "Creating new package."
                        Write-CMTraceLog -Message "Creating new package." -Component $Component -type 1 -Logfile $LogFile

                        If ($PackageDate)
                        {
                            Write-CMTraceLog -Message "Using date passed from command line." -Component $Component -type 1 -Logfile $LogFile
                            $NewPackage = New-CMPackage -Name $PackageName -Manufacturer $Manufacturer -Path $Path -Language "$Manufacturer $($ID.ToUpper()) $OS $OSBuild" -Version $PackageDate -Verbose:$false
                        }
                        else
                        {
                            Write-CMTraceLog -Message "Using today's date for package." -Component $Component -type 1 -Logfile $LogFile
                            $NewPackage = New-CMPackage -Name $PackageName -Manufacturer $Manufacturer -Path $Path -Language "$Manufacturer $($ID.ToUpper()) $OS $OSBuild" -Version $(get-date).ToString("yyyy-MM") -Verbose:$false
                        }
      
                        Write-CMTraceLog -Message "New package Name: $($NewPackage.Name)" -Component $Component -type 1 -Logfile $LogFile 
                        Write-CMTraceLog -Message "New package ID: $($NewPackage.PackageID)" -Component $Component -type 1 -Logfile $LogFile 
                        
                        Write-Verbose "Updating settings on new package."
                        Write-CMTraceLog -Message "Updating settings on new package." -Component $Component -type 1 -Logfile $LogFile 
                        # Set-CMPackage -InputObject $NewPackage -EnableBinaryDeltaReplication $true -CopyToPackageShareOnDistributionPoint $true -SendToPreferredDistributionPoint $true -Verbose:$false
                        [void](Set-CMPackage -InputObject $NewPackage -EnableBinaryDeltaReplication $true -SendToPreferredDistributionPoint $true -Verbose:$false)
        
                        # If ($PackageType -eq "DriverRepository")
                        # {
                        Write-CMTraceLog -Message "Creating `"Download`" program in package $($NewPackage.Name)." -Component $Component -type 1 -Logfile $LogFile 
                        [void](New-CMProgram -PackageName $($NewPackage.Name) -CommandLine "cmd.exe /c" -StandardProgramName "Download" -ProgramRunType WhetherOrNotUserIsLoggedOn -RunMode RunWithAdministrativeRights -RunType Hidden -Verbose:$false)
                        [void](Get-CMProgram -PackageName $($NewPackage.Name) -ProgramName "Download" -Verbose:$false | Set-CMProgram -StandardProgram -EnableTaskSequence $true -AfterRunningType NoActionRequired -Verbose:$false)
                        # }
        
                        # Move package to correct folder
                        # Write-Verbose "Moving new packge to correct folder."
                        Write-CMTraceLog -Message "Moving new packge to folder: $CMFolder." -Component $Component -type 1 -Logfile $LogFile 
                        [void](Move-CMObject -InputObject $NewPackage -FolderPath $CMFolder -Verbose:$false)
        
                        # Write-Verbose "Distributing contents of new package."
                        Write-CMTraceLog -Message "Distributing contents of new package." -Component $Component -type 1 -Logfile $LogFile 
                        [void](Invoke-DM_CMPackageDistribution -PackageID $($NewPackage.PackageID))
        
                        <# If (Get-CMDistributionPointGroup -Name $DistributionPointGroupName)
                        {
                            Write-Verbose "Distribution point group `"$DistributionPointGroupName`" is vaild."
                            # Distribute package content
                            Write-Verbose "Distributing contents of new package."
                            Start-CMContentDistribution -InputObject $NewPackage -DistributionPointGroupName $DistributionPointGroupName
                        } #>
                        Write-CMTraceLog -Message "Returning object for package: $($NewPackage.PackageID)." -Component $Component -type 1 -Logfile $LogFile 
                        $PackageOut = Get-CMPackage -Id $($NewPackage.PackageID) -Fast -Verbose:$false
                    }
        
                    Set-Location $CurrentLocation
        
                    return, $PackageOut;
                }   
                else
                {
                    Write-CMTraceLog -Message "Package `"$PackageName`" exists." -Component $Component -type 2 -Logfile $LogFile
                    Write-Warning "Package `"$PackageName`" exists."

                    if ($UpdateExistingPackage)
                    {
                        Write-CMTraceLog -Message "UpdateExistingPackage parameter passed. Updating version and redistrbuting existing package." -Component $Component -type 1 -Logfile $LogFile
                        Write-Information -MessageData "UpdateExistingPackage parameter passed. Updating version and redistrbuting existing package." -InformationAction Continue
                        #Update date of existing driver package.
                        Write-CMTraceLog -Message "Updating version date for package `"$PackageName`"." -Component $Component -type 2 -Logfile $LogFile
                        Write-Information -MessageData "Updating version date for package `"$PackageName`"." -InformationAction Continue
                        Set-DM_CMDriverManagementPackage -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -PackageType $PackageType -UpdateVersion $($(get-date).ToString("yyyy-MM"))

                        Get-DM_CMDriverManagementPackage -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -PackageType $PackageType | Invoke-DM_CMPackageDistribution
                        Write-CMTraceLog -Message "Redistribution of existing package started." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Redistribution of existing package started." -InformationAction Continue
                    }
                    else
                    {
                        # Write-Verbose "Package already exists."
                        Write-Warning "Use the -UpdateExistingPackage parameter with New-DM_CMDriverManagementPackage to redistribute content when the package already exists."
                    }
        
                    Set-Location $CurrentLocation
                    return $PackageObj
                }
            }

        }
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-CMTraceLog -Message "Something went wrong." -Component $Component -type 2 -Logfile $LogFile 
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution. $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            Set-Location $CurrentLocation
        }
    }
}
#EndRegion '.\Public\New-DM_CMDriverManagementPackage.ps1' 285
#Region '.\Public\New-DM_HPDriverPack.ps1' -1

function New-DM_HPDriverPack ()
{
    <#
        .SYNOPSIS
        Creates an HP driver pack for the PlatformID, OS, and OS Build.

        .DESCRIPTION
        Creates an HP driver pack for the PlatformID, OS, and OS Build.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

        *** Updated to only allow the creation of "Test" DriverPacks.

        .Parameter UnselectList
        Aligns with the same parameter in New-HPDriverPack, which this function uses.

        Specifies a list of SoftPaq numbers and SoftPaq names to not be included in the Driver Pack. A partial name can be specified. Examples include 'Docks', 'USB', 'sp123456'.

        .PARAMETER DriverRoot
        Working path where the drivers will be download to and extracted.

        .PARAMETER Compress
        Compress the driver pack with 7-Zip.

        .PARAMETER Overwite
        Overwite and existing drivers. Needed when the command has already been ran.

        .PARAMETER CreatePackage
        Create an ConfigMgr package for the driver pack. Uses New-DM_CMDriverManagementPackage to create the package.

        .PARAMETER Cleanup
        Removes files in the temp directory used to download, extrace, and compress the driver pack.

        .PARAMETER CopyDP

        Copies the driver pack and supporting files to the ConfigMgr sourcefiles share.

        "\\corp.viamonstra.com\CMSource\OSD\Drivers\DriverPacks"

        .PARAMETER UpdateExistingPackage
        If an existing ConfigMgr package is found, update it instead of creating a new package. If this parameter is not
        specified and the package already exists, the existing package will NOT be updated and you will need
        to update the version and distribute the content manually.
        
        .PARAMETER PackageContentPath
        Path to copy the source files for the SCCM package.

        .PARAMETER OverrideVPNCheck
        The driver pack download can take a long time over a VPN connection. If the -OverrideVPNCheck parameter is passed, the built-in VPN check will be bypassed.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        Outpus a custom object that contains the details of the new driver pack.

        'PlatformID'
        'OS'
        'OSBuild'
        'DriverRoot'
        'Path'
        'Status'

        .EXAMPLE
        New-DM_HPDriverPack -PlatformID 8711 -OS Win10 -OsVer 22H2 -Status Test -Compress -Overwite -CreatePackage -CopyDP

        Create a new driver pack for platform 8711, OS Win10, build 22H2, that will be compressed and copied to the CMSource file share and a package created.

        .EXAMPLE
        Import-Csv C:\Temp\DrivePackTest.csv | New-DM_HPDriverPack -Status Test -Compress -Overwite -CreatePackage -CopyDP

        Pipe a CSV with different models to the script to download each one.

        Example CSV file

        Model,Platform,OS,OsVer
        HP EliteDesk 800 G5 Desktop Mini,8595,Win10,22H2
        HP ZBook Firefly 14 inch G8 Mobile Workstation PC,8AB3,Win11,22H2

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(DefaultParameterSetName='default', SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
        #Define a configuration file.
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
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
        #[ValidateSet("Prod", "Test")]
        [ValidateSet("Test")]
        [string]$Status = 'Test',
        # HP parameter to: Specifies a list of SoftPaq numbers and SoftPaq names to not be included in the Driver Pack. A partial name can be specified. Examples include 'Docks', 'USB', 'sp123456'.
        [string]$UnselectList,
        [string]$DriverRoot = "C:\Temp\Drivers",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Compress')]
        [Parameter(ParameterSetName = 'Default')]
        [switch]$Compress,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName,ParameterSetName = 'Compress')]
        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("7Zip")]
        # [ValidateSet("7Zip", "Zip", "WIM")]
        [string]$CompressionMethod = '7Zip',
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [switch]$Overwite,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='package',Mandatory=$True)]
        [Parameter(ParameterSetName = 'Default')]
        [switch]$CopyDP,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='package')]
        [Parameter(ParameterSetName = 'Default')]
        [switch]$CreatePackage,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='package')]
        [Parameter(ParameterSetName = 'Default')]
        [alias('SyncExistingPackage')]
        [switch]$UpdateExistingPackage,
        [bool]$Cleanup = $True,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
        [string]$PackageContentPath,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [switch]$OverrideVPNCheck,
        [Switch]$Force,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        #region Functions

        #endregion

        #region #################################### START GLOBAL VARIABLES ####################################>

        Write-Verbose "Called by: $((Get-PSCallStack)[1].Command)"
        # Get-PSCallStack | Select-Object -Property *

        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $Date = Get-Date -Format ("MM-dd-yyyy")

        Write-CMTraceLog -Message "Date: $Date" -Component $Component -type 1 -Logfile $LogFile 

        $DPDestination = Join-Path $PackageContentPath "HP"

        if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
        {
            Write-Warning "When creating a HP Driver pack you must run Powershell with admin privileges. Please open an elevated Powershell prompt and try again."
            Write-CMTraceLog -Message "When creating a HP Driver pack you must run Powershell with admin privileges. Please open an elevated Powershell prompt and try again." -Component $Component -Type 3

            break
        }

        If ((Helper-GetDM_HPCMSLInstallStatus) -eq $false)
        {
            Write-Warning "HPCMSL is not installed. Please install and try again."
            Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
            break
        }

        If ($Compress)
        {
            Write-CMTraceLog -Message "Compress parameter passed, compression method selected: $CompressionMethod." -Component $Component -type 1 -Logfile $LogFile
            Write-CMTraceLog -Message "Compress parameter passed, checking for 7-Zip." -Component $Component -type 1 -Logfile $LogFile 
            If ((Check-DM_PreReqSoftware -PreReq 7Zip) -eq $false) { break }
            Write-CMTraceLog -Message "7-Zip EXE to use: $Global:EXE." -Component $Component -type 1 -Logfile $LogFile 
        }

        If ($CreatePackage)
        {
            Write-CMTraceLog -Message "Create package parameter passed, checking for SCCM Console." -Component $Component -type 1 -Logfile $LogFile 
            If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false) { break }
        }

        If ($CopyDP)
        {
            Write-CMTraceLog -Message "CopyDP parameter passed, checking for write access to CMSource." -Component $Component -type 1 -Logfile $LogFile 
            If ((Invoke-PathPermissionsCheck -Path $PackageContentPath) -eq $false) { break }
        }

        #endregion #################################### END GLOBAL VARIABLES ####################################>
    }

    Process
    {
        #region #################################### START MAIN LOGIC ####################################>
        try {
            # $DiskInfo = Get-CimInstance -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "C:" } | Select-Object -Property DeviceID, VolumeName, @{Label='FreeSpace (Gb)'; expression={($_.FreeSpace/1GB).ToString('F2')}},@{Label='Total (Gb)'; expression={($_.Size/1GB).ToString('F2')}},@{label='FreePercent'; expression={[Math]::Round(($_.freespace / $_.size) * 100, 2)}}
            $DiskInfo = Get-CimInstance -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "C:" } | Select-Object -Property DeviceID, VolumeName, @{Label='FreeSpace (Gb)'; expression={($_.FreeSpace/1GB)}},@{Label='Total (Gb)'; expression={($_.Size/1GB)}},@{label='FreePercent'; expression={[Math]::Round(($_.freespace / $_.size) * 100, 2)}}

            If ($DiskInfo.FreePercent -lt 20)
            {
                Write-CMTraceLog -Message "Low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available." -Component $Component -Type 2
                Write-Warning "Low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available."
                # throw "Low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available."
            }

            If ($DiskInfo.'FreeSpace (Gb)' -lt 5)
            {
                Write-CMTraceLog -Message "Really low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available." -Component $Component -Type 3
                Write-Warning "Really low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available."
                throw "Low disk space. Only $($DiskInfo.'FreeSpace (Gb)') available."
            }

            $PulseAdapterStatus = (Get-NetAdapter -InterfaceDescription "Juniper Networks Virtual Adapter" -ErrorAction SilentlyContinue).Status
            
            # If OverrideVPNCheck is passed, set PulseAdapterStatus to False to bypass the prompt.
            if ($PSBoundParameters.ContainsKey('OverrideVPNCheck'))
            {
                $PulseAdapterStatus = 'Down'
                Write-CMTraceLog -Message "Parameter OverrideVPNCheck passed. Bypassing VPN check." -Component $Component -type 1 -Logfile $LogFile 
            }

            if ($PulseAdapterStatus -eq 'Up')
            {
                Write-CMTraceLog -Message "Script running over VPN, prompt to continue." -Component $Component -type 1 -Logfile $LogFile 

                $title    = 'Continue?'
                $question = "Looks like you're connected over the VPN. What your about to do will take a while to complete.`nDo you want to continue?"
                $choices  = '&Yes', '&No'

                $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                if ($decision -eq 0) {
                    $Runscript = $True
                    Write-CMTraceLog -Message "User decided to continue over VPN." -Component $Component -type 1 -Logfile $LogFile 
                } else {
                    $Runscript = $false
                    Write-CMTraceLog -Message "User decided not to continue over VPN." -Component $Component -type 1 -Logfile $LogFile 
                }
            }
            else
            {
                $Runscript = $True
            }

            If ($Runscript -eq $True)
            {
                # If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.
                if ($Force -and -not $Confirm)
                {
                    $ConfirmPreference = 'None'
                }

                Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
                # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

                $PlatformID = $($PlatformID.ToUpper())

                Write-CMTraceLog -Message "------ Start $PlatformID Start------" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Driver pack destination: $DPDestination" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Platform: $PlatformID" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "OS: $OS" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "OS version: $OSBuild" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Driver root: $DriverRoot" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Driver pack destination: $DPDestination" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "CopyDP: $CopyDP" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Compress: $Compress" -Component $Component -type 1 -Logfile $LogFile 
                Write-CMTraceLog -Message "Overwrite: $Overwite" -Component $Component -type 1 -Logfile $LogFile 

                switch ($OS)
                {
                    Win10 {$FullOS = "Microsoft Windows 10"}
                    Win11 {$FullOS = "Microsoft Windows 11"}
                }

                Write-CMTraceLog -Message "Full OS: $FullOS" -Component $Component -type 1 -Logfile $LogFile 

                if (!(Get-InstalledModule HPCMSL))
                {
                    # Write-Verbose "HPCMSL is not installed."
                    Write-CMTraceLog -Message "HPCMSL is not installed." -Component $Component -Type 3 -Logfile $LogFile 
                    break
                }
                Else
                {
                    # Write-Verbose "HPCMSL is installed. Let's work."
                    Write-CMTraceLog -Message "HPCMSL is installed. Let's work." -Component $Component -type 1 -Logfile $LogFile 

                    If ((Get-DM_HPPlatformIDIsValid -PlatformID $PlatformID) -eq $true)
                    {
                        If (Get-HPDeviceDetails -Platform $PlatformID -oslist | Where-Object {$_.OperatingSystemRelease -eq $OSBuild -and $_.OperatingSystem -eq "$FullOS"})
                        {
                            $PlatformDriverPath = Join-Path $DriverRoot "$PlatformID\$os\$OSBuild\$Date"
                            $PlatformRoot = Join-Path $DriverRoot "$PlatformID"

                            if (-Not(Test-Path -Path $PlatformDriverPath))  {
                                # New-Item -ItemType Directory $PlatformDriverPath -Force
                                [void][System.IO.Directory]::CreateDirectory($PlatformDriverPath)
                            }

                            # Write-Verbose "Driver platform path: $PlatformDriverPath"
                            Write-CMTraceLog -Message "Driver platform path: $PlatformDriverPath" -Component $Component -type 1 -Logfile $LogFile 
                            
                            Try{
                                If (!(Test-Path "$PlatformDriverPath\DP$PlatformID") -or $Overwite)
                                {
                                    if($PSCmdlet.ShouldProcess($PlatformID,"Create driver pack for platform $PlatformID, OS $OS, and OSBuild $OSBuild" + "?"))
                                    {
                                        Write-CMTraceLog -Message "Folder $PlatformDriverPath\DP$PlatformID does not exist or -Overwrite was passed." -Component $Component -type 1 -Logfile $LogFile 
                                        If ($Overwite)
                                        {
                                            Write-CMTraceLog -Message "Overwrite parameter passed." -Component $Component -type 1 -Logfile $LogFile 
                                            If (test-path "$PlatformDriverPath\DP$PlatformID")
                                            {
                                                Write-CMTraceLog -Message "Removing $PlatformDriverPath\DP$PlatformID." -Component $Component -type 1 -Logfile $LogFile 
                                                remove-item -Path "$PlatformDriverPath\DP$PlatformID" -Force -Recurse
                                            }
                                        }
                                        # [void][System.IO.Directory]::CreateDirectory("$PlatformDriverPath\DP$Platform")
                                        Write-CMTraceLog -Message "Downloading driver pack." -Component $Component -type 1 -Logfile $LogFile 

                                        if ($UnselectList)
                                        {
                                            Write-CMTraceLog -Message "UnSelectList: $UnselectList." -Component $Component -type 1 -Logfile $LogFile
                                            Write-CMTraceLog -Message "UnSelectList: $UnselectList." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"

                                            $ExcludeList = @()
                                            foreach ($Item in $UnselectList)
                                            {
                                                Clear-Variable SPFile -ErrorAction SilentlyContinue
                                                If ($Item -match "^sp\d+$")
                                                {
                                                    Write-CMTraceLog -Message "Item appears to already be in SP format. Adding to array. $Item" -Component $Component -type 1 -Logfile $LogFile
                                                    Write-CMTraceLog -Message "Item appears to already be in SP format. Adding to array. $Item" -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"
                                                    $ExcludeList += $Item
                                                }
                                                else
                                                {
                                                    Write-CMTraceLog -Message "Item appears to not be in SP format. $Item" -Component $Component -type 1 -Logfile $LogFile
                                                    Write-CMTraceLog -Message "Item appears to not be in SP format. $Item" -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"

                                                    Write-CMTraceLog -Message "Looking up $Item." -Component $Component -type 1 -Logfile $LogFile
                                                    Write-CMTraceLog -Message "Looking up $Item." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"
                                                    $SPFile = Get-SoftpaqList -Platform $PlatformID -Bitness 64 -Os $OS -OsVer $OSBuild | Where-Object {$_.name -eq "$Item"} | Select-Object -ExpandProperty id
                                                    If ($SPFile)
                                                    {
                                                        Write-CMTraceLog -Message "$Item was found." -Component $Component -type 1 -Logfile $LogFile
                                                        Write-CMTraceLog -Message "$Item was found." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"

                                                        Write-CMTraceLog -Message "SPFile: $SPFile." -Component $Component -type 1 -Logfile $LogFile
                                                        Write-CMTraceLog -Message "SPFile: $SPFile." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"
        
                                                        $ExcludeList += $SPFile
                                                    }
                                                }

                                            }
                                            If ($Excludelist)
                                            {
                                                $ExcludeList = $ExcludeList -join "," | Select-Object -Unique
                                                Write-CMTraceLog -Message "UnselectList was passed, excluding $Excludelist." -Component $Component -type 1 -Logfile $LogFile
                                                Write-CMTraceLog -Message "UnselectList was passed, excluding $Excludelist." -Component $Component -type 1 -Logfile "$PlatformRoot\Exclude.log"

                                                "The following has been excluded from this DriverPack: $Excludelist" | Out-File "$PlatformRoot\Excluded.txt"
                                                $HPDriverPackResult = New-HPDriverPack -Platform $PlatformID -OS $os -OSVer $OSBuild -Path $PlatformDriverPath -RemoveOlder -UnselectList $ExcludeList

                                                $ExcludeSupportFiles = 'Exclude.log','Excluded.txt'
                                            }
                                        }
                                        Else
                                        {
                                            $HPDriverPackResult = New-HPDriverPack -Platform $PlatformID -OS $os -OSVer $OSBuild -Path $PlatformDriverPath -RemoveOlder
                                        }
                                        Write-CMTraceLog -Message "Driver pack result: $HPDriverPackResult." -Component $Component -type 1 -Logfile $LogFile 
                                        "Platform: $PlatformID`nFull OS: $FullOS`nOS Version: $OSBuild`nDate created: $((get-date).tostring())`nCreated by: $env:USERNAME" | out-file -FilePath "$PlatformDriverPath\DP$PlatformID\DriverInfo.txt"

                                        # Write-Output $DP

                                        If ($Compress)
                                        {
                                            # Write-Verbose "Compress drivers is enabled."
                                            Write-CMTraceLog -Message "Compress drivers is enabled." -Component $Component -type 1 -Logfile $LogFile

                                            Write-CMTraceLog -Message "Compression method selected: $CompressionMethod." -Component $Component -type 1 -Logfile $LogFile

                                            If ($CompressionMethod -eq '7Zip')
                                            {
                                                Write-CMTraceLog -Message "7Zip compression method selected." -Component $Component -type 1 -Logfile $LogFile

                                                # Check for the z-zip exe.
                                                if (Test-Path $EXE)
                                                {
                                                    # Check for the existance if the 7z file.
                                                    if (!(Test-Path "$PlatformDriverPath\DriverPack.7z") -or $Overwite)
                                                    {
                                                        if($PSCmdlet.ShouldProcess($PlatformID,"Create 7-Zip of driver pack for platform $PlatformID, OS $OS, and OSVer $OSBuild" + "?"))
                                                        {
                                                            If ($Overwite)
                                                            {
                                                                If (Test-Path "$PlatformDriverPath\DriverPack.7z")
                                                                {
                                                                    remove-item -Path "$PlatformDriverPath\DriverPack.7z" -Force
                                                                }
                                                            }
                                                            Write-CMTraceLog -Message "Using 7-Zip to compress driver pack." -Component $Component -type 1 -Logfile $LogFile 
                                                            Write-Information -MessageData "Using 7-Zip to compress driver pack." -InformationAction Continue
                                                            $Result = & $EXE -mx=9 a "$PlatformDriverPath\DriverPack.7z" "$PlatformDriverPath\DP$PlatformID\*"

                                                            If ((Get-Item "$PlatformDriverPath\DriverPack.7z").Length -eq 0)
                                                            {
                                                                Write-CMTraceLog -Message "DriverPack.7z is 0 bytes. Something went wrong." -Component $Component -Type 3 -Logfile $LogFile 
                                                                Write-Warning "DriverPack.7z is 0 bytes. Something went wrong."
                                                                throw "DriverPack.7z is 0 bytes. Something went wrong."
                                                            }

                                                            Write-CMTraceLog -Message "Result of 7-Zip operation: $Result." -Component $Component -type 1 -Logfile $LogFile 
                                                            Write-Information -MessageData "Result of 7-Zip operation: $Result." -InformationAction Continue
                                                            
                                                            If (!(Test-Path "$PlatformDriverPath\DriverPack.7z"))
                                                            {
                                                                # Write-Verbose "The 7-Zip file failed to get created."
                                                                Write-CMTraceLog -Message "The 7-Zip file failed to get created." -Component $Component -Type 3 -Logfile $LogFile 
                                                                Write-Warning "The 7-Zip file failed to get created."
                                                                throw "The 7-Zip file failed to get created."
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        # Write-Verbose "File $PlatformDriverPath\DriverPack.7z already exists."
                                                        Write-CMTraceLog -Message "File $PlatformDriverPath\DriverPack.7z already exists." -Component $Component -Type 3 -Logfile $LogFile 
                                                    }
                                                }
                                            }
                                            elseif ($CompressionMethod -eq 'Zip')
                                            {
                                                Write-CMTraceLog -Message "Zip compression method selected." -Component $Component -type 1 -Logfile $LogFile
                                            }
                                            elseif ($CompressionMethod -eq 'WIM')
                                            {
                                                Write-CMTraceLog -Message "WIM compression method selected." -Component $Component -type 1 -Logfile $LogFile
                                            }

                                        } # if compress
                                        
                                        # Generate supporting files
                                        Get-HPDeviceDetails -Platform $PlatformID | Out-File "$PlatformRoot\PlatformInfo.txt"
                                        Get-HPDeviceDetails -Platform $PlatformID -OSList | Out-File "$PlatformRoot\OSSupport.txt"

                                        if ($CopyDP)
                                        {
                                            # $DestPath = "$DPDestination\HP_DP_$($PlatformID)_$OS-$OSBuild-$($(get-date).ToString("yyyyMM"))"
                                            $DestPath = "$DPDestination\$((Get-Culture).TextInfo.ToTitleCase($Status))\$OS\$OSBuild\$PlatformID"
                                            if($PSCmdlet.ShouldProcess($PlatformID,"Copy files for driver pack to $DestPath and create package" + "?"))
                                            {
                                                If ($Compress)
                                                {
                                                    # Write-Verbose "Copy driver pack to $DPDestination\HP_DP_$($Platform)_$OS-$OSBuild-$((Get-date).year)$((Get-date).month)."
                                                    Write-CMTraceLog -Message "Copy driver pack to $DestPath." -Component $Component -type 1 -Logfile $LogFile 
                                                    Write-Information -MessageData "Copy driver pack to $DestPath." -InformationAction Continue

                                                    If (!(Test-Path $DestPath))
                                                    {
                                                        # New-Item -ItemType Directory -Path "$DPDestination\HP_DP_$($Platform)_$OS-$OSBuild-$((Get-date).year)$((Get-date).month)" -Force
                                                        [void][System.IO.Directory]::CreateDirectory($DestPath)
                                                    }

                                                    Copy-FileWithProgress -SourceDir $PlatformDriverPath -DestDir $DestPath -FileName "DriverPack.7z"
                                                    
                                                    # Write-Verbose "Copying 7-Zip files needed to decompress file."
                                                    Write-CMTraceLog -Message "Copying 7-Zip files needed to decompress file to $DestPath." -Component $Component -type 1 -Logfile $LogFile 
                                                    Write-Information -MessageData "Copying 7-Zip files needed to decompress file to $DestPath." -InformationAction Continue
                                                    Copy-7ZipFiles -Path $DestPath

                                                    If ($CreatePackage)
                                                    {
                                                        Write-CMTraceLog -Message "Creating new ConfigMgr package: `"DriverPack: HP $($PlatformID) $OS $OSBuild - $((Get-Culture).TextInfo.ToTitleCase($Status))`" at $DestPath." -Component $Component -type 1 -Logfile $LogFile 
                                                        Write-Information -MessageData "Creating new ConfigMgr package: `"DriverPack: HP $($PlatformID) $OS $OSBuild - $((Get-Culture).TextInfo.ToTitleCase($Status))`" at $DestPath." -InformationAction Continue

                                                        If ($UpdateExistingPackage)
                                                        {
                                                            Write-CMTraceLog -Message "UpdateExistingPackage paramater passed. Updating existing package if it exists." -Component $Component -type 1 -Logfile $LogFile 
                                                            Write-Information -MessageData "UpdateExistingPackage paramater passed. Updating existing package if it exists." -InformationAction Continue
                                                            $NewPackageInfo = New-DM_CMDriverManagementPackage -PlatformID $PlatformID -OS $OS -OSBuild $OSBuild -Status $((Get-Culture).TextInfo.ToTitleCase($Status)) -PackageType DriverPack -Manufacturer 'HP' -Path $DestPath -UpdateExistingPackage
                                                        }
                                                        else
                                                        {
                                                            $NewPackageInfo = New-DM_CMDriverManagementPackage -PlatformID $PlatformID -OS $OS -OSBuild $OSBuild -Status $((Get-Culture).TextInfo.ToTitleCase($Status)) -PackageType DriverPack -Manufacturer 'HP' -Path $DestPath
                                                        }

                                                        # Write-CMTraceLog -Message "NewPackageInfo $NewPackageInfo" -Component $Component -type 1 -Logfile $LogFile
                                                    }
                                                }

                                                # Write-Verbose "Copy driver pack support files..."
                                                Write-CMTraceLog -Message "Copy driver pack support files from $PlatformRoot to $DestPath..." -Component $Component -type 1 -Logfile $LogFile
                                                Copy-FileWithProgress -SourceDir $PlatformRoot -DestDir $DestPath -FileName 'PlatformInfo.txt'
                                                # Copy-Item -Path "$PlatformRoot\PlatformInfo.txt" -Destination "$DestPath\PlatformInfo.txt"
                                                Copy-FileWithProgress -SourceDir $PlatformRoot -DestDir $DestPath -FileName 'OSSupport.txt'
                                                # Copy-Item -Path "$PlatformRoot\OSSupport.txt" -Destination "$DestPath\OSSupport.txt"

                                                Copy-FileWithProgress -SourceDir "$PlatformDriverPath\DP$PlatformID" -DestDir $DestPath -FileName 'DriverInfo.txt'

                                                if ($ExcludeSupportFiles)
                                                {
                                                    Foreach ($ESF in $ExcludeSupportFiles)
                                                    {
                                                        If (test-path "$PlatformRoot\$ESF")
                                                        {
                                                            Write-CMTraceLog -Message "Copying exclude support file(s): $ESF" -Component $Component -type 1 -Logfile $LogFile 
                                                            Copy-FileWithProgress -SourceDir $PlatformRoot -DestDir $DestPath -FileName $ESF
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        $props = [pscustomobject]@{
                                            'PlatformID'=$PlatformID
                                            'OS'=$OS
                                            'OSBuild'=$OSBuild
                                            'DriverRoot'=$DriverRoot
                                            'Path'="$DestPath"
                                            'Status'=$((Get-Culture).TextInfo.ToTitleCase($Status))           
                                        }

                                        If ($NewPackageInfo)
                                        {
                                            # If $CreatePackage is true add needed values to the custom object before output.
                                            $props | Add-Member -MemberType NoteProperty -Name 'PackageID' -Value $NewPackageInfo.PackageID
                                            $props | Add-Member -MemberType NoteProperty -Name 'Name' -Value $NewPackageInfo.Name
                                            $props | Add-Member -MemberType NoteProperty -Name 'ObjectPath' -Value $NewPackageInfo.ObjectPath
                                            $props | Add-Member -MemberType NoteProperty -Name 'Version' -Value $NewPackageInfo.Version
                                        }

                                        # Write-Verbose "Process complete."
                                        Write-CMTraceLog -Message "Process complete." -Component $Component -type 1 -Logfile $LogFile 

                                        If ($Cleanup -eq $true)
                                        {
                                            Write-CMTraceLog -Message "Cleanup enabled." -Component $Component -type 1 -Logfile $LogFile 
                                            Write-CMTraceLog -Message "Removing `"$PlatformDriverPath\DP$PlatformID`"." -Component $Component -type 1 -Logfile $LogFile 
                                            remove-item -Path "$PlatformDriverPath\DP$PlatformID" -Force -Recurse

                                            Write-CMTraceLog -Message "Removing `"$PlatformDriverPath\DriverPack.7z`"." -Component $Component -type 1 -Logfile $LogFile 
                                            remove-item -Path "$PlatformDriverPath\DriverPack.7z" -Force

                                            Write-CMTraceLog -Message "Cleanup complete." -Component $Component -type 1 -Logfile $LogFile 
                                        }

                                        Write-CMTraceLog -Message "------ End $Component End ------" -Component $Component -type 1 -Logfile $LogFile 

                                        return, $props;
                                    }
                                }
                                else
                                {
                                    # Write-Verbose "The drivers for PlatformID have already been downloaded today."
                                    Write-CMTraceLog -Message "The drivers for $PlatformID have already been downloaded today." -Component $Component -type 1 -Logfile $LogFile 
                                }
                            }
                            catch
                            {
                                Write-Warning "Oh snap! An error as occured. $_"
                                $Error[0]
                                Write-CMTraceLog -Message "Oh snap! An error as occured. $_" -Component $Component -Type 3 -Logfile $LogFile 
                                Get-ErrorInformation -incomingError $_
                            }
                        }
                        else
                        {
                            Write-Warning "Platform $PlatformID on OS $OS Version $OSBuild not supported. Check yo self fool."
                            Write-CMTraceLog -Message "Platform $PlatformID on OS $OS Version $OSBuild not supported. Check yo self fool." -Component $Component -Type 3 -Logfile $LogFile 
                            "Platform $PlatformID on OS $OS Version $OSBuild not supported. Check yo self fool."
                        }
                    }
                    else
                    {
                        Write-CMTraceLog -Message "PlatformID: $PlatformID, is not valid." -Component $Component -type 1 -Logfile $LogFile
                        Write-Warning "The PlatformID: $PlatformID, is not valid. Unable to continue. Exiting."
                        Write-Error "The PlatformID: $PlatformID, is not valid. Unable to continue. Exiting." -ErrorAction Stop
                    }

                }

                #endregion #################################### END MAIN LOGIC ####################################>
            }
            else {
                # Write-Verbose "User elected not to continue with script because of VPN connection."
                Write-CMTraceLog -Message "User elected not to continue with script because of VPN connection." -Component $Component -type 1 -Logfile $LogFile 
            }
        } # End of Try
        catch
        {
            Write-Warning "Something went wrong: $_"
            Write-Warning -Message "An error has occured during script execution."
            Write-CMTraceLog -Message "An error has occured during script execution. $_" -Component $Component -type 3 -Logfile $LogFile 
            Get-ErrorInformation -incomingError $_
            if ($CurrentLocation)
            {
                Set-Location $CurrentLocation
            }
        }
    } # End of Process

    End
    {
        # End
    }

}
#EndRegion '.\Public\New-DM_HPDriverPack.ps1' 624
#Region '.\Public\New-DM_HPRepository.ps1' -1

function New-DM_HPRepository ()
{
        <#
        .SYNOPSIS
        Creates a new HP driver repository for a PlatformID, OS, and OS Build.

        .DESCRIPTION
        Creates a new HP driver repository for a PlatformID, OS, and OS Build.

        .PARAMETER PlatformID
        The platform ID from a HP computer.

        If you need to create multiple repositories at a time, you can pass multiple Platform IDs at a time.

        .PARAMETER OS
        Specifies the OS. Windows 10 or Windows 11.

        .PARAMETER OSBuild
        The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

        .PARAMETER Status
        Specifies if the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

        *** Updated to only allow the creation of "Test" repositories.

        .PARAMETER Category
        Sets the different categories supported by the repository. Multiple values can be passed by separating them with commas.

        "All", "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility"

        If "All" is specified, the all supported categories will be added to the repository. This saves you from having to specify them seperately.

        .PARAMETER HPRepoPath
        Root path when the HP repositories are stored.

        .PARAMETER Force
        If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.

        .INPUTS
        Supports pipeline input by name.

        .OUTPUTS
        Outpus a custom object that contains the details of the new repository.

        'PlatformID'
        'OS'
        'OSBuild'
        'RootPath'
        'Path'
        'Status'

        Example:
        PlatformID : DDDD
        OS         : Win10
        OSBuild    : 22H2
        RootPath   : \\corp.viamonstra.com\CMSource\WorkstationDriverRepository
        Path       : \\corp.viamonstra.com\CMSource\WorkstationDriverRepository\Test\Win10\22H2\DDDD
        Status     : Test

        .EXAMPLE
        New-DM_HPRepository -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS,Driver,Firmware,Software

        .EXAMPLE
        New-DM_HPRepository -PlatformID 8711 -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS

        .EXAMPLE
        New-DM_HPRepository -PlatformID AAAA,BBBB,CCCC,DDDD -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS,Driver,Firmware,Software

        .NOTES
        Requires the HPCMSL to be installed on the system running the command.
    #>
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
    #[ValidateSet("Prod", "Test")]
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [ValidateSet("All", "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility")]
    [string[]]$Category,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin
    {
        $Categories = "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility"
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        # If the force paramter has been passed, disable the confirm option so the script runs without prompts. Same as passing -confirm:$false.
        if ($Force -and -not $Confirm){
            $ConfirmPreference = 'None'
        }

        # [bool]$Global:EnableLogWriteVerbose = $false

        $CurrentLocation = Get-Location

        If ((Helper-GetDM_HPCMSLInstallStatus) -eq $false)
        {
            Write-Warning "HPCMSL is not installed. Please install and try again."
            Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
            break
        }
        elseif (!(Get-Module HPCMSL))
        {
            Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
            Import-Module HPCMSL

            If (!(Get-Module HPCMSL))
            {
                Write-Warning "HPCMSL was not imported."
                Write-CMTraceLog -Message "HPCMSL was not imported." -Component $Component -type 1 -Logfile $LogFile 
                break
            }
        }
    }

    Process{
        # If ((Check-DM_PreReqFilePath -Path $PackageContentPath -TestFile '!README!.txt') -eq $false) { break }
        # If (Test-Path $HPRepoPath)
        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $true)
        {
            # Write-Verbose "Path $RootPath exists."
            Write-CMTraceLog -Message "Path $HPRepoPath exists." -Component $Component -type 1 -Logfile $LogFile

            switch ($OS)
            {
                Win10 {$FullOS = "Microsoft Windows 10"}
                Win11 {$FullOS = "Microsoft Windows 11"}
            }

            $RepositoryObject = @()

            Foreach ($ID in $PlatformID)
            {
                If ((Get-DM_HPPlatformIDIsValid -PlatformID $ID) -eq $true)
                {
                    If (Get-HPDeviceDetails -Platform $ID -oslist | Where-Object {$_.OperatingSystemRelease -eq $OSBuild -and $_.OperatingSystem -eq "$FullOS"})
                    {
                        if($PSCmdlet.ShouldProcess($HPRepoPath,"Create new repository $Status\$os\$OSBuild\$ID at $HPRepoPath"))
                        {
                            # Write-Verbose "PlatformID: $ID."
                            Write-CMTraceLog -Message "PlatformID: $ID." -Component $Component -type 1 -Logfile $LogFile 
                            $PlatformPath = "$HPRepoPath\$Status\$os\$OSBuild\$($ID.ToUpper())\Repository"

                            If (!(Test-Path $PlatformPath))
                            {
                                # Write-Verbose "The path $RootPath\$Status\$os\$OSBuild\$ID does not exist."
                                Write-CMTraceLog -Message "The path $HPRepoPath\$Status\$os\$OSBuild\$($ID.ToUpper()) does not exist." -Component $Component -type 1 -Logfile $LogFile 

                                try
                                {
                                    # Write-Verbose "Creating path $PlatformPath"
                                    Write-CMTraceLog -Message "Creating path $PlatformPath" -Component $Component -type 1 -Logfile $LogFile 
                                    # New-Item -Path $PlatformPath -ItemType Directory -Force -ErrorAction Stop
                                    [void][System.IO.Directory]::CreateDirectory($PlatformPath)
                                }
                                catch
                                {
                                    Write-Warning "Something went wrong creating the path $PlatformPath."
                                    Write-CMTraceLog -Message "Something went wrong creating the path $PlatformPath." -Component $Component -type 1 -Logfile $LogFile 
                                    exit
                                }
                            }

                            If (Get-Module HPCMSL)
                            {
                                Set-Location $PlatformPath
                                If (!((Test-Path "$PlatformPath\.repository") -and (Test-Path "$PlatformPath\.repository\repository.json")))
                                {
                                    # Write-Verbose "Repository does not exist."
                                    Write-CMTraceLog -Message "Repository does not exist." -Component $Component -type 1 -Logfile $LogFile 

                                    try
                                    {
                                        # Write-Verbose "Creating repository for $ID."
                                        Write-CMTraceLog -Message "Creating repository for $($ID.ToUpper())." -Component $Component -type 1 -Logfile $LogFile 
                                        Initialize-Repository -ErrorAction Stop

                                        # Write-Verbose "Configuring repository settings."
                                        Write-CMTraceLog -Message "Configuring repository settings." -Component $Component -type 1 -Logfile $LogFile 
                                        
                                        # When using HP Image Assistant and offline mode, OfflineCacheMode must be set to Enable.
                                        Set-RepositoryConfiguration -setting OfflineCacheMode -Cachevalue Enable -ErrorAction Stop
                                        
                                        # The default setting is to Fail, setting to LogAndContinue allows the sync process to continue.
                                        Set-RepositoryConfiguration -setting OnRemoteFileNotFound -Value LogAndContinue -ErrorAction Stop

                                        # Handle the use of the ALL parameter to update the categories
                                        If ($Category -eq 'All'){$Category = $Categories}
                                        Foreach ($Cat in $Category)
                                        {
                                            Add-RepositoryFilter -Platform $ID -Os $OS -OsVer $OSBuild -Category $Cat -ErrorAction Stop
                                        }
                                        
                                        # Write-Verbose "Copying repository info."
                                        Write-CMTraceLog -Message "Copying repository info." -Component $Component -type 1 -Logfile $LogFile 
                                        Get-HPDeviceDetails -Platform $ID | Out-File "$HPRepoPath\$Status\$os\$OSBuild\$ID\PlatformInfo.txt"
                                        Get-HPDeviceDetails -Platform $ID -OSList | Out-File "$HPRepoPath\$Status\$os\$OSBuild\$ID\OSSupport.txt"
                                        "Platform: $ID`nFull OS: $OS`nOS Version: $OSBuild`nDate created: $((get-date).tostring())`nPerpetrator: $env:USERNAME" | out-file -FilePath "$HPRepoPath\$Status\$os\$OSBuild\$ID\RepositoryInfo.txt"

                                        # Write-Verbose "Repository setup complete."
                                        Write-CMTraceLog -Message "Repository setup complete." -Component $Component -type 1 -Logfile $LogFile 

                                        $RepoPath = join-path $HPRepoPath $Status\$OS\$OSBuild\$ID

                                        $props = [pscustomobject]@{
                                            'PlatformID'=$ID
                                            'OS'=$OS
                                            'OSBuild'=$OSBuild
                                            'RootPath'=$HPRepoPath
                                            'Path'=$RepoPath
                                            'Status'=$Status            
                                        }

                                        $RepositoryObject += $props
                                    }
                                    catch
                                    {
                                        Write-Warning "Something went wrong with repository creation."
                                        Write-CMTraceLog -Message "Something went wrong with repository creation." -Component $Component -type 3 -Logfile $LogFile 
                                        Write-Warning -Message "An error has occured during script execution."
                                        Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile 
                                        # Write-Log -Message "An error has occured during script execution." -Component "Catch" -Type 3
                                        Get-ErrorInformation -incomingError $_
                                    }
                                }
                                else
                                {
                                    Write-Warning "The repository has already been initilized. Nothing to do."
                                    Write-CMTraceLog -Message "The repository has already been initilized. Nothing to do." -Component $Component -type 2 -Logfile $LogFile

                                    $RepositoryObject = Get-DM_HPRepository -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status
                                }
                            }
                        }#should

                        Set-Location $CurrentLocation

                        Write-Output $RepositoryObject
                    }
                    else
                    {
                        Write-Warning "Platform $ID on OS $OS Version $OSBuild not supported. Check yo self fool."
                        Write-CMTraceLog -Message "Platform $ID on OS $OS Version $OSBuild not supported. Check yo self fool." -Component $Component -Type 3 -Logfile $LogFile 
                        Write-Error "Platform $ID on OS $OS Version $OSBuild not supported. Check yo self fool."
                    }
                }
                else
                {
                    Write-CMTraceLog -Message "PlatformID: $ID, is not valid." -Component $Component -type 1 -Logfile $LogFile
                    Write-Warning "The PlatformID: $ID, is not valid. Unable to continue. Exiting."
                    Write-Error "The PlatformID: $ID, is not valid. Unable to continue. Exiting." -ErrorAction Stop
                }
            }
        }
        else
        {
            Write-Warning "Unable to continue. Exiting script."
            Write-CMTraceLog -Message "Unable to continue. Exiting script." -Component $Component -type 3 -Logfile $LogFile 
        }
    }
}
#EndRegion '.\Public\New-DM_HPRepository.ps1' 282
#Region '.\Public\New-DM_HPRepositoryIncludeExcludeConfig.ps1' -1

Function New-DM_HPRepositoryIncludeExcludeConfig ()
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

    begin
    {
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        Write-CMTraceLog -Message "PlatformID: $PlatformID" -Component $Component -type 1 -Logfile $LogFile

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }

        $ReturnValue = $false
    }

    process
    {
        Foreach ($ID in $PlatformID)
        {

$JsonTemplate = @"
{
    "$ID": {
    "$OS": {
    "$OSBuild": {
        "Exclude": "",
        "Include": "",
        "Modified": "",
        "Author": "",
        "Environment": "$Status"
            }
        }
    }
}
"@

            Write-CMTraceLog -Message "Processing $ID." -Component $Component -type 1 -Logfile $LogFile 
            $ConfigFile = "$HPRepoPath\$Status\$OS\$OSBuild\$ID\Repository\.repository\Exclude.json"

            Write-CMTraceLog -Message "Config file: $ConfigFile." -Component $Component -type 1 -Logfile $LogFile 

            If (-Not (Test-Path $ConfigFile))
            {
                if($PSCmdlet.ShouldProcess("Platform $ID, OS: $OS, and OSBuild: $OSBuild", "Create HP repository exclude file."))
                {
                    $Json = $JsonTemplate | ConvertFrom-Json -Verbose
        
                    Write-CMTraceLog -Message "Adding date modified." -Component $Component -type 1 -Logfile $LogFile 
                    ($Json.$ID).$OS.$OSBuild.Modified = Get-Date -Format MM/dd/yyyy

                    Write-CMTraceLog -Message "Adding author." -Component $Component -type 1 -Logfile $LogFile 
                    ($Json.$ID).$OS.$OSBuild.Author =  $(whoami)
        
                    Write-CMTraceLog -Message "Saving default Json to `"$ConfigFile`"." -Component $Component -type 1 -Logfile $LogFile 
                    $Json | ConvertTo-Json -Depth 3 | Format-Json | Set-Content $ConfigFile
        
                    Write-CMTraceLog -Message "Process complete." -Component $Component -type 1 -Logfile $LogFile 
                    $ReturnValue = $true
                }
            }
            else
            {
                Write-Warning "Config file `"$ConfigFile`" already exists."
                Write-CMTraceLog -Message "Config file `"$ConfigFile`" already exists." -Component $Component -type 1 -Logfile $LogFile 
                $ReturnValue = $false
            }
        }
    Return $ReturnValue
    }
}
#EndRegion '.\Public\New-DM_HPRepositoryIncludeExcludeConfig.ps1' 92
#Region '.\Public\Set-DM_CMDriverManagementPackage.ps1' -1

Function Set-DM_CMDriverManagementPackage ()
{
    <#
    .SYNOPSIS
    Used to update some settings on a ConfigMgr package for either a HP driver package or HP repository package.

    .DESCRIPTION
    Used to update some settings on a ConfigMgr package for either a HP driver package or HP repository package.

    .PARAMETER PlatformID
    The platform ID from a HP computer.

    .PARAMETER OS
    Specifies the OS. Windows 10 or Windows 11.

    .PARAMETER OSBuild
    The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

    .PARAMETER Status
    Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

    .PARAMETER Packagetype
    Indicates what type of package needs to be created.
    
    DriverPack = ConfigMgr package containing drivers
    
    DriverRepository = ConfigMgr package containing an HP driver repository.

    .PARAMETER Manufacturer
    Specifies the manufacturer that will be used to set the manufacturer field on the ConfigMgr package

    .PARAMETER UpdateVersion
    New version that will be used as the version of the ConfigMgr package.

    .PARAMETER UpdateLanguage
    New language that will be used as the language of the ConfigMgr package.  

    .PARAMETER UpdatePath
    New path that will be used as the source of the ConfigMgr package.

    .PARAMETER SendToPreferredDistributionPoint
    Used to check the On-Demand box for the ConfigMgr package.

    .PARAMETER CopyToPackageShareOnDistributionPoint
    Used to update the 'Copy the content in this package to a package share on distribution points' box on the 'Data Access' tab for the ConfigMgr package.
    
    .PARAMETER SiteServer
    ConfigMgr site server name.

    .PARAMETER SiteCode
    ConfigMgr site code.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    Outputs the object of the ConfigMgr package found.

    .EXAMPLE
    Set-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverRepository -UpdateStatus Prod

    Changes the status of a DriverManagement package from Test to Prod.

    .EXAMPLE
    Set-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverPack -UpdateVersion '2203-03'

    Updates the version field of the DriverManagement package to the value passed.

    .EXAMPLE
    Set-DM_CMDriverManagementPackage -PlatformID 880d -OS Win10 -OSBuild 22H2 -Status Test -PackageType DriverPack -UpdatePath \\corp.viamonstra.com\shared\CMsource\OSD\Drivers\DriverPacks\HP\HP_DP_880D_Win10-22H2-20232

    Updates the path field of the DriverManagement package to the value passed.

    .NOTES
    Requires the ConfigMgr console to be installed on the system running the command.

    Version: 1.0.0.0 - Initial Build
        # Added ShouldProcess to script.

    #>

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string[]]$PlatformID,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("Win10", "Win11")]
        [string]$OS,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("22H2", "23H2", "24H2")]
        [string]$OSBuild,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("Prod", "Test")]
        [string]$Status,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet("DriverPack", "DriverRepository")]
        [string]$PackageType,
        [string]$Manufacturer = 'HP',
        [string]$UpdateVersion = $($(get-date).ToString("yyyy-MM")),
        [string]$UpdateLanguage,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
        [alias('PkgSourcePath')]
        [string]$UpdatePath,
        [bool]$SendToPreferredDistributionPoint,
        [bool]$CopyToPackageShareOnDistributionPoint,
        <#
        [ValidateSet("Prod", "Test")]
        [ValidateNotNullOrEmpty()]
        [string]$UpdateStatus,
        #>
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteServer,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [string]$SiteCode,
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    try
    {
        $Component = $($myinvocation.mycommand)

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "DriverManagement"

        If ((check-DM_PreReqSoftware -PreReq SCCM) -eq $false) { break }

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $CurrentLocation = Get-Location

        Foreach ($ID in $PlatformID)
        {
            Write-CMTraceLog -Message "Processing PlatformID: $ID." -Component $Component -type 1 -Logfile $LogFile 
            Write-Information -MessageData "Processing PlatformID: $ID." -InformationAction Continue

            Write-CMTraceLog -Message "Getting package info." -Component $Component -type 1 -Logfile $LogFile 
            Write-Information -MessageData "Getting package info." -InformationAction Continue
            $CMDriverManagementPackage = Get-DM_CMDriverManagementPackage -PlatformID $ID -OS $OS -OSBuild $OSBuild -Status $Status -PackageType $PackageType -OutputCMObject

            If ($CMDriverManagementPackage)
            {
                # Write-Verbose "Importing SCCM PS Module"
                Write-CMTraceLog -Message "Importing SCCM PS Module" -Component $Component -type 1 -Logfile $LogFile 

                # Load CM PowerShell Module
                Import-CMPSModule
            
                # Write-Verbose "SiteCode: $SiteCode"
                Write-CMTraceLog -Message "SiteCode: $SiteCode" -Component $Component -type 1 -Logfile $LogFile 
            
                Set-Location "$($SiteCode):\" -Verbose:$false

                Write-CMTraceLog -Message "Package exists." -Component $Component -type 1 -Logfile $LogFile

                if ($PSBoundParameters.ContainsKey('UpdateVersion'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update version to $UpdateVersion on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating version to $UpdateVersion." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating version to $UpdateVersion." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage -Version $UpdateVersion -Verbose:$false)
                    }
                }

                if ($PSBoundParameters.ContainsKey('UpdatePath'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update path to $Path on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating path to $Path." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating path to $Path." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage -Path $Path -Verbose:$false)
                    }
                }

                if ($PSBoundParameters.ContainsKey('UpdateLanguage'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update language to ($Manufacturer $($ID.ToUpper()) $OS $OSBuild) on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating language to ($Manufacturer $($ID.ToUpper()) $OS $OSBuild)." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating language to ($Manufacturer $($ID.ToUpper()) $OS $OSBuild)." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage "$Manufacturer $($ID.ToUpper()) $OS $OSBuild" -Verbose:$false)
                    }
                }

                if ($PSBoundParameters.ContainsKey('SendToPreferredDistributionPoint'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update On-Demand setting to `"$SendToPreferredDistributionPoint`" on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating On-Demand setting to True." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating On-Demand setting to True." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage -SendToPreferredDistributionPoint $SendToPreferredDistributionPoint -Verbose:$false)
                    }
                }

                if ($PSBoundParameters.ContainsKey('CopyToPackageShareOnDistributionPoint'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update `"Copy to share`" setting to `"$CopyToPackageShareOnDistributionPoint`" on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Updating `"Copy to share`" setting to $CopyToPackageShareOnDistributionPoint." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating `"Copy to share`" setting to $CopyToPackageShareOnDistributionPoint." -InformationAction Continue
                        [void](Set-CMPackage -InputObject $CMDriverManagementPackage -CopyToPackageShareOnDistributionPoint $CopyToPackageShareOnDistributionPoint -Verbose:$false)
                    }
                }

<#                 if ($PSBoundParameters.ContainsKey('UpdateStatus'))
                {
                    if($PSCmdlet.ShouldProcess($ID,"Update status from `"$status`" to `"$UpdateStatus`" on $ID, OS $OS, and OSVer $OSBuild" + "?"))
                    {
                        Write-CMTraceLog -Message "Processing a $PackageType package." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Processing a $PackageType package." -InformationAction Continue

                        if ($PackageType -eq "DriverPack")
                        {
                            Write-CMTraceLog -Message "Update package status from $Status to $UpdateStatus." -Component $Component -type 1 -Logfile $LogFile 
                            Write-Information -MessageData "Update package status from $Status to $UpdateStatus." -InformationAction Continue

                            $NewName = $CMDriverManagementPackage.Name -replace "$Status","$UpdateStatus"

                            Write-CMTraceLog -Message "Old name: $($CMDriverManagementPackage.Name) - New Name: $NewName" -Component $Component -type 1 -Logfile $LogFile 

                            If ($NewName)
                            {
                                If ($($CMDriverManagementPackage.Name) -eq $NewName)
                                {
                                    Write-CMTraceLog -Message "Package name already equals `"$NewName`"." -Component $Component -type 2 -Logfile $LogFile 
                                    Write-Information -MessageData "Package name already equals `"$NewName`"." -InformationAction Continue
                                    Write-Warning "Package name already equals `"$NewName`"."
                                }
                                else
                                {
                                    Write-CMTraceLog -Message "Updating package name." -Component $Component -type 1 -Logfile $LogFile 
                                    Set-CMPackage -InputObject $CMDriverManagementPackage -NewName $NewName -Verbose:$false
                                }

                            }
                        }
                        elseif ($PackageType -eq "DriverRepository")
                        {
                            Write-CMTraceLog -Message "The the `"UpdateStatus`" parameter is not supported for DriverRepository packages." -Component $Component -type 2 -Logfile $LogFile 
                            Write-Information -MessageData "The the `"UpdateStatus`" parameter is not supported for DriverRepository packages." -InformationAction Continue
                            Write-Warning "The the `"UpdateStatus`" parameter is not supported for DriverRepository packages."
                        }
                    }
                }
                 #>
            }
        }

        Set-Location $CurrentLocation
    }
    catch
    {
        Write-Warning "Something went wrong: $_"
        Write-CMTraceLog -Message "Something went wrong: $_" -Component $Component -type 2
        Write-Warning -Message "An error has occured during script execution."
        Write-CMTraceLog -Message "An error has occured during script execution." -Component $Component -type 3 -Logfile $LogFile 
        Get-ErrorInformation -incomingError $_
        Set-Location $CurrentLocation
    }

}
#EndRegion '.\Public\Set-DM_CMDriverManagementPackage.ps1' 263
#Region '.\Public\Set-DM_HPRepositoryCategory.ps1' -1

Function Set-DM_HPRepositoryCategory ()
{
    <#
    .SYNOPSIS
    Updates an HP driver repository for a PlatformID, OS, and OS Build with additional category support.

    .DESCRIPTION
    Updates an HP driver repository for a PlatformID, OS, and OS Build with additional category support.

    .PARAMETER PlatformID
    The platform ID from a HP computer.

    If you need to update the categories for multiple repositories, you can pass multiple Platform IDs at a time.

    .PARAMETER OS
    Specifies the OS. Windows 10 or Windows 11.

    .PARAMETER OSBuild
    The Windows build designation in the form of YYH[1/2]. Examples, 20H2, 21H1, 22H2.

    .PARAMETER Status
    Specifies of the repository is Test or Prod. This allows two separate repositories for each Platform, OS and Build.

    .PARAMETER Category
    Sets the different categories supported by the repository. Multiple values can be passed by separating them with commas.

    "All", "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility"

    If "All" is specified, the all supported categories will be added to the repository. This saves you from having to specify them seperately.

    .PARAMETER HPRepoPath
    Root path when the HP repositories are stored.

    .INPUTS
    Supports pipeline input by name.

    .OUTPUTS
    No output.

    .EXAMPLE
    Set-DM_HPRepositoryCategory -PlatformID 880D -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS,Driver,Firmware,Software

    .EXAMPLE
    Set-DM_HPRepositoryCategory -PlatformID aaaa -OS Win10 -OSBuild 22H2 -Status Test -Category Driver

    .EXAMPLE
    Set-DM_HPRepositoryCategory -PlatformID AAAA,BBBB,CCCC,DDDD -OS Win10 -OSBuild 22H2 -Status Test -Category BIOS,Driver,Firmware,Software

    When passing multiple PlatformIDs, the OS, OSBuild, and Status must be the same.

    .NOTES
    Requires the HPCMSL to be installed on the system running the command.
    #>
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern("^[a-fA-F0-9]{4}$")]
    [alias('Platform')]
    [string[]]$PlatformID,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Win10", "Win11")]
    [string]$OS,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("22H2", "23H2", "24H2")]
    [string]$OSBuild,
    [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("Test")]
    [string]$Status = "Test",
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidateSet("All", "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility")]
    [string[]]$Category,
    [Parameter(Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    begin{
        $Categories = "BIOS", "Driver", "Firmware", "Software", "OS", "UWPPack", "Dock", "Utility"
        $Component = $($myinvocation.mycommand)

        Write-CMTraceLog -Message "------ $Component ------" -Component $Component -type 1 -Logfile $LogFile 

        Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Invoke-ModuleVersionCheck -Module "DriverManagement"
    
        # [bool]$Global:EnableLogWriteVerbose = $false
        
        $CurrentLocation = Get-Location

        <# If (!(Get-Module HPCMSL))
        {
            #Write-Verbose "Importing HPCMSL module."
            Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
            Import-Module HPCMSL
        } #>
        If ((Helper-GetDM_HPCMSLInstallStatus) -eq $false)
        {
            Write-Warning "HPCMSL is not installed. Please install and try again."
            Write-CMTraceLog -Message "HPCMSL is not installed. Please install and try again." -Component $Component -type 1 -Logfile $LogFile 
            break
        }
        elseif (!(Get-Module HPCMSL))
        {
            Write-CMTraceLog -Message "Importing HPCMSL module." -Component $Component -type 1 -Logfile $LogFile 
            Import-Module HPCMSL

            If (!(Get-Module HPCMSL))
            {
                Write-Warning "HPCMSL was not imported."
                Write-CMTraceLog -Message "HPCMSL was not imported." -Component $Component -type 1 -Logfile $LogFile 
                break
            }
        }
    }

    Process
    {
        # If (Test-Path $HPRepoPath)
        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $true)
        {
            #Write-Verbose "Path $Path exists."
            Write-CMTraceLog -Message "Path $HPRepoPath exists." -Component $Component -type 1 -Logfile $LogFile 

            Foreach ($ID in $PlatformID)
            {

                # Write-Verbose "PlatformID: $ID."
                Write-CMTraceLog -Message "PlatformID: $ID." -Component $Component -type 1 -Logfile $LogFile 
                Write-Information -MessageData "PlatformID: $ID." -InformationAction Continue

                $PlatformPath = "$HPRepoPath\$Status\$os\$OSBuild\$ID\Repository"

                If (Get-Module HPCMSL)
                {
                    Set-Location $PlatformPath
                    If ((Test-Path "$PlatformPath\.repository") -and (Test-Path "$PlatformPath\.repository\repository.json"))
                    {
                        # Write-Verbose "Updating $ID repository settings."
                        Write-CMTraceLog -Message "Updating $ID repository settings." -Component $Component -type 1 -Logfile $LogFile 
                        Write-Information -MessageData "Updating $ID repository settings." -InformationAction Continue
                        try
                        {
                            if($PSCmdlet.ShouldProcess($ID,"Update category on repository $PlatformPath"))
                            {
                                # Write-Verbose "Configuring required repository settings."
                                Write-CMTraceLog -Message "Configuring required repository settings." -Component $Component -type 1 -Logfile $LogFile 
                                Write-Information -MessageData "Configuring required repository settings." -InformationAction Continue
                                Set-RepositoryConfiguration -setting OfflineCacheMode -Cachevalue Enable -ErrorAction Stop

                                If ($Category -eq 'All'){$Category = $Categories}
                                Foreach ($Cat in $Category)
                                {
                                    #Write-Verbose "Adding category $Cat to repository."
                                    Write-CMTraceLog -Message "Adding category `"$Cat`" to repository." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Adding category `"$Cat`" to repository." -InformationAction Continue
                                    Add-RepositoryFilter -Platform $ID -Os $OS -OsVer $OSBuild -Category $Cat -ErrorAction Stop
                                    Write-CMTraceLog -Message "Category `"$Cat`" has been added." -Component $Component -type 1 -Logfile $LogFile 
                                    Write-Information -MessageData "Category `"$Cat`" has been added." -InformationAction Continue
                                }
                            }
                        }
                        catch
                        {
                            Write-Warning "Something went wrong with repository update."
                            Write-CMTraceLog -Message "Something went wrong with repository update." -Component $Component -type 2 -Logfile $LogFile 
                        }
                    }
                    else
                    {
                        Write-Warning "Repository does not exist. Please Initialize the repository."
                        Write-CMTraceLog -Message "Repository does not exist. Please Initialize the repository." -Component $Component -type 3 -Logfile $LogFile 
                    }
                }

                Set-Location $CurrentLocation
            }
        }
    }
}
#EndRegion '.\Public\Set-DM_HPRepositoryCategory.ps1' 181
#Region '.\Public\Update-DriverManagement.ps1' -1

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
#EndRegion '.\Public\Update-DriverManagement.ps1' 36
