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