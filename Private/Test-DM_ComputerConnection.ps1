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