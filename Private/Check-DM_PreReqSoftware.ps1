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