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