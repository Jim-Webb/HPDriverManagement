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
