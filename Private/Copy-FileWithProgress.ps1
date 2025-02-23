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
        # /NC - Hides output the file class “Text Tags” (Go here for more information: https://www.uvm.edu/~gcd/2015/04/robocopy-file-classes/)
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