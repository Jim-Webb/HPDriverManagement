[CmdletBinding()]
    Param (
        [switch]$BuildModule,
        [array]$CopyFile,
        [string]$ChangeLog,
        [switch]$SignModule,
        [switch]$PublishModule
    )

Write-Output "Working path: $PSScriptRoot"

# Split-Path -Parent $myInvocation.MyCommand.Definition

# Split-Path -Parent $MyInvocation.MyCommand.Path

$ParentDir = ($PSScriptRoot| Get-Item).BaseName

$F = Import-PowerShellDataFile -Path ".\$ParentDir.psd1"

Write-Output "Module version: $($f.ModuleVersion)"

If ($BuildModule)
{
    build -OutputDirectory "$PSScriptRoot\Output"
}

If ($CopyFile)
{
    Foreach ($File in $CopyFile)
    {
        Write-Output "Copying $file to $PSScriptRoot\Output\$ParentDir\$($f.ModuleVersion)"
        Copy-Item -Path "$PSScriptRoot\$File" -Destination "$PSScriptRoot\Output\$ParentDir\$($f.ModuleVersion)" -Force
    }
}

If ($ChangeLog)
{
    If (Test-Path "$PSScriptRoot\$ChangeLog")
    {
        Write-Output "Adding release notes to $ParentDir.psd1"
        Update-Metadata "$PSScriptRoot\Output\$ParentDir\$($f.ModuleVersion)\$ParentDir.psd1" -Property ReleaseNotes -Value (Get-Content "$PSScriptRoot\$ChangeLog" -Raw)
    }
}

If ($SignModule)
{
    Write-Output "Signing module."
    
    $Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert

    If ($Cert)
    {
        If ($cert.count -eq 1)
        {
            $Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
        }
        elseif ($cert.count -gt 1)
        {
            $GVResult = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | select Thumbprint,Subject,NotAfter,FriendlyName | Out-GridView -Title "Select the correct certificate." -PassThru
        
            $Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object {$_.Thumbprint -eq $($GVResult.Thumbprint)}
        }
    }
    else
    {
        Write-warning "A signing certificate could not be found."
    }

    # $Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object {$_.FriendlyName -eq 'Current'}

    Set-AuthenticodeSignature -FilePath "$PSScriptRoot\Output\$ParentDir\$($f.ModuleVersion)\$ParentDir.psd1" -Certificate $cert -TimestampServer http://timestamp.digicert.com
    
    Set-AuthenticodeSignature -FilePath "$PSScriptRoot\Output\$ParentDir\$($f.ModuleVersion)\$ParentDir.psm1" -Certificate $cert -TimestampServer http://timestamp.digicert.com
}

If ($PublishModule)
{
    Write-Output "Publishing module $ParentDir version $($f.ModuleVersion) to repository."
    Publish-Module -Path "$PSScriptRoot\Output\$ParentDir\$($f.ModuleVersion)" -NuGetApiKey *key* -Repository RepoName
}