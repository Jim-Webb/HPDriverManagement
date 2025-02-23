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