Function New-DM_HPRepositoryGlobalIncludeExcludeConfig ()
{

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact = 'High')]
    Param(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName)]
    [ValidateSet("Test","Prod")]
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

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }

        $ReturnValue = $false
    }

    process
    {

$JsonTemplate = @"
{
    "Win10": {
        "Exclude": "HP Smart Health,HP Privacy Settings,HP Support Assistant,HP Sure Run,HP Sure Recover,HP Sure Recover agent,Cloud Recovery Client,Poly Lens,myHP with HP Presence,HP Collaboration Keyboard Software,HP Wolf Security Console,HP Wolf Security for Business",
        "Modified": "04/21/2023",
        "Author": "ViaMonstra\\Administrator"
    },
    "Win11": {
        "Exclude": "HP Smart Health,HP Privacy Settings,HP Support Assistant,HP Sure Run,HP Sure Recover,HP Sure Recover agent,Cloud Recovery Client,Poly Lens,myHP with HP Presence,HP Collaboration Keyboard Software,HP Wolf Security Console,HP Wolf Security for Business",
        "Modified": "04/21/2023",
        "Author": "ViaMonstra\\Administrator"
    }
}
"@

        Write-CMTraceLog -Message "Checking for global include\exclude config file." -Component $Component -type 1 -Logfile $LogFile 
        $ConfigFile = "$HPRepoPath\$Status\GlobalIncludeExclude.json"

        Write-CMTraceLog -Message "Config file: $ConfigFile." -Component $Component -type 1 -Logfile $LogFile 

        $SupportedOS = @('Win10','Win11')

        If (-Not (Test-Path $ConfigFile))
        {
            if($PSCmdlet.ShouldProcess("$Status repo folder?", "Create HP global repository include\exclude file."))
            {
                $Json = $JsonTemplate | ConvertFrom-Json -Verbose

                Foreach ($OS in $SupportedOS)
                {
                    Write-CMTraceLog -Message "Adding date modified." -Component $Component -type 1 -Logfile $LogFile 
                    ($Json.$OS).Modified = Get-Date -Format MM/dd/yyyy

                    Write-CMTraceLog -Message "Adding author." -Component $Component -type 1 -Logfile $LogFile 
                    ($Json.$OS).Author = $(whoami)
        
                    Write-CMTraceLog -Message "Saving default Json to `"$ConfigFile`"." -Component $Component -type 1 -Logfile $LogFile 
                    $Json | ConvertTo-Json -Depth 3 | Format-Json | Set-Content $ConfigFile
        
                    Write-CMTraceLog -Message "Process complete." -Component $Component -type 1 -Logfile $LogFile 
                    $ReturnValue = $true
                }
            }
        }
        else
        {
            Write-Warning "Config file `"$ConfigFile`" already exists."
            Write-CMTraceLog -Message "Config file `"$ConfigFile`" already exists." -Component $Component -type 1 -Logfile $LogFile 
            $ReturnValue = $false
        }
        
        Return $ReturnValue
    }
}