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