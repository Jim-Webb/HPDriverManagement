Function Add-DM_HPRepositoryIncludeExclude ()
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
    [ValidateSet("Include", "Exclude")]
    [string[]]$Action,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
    [string[]]$App,
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName)]
    [string]$HPRepoPath,
    [Switch]$Force,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    Begin
    {
        $Component = $($myinvocation.mycommand)

        $PSDefaultParameterValues = $Global:PSDefaultParameterValues

        $ReturnValue = $false

        If ((Invoke-PathPermissionsCheck -Path $HPRepoPath) -eq $false) { break }
    }

    Process
    {
        foreach ($ID in $PlatformID)
        {
            $ChildPath = "$Status\$OS\$OSBuild\$ID\Repository\.repository\Exclude.json"
    
            Write-CMTraceLog -Message "Child path: $ChildPath" -Component $Component -type 1 -Logfile $LogFile 
        
            # Use Join-Path since $RootPath can be passed and may or may not contain a trailing \.
            $FullFilePath = Join-Path $HPRepoPath -childpath $ChildPath
        
            Write-CMTraceLog -Message "Full path: $FullFilePath" -Component $Component -type 1 -Logfile $LogFile 
        
            $ConfigFile = $FullFilePath
        
            Write-CMTraceLog -Message "Config file: $ConfigFile" -Component $Component -type 1 -Logfile $LogFile 
        
            Write-CMTraceLog -Message "App(s) to exclude: $App" -Component $Component -type 1 -Logfile $LogFile 

            # The config file needs to exist before we can continue.
            If (Test-Path $ConfigFile)
            {
                if($PSCmdlet.ShouldProcess("Platform $ID, OS: $OS, and OSBuild: $OSBuild.", "Update HP repository include/exclude file"))
                {
                    $Json = Get-Content $ConfigFile | ConvertFrom-Json
            
                    If ($Json)
                    {
                        $Exclude = @()
                        $Apps = @()
                        If ($App)
                        {
                            foreach ($A in $App)
                            {
                                Write-CMTraceLog -Message "Adding app $A to list." -Component $Component -type 1 -Logfile $LogFile 
                                $Apps += $A
                            }
            
                            Write-CMTraceLog -Message "Current list: $Apps." -Component $Component -type 1 -Logfile $LogFile

                            # The $Action variable represents either to Include or Exclude an application from the driver repository.
            
                            If (($Json.$ID).$OS.$OSBuild.$Action -eq "")
                            {
                                Write-CMTraceLog -Message "$Action empty, adding first entry." -Component $Component -type 1 -Logfile $LogFile 
                                
                                Write-CMTraceLog -Message "Current ($Action): $(($Json.$ID).$OS.$OSBuild.$Action)." -Component $Component -type 1 -Logfile $LogFile 
            
                                if ($Apps.count -eq 1)
                                {
                                    ($Json.$ID).$OS.$OSBuild.$Action = $Apps
                                }
                                else
                                {
                                    ($Json.$ID).$OS.$OSBuild.$Action = $Apps -join ","
                                }
                                Write-CMTraceLog -Message "New ($Action): $(($Json.$ID).$OS.$OSBuild.$Action)." -Component $Component -type 1 -Logfile $LogFile 
            
                            }
                            Else
                            {
                                Write-CMTraceLog -Message "$Action has entries." -Component $Component -type 1 -Logfile $LogFile 
                                $Exclude = (($Json.$ID).$OS.$OSBuild.$Action).Split(",")
                    
                                If ($Exclude -contains $Apps)
                                {
                                    Write-Warning "Application $Apps is already in the $action section.."
                                    $ReturnValue = $false
                                }
                                else
                                {
                                    $Exclude = $Exclude += $Apps
                                    ($Json.$ID).$OS.$OSBuild.$Action = $Exclude -join ","
                                }
                            }
                            
                            Write-CMTraceLog -Message "Saving changes to config file." -Component $Component -type 1 -Logfile $LogFile 
                            
                            Write-CMTraceLog -Message "Updating date modified to $(Get-Date -Format MM/dd/yyyy)." -Component $Component -type 1 -Logfile $LogFile 
                            ($Json.$ID).$OS.$OSBuild.Modified = Get-Date -Format MM/dd/yyyy
            
                            Write-CMTraceLog -Message "Updating author to $(whoami)." -Component $Component -type 1 -Logfile $LogFile 
                            ($Json.$ID).$OS.$OSBuild.Author =  $(whoami)
            
                            Write-CMTraceLog -Message "Exporting json file." -Component $Component -type 1 -Logfile $LogFile 
                            $Json | ConvertTo-Json -Depth 3 | Format-Json | Set-Content $ConfigFile
                            
                            #Save-JsonContent -PlatformID $PlatformID -OS $OS -OSBuild $OSBuild -Status $Status -Json $Json -File $ConfigFile
            
                            $ReturnValue = $true
                        }
                    }
                }
            }
            else
            {
                Write-Warning "Config file `"$ConfigFile`" doesn't exist."
                Write-CMTraceLog -Message "Config file `"$ConfigFile`" doesn't exist." -Component $Component -type 1 -Logfile $LogFile 
                return $false
            }
        }
        return $ReturnValue
    }
}