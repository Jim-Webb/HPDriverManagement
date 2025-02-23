function Get-DM_SystemInformation ()
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$Computer = $env:COMPUTERNAME,
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:ProgramData\Logs\$($myinvocation.mycommand).log"
    )

    # Collection system info

    $Component = $($myinvocation.mycommand)

    $PSDefaultParameterValues = $Global:PSDefaultParameterValues

    $InformationPreference = 'Continue'

    $Result = Test-DM_ComputerConnection -ComputerName $Computer

    If ($Result)
    {
        # Write-Output "Computer connection succedded."
        Write-CMTraceLog -Message "Computer connection succedded." -Component $Component -type 1 -Logfile $LogFile
        Write-Information -MessageData "Computer connection succedded." -InformationAction Continue

        # Write-CMTraceLog -Message "Checking module version." -Component $Component -type 1 -Logfile $LogFile 
        # Write-Information -MessageData "Checking module version." -InformationAction Continue
        # Invoke-ModuleVersionCheck -Module "HPDriverManagement"

        If ($env:COMPUTERNAME -ne $Computer)
        {
            Write-CMTraceLog -Message "Opening session on $Computer." -Component $Component -type 1 -Logfile $LogFile
            Write-Information -MessageData "Opening session on $Computer." -InformationAction Continue
            $Session = New-PSSession -ComputerName $Computer
    
            $SCriptBlock = {
        
                $PlatformID = Get-WmiObject win32_baseboard | Select-Object -ExpandProperty Product
                $Manufacturer = Get-wmiobject win32_computersystem | Select-Object -ExpandProperty Manufacturer
                $Model = Get-wmiobject win32_computersystem | Select-Object -ExpandProperty Model
                $Serial = Get-wmiobject win32_bios | Select-Object -ExpandProperty SerialNumber
                $Caption = Get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Caption
                $OSVersion = Get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Version
                
                $props = [pscustomobject]@{
                    'PlatformID'=$PlatformID
                    'Manufacturer'=$Manufacturer
                    'Model'=$Model
                    'SerialNumber'=$Serial
                    'OS'=$Caption
                    'OS Version'=$OSVersion           
                }
            }
            
            return, $props;
        }
        else
        {
            Write-CMTraceLog -Message "Connecting to local computer: $Computer." -Component $Component -type 1 -Logfile $LogFile
            Write-Information -MessageData "Connecting to local computer: $Computer." -InformationAction Continue
        
            $PlatformID = Get-WmiObject win32_baseboard | Select-Object -ExpandProperty Product
            $Manufacturer = Get-wmiobject win32_computersystem | Select-Object -ExpandProperty Manufacturer
            $Model = Get-wmiobject win32_computersystem | Select-Object -ExpandProperty Model
            $Serial = Get-wmiobject win32_bios | Select-Object -ExpandProperty SerialNumber
            $Caption = Get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Caption
            $OSVersion = Get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Version
            
            $props = [pscustomobject]@{
                'PlatformID'=$PlatformID
                'Manufacturer'=$Manufacturer
                'Model'=$Model
                'SerialNumber'=$Serial
                'OS'=$Caption
                'OS Version'=$OSVersion           
            }
        
            # Add-Member -InputObject $obj -MemberType NoteProperty -Name "Session" -Value "Current"
            # $Output = $obj
    
            return, $props;
        }
    
        Write-CMTraceLog -Message "Running scriptblock on $Computer." -Component $Component -type 1 -Logfile $LogFile
        Write-Information -MessageData "Running scriptblock on $Computer." -InformationAction Continue
        $Result = Invoke-Command -Session $Session -ScriptBlock $SCriptBlock

        Write-CMTraceLog -Message "$Result." -Component $Component -type 1 -Logfile $LogFile 

        Write-CMTraceLog -Message "Removing session on $Computer." -Component $Component -type 1 -Logfile $LogFile
        Write-Information -MessageData "Removing session on $Computer." -InformationAction Continue
        Remove-PSSession -Session $Session

        return, $Result;
    }
    else
    {
        Write-Warning "Computer connection did not succedded."
        Write-CMTraceLog -Message "Computer connection did not succedded." -Component $Component -type 1 -Logfile $LogFile 
    }
}