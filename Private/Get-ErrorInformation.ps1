function Get-ErrorInformation() {
    [cmdletbinding()]
    param (
        $incomingError,
        $Component
    )
    
    if (!($Component))
    {
        $Component = 'Get-ErrorInformation'
    }

    if ($incomingError -and (($incomingError | Get-Member | Select-Object -ExpandProperty TypeName -Unique) -eq 'System.Management.Automation.ErrorRecord')) {
        Write-Host `n"Error information:"`n
        Write-CMTraceLog -Message "Error information:" -Component $Component -Type 1
        Write-Host `t"Exception type for catch: [$($IncomingError.Exception | Get-Member | Select-Object -ExpandProperty TypeName -Unique)]"`n
        Write-CMTraceLog -Message "Exception type for catch: [$($IncomingError.Exception | Get-Member | Select-Object -ExpandProperty TypeName -Unique)]" -Component $Component -Type 1
        
        if ($incomingError.InvocationInfo.Line) {
            Write-Host `t"Command                 : [$($incomingError.InvocationInfo.Line.Trim())]"
            Write-CMTraceLog -Message "Command: [$($incomingError.InvocationInfo.Line.Trim())]" -Component $Component -Type 1
        }
        else {
            Write-Host `t"Unable to get command information! Multiple catch blocks can do this :("`n
            Write-CMTraceLog -Message "Unable to get command information! Multiple catch blocks can do this :(" -Component $Component -Type 1
        }
        
        Write-Host `t"Exception               : [$($incomingError.Exception.Message)]"`n
        Write-CMTraceLog -Message "Exception: [$($incomingError.Exception.Message)]" -Component $Component -Type 1
        Write-Host `t"Target Object           : [$($incomingError.TargetObject)]"`n
        Write-CMTraceLog -Message "Target Object: [$($incomingError.TargetObject)]" -Component $Component -Type 1
    }
    Else {
        Write-Host "Please include a valid error record when using this function!" -ForegroundColor Red -BackgroundColor DarkBlue
        Write-CMTraceLog -Message "Please include a valid error record when using this function!" -Component $Component -Type 1
    }
}