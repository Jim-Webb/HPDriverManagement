function Get-JsonContent ($File)
{
    If (Test-Path $File)
    {
        try{
            $Config = Get-Content $File | ConvertFrom-Json
            return $Config
        }
        catch
        {
            Write-Warning "An error occured reading the Json file."
        }
    }
    else
    {
        Write-Warning "File $File not found."
    }
}