<#
https://raw.githubusercontent.com/anBrick/WindowsHealthReport/refs/heads/main/Install-PSScriptFromURI.ps1
powershell -c "irm https://tinyurl.com/anbrick | iex"
#>
#Variables
$Script2Install = @(
    @{Name = "Alert-PrivUserLogon.ps1"; Params = "-Install -emailTo BETA@ARION.cz"},
    @{Name = "Report-PAChanges.ps1"; Params = "-Install -emailTo BETA@ARION.cz"}
)
$BaseURI = "https://raw.githubusercontent.com/anBrick/WindowsHealthReport/main/"

# Define Write-Status function
function Write-Status {
    param (
        [Parameter]
        [string]$Status = 'Info',
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    switch ($Status) {
        "Warning" { Write-Host "WARNING: $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "ERROR: $Message" -ForegroundColor Red }
        default   { Write-Host "INFO: $Message" -ForegroundColor Green }
    }
}

# Runtime
# Check high privileged execution and exit when not running as admin
$IsAdmin = [Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -ne $TRUE) {
    throw "The Script needs to run with the highest privileges! Otherwise, we can't continue :("
}

$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

foreach ($script in $Script2Install) {
    $LocalFileCopy = Join-Path $ENV:TEMP $script.Name
    try {
    	  Write-Status -message "Downloading $script.Name"
        Invoke-WebRequest -Uri $($BaseURI + $script.Name) -UseDefaultCredentials -OutFile $LocalFileCopy
        Write-Status -message "Unblocking $LocalFileCopy"
        Unblock-File $LocalFileCopy
        Write-Status -message "Copy $LocalFileCopy to $ScriptPath"
        Copy-Item $LocalFileCopy -Destination $ScriptPath -Force
        Remove-Item $LocalFileCopy -ErrorAction SilentlyContinue
    }
    catch {
        Write-Status -Status Error -Message "Unable to Download from $BaseURI. Skipped $($script.Name)"
    }
    Write-Status -message "Prepare to run $script.Name"
    $ScriptToRun = Join-Path $ScriptPath $script.Name
    Write-Status -message "Invoke $script.Name"
    Invoke-Expression "& `"$ScriptToRun`" $($script.Params)"
}
#EndofScript