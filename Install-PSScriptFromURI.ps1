#Variables
$Script2Install = @(
    @{Name = "Alert-PrivUserLogon.ps1"; Params = "-Install -emailTo BETA@ARION.cz"},
    @{Name = "Report-PAChanges.ps1"; Params = "-Install -emailTo BETA@ARION.cz"}
)
$BaseURI = "https://raw.githubusercontent.com/anBrick/WindowsHealthReport/main/"

# Define Write-Status function
function Write-Status {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Status,
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    switch ($Status) {
        "Info"    { Write-Host "INFO: $Message" -ForegroundColor Green }
        "Warning" { Write-Host "WARNING: $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "ERROR: $Message" -ForegroundColor Red }
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
        Invoke-WebRequest -Uri $($BaseURI + $script.Name) -UseDefaultCredentials -OutFile $LocalFileCopy
        Unblock-File $LocalFileCopy
        Copy-Item $LocalFileCopy -Destination $ScriptPath -Force
        Remove-Item $LocalFileCopy -ErrorAction SilentlyContinue
    }
    catch {
        Write-Status -Status Error -Message "Unable to Download from $BaseURI. Skipped $($script.Name)"
    }
    
    $ScriptToRun = Join-Path $ScriptPath $script.Name
    Invoke-Expression "& `"$ScriptToRun`" $($script.Params)"
}
#EndofScript