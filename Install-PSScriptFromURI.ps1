<#
https://raw.githubusercontent.com/anBrick/WindowsHealthReport/refs/heads/main/Install-PSScriptFromURI.ps1
probably antivirus blocking
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $scriptUrl = "https://tinyurl.com/anbrick"; IEX (Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing).Content
if A/V block use this:
Invoke-WebRequest -Uri 'https://tinyurl.com/anbrick' -OutFile '.\Install-PSScriptFromURI.ps1'
& '.\Install-PSScriptFromURI.ps1'
#>
#Variables
$Script2Install = @(
    @{Name = "Alert-PrivUserLogon.ps1"; Params = "-Install -emailTo BETA@ARION.cz"},
    @{Name = "Report-PAChanges.ps1"; Params = "-Install -emailTo BETA@ARION.cz"}
)
$BaseURI = "https://raw.githubusercontent.com/anBrick/WindowsHealthReport/main/"

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
    	  Write-Host "Downloading $($script.Name)"
        Invoke-WebRequest -Uri $($BaseURI + $script.Name) -UseDefaultCredentials -OutFile $LocalFileCopy
        Write-Host "Unblocking $LocalFileCopy"
        Unblock-File $LocalFileCopy
        Write-Host "Copy $LocalFileCopy to $ScriptPath"
        Copy-Item $LocalFileCopy -Destination $ScriptPath -Force
        Remove-Item $LocalFileCopy -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Unable to Download from $BaseURI. Skipped $($script.Name)"
    }
    Write-Host "Prepare to run $($script.Name)"
    $ScriptToRun = Join-Path $ScriptPath $script.Name
    Write-Host "Invoke $ScriptToRun"
    Invoke-Expression "& `"$ScriptToRun`" $($script.Params)"
}
#EndofScript