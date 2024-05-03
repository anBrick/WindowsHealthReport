<#	
	.DESCRIPTION
		safe update module
  		new version
    		checking source at GIT, local folder, domain logon folder
#>

#update itself from defined location
$ScriptDistributionPoints = @('c:\report\',$($ENV:LOGONSERVER + "\NETLOGON\"),"https://raw.githubusercontent.com/anBrick/WindowsHealthReport/main/") ## path for automatic upgrade from

foreach ($ScriptDistributionPoint in $ScriptDistributionPoints){
if ($ScriptDistributionPoint -match "^(https?:\/\/)") {
	$UpdatesFile = $ENV:TEMP + '\' + $MyInvocation.myCommand.name
	try {
		Invoke-WebRequest -Uri $($ScriptDistributionPoint + $MyInvocation.myCommand.name) -UseDefaultCredentials -OutFile $UpdatesFile
		Unblock-File $UpdatesFile
		Copy-Item $UpdatesFile -Destination $($MyInvocation.MyCommand.Path) -Force;
	}
	catch {Write-Error "ERROR: Unable to install updates from $ScriptDistributionPoint, running as is."}
}
else {
	if ((Test-Path -PathType Leaf -LiteralPath ($ScriptDistributionPoint + $MyInvocation.myCommand.name)) -and ((Get-Item ($ScriptDistributionPoint + $MyInvocation.myCommand.name)).LastWriteTime.ticks -gt ((Get-Item $MyInvocation.MyCommand.Path).LastWriteTime.ticks)))
	{
		Write-Host ('The Distribution point has the newest version of the script. Starting Upgrade itself') -BackgroundColor DarkYellow -ForegroundColor Black
		try { Copy-Item ($ScriptDistributionPoint + $MyInvocation.myCommand.name) -Destination $($MyInvocation.MyCommand.Path) -Force; }
		catch { Write-Error "ERROR: Impossible to upgrade the script from the $ScriptDistributionPoint, leaving it as is." }
	}
}
}
