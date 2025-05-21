<#	
	.DESCRIPTION
		safe update module
  		new version
    		checking source at GIT, local folder, domain logon folder
#>

function Write-Status {
Param( 
	[Parameter(Mandatory=$true)]
	[string]$Message,
	[Parameter(Mandatory=$false)]
	[ValidateSet("Information", "Warning", "Error")]
	$Status = 'Information'
)
	switch ($Status) {
		'Information' {Write-host $Message}
		'Warning' {Write-host $Message -foregroundColor yellow}
		'Error' {Write-Error $Message}
	}
	# Log source for Application Event Log
	$source = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.PSCommandPath)
	if ([string]::IsNullOrEmpty($source)) {$source = [IO.Path]::GetFileNameWithoutExtension($PSCommandPath)}
	if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {[System.Diagnostics.EventLog]::CreateEventSource($source, "Application")} #register EvtLog Source
	Write-EventLog -LogName Application -Source $source -EntryType $Status -EventID 34343 -Message $(( '{0} Runtime message:: {1}') -f $MyInvocation.myCommand.name,$Message) -ea 0 
}
#update itself from defined location
$ScriptDistributionPoints = @('c:\report\',$($ENV:LOGONSERVER + "\NETLOGON\"),"https://raw.githubusercontent.com/anBrick/WindowsHealthReport/main/") ## path for automatic upgrade from

foreach ($ScriptDistributionPoint in $ScriptDistributionPoints){
if ($ScriptDistributionPoint -match "^(https?:\/\/)") {
	$UpdatesFile = $ENV:TEMP + '\' + $MyInvocation.myCommand.name
	try {Invoke-WebRequest -Uri $($ScriptDistributionPoint + $MyInvocation.myCommand.name) -UseDefaultCredentials -OutFile $UpdatesFile
		Write-Status -Status Information -Message "New version downloaded from $($ScriptDistributionPoint + $MyInvocation.myCommand.name), begin updating itself."
	}
	catch {Write-Status -Status Error -Message "ERROR $_ : Unable to downlaod updates from $($ScriptDistributionPoint + $MyInvocation.myCommand.name), running as local version."}
	Unblock-File $UpdatesFile
	try {Copy-Item $UpdatesFile -Destination $($MyInvocation.MyCommand.Path) -Force;
		Write-Status -Status Information -Message "New version installed to $($MyInvocation.MyCommand.Path)."
	}
	catch {Write-Status -Status Error -Message "ERROR $_ : Unable to uplaod updates to $($MyInvocation.MyCommand.Path), update failed."}
	Remove-Item $UpdatesFile -ea 0
}
else {
	if ((Test-Path -PathType Leaf -LiteralPath ($ScriptDistributionPoint + $MyInvocation.myCommand.name)) -and ((Get-Item ($ScriptDistributionPoint + $MyInvocation.myCommand.name)).LastWriteTime.ticks -gt ((Get-Item $MyInvocation.MyCommand.Path).LastWriteTime.ticks)))
	{
		Write-Status -Status Information -Message ('The Distribution point has the newest version of the script. Starting Upgrade itself')
		try { Copy-Item ($ScriptDistributionPoint + $MyInvocation.myCommand.name) -Destination $($MyInvocation.MyCommand.Path) -Force; }
		catch { Write-Status -Status Error -Message  "ERROR $_ : Impossible to upgrade the script from the $ScriptDistributionPoint, leaving it as is." }
	}
}
}#END SelfUpdate