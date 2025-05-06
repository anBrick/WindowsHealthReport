#Purpose: alert if a privileged user logigged in (RDP primary) Create a task run as _local_ system. 
Param( 
	[Parameter(Mandatory=$false)]
	[switch]$Install, # set to install to current host (copy to %systemroot%, create system task to run on eany user's logon)
	# Setup email alert parameters
	[Parameter(Mandatory=$false)]
	[string]$emailTo = "BETA@ARION.cz",
	[Parameter(Mandatory=$false)]
	[string]$emailFrom = (Get-WmiObject win32_computersystem).DNSHostName+"@" + 'report.' + (Get-WmiObject win32_computersystem).Domain,
	[Parameter(Mandatory=$false)]
	[string]$smtpServer = 'localhost', 
	[Parameter(Mandatory=$false)]
	[int]$smtpServerPort = 25,
	[Parameter(Mandatory=$false)]
	[bool]$EnableSsl = $false,
	[Parameter(Mandatory=$false)]
	[string]$SmtpUser,
	[Parameter(Mandatory=$false)]
	[string]$SmtpPass
)

#chech high privileged execution and exit when nope
$IsAdmin = [Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -ne $TRUE) {throw "The Script need to run with the highest privileges! Otherwise, we can't continue :("}

$ExcludedAccounts = '({0})' -f ((@("^Health",'\$$',"^test",'test$',"^SQL","^MSOL",'[0-9a-fA-F]{4,}')) -join "|") #fill if you want to exclude from alerting
#init Environment
$IgnoreParams = 'Install'
$Warning = $false
$emailpriority = 2 # High = 2, Low = 1, Normal = 0 
$ServerName = $ENV:COMPUTERNAME
[Net.ServicePointManager]::SecurityProtocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
#Functions
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
	Write-EventLog -LogName Application -Source "Userenv" -EntryType $Status -EventID 34343 -Message $($MyInvocation.myCommand.name + " :: " + $Message) -ea 0 
}
#Auto Update Code
$ScriptDistributionPoints = @('c:\report\',$($ENV:LOGONSERVER + "\NETLOGON\"),"https://raw.githubusercontent.com/anBrick/WindowsHealthReport/main/") ## path for automatic upgrade from
foreach ($ScriptDistributionPoint in $ScriptDistributionPoints){
if ($ScriptDistributionPoint -match "^(https?:\/\/)") {
	$UpdatesFile = $ENV:TEMP + '\' + $MyInvocation.myCommand.name
	try {
		Invoke-WebRequest -Uri $($ScriptDistributionPoint + $MyInvocation.myCommand.name) -UseDefaultCredentials -OutFile $UpdatesFile
		Unblock-File $UpdatesFile
		Copy-Item $UpdatesFile -Destination $($MyInvocation.MyCommand.Path) -Force;
		Remove-Item $UpdatesFile -ea 0
	}
	catch {Write-Status -Status Error -Message "ERROR: Unable to install updates from $ScriptDistributionPoint, running as is."}
}
else {
	if ((Test-Path -PathType Leaf -LiteralPath ($ScriptDistributionPoint + $MyInvocation.myCommand.name)) -and ((Get-Item ($ScriptDistributionPoint + $MyInvocation.myCommand.name)).LastWriteTime.ticks -gt ((Get-Item $MyInvocation.MyCommand.Path).LastWriteTime.ticks)))
	{
		Write-Status -Status Information -Message ('The Distribution point has the newest version of the script. Starting Upgrade itself')
		try { Copy-Item ($ScriptDistributionPoint + $MyInvocation.myCommand.name) -Destination $($MyInvocation.MyCommand.Path) -Force; }
		catch { Write-Status -Status Error -Message  "ERROR: Impossible to upgrade the script from the $ScriptDistributionPoint, leaving it as is." }
	}
}
}
#
# Get today's date for the report 
$today = Get-Date
 
#Region - Register System Scheduled Task
if ($install) {
	#copy script to %SystemRoot%
	$scriptpath = $MyInvocation.MyCommand.Path
	try {Copy-Item $scriptpath -Destination $($ENV:SystemRoot + '\SYSTEM32') -Force; $scriptpath = $($ENV:SystemRoot + '\SYSTEM32\' + $MyInvocation.myCommand.name) }
	catch {Write-Error "unable to copy script to the %SYSTEMROOT%, running as is."}
	$LaunchingUserEmail = ([adsi]"WinNT://$env:USERDOMAIN/$env:USERNAME,user").Properties["mail"]
	if ([string]::IsNullOrEmpty($emailTo) -And (![string]::IsNullOrEmpty($LaunchingUserEmail)) ) { $emailTo = $LounchingUserEmail}
	if ($PSBoundParameters.ContainsKey('Install')) {$PSBoundParameters.Remove('Install')}
	foreach($h in $MyInvocation.MyCommand.Parameters.GetEnumerator()){
	   $key = $h.Key;$val = $null; 
   	if ($key -and ($IgnoreParams -notmatch $key)) {$val = Get-Variable -Name $key -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
   	if ($val) {[string]$params += $(' -' + $key + ' ' + $val)}
		}
	}
	$reporttask = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $('-NoProfile -NonInteractive -ExecutionPolicy ByPass -command ' + '"& {. ''' + $scriptpath + '''' + $params + ';}"')
	$tasktrigger = New-ScheduledTaskTrigger -AtLogOn
	Register-ScheduledTask -TaskName "Alert-PAUserLogon" -Action $reporttask -Trigger $tasktrigger -Description "send Email Alert when a privileged User was Logged on" -User "SYSTEM" -RunLevel Highest -Force
	Write-Status -Status Information -Message ('SUCCESS: The scheduled task "Alert-PAUserLogon" has successfully been created.')
}
#Region Funcions
function Is-Admin { #test does the user hold the high privilege on local system
param(
  [Parameter(Position=0, ValueFromPipelineByPropertyName=$true)]
	[string]$UserName
)
	Add-Type -AssemblyName System.DirectoryServices.AccountManagement
	$userprincipal = ([System.DirectoryServices.AccountManagement.UserPrincipal]) -as [type]
	$up = $userprincipal::FindByIdentity([system.DirectoryServices.Accountmanagement.contextType]::Domain,[System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName,$UserName)
	if ($up) { 
        try {
		    $ID = New-Object Security.Principal.WindowsIdentity -ArgumentList $up.SamAccountName
		    $ID.Claims.Value.Contains('S-1-5-32-544')
        } catch {$null}
	}
	else {
        try {
		    $up = $userprincipal::FindByIdentity([System.DirectoryServices.AccountManagement.ContextType]::Machine,[System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName,$UserName)
		    $up.GetGroups().sid.Value.Contains('S-1-5-32-544')
        } catch {$null}
	}
}
#Region MAIN
$SessionList = @();$Warning = $false;
# Run the qwinsta.exe and parse the output 
$queryResults = [object[]](quser /server:$ServerName | foreach { (($_.trim() -replace " {2,}",","))} | ConvertFrom-Csv)  
#$queryResults = (qwinsta /server:$ServerName | foreach { (($_.trim() -replace "\s+",","))} | ConvertFrom-Csv) 
   
# Pull the session information from each instance 
ForEach ($queryResult in $queryResults) { 
	#write-host $queryResult
	$RDPUser = $queryResult.USERNAME 
   $sessionType = $queryResult.SESSIONNAME 
	$sessionState = $queryResult.STATE
	$logonTime = $queryResult."LOGON TIME"
         write-host ">> The User: " $RDPUser " State: " $sessionState " Connection: " $sessionType " Server: " $ServerName
        # We only want to display where a "person" is logged in. Otherwise unused sessions show up as USERNAME as a number
        If ($RDPUser) {  
            # When running interactively, uncomment the Write-Host line below to show the output to screen 
#            Write-Host $ServerName logged in by $RDPUser on $sessionState
			if ((Is-Admin $RDPUser.ToUpper()) -and ($RDPUser.ToUpper() -notmatch $ExcludedAccounts.ToUpper())) { #Send Alert - admin user detected
			 	$Warning = $true; write-host ">> The User: " $RDPUser " is hight-prililedged"  -foreground magenta
				$Events = Get-WinEvent -ComputerName $ServerName -FilterHashTable @{LogName="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";StartTime=[DateTime]::Parse($queryResult."logon time" -replace '\s(?:0?\d|1\d|2[0-3]):[0-5]\d(?:\:[0-5]\d)?\s?(?:AM|PM)?$');ID=21} -MaxEvents $queryResults.Count -ea 0 | Select -Property TimeCreated, Message
				foreach ($Event in $Events) {
  					$EventTimeCreated = $Event.TimeCreated.ToString("dd/MM/yyyy HH:mm:ss"); $EventMessage = $Event.Message -split "`n" | Select-Object -Index "2"; $EventMessageUser = ($EventMessage -split ":" | Select-Object -Index "1").Trim(); $EventMessage = $Event.Message -split "`n" | Select-Object -Index "4"; $EventMessageHostIP = ($EventMessage -split ":" | Select-Object -Index "1").Trim() 
  					if ($EventMessageUser -match $RDPUser) {
						try {  $EventMessageHost = [system.net.dns]::gethostentry($EventMessageHostIP).HostName }
						catch { 	$EventMessageHost = $EventMessageHostIP }
						if (($EventMessageHostIP -MATCH "^192\.168\.") -or ($EventMessageHostIP -MATCH '^172\.(1[6-9]|2[0-9]|3[0-1])\.') -or ($EventMessageHostIP -MATCH "^10\.") -or ($EventMessageHostIP -MATCH 'LOCAL')) {$IPLocation = [ordered]@{City = "LOCAL";Country = "NET"}}
						else {
							try {$IPLocation = Invoke-RestMethod -Method Get -Uri $("https://ipinfo.io/" + $EventMessageHostIP) }
							catch {$IPLocation = [ordered]@{City = $EventMessageHostIP;Country = ((Invoke-RestMethod -Method Get -URI $("http://ip2c.org/" +  $EventMessageHostIP)) -split ";")[3]}}
						}
						$Connection = [PSCustomObject]@{'LoginTime'=$EventTimeCreated;'UserName'=$EventMessageUser;'HostIp'=$EventMessageHostIP;'HostName'=$EventMessageHost;'Location'=$($IPLocation.City + ", " + $IPLocation.country)}
	  					Write-Host "$EventTimeCreated, $EventMessageHostIP, $EventMessageHost, $EventMessageUser, $($IPLocation.City + ", " + $IPLocation.country)" -foreground yellow
						#Create message
						if (!([string]::IsNullOrEmpty($emailTo))) {
							$subject = "PA LOGON ALERT FROM " + $ServerName + " : " + $today + " : " + $RDPUser.ToUpper() + " is just connected!"
					# <table style= "width: 80%"><tr><td style="text-align: center; background-color: red; width: 5%; color: #ffd261; font-size:36pt; font-weight: bold">!</td><td style="background-color: #ffd261; color: RED; font-weight: bold">&nbsp;POZOR: PODEZØELÁ ZPRÁVA. PROSÍM VÌNUJTE POZORNOST ODESÍLATELI A OBSAHU. MOŽNÉ PODVODNÉ JEDNÁNÍ</td></tr></table>		
							$body = $Connection | convertto-html -Fragment -PreContent $('<table style= "width: 80%"><tr><td style="text-align: center; background-color: red; width: 5%; color: #ffd261; font-size:36pt; font-weight: bold">!</td><td style="background-color: #ffd261; color: RED; font-weight: bold">&nbsp;HOST: <font color=green>' + $($ServerName) + ' </font> | Logon Alert:</td><td style="background-color: #ffd261; color: RED; font-weight: bold">&nbsp;High privileged account just connected to the host <font color=green>' + $($ServerName) + '</font><br>') -PostContent '</td></tr></table>' 
							# Send the report email 
							write-host "Sending email to $emailTo"
							# generate FROM address by server DNS name
							if ($emailFrom -notmatch '^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$') {
								try { $EmailFrom = ((Invoke-RestMethod "http://ipinfo.io/json" | Select-Object hostname).hostname -replace '^(.*?)\.', '${1}@') -replace '^(.*?)\@', "$ServerName@" }
								catch {$emailFrom = (Get-WmiObject win32_computersystem).DNSHostName+"@"+($emailTo -split "@")[1]}
							}
					 		#Check MX server for TO Address
							$ToDomain = $emailTo.Split("@")[1]
							if (!([System.Net.Sockets.TcpClient]::new().ConnectAsync($smtpServer, $SmtpServerPort).Wait(600)))
							{
								$DomainSMTPServer = (Resolve-DnsName -Name $ToDomain -Type MX).NameExchange
								if ($NULL -ne $DomainSMTPServer) { $smtpServer = $DomainSMTPServer }
							}
							if ([System.Net.Sockets.TcpClient]::new().ConnectAsync($smtpServer, $SmtpServerPort).Wait(600)) {
							Write-Host "Sending report to $($emailTo) from $($emailFrom) by SMTP:$smtpServer" -foreground magenta
							$emailMessage = New-Object System.Net.Mail.MailMessage
							$emailMessage.Priority = $emailpriority 
							$emailMessage.From = $emailFrom
							$emailMessage.To.Add( $emailTo )
							$emailMessage.Subject = $subject
							$emailMessage.IsBodyHtml = $true
							$emailMessage.BodyEncoding = [System.Text.Encoding]::Unicode
							$emailMessage.Body = $body
							$emailMessage.Headers.Add('Content-Type', 'content=text/html; charset="UTF-8"');
							$emailMessage.headers.Add('X-TS-ALERT','ALERT MESSAGE')
							$SMTPClient = New-Object System.Net.Mail.SmtpClient( $smtpServer , $SmtpServerPort )
							$SMTPClient.EnableSsl = $EnableSsl
							if ( ($emailSmtpUser -ne "") -and ($emailSmtpPass -ne "")) {$SMTPClient.Credentials = New-Object System.Net.NetworkCredential( $emailSmtpUser , $emailSmtpPass );}
							$SMTPClient.Send( $emailMessage )
							}
							else {Write-Host "No SMTP servers available" -foreground magenta}
							Write-EventLog -LogName Application -Source "Winlogon" -EntryType "Warning" -EventID 21 -Message $($subject + " from: " + $EventMessageHostIP + " " + $($IPLocation.City + ", " + $IPLocation.country)) 	
						}#send mail
					} #select event for the RDPUser
				} 				
			} #is-Admin check  
        } 
} 
