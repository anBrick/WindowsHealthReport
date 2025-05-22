#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory
#Requires -Modules DnsClient

[CmdletBinding()]
param(
    [switch]$Install,
    [string]$emailTo = "administrator@$((Get-WmiObject win32_computersystem).Domain)",
    [string]$emailFrom = (Get-WmiObject win32_computersystem).DNSHostName+"@" + 'report.' + (Get-WmiObject win32_computersystem).Domain,
	[string]$smtpServer = 'localhost', 
	[Parameter(Mandatory=$false)]
	[int]$smtpServerPort = 25,
	[Parameter(Mandatory=$false)]
	[bool]$EnableSsl = $false,
	[Parameter(Mandatory=$false)]
	[string]$SmtpUser,
	[Parameter(Mandatory=$false)]
	[string]$SmtpPass)

#Global Vars
$ExcludeAccounts = @("^Health", '\$$', "^test", 'test$', "^SQL", "^MSOL", '[0-9a-fA-F]{4,}')
$emailpriority = 2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ServerName = $ENV:COMPUTERNAME
$Warning = $false
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
		'Warning' {Write-Warning $Message -foregroundColor yellow}
		'Error' {Write-Error $Message}
	}
	# Log source for Application Event Log
	$source = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.PSCommandPath)
	if ([string]::IsNullOrEmpty($source)) {$source = [IO.Path]::GetFileNameWithoutExtension($PSCommandPath)}
	if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {[System.Diagnostics.EventLog]::CreateEventSource($source, "Application")} #register EvtLog Source
	Write-EventLog -LogName Application -Source $source -EntryType $Status -EventID 34343 -Message $(( '{0} Runtime message:: {1}') -f $MyInvocation.myCommand.name,$Message) -ea 0 
}
#SELF Update Code
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
# Register Scheduled Task (if -Install is used)
if ($Install) {
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        $destPath = "$env:SystemRoot\System32\$($MyInvocation.MyCommand.Name)"
        Copy-Item -Path $scriptPath -Destination $destPath -Force -ErrorAction Stop
        Write-Verbose "Script copied to $destPath"
    }
    catch {
        Write-Warning "Failed to copy script to System32: $_"
    }

    # Build parameter string
    $params = ""
    foreach ($h in $MyInvocation.MyCommand.Parameters.GetEnumerator()) {
        $key = $h.Key
        if ($key -ne 'Install') {
            $val = Get-Variable -Name $key -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
            if ($val) { $params += " -$key `"$val`"" }
        }
    }

    # Create event subscription for privileged account changes
# Variables
$taskName = "Alert-PAUserChanges"
#$TaskDescription = "Send Email Alert when a Privileged User Account property was modified"
$xmlPath = "$env:SystemRoot\System32\Alert-PAUserChanges.xml"

# Event filter with multiple event IDs in the Security log
$xmlQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[
        (EventID=4724 or EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)
        and
        Provider[@Name='Microsoft-Windows-Security-Auditing']
      ]]
    </Select>
  </Query>
</QueryList>
"@

# Build full XML for scheduled task
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Monitors and alerts on privileged account group membership and password changes</Description>
    <Author>ARION Administrator</Author>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>$([System.Security.SecurityElement]::Escape($xmlQuery))</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId> <!-- SYSTEM account -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$scriptpath" $params</Arguments>
    </Exec>
  </Actions>
</Task>
"@

# Ensure directory exists
$folder = Split-Path $xmlPath
if (-not (Test-Path $folder)) {
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
}

# Save the task XML
$taskXml | Out-File -FilePath $xmlPath -Encoding Unicode

# Register the task using schtasks
schtasks /Create /TN $taskName /XML $xmlPath /F

# Clean up the XML file after registration (optional)
Remove-Item -Path $xmlPath -Force
    exit
}

# Registry for LastRunTime tracking
$RegistryPath = 'HKLM:\Software\PowerShell\Scripts\ReportPrivilegedUserActivity'
$Name = 'LastRunTime'
try { $LastRunTime = [datetime]::ParseExact((Get-ItemPropertyValue -Path $RegistryPath -Name $Name), "yyyyMMddHHmm", $null)}
catch { $LastRunTime = [datetime]::Now.AddMinutes(-1440)} # Default to last 24 hours

# Update LastRunTime
New-Item -Path $RegistryPath -Force | Out-Null
New-ItemProperty -Path $RegistryPath -Name $Name -Value ([datetime]::Now.ToString("yyyyMMddHHmm")) -PropertyType String -Force

# Load modules
Import-Module ActiveDirectory,DnsClient -ErrorAction Stop

# Build exclusion regex pattern
$PAUExPatterns = '({0})' -f ($ExcludeAccounts -join "|")

# Retrieve privileged AD objects
try {
	$ADPrivilegedObjects = (Get-Acl $("AD:" + (Get-ADDomain).DistinguishedName)).Access.where({$_.AccessControlType -eq 'Allow' -and ($_.ActiveDirectoryRights -match 'GenericAll|WriteProperty|ExtendedRight')}) | Sort-Object IdentityReference -Unique | ForEach-Object { $_.IdentityReference.Value.Split('\')[1] }
	
	$global:ADPrivilegedGroups = $ADPrivilegedObjects.ForEach({ Get-ADObject -Filter "sAMAccountName -eq '$_'" | Where-Object {$_.ObjectClass -eq 'group'}})
	$ADPPUA = $ADPrivilegedObjects.ForEach({(Get-ADObject -Filter "sAMAccountName -eq '$_'" | Where-Object {$_.ObjectClass -eq 'user'} | Select-Object Name).Name})
	# Get nested members of privileged groups
	foreach ($group in $global:ADPrivilegedGroups) {
	        $groupDN = $group.DistinguishedName
	        $nestedMembers = ([adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User)(memberOf:1.2.840.113556.1.4.1941:=$groupDN))").FindAll()
	        $ADPPUA += $nestedMembers | ForEach-Object { $_.Properties["samaccountname"][0] }
	    }
	$ADPPUA
   $global:ADPrivilegedUsers = $ADPPUA
}
catch { Write-Error "Failed to retrieve privileged objects: $_"; exit }

# Function to check if an account is monitored
function Test-MonitoredAccount {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$SAMAccountName
    )
    process {
        if (($global:ADPrivilegedUsers -contains $SAMAccountName) -and ($SAMAccountName -notmatch $PAUExPatterns)) { return $true }
        else {return $false}
    }
}

# Get domain controllers
try {
    $DCNames = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | Select-Object -ExpandProperty Servers
}
catch { Write-Error "Failed to retrieve domain controllers: $_"; exit }

# Initialize report arrays
$ReportObj = @()
$ReportMessage = @()

# Event IDs to monitor
$eventIDs = @(4724, 4728, 4729, 4732, 4733, 4756, 4757)

foreach ($dc in $DCNames) {
    try {
        # Query all relevant events in one call
        $events = Get-WinEvent -ComputerName $dc.Name -FilterHashtable @{
            LogName = 'Security'
            ID = $eventIDs
            StartTime = $LastRunTime
            EndTime = [datetime]::Now
        } -ErrorAction Stop

        foreach ($event in $events) {
            switch ($event.Id) {
                # Password change (4724)
                4724 {
                    $targetUser = $event.Properties[0].Value  # TargetUserName
                    $adminUser = $event.Properties[4].Value   # SubjectUserName

                    if ((Test-MonitoredAccount $adminUser) -or (Test-MonitoredAccount $targetUser)) {
                        $time = $event.TimeCreated.ToString("dd-MM-yyyy HH:mm:ss")
                        $group = ([object[]](Get-ADPrincipalGroupMembership $targetUser)).Where({$_.GroupCategory -eq 'Security'}).Name -join ", `n"

                        $ReportObj += [PSCustomObject]@{
                            Account   = $targetUser
                            Group  = $group
                            DC     = $dc.Name
                            Time   = $time
									 Action  = 'Password set'
									 'By Actor' = $adminUser
                        }
                        $ReportMessage += "Administrator '$adminUser' invoked password reset on '$targetUser' at '$($dc.Name)' at $time`n"
                    }
                }

                # Group membership changes
                {4728, 4729, 4732, 4733, 4756, 4757 -contains $_} {
                    $groupName = $event.Properties[2].Value   # GroupName
                    $adminUser = $event.Properties[6].Value   # SubjectUserName
                    $targetUser = $event.Properties[0].Value  # MemberName

                    if ($Glogal:ADPrivilegedGroups.Name -contains $groupName -and ((Test-MonitoredAccount $adminUser) -or (Test-MonitoredAccount $targetUser))) {
                        $time = $event.TimeCreated.ToString("dd-MM-yyyy HH:mm:ss")
                        $action = switch ($event.Id) {
                            {4728, 4732, 4756 -contains $_} { 'User was added to group' }
                            {4729, 4733, 4757 -contains $_} { 'User was removed from group' }
                        }

                        $ReportObj += [PSCustomObject]@{
                            Account   = $targetUser
                            Group  = $groupName
                            DC     = $dc.Name
                            Time   = $time
                            Action = $action
                            'By Actor'  = $adminUser
                        }
                        $ReportMessage += "'$targetUser' $action '$groupName' by Administrator '$adminUser' at '$($dc.Name)' at $time`n"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error querying events on $($dc.Name): $_"
    }
}

# Send email report if changes were detected
if ($ReportObj.Count -gt 0) {
			write-host "Preparing meail report message"
			[string]$body = ""
			#$body = '<table class=scope><tr><td><H3 style="font-size:17px; font-weight:normal; background-color:#66ccee; margin-top:3px; margin-bottom:1px; margin-left:4px; text-align:left;">' + $($ReportMessage -replace "`n","<br>") + "</H3></td></tr></table>"
			$body += ($ReportObj | ConvertTo-Html  -Fragment -PreContent $('<table style= "width: 100%"><tr><td style="text-align: center; background-color: red; width: 5%; color: #ffd261; font-size:36pt; font-weight: bold">!</td><td style="background-color: #ffd261; color: RED; font-weight: bold">&nbsp;HOST: <font color=green>' + $($ServerName) + ' </font> | PUA Activity Alert:</td><td style="background-color: #ffd261; color: RED; font-weight: bold"><BR>&nbsp;Highly privileged activities have occurred in AD ' + $((Get-ADDomain).DistinguishedName)) -PostContent '</td></tr></table>') -replace ", `n","<br>"
			$body += '<div></div><!--End ReportBody--><div><br><center><i>' + $(Get-Date -Format "dd/MM/yyyy HH:mm:ss") + '</i><p style="font-size:8px;color:#7d9797">Script Version: 2025.05 | By: Vladislav Jandjuk | Feedback: jandjuk@arion.cz | Git: github.com/anBrick/WindowsHealthReport</p></center><br></div></body></html>'
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
			Write-Host "Sending report to $($emailTo) by SMTP:$smtpServer" -foreground magenta
			$emailMessage = New-Object System.Net.Mail.MailMessage
			$emailMessage.Priority = $emailpriority 
			$emailMessage.From = $emailFrom
			$emailMessage.To.Add( $emailTo )
			$emailMessage.Subject = "Privileged Account Changes Detected - $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
			$emailMessage.IsBodyHtml = $true
			$emailMessage.SubjectEncoding = [System.Text.Encoding]::UTF8
			$emailMessage.BodyEncoding = [System.Text.Encoding]::UTF8
			$emailMessage.Body = $body 
			$emailMessage.Headers.Add('Content-Type', 'content=text/html; charset="UTF-8"');
			$emailMessage.headers.Add('X-TS-ALERT','ALERT MESSAGE')
			$SMTPClient = New-Object System.Net.Mail.SmtpClient( $smtpServer , $SmtpServerPort )
			$SMTPClient.EnableSsl = $EnableSsl
			if ( ($emailSmtpUser -ne "") -and ($emailSmtpPass -ne "")) {$SMTPClient.Credentials = New-Object System.Net.NetworkCredential( $emailSmtpUser , $emailSmtpPass );}
			try {$SMTPClient.Send( $emailMessage )} catch {Write-Error "Failed to send email: $_"}
			}
			else {Write-Host "No SMTP servers available" -foreground magenta}
			Write-EventLog -LogName Application -Source "Winlogon" -EntryType "Warning" -EventID 21 -Message $($subject + " from: " + $EventMessageHostIP + " " + $($IPLocation.City + ", " + $IPLocation.country)) 	
        Write-Output "Email alert sent successfully"
}

# Output results (for logging or console)
$ReportMessage