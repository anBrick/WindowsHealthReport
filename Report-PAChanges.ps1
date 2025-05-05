#Requires -RunAsAdministrator
#AD Module required
#Requires -Modules ActiveDirectory
#Requires -Modules DnsClient

param(
		[Parameter(Mandatory=$false)]
		[switch]$Install, # set to install to current host (copy to %systemroot%, create system task to run on eany user's logon)
		[Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = 'Provide User SAM Account Name(s) for monitoring or use * to monitor ALL DOMAIN user acconts')]
		[string[]]$ExcludeAccounts = @("^Health",'\$$',"^test",'test$',"^SQL","^MSOL",'[0-9a-fA-F]{4,}'), #Use REGEX Pattern format like: "^Health",'\$$',"^test",'test$',"^SQL","^MSOL",'[0-9a-fA-F]{4,}'
		[Parameter(Mandatory = $false, HelpMessage = 'This parameter not used for now')]
		[int]$EventCode, #not used for now
		[Parameter(Mandatory = $false)]
		[string]$emailTo = "administrator" + "@"+(Get-WmiObject win32_computersystem).Domain,
		[Parameter(Mandatory = $false)]
		$emailFrom = (Get-WmiObject win32_computersystem).DNSHostName+"@"+(Get-WmiObject win32_computersystem).Domain,
		[Parameter(Mandatory = $false)]
		$emailSMTP = (Resolve-DnsName -Name (Get-WmiObject win32_computersystem).Domain -Type MX).NameExchange
)
#Register Task for schedulled running
$IgnoreParams = 'Install'
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
	$xmlQuery = @"
	<QueryList>
	  <Query Id="0" Path="Security">
	    <Select Path="Security">
	      *[System[(EventID=4724 or EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)]]
	    </Select>
	  </Query>
	</QueryList>
	"@
	$trigger = New-ScheduledTaskTrigger -AtLogOn
	$trigger.Subscription = $xmlQuery
	$reporttask = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $('-NoProfile -NonInteractive -ExecutionPolicy ByPass -command ' + '"& {. ''' + $scriptpath + '''' + $params + ';}"')
	Register-ScheduledTask -TaskName "Alert-PAUserChanges" -Action $reporttask -Trigger $trigger -Description "send Email Alert when a privileged User account was changed" -User "SYSTEM" -RunLevel Highest -Force
}

#Prepare Registry for LastRunTime Settings
# Set variables to indicate value and key to set
$RegistryPath = 'HKLM:\Software\PowerShell\Scripts\ReportPriviledgedUserActivity'
$Name         = 'LastRunTime'
$Value        = '{0}' -f ([system.string]::format('{0:yyyyMMddHHmm}',([datetime]::Now)))
#Get Last Run Time if available
try { $LastRunTime = [datetime]::ParseExact((Get-ItemPropertyValue -Path $RegistryPath -Name $Name), "yyyyMMddHHmm", $null) }
catch {$LastRunTime = [datetime]::Now.AddMinutes(-720)}
# Create the key if it does not exist
If (-NOT (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }  
# Now set the value of last run time
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType String -Force

Import-module ActiveDirectory,DnsClient
$PAUExPatterns = '({0})' -f (($ExcludeAccounts) -join "|") #fill if you want to exclude from alerting
#Get Priviledged Groups and Users
$global:ADPrivilegedObjects = (Get-ACL $('AD:\'+ (Get-ADDomain).DistinguishedName)).Access | ?{$_.AccessControlType -eq 'Allow' -and (($_.ActiveDirectoryRights -contains 'GenericAll') -or ($_.ActiveDirectoryRights -like '*WriteProperty*') -or ($_.ActiveDirectoryRights -like '*ExtendedRight*'))} |sort IdentityReference -Unique  | foreach-object {(($_.IdentityReference.Value).Split('\')[1]).ToString()}
$global:ADPrivilegedGroups = $ADPrivilegedObjects | foreach-object {Get-ADObject -Filter "sAMAccountName -eq `"$_`"" | where {$_.ObjectClass -eq 'group'}} 
$global:ADPrivilegedUsers = $ADPrivilegedObjects | foreach-object {Get-ADObject -Filter "sAMAccountName -eq `"$_`"" | where {$_.ObjectClass -eq 'user'}}

$ADPrivilegedGroups | % { 
		$ADPrivilegedUsers += ([adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User)(memberOf:1.2.840.113556.1.4.1941:=$_))").FindAll().GetDirectoryEntry().SamAccountName
	}
$ADPrivilegedUsers = $ADPrivilegedUsers | sort -unique
$ReportObj = @()
$ReportMessage = @()
function MonitoredAccount #Verify the user belongs to priviledged objects in AD
{
param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = 'Provide User SAM Account Name to check')]
		[string]$SAMAccountName
		)
	if ($UserSAMAccountNames -contains '*') {return $true}
	elseif ($SAMAccountName.ToUpper() -notmatch $PAUExPatterns.ToUpper()) {return $true}
	else {return $false}	
}


$DCNames = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Sites | % { $_.Servers }
	$DCNames | foreach {
			#Catch Password Changes
			Get-WinEvent -ComputerName $_.Name -FilterHashtable @{ProviderName= "Microsoft-Windows-Security-Auditing";LogName="Security";Level=0;ID=4724;StartTime=$LastRunTime;EndTime=[datetime]::Now } -ea 0 | Foreach {
				$event = [xml]$_.ToXml()
				if($event) {
					$Time = Get-Date $_.TimeCreated -UFormat "%d-%m-%Y %H:%M:%S"
					$AdmUser = $event.Event.EventData.Data[4]."#text"
					$User = $event.Event.EventData.Data[0]."#text"
					$dc = $event.Event.System.computer
					if ((MonitoredAccount $AdmUser) -or (MonitoredAccount $User)) {
						$ReportObj += [pscustomobject]@{ 'Admin' = $AdmUser; 'User' = $User; 'Group' = ((Get-ADPrincipalGroupMembership $User).Where({$_.GroupCategory -eq 'Security'}).Name -Join ','); 'DC' = $dc; 'Time' = $Time; 'Action' = 'Password set'} 
						$ReportMessage += "`nThe Admin " + $AdmUser + " has set the password for an account " + $User + " on " + $dc + " at " + $Time 
						write-host $ReportMessage[-1]
					}
				}
			}
			#Catch Group Membership Changes EventIDs: 4728,4729, 4732,4733, 4756,4757
			Get-WinEvent -ComputerName $_.Name -FilterHashtable @{ProviderName= "Microsoft-Windows-Security-Auditing";LogName="Security";Level=0;ID=4728;StartTime=$LastRunTime;EndTime=[datetime]::Now } -ea 0 | Foreach {
				$event = [xml]$_.ToXml()
				if($event) {
					$Time = Get-Date $_.TimeCreated -UFormat "%d-%m-%Y %H:%M:%S"
					$GroupName = $event.Event.EventData.Data[2]."#text"
					$AdmUser = $event.Event.EventData.Data[6]."#text"
					$User = $event.Event.EventData.Data[0]."#text"
					$dc = $event.Event.System.computer
					if (($ADPrivilegedGroups.Name -contains $GroupName) -and ((MonitoredAccount $AdmUser) -or (MonitoredAccount $User))) {
						$ReportObj += [pscustomobject]@{ 'Admin' = $AdmUser; 'User' = $User; 'Group' = $GroupName; 'DC' = $dc; 'Time' = $Time; 'Action' = 'User was joined to the group'}
						$ReportMessage += "`nThe Admin " + $AdmUser + " join the user " + $User + " to the group " + $GroupName + " on " + $dc + " at " + $Time 
						write-host $ReportMessage[-1]
					}
				}
			}
			Get-WinEvent -ComputerName $_.Name -FilterHashtable @{ProviderName= "Microsoft-Windows-Security-Auditing";LogName="Security";Level=0;ID=4729;StartTime=$LastRunTime;EndTime=[datetime]::Now } -ea 0 | Foreach {
				$event = [xml]$_.ToXml()
				if($event) {
					$Time = Get-Date $_.TimeCreated -UFormat "%d-%m-%Y %H:%M:%S"
					$GroupName = $event.Event.EventData.Data[2]."#text"
					$AdmUser = $event.Event.EventData.Data[6]."#text"
					$User = $event.Event.EventData.Data[0]."#text"
					$dc = $event.Event.System.computer
					if (($ADPrivilegedGroups.Name -contains $GroupName) -and ((MonitoredAccount $AdmUser) -or (MonitoredAccount $User))) {
						$ReportObj += [pscustomobject]@{ 'Admin' = $AdmUser; 'User' = $User; 'Group' = $GroupName; 'DC' = $dc; 'Time' = $Time; 'Action' = 'User was removed from the group'}
						$ReportMessage += "`nThe Admin " + $AdmUser + " remove the user " + $User + " from the group " + $GroupName + " on " + $dc + " at " + $Time 
						write-host $ReportMessage[-1]
					}
				}
			}
			Get-WinEvent -ComputerName $_.Name -FilterHashtable @{ProviderName= "Microsoft-Windows-Security-Auditing";LogName="Security";Level=0;ID=4732;StartTime=$LastRunTime;EndTime=[datetime]::Now } -ea 0 | Foreach {
				$event = [xml]$_.ToXml()
				if($event) {
					$Time = Get-Date $_.TimeCreated -UFormat "%d-%m-%Y %H:%M:%S"
					$GroupName = $event.Event.EventData.Data[2]."#text"
					$AdmUser = $event.Event.EventData.Data[6]."#text"
					$User = $event.Event.EventData.Data[0]."#text"
					$dc = $event.Event.System.computer
					if (($ADPrivilegedGroups.Name -contains $GroupName) -and ((MonitoredAccount $AdmUser) -or (MonitoredAccount $User))) {
						$ReportObj += [pscustomobject]@{ 'Admin' = $AdmUser; 'User' = $User; 'Group' = $GroupName; 'DC' = $dc; 'Time' = $Time; 'Action' = 'User was joined to the group'}
						$ReportMessage += "`nThe Admin " + $AdmUser + " join the user " + $User + " to the group " + $GroupName + " on " + $dc + " at " + $Time 
						write-host $ReportMessage[-1]
					}
				}
			}
			Get-WinEvent -ComputerName $_.Name -FilterHashtable @{ProviderName= "Microsoft-Windows-Security-Auditing";LogName="Security";Level=0;ID=4733;StartTime=$LastRunTime;EndTime=[datetime]::Now } -ea 0 | Foreach {
				$event = [xml]$_.ToXml()
				if($event) {
					$Time = Get-Date $_.TimeCreated -UFormat "%d-%m-%Y %H:%M:%S"
					$GroupName = $event.Event.EventData.Data[2]."#text"
					$AdmUser = $event.Event.EventData.Data[6]."#text"
					$User = $event.Event.EventData.Data[0]."#text"
					$dc = $event.Event.System.computer
					if (($ADPrivilegedGroups.Name -contains $GroupName) -and ((MonitoredAccount $AdmUser) -or (MonitoredAccount $User))) {
						$ReportObj += [pscustomobject]@{ 'Admin' = $AdmUser; 'User' = $User; 'Group' = $GroupName; 'DC' = $dc; 'Time' = $Time; 'Action' = 'User was removed from the group'}
						$ReportMessage += "`nThe Admin " + $AdmUser + " remove the user " + $User + " from the group " + $GroupName + " on " + $dc + " at " + $Time 
						write-host $ReportMessage[-1]
					}
				}
			}
			Get-WinEvent -ComputerName $_.Name -FilterHashtable @{ProviderName= "Microsoft-Windows-Security-Auditing";LogName="Security";Level=0;ID=4756;StartTime=$LastRunTime;EndTime=[datetime]::Now } -ea 0 | Foreach {
				$event = [xml]$_.ToXml()
				if($event) {
					$Time = Get-Date $_.TimeCreated -UFormat "%d-%m-%Y %H:%M:%S"
					$GroupName = $event.Event.EventData.Data[2]."#text"
					$AdmUser = $event.Event.EventData.Data[6]."#text"
					$User = $event.Event.EventData.Data[0]."#text"
					$dc = $event.Event.System.computer
					if (($ADPrivilegedGroups.Name -contains $GroupName) -and ((MonitoredAccount $AdmUser) -or (MonitoredAccount $User))) {
						$ReportObj += [pscustomobject]@{ 'Admin' = $AdmUser; 'User' = $User; 'Group' = $GroupName; 'DC' = $dc; 'Time' = $Time; 'Action' = 'User was joined to the group'}
						$ReportMessage += "`nThe Admin " + $AdmUser + " join the user " + $User + " to the group " + $GroupName + " on " + $dc + " at " + $Time 
						write-host $ReportMessage[-1]
					}
				}
			}
			Get-WinEvent -ComputerName $_.Name -FilterHashtable @{ProviderName= "Microsoft-Windows-Security-Auditing";LogName="Security";Level=0;ID=4757;StartTime=$LastRunTime;EndTime=[datetime]::Now } -ea 0 | Foreach {
				$event = [xml]$_.ToXml()
				if($event) {
					$Time = Get-Date $_.TimeCreated -UFormat "%d-%m-%Y %H:%M:%S"
					$GroupName = $event.Event.EventData.Data[2]."#text"
					$AdmUser = $event.Event.EventData.Data[6]."#text"
					$User = $event.Event.EventData.Data[0]."#text"
					$dc = $event.Event.System.computer 
					if (($ADPrivilegedGroups.Name -contains $GroupName) -and ((MonitoredAccount $AdmUser) -or (MonitoredAccount $User))) {
						$ReportObj += [pscustomobject]@{ 'Admin' = $AdmUser; 'User' = $User; 'Group' = $GroupName; 'DC' = $dc; 'Time' = $Time; 'Action' = 'User was removed from the group'}
						$ReportMessage += "`nThe Admin " + $AdmUser + " remove the user " + $User + " from the group " + $GroupName + " on " + $dc + " at " + $Time 
						write-host $ReportMessage[-1]
					}
				}
			}
	}

If ($ReportObj -ne $null)
		{
			$MessageSubject = "Privileged Account changes detected at " + (Get-Date ([datetime]::Now) -UFormat "%d-%m-%Y %H:%M:%S")
			$MessageBody = "<head><meta http-equiv='Content-Type' content='text/html; charset=UTF-8' /><STYLE>body {background-color: powderblue;}table {border-collapse: collapse;}</STYLE><title>Privileged Account changes detected</title></head><body><br>"
			$MessageBody += $ReportObj | convertto-html -Fragment 
			$MessageBody += "</body></html>" 

			$smtp= New-Object System.Net.Mail.SmtpClient $emailSMTP 
			$msg = New-Object System.Net.Mail.MailMessage $emailFrom, $EmailTo, $MessageSubject, $MessageBody
			$msg.isBodyhtml = $true 
			$msg.BodyEncoding =  [System.Text.Encoding]::UTF8
			$msg.SubjectEncoding = [System.Text.Encoding]::UTF8
			$smtp.send($msg) 
			write-host "."
}

$ReportObj
