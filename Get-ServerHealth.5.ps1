<#
todo:
	done : Loggedon user list
	done : OS info: OS ver and SP, Install date, last booted, AD role
	done : HNW: MFG, Model, CPU, Cores, Total RAM, free RAM, HDD units, disk drives etc
	done : NET : NICS, Ips, DNS, net types (priv, pub, up/down) etc.
	done : Processes: TOP processes
	done : Windows Update status
	done : AV config & update status - only MS Defender
	done : FW config (en/dis, rules)
	done : Services (anomalies)
	done : Roles installed : Get-WindowsFeature -ComputerName $ServerName | Where-Object {$_.InstallState -eq 'Installed'}
	done : SW inventory
	done : EVT LOGs (sys, app, sec errors & warn)
	done : Certificates: Expiration, properties
	done : verify running processes for signatures
	done : analyze tasks
	done : shares
	done : open TCP ports
	done : DNS config
	done : non ms processes & services
	done : time sync services config
	DONE : GPO applied
	TODO : local policy settings which are not in default settings?
	done : oldest events in EVTLOGs 
	in-progress : TPM, secureboot? system sec features memory protection, 
	DONE: REBOOT PENDING STATUS, AZURE JOIN STATE...
	*
	analyze and warn: ?
	Wat`s new: Automatic install option

#>

[cmdletbinding(
    SupportsShouldProcess=$true,
    ConfirmImpact="Low"
    )]
param(
	[Parameter(Mandatory=$false)]
	[switch]$Install, # set to install to current host (copy to %systemroot%, create system task to run every morning)
  [Parameter(Position=0, Mandatory=$false, ValueFromPipelineByPropertyName=$true, 
	HelpMessage={("`nEnter a local or remote hostname for the ServerName parameter.`n Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -EmailTo it@domain.com`n")})] 
  [string]$ServerName = "localhost",
  [Parameter(Mandatory=$false, 
   HelpMessage={("`nEnter an email address for report.`n  Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -EmailTo it@domain.com`n")})] 
  [string]$EmailTo = "administrator@"+(Get-WmiObject win32_computersystem).Domain,
  [Parameter(Mandatory=$false, 
   HelpMessage={("`nEnter an email address for sender.`n  Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -EmailFrom server@domain.com`n")})]
	[string]$EmailFrom = (Get-WmiObject win32_computersystem).DNSHostName + "@" + "report." + (Get-WmiObject win32_computersystem).Domain,
	[Parameter(Mandatory = $false,
			   HelpMessage = { ("`nEnter an SMTP server address.`n  Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -SMTPServer mail.domain.com`n") })]
	[string]$smtpServer = "localhost",
  [Parameter(Mandatory=$false, 
   HelpMessage={("`nUse -Ignore to skip modules to check. `n Available modules:`
		`n`t LUS - Skip Review LoggenOn Users`
		`n`t WHW - Skip HardWare analysis`
		`n`t NET - Skip Network config retrieve`
		`n`t PRC - Skip Processes analysis`
		`n`t APP - Skip Installed Application retrieve`
		`n`t WUS - Skip Windows Update check`
		`n`t WAV - Skip Windows Antivirus check`
		`n`t WFW - Skip Windows Firewall check`
		`n`t SVC - Skip Services Analysis`
		`n`t ROL - Skip Installed Roles enumeration`
		`n`t EVT - Skip Events retrieve`
		`n`t USR - Skip Users and Groups Analysis`
	   `n`t CRT - Skip Certificates Analysis`
		`n`t TSK - Skip Tasks Analysis`
		`n`t SHA - Skip Shares Analysis`
		`n`t NST - Skip NETStat Analysis`
		`n`t NTP - Skip NTP Status`
		`n`t GPO - Skip GPO Results`
		`n`t AZS - Skip AzureAD Join State check`
 		`n  Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -EmailTo it@domain.com -Ignore APP,WUS,WAV etc.`n")})]
  [Alias('Skip')]
	[String]$Ignore,
	[Parameter(Mandatory = $false,
			   HelpMessage = { ("`nUse -Iclude to run modules to check. `n Available modules:`
		`n`t LUS - Review LoggenOn Users`
		`n`t WHW - HardWare analysis`
		`n`t NET - Network config retrieve`
		`n`t PRC - Processes analysis`
		`n`t APP - Installed Application retrieve`
		`n`t WUS - Windows Update check`
		`n`t WAV - Windows Antivirus check`
		`n`t WFW - Windows Firewall check`
		`n`t SVC - Services Analysis`
		`n`t ROL - Installed Roles enumeration`
		`n`t EVT - Events retrieve`
		`n`t USR - Users and Groups Analysis`
	   `n`t CRT - Certificates Analysis`
		`n`t TSK - Tasks Analysis`
		`n`t SHA - Shares Analysis`
		`n`t NST - NETStat Analysis`
		`n`t NTP - NTP Status`
		`n`t GPO - GPO Results`
		`n`t AZS - Do AzureAD Join State check`
 		`n  Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -EmailTo it@domain.com -Include APP,WUS,WAV etc.`n")
		})]
	[Alias('Check')]
	[String]$Include
)
#Set-StrictMode -version latest
#Create Ignore list from include array
[System.Collections.ArrayList]$RunTest = @('APP', 'AZS', 'CRT', 'EVT', 'GPO', 'LUS', 'NET', 'NTP', 'NST', 'PRC', 'ROL', 'SHA', 'SVC', 'TSK', 'USR', 'WAV', 'WFW', 'WHW', 'WUS')
if ($Include) { $RunTest = $Include -split ','}
if ($Ignore)
{
	[System.Collections.ArrayList]$it = $Ignore -split ','
	$It.foreach({ $RunTest.Remove($_) })
}
#Check if we are in CONSTRAINED MODE localy or remotely
if ($ExecutionContext.Sessionstate.LanguageMode -ne 'FullLanguage') {Write-host "`nThe Local POWERSHELL is not in FULL LANGUAGE MODE. The report will have limited details.`n" -ForegroundColor Yellow; }	
#############################################################################
#If Powershell is running the 32-bit version on a 64-bit machine, we 
#need to force powershell to run in 64-bit mode .
#############################################################################
if (($pshome -like "*syswow64*") -and ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -like "64*")) {
    write-warning "Restarting script under 64 bit powershell"
    # relaunch this script under 64 bit shell
    & (join-path ($pshome -replace "syswow64", "sysnative")\powershell.exe) -file $myinvocation.mycommand.Definition @args
    # This will exit the original powershell process. This will only be done in case of an x86 process on a x64 OS.
    exit
}
# Show a brief help message if no parameters passed
if ($PSBoundParameters.Count -lt 1) { Write-host "`nCreate Server Health report and (optionaly) send it by email.`n  Usage:  .\$($myinvocation.MyCommand.Name) -ServerName localhost -EmailTo it@domain.com -Ignore ROL`n" -ForegroundColor Yellow}
$IgnoreParams = 'Install'
#############################################################################
# - Customizable variables. Setup them for your actual environment
$ScriptDistributionPoint = 'c:\report\'
$WorkDir = "$ENV:ALLUSERSPROFILE\Microsoft\Diagnosis\"
$ReportFilePath = [Environment]::GetFolderPath('MyDocuments')
#$WUDepth = 8 # Number of last Windows Update modules installed
$DriveLowFreeSpaceLimit = 19 #GB
$RAMLowFreeLimit = 1 #GB
$JobRunningLimit = 21 # Minutes
$ExcludeUsers = @('^netwrix','^Symantec',"^Health",'\$$',"LOCAL SERVICE",'NETWORK SERVICE','SYSTEM','ANONYMOUS LOGON',"^SQL","^MSOL",'[0-9a-fA-F]{4,}')
$Global:TaskIgnorePrincipals = @('NT AUTHORITY\SYSTEM','LocalService','LocalSystem','LOCAL SERVICE','NETWORK SERVICE','NT AUTHORITY\SYSTEM','SYSTEM','S-1-5-18','S-1-5-19','S-1-5-20')
# - Setup email related variables
$emailpriority = 2 # High = 2, Low = 1, Normal = 0 
$emailSmtpServerPort = "25"
$EnableSsl = $false
$emailSmtpUser = "username"
$emailSmtpPass = "password"
# - Report html Header
$Header = @"
<!DOCTYPE html><html><head>
<title>$ServerName Health report Report</title>
<style>
    body{ width:100%; min-width:1024px; font-family: Verdana, sans-serif; font-size:14px; /*font-weight:300;*/ line-height:1.2; color:#222222; background-color:#ffffff;}
    .warning { font-family: monospace, monospace; font-size:17px; font-weight: normal; color:red; margin-left:6px; line-height:1; background-color:#fbffdb;}
    strong{ font-weight:600;}
	p{ color:222222;}
	h1{ font-size:17px; font-weight:bold;}
   h2{ font-size:14px; font-weight:normal;}
   h3{ font-size:17px; font-weight:normal; background-color:#f3f3f3; margin-top:3px; margin-bottom:1px; margin-left:4px; text-align:left;}
   table { width:98%; border: 0px solid #6E8BB6; background:#f3f3f3; margin-top:0px;}
	table.scope { width:98%; border-collapse: collapse; border: 0px solid #ffffff; padding:6px; background-color:#f3f3f3; margin-top:24px; text-align:left;}
	table.warning { width:auto; background-color:#f3f587; padding:6px; border-collapse: collapse; border: 0px solid #ffffff; font-family:Arial, Helvetica, sans-serif; font-size:16px; font-weight: normal; color:red; text-align:left;}
	table th { padding:0px; border-collapse: collapse; border: 0px solid #f3f3f3; text-align:left; vertical-align:middle; background-color:#6E8BB6; color:white; font-size:14px; font-weight: bold;}
   table td { padding:1px; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; background-color:#f2f8fc; font-size:12px; font-family: monospace, monospace; margin-left:4px;}
</style>
</head><body>
"@
$Footer = @"
    </div><!--End ReportBody-->
    <br><center><i>$(Get-Date -Format "dd/MM/yyyy HH:mm:ss")</i><p style="" font-size:8px;color:#7d9797"">ScriptVersion: 2023.06 | By: Vladislav Jandjuk | Feedback: jandjuk@arion.cz</p></center>
    <br></body></html>
"@
#End of var area. You have not change the script code below
#############################################################################
Write-Host "Prepare environment on $($ServerName) at $(Get-Date)" -foregroundcolor yellow
#Enabling PSRemote
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ServerName -Concatenate -Force
Enable-WSManCredSSP -Role server -Force
Restart-Service WinRM -Force

#Region - Register System Scheduled Task
if ($install) {
	Write-Host "Install Switch active. The script will be registered on $($ServerName) at as SYSTEM task for 06:00 AM every day" -foregroundcolor yellow
	#copy script to %SystemRoot%
	$scriptpath = $MyInvocation.MyCommand.Path
	try {Copy-Item $scriptpath -Destination $($ENV:SystemRoot + '\SYSTEM32') -Force; $scriptpath = $($ENV:SystemRoot + '\SYSTEM32\' + $MyInvocation.myCommand.name) }
	catch {Write-Error "unable to copy script to the %SYSTEMROOT%, running as is."}
	#Create parameters string to path to the script
	if ($PSBoundParameters.ContainsKey('Install')) {$PSBoundParameters.Remove('Install')}
	foreach($h in $MyInvocation.MyCommand.Parameters.GetEnumerator()){
	   $key = $h.Key;$val = $null;
   	if ($key -and ($IgnoreParams -notmatch $key)) {$val = Get-Variable -Name $key -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
   	if ($val) {[string]$params += $(' -' + $key + ' ' + $val)}
		}
	}
	$reporttask = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $('-NoProfile -NonInteractive -ExecutionPolicy ByPass -command ' + '"& {. ''' + $scriptpath + '''' + $params + ';}"')
	$tasktrigger = New-ScheduledTaskTrigger -Daily -At 6am
	Register-ScheduledTask -TaskName "Send-ServerHealthMailReport" -Action $reporttask -Trigger $tasktrigger -Description "Daily send server health report by email to $($EmailTo)" -User "SYSTEM" -RunLevel Highest -Force
}
# region: Functions
function Convert-Object2BiArray {
[cmdletbinding()]
Param(
    [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$True)]
    [object]$Inputobject
    )
Begin { Write-Verbose "Starting $($myinvocation.mycommand)";}

	Process {
     Write-Verbose "Create array"
     [array]$result = @()
     $Inputobject.PSObject.Properties.foreach({
        $NewPropertyName = ($_.Name | Out-String); $NewPropertyValue = $_.Value
        $NewMember = @{"$NewPropertyName" = $NewPropertyValue}
        Write-Verbose $NewMember
        $result += $NewMember})
	}
End {
    Write-Verbose "Created array with $result.Length members"
    Write-Verbose "Writing results to the pipeline"
    $result
    Write-Verbose "Ending $($myinvocation.mycommand)"
    }
}#end function
function Convert-Array2HTML {
[cmdletbinding()]
Param(
    [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$True)]
    	[array]$InputArray,
	 [parameter(Mandatory=$false)]
    	[switch]$Fragment, 
	 [parameter(Mandatory=$false)]
		[string]$PreContent,
	 [parameter(Mandatory=$false)]
		[string]$PostContent
    )
begin { if (!$Fragment.IsPresent) {$result = "<HTML><TITLE><head></head><BODY>`n"}; $result += $PreContent + "<table>`n" }
Process {     $InputArray.ForEach({$result += $('<TR><TD>{0}</TD><TD>{1}</TD></TR>{2}' -f $_.Name,$_.Value,[Environment]::NewLine)}) } #$('{0} = {1}; ' -f $_.Name,$_.Value)
end{ $result += "</table>`n" + $PostContent; if (!$Fragment.IsPresent) {$result += "</BODY></HTML>`n"}; $result } 
}#end function
function Get-RemoteRegistryValue {
param(
	[string]$ServerName = $env:COMPUTERNAME,
	[string]$Hive = 'LocalMachine',
 	[Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
	[string]$Key = "", # like: "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
	[string]$Value = ""
)
    switch ($Hive) {
    'HKLM' {$Hive = 'LocalMachine'}
    'HKCU' {$Hive = 'CurrentUser'}
    'HKCR' {$Hive = 'ClassesRoot'}
    'HKCC' {$Hive = 'CurrentConfig'}
    'HKPD' {$Hive = 'PerformanceData'}
    'HKU' {$Hive = 'Users'}
    }

    if (($ServerName -eq 'localhost') -or ($ServerName -eq "127.0.0.1")) {$ServerName = $env:COMPUTERNAME}
    try {
        [System.Net.IPAddress]::Parse($ServerName)
        $ServerName = [System.Net.Dns]::GetHostEntry($ServerName)
    } catch {}
	$result = $Null
    try {$RemoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $ServerName)}
    catch {$result = $Null}
    if ($RemoteRegistry) {
        try {
   		    if (![string]::IsNullOrEmpty($Value)) {$result = $RemoteRegistry.OpenSubKey($Key).getvalue($Value)}
		    else {$result = $RemoteRegistry.OpenSubKey($Key)}
        }
        catch {$result = $Null}
    }else {$result = $Null}
    $result
} #function
function Get-PendingRebootState {
param(
	[string]$ServerName = $env:COMPUTERNAME
)
$tests = @(
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootInProgress' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackagesPending' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\PostRebootReporting' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Value 'PendingFileRenameOperations' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Value 'PendingFileRenameOperations2' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SOFTWARE\\Microsoft\\Updates' -Value 'UpdateExeVolatile'}
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' -Value 'DVDRebootSignal' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SOFTWARE\\Microsoft\\ServerManager\\CurrentRebootAttemps' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SYSTEM\\CurrentControlSet\\Services\\Netlogon' -Value 'JoinDomain' }
        { Get-RemoteRegistryValue -ServerName $ServerName -Key 'SYSTEM\\CurrentControlSet\\Services\\Netlogon' -Value 'AvoidSpnSet' }
        { 
				$acn = Get-RemoteRegistryValue -ServerName $ServerName -key 'SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName' -Value 'ComputerName'
				$ccn = Get-RemoteRegistryValue -ServerName $ServerName -Key 'SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName' -Value 'ComputerName'
				if ($acn -and $ccn) {($acn -ne $ccn)} else {$Null}   
        }
        {
            # Added test to check first if key exists
            $pnd = Get-RemoteRegistryValue -ServerName $ServerName -Key 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Services\\Pending'
			if ($pnd -and ($pnd.ValueCount -gt 0))  { $true } else {$Null}
        }
    )
foreach ($test in $tests) { if (& $test) { $true; break } }
} #function
#Region MAIN
#############################################################################
$ComputerRole = @("Standalone Workstation","Member Workstation","Standalone Server","Member Server","Domain Controller","Domain Controller","Unknown Role")
$OSLicensingStatus = @('Unlicensed','Licensed','OOBGrace','OOTGrace','NonGenuineGrace','Notification','ExtendedGrace','Undefined')
# * main script * #
[Collections.ArrayList]$ReportHTMLArray = @()
[Collections.ArrayList]$Problems = @()
if ($emailFrom -notmatch '^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$') {[void]$Problems.Add("<p><div class='warning'>RUNTIME: Warning: `t<i>From address $emailFrom not seems to be valid email address. Report may not being send.</i></div>"); Write-Host "Warning: `tFrom address $emailFrom not seems to be valid email address. Report may not being send." -foregroundcolor Magenta}
#check Distribution Point for a newer version and upgrade itself...
#Write-Host ('ScripDistributionPoint: {0} | Script Path: {1} | Script Name: {2}' -f $ScriptDistributionPoint, $MyInvocation.MyCommand.Path, $MyInvocation.MyCommand.Name) -BackgroundColor DarkCyan -ForegroundColor Yellow
if ((Test-Path -PathType Leaf -LiteralPath ($ScriptDistributionPoint + $MyInvocation.myCommand.name)) -and ((Get-Item ($ScriptDistributionPoint + $MyInvocation.myCommand.name)).LastWriteTime.ticks -gt ((Get-Item $MyInvocation.MyCommand.Path).LastWriteTime.ticks)))
{
	Write-Host ('The Distribution point has the newest version of the script. Starting Upgrade itself') -BackgroundColor DarkYellow -ForegroundColor Black
	try { Copy-Item ($ScriptDistributionPoint + $MyInvocation.myCommand.name) -Destination $($MyInvocation.MyCommand.Path) -Force; }
	catch { Write-Error "ERROR: Impossible to upgrade the script from the $ScriptDistributionPoint, leaving it as is." }
}
#Check Language mode locally and remotely
if ($ExecutionContext.Sessionstate.LanguageMode -ne 'FullLanguage') {[void]$Problems.Add("<p><div class='warning'>RUNTIME: Warning: `t<i>The Local POWERSHELL is not in FULL LANGUAGE MODE. The report will have limited details.</i></div>")}
$remotesesstion = New-PSSession -ComputerName $ServerName
if ((Invoke-Command -Session $remotesesstion -ScriptBlock { $ExecutionContext.SessionState.LanguageMode }).Value -ne 'FullLanguage') {[void]$Problems.Add("<p><div class='warning'>RUNTIME: Warning: `t<i>The POWERSHELL on host $ServerName is not in FULL LANGUAGE MODE. The report will have limited details or unreliable details.</i></div>")}
Remove-PSSession -Id $remotesesstion.Id
Write-Host "Starting gathering date on $($ServerName) at $(Get-Date)" -foregroundcolor yellow
# REGION MODULES
# - STAGE 1 - #
# Check Server IP address and issue warning if the public IP is detected
# Test Connection and warn if no responce
if (!(test-connection $ServerName -count 1 -quiet -ea 0)) {Write-Warning "No responce from the host $ServerName."; [void]$Problems.Add("<p><div class='warning'>RUNTIME: Warning: `t<i>No ping responce from the host: $ServerName.</i></div>")}
$ServerNameIPResolved =  ((Test-Connection $ServerName -count 1 | Select-Object @{Name=$ServerName;Expression={$_.Address}},Ipv4Address).IPV4Address).IPAddressToString
if (($ServerNameIPResolved -NOTMATCH "^192\.168\.") -AND ($ServerNameIPResolved -NOTMATCH "^172\.(1[6-9]|2[0-9]|3[0-1])\.") -AND ($ServerNameIPResolved -NOTMATCH "^10\.") -AND ($ServerNameIPResolved -NOTMATCH "^127\.0\.0")) {
	Write-Warning "The IP Address for host $ServerName is resolved to Public v4 IP [$ServerNameIPResolved]. Report could may be proceeded incorrectly."; [void]$Problems.Add("<p><div class='warning'>RUNTIME: Warning: `t<i>The IP Address for host $ServerName is resolved to Public v4 IP [$ServerNameIPResolved]. Report could not be proceeded correctly.</i></div>")
	#try to obtain Host local IP 
	$HostIpv4Addresses = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ServerName -filter 'IPEnabled="True"' | Select-Object -expand IPAddress | Where-Object{$_ -notmatch ':'}
	$HostIpv4Addresses.foreach({if (($_ -MATCH "^192\.168\.") -or ($_ -MATCH "^172\.(1[6-9]|2[0-9]|3[0-1])\.") -or ($_ -MATCH "^10\.")) {$ServerName = $_} 
	else {
		[void]$Problems.Add("<p><div class='warning'>NET: Warning: `t<i>The host $ServerName has Public IP v4 address [$_].</i></div>")
		
	}})
}
$HostName = (Get-WmiObject win32_computersystem -ComputerName $ServerName).Name
try {$InternetInfo = Invoke-RestMethod "http://ipinfo.io/json" | Select-Object ip,hostname,city,region,country
	[void]$ReportHTMLArray.Add($($InternetInfo | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3><H3>HOST: <font color=green>$($HostName) </font> | Internet Connection info </H3></td></tr></table>"))
	if (($emailFrom -notmatch '^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$') -and ($InternetInfo)) {$EmailFrom = $InternetInfo.hostname -replace '^(.*?)\.', '${1}@'}
	}
catch {[void]$Problems.Add("<p><div class='warning'>NET: Warning: `t<i>The host $ServerName has probably no internet access.</i></div>")}
 
#get computername and domain name
	Write-Verbose "We are running on $ServerName and getting report for the $HostName..."
	$DomainName = ((Get-WmiObject win32_computersystem -ComputerName $ServerName).Domain -Split "\.")[0]
	Write-Verbose "Host Name is : $HostName ; Local Domain is : $DomainName"
	$DCName = (Get-WmiObject -Class win32_ntdomain -Filter "DomainName = '$DomainName'" -ComputerName $ServerName).DomainControllerName
	if (!$DCName) {[void]$Problems.Add("<p><div class='warning'>LAN: Warning: `t<i>No Domain Controller found.</i></div>")}
	Write-Verbose "DC Name is $DCName"
# - STAGE 1 - #
# - Get OS Info
	$computerSystem = get-wmiobject Win32_ComputerSystem -ComputerName $ServerName | Select-Object -property *
	if ($computerSystem.DomainRole -lt 2) {[void]$Problems.Add("<p><div class='warning'>OS: Warning: `t<i>Target OS at $ServerName is not Server OS. Result may not be reliable.</i></div>")}
	$computerOS = get-wmiobject Win32_OperatingSystem -ComputerName $ServerName | Select-Object -property *
	$OSLicensing = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ComputerName $ServerName | Where-Object { $_.PartialProductKey } | Select-Object Name, Description, LicenseStatus
	if ($OSLicensing.LicenseStatus -ne 1) {[void]$Problems.Add("<p><div class='warning'>OS: Warning: `t<i>The licensing status for the $HostName is not normal: $($OSLicensingStatus[$OSLicensing.LicenseStatus]).</i></div>")}
$HostOSinfo = [PSCustomObject]@{ 'Installed' = ([Management.ManagementDateTimeConverter]::ToDateTime($computerOS.InstallDate)).ToString("dd.MM.yyyy"); 'PCName' = $computerOS.PSComputerName; 'Role' = $ComputerRole[$computerSystem.DomainRole]; 'Domain' = $DomainName; 'Note' = $computerOS.Description; 'BootTime' = ([Management.ManagementDateTimeConverter]::ToDateTime($computerOS.LastBootUpTime)).ToString("dd.MM.yyyy"); 'BootupState' = $computerSystem.BootupState; 'OS' = $computerOS.caption; 'SP' = $computerOS.ServicePackMajorVersion; 'Owner' = $computerOS.RegisteredUser; "Free RAM (GB)" = [math]::ceiling($computerOS.FreePhysicalMemory /1MB); 'WinDir' = $computerOS.WindowsDirectory; 'OS Lang' = [System.Globalization.CultureInfo]::GetCultureInfo([int]$computerOS.OSLanguage).DisplayName; 'Reboot Pending' = (Get-PendingRebootState -ServerName $ServerName) }
if (!$HostOSinfo) {[void]$Problems.Add("<p><div class='warning'>OS: Error: `t<i>No Access to WMI at $ServerName.</i></div>")}
	if ([math]::ceiling($computerOS.FreePhysicalMemory /1MB) -lt $RAMLowFreeLimit) {[void]$Problems.Add("<p><div class='warning'>OS: Warning: `t<i>Low Free RAM on $ServerName : $([math]::ceiling($computerOS.FreePhysicalMemory /1MB)) GB.</i></div>")}
	[void]$ReportHTMLArray.Add($($HostOSinfo | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Operating System </H3></td></tr></table>"))
	[void]$ReportHTMLArray.Add($($OSLicensing | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Operating System Licensing State</H3></td></tr></table>"))
# - STAGE 2 - #
#get currently logged on usesrs - from QUSER
$rLUS = { #RUN Remotely		
param ($ServerName)
function Is-Admin { #test does the user hold the high privilege on local system
param(
	  [Parameter(Position=0, ValueFromPipelineByPropertyName=$true)]
		[string]$UserName
	)
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$userprincipal = ([System.DirectoryServices.AccountManagement.UserPrincipal]) -as [type]
		$up = $userprincipal::FindByIdentity([system.DirectoryServices.Accountmanagement.contextType]::Domain,[System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName,$UserName)
		if ($up) { 
			$ID = New-Object Security.Principal.WindowsIdentity -ArgumentList $UserName
			$ID.Claims.Value.Contains('S-1-5-32-544')
		}
		else {
			$up = $userprincipal::FindByIdentity([System.DirectoryServices.AccountManagement.ContextType]::Machine,[System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName,$UserName)
			$up.GetGroups().sid.Value.Contains('S-1-5-32-544')
		}
	}
function Get-LocalRegistryValue {
param(
	[string]$ServerName = $env:COMPUTERNAME, #dummi, not used
	[string]$Hive = 'HKLM',
 	[Parameter(Mandatory)]
   [ValidateNotNullOrEmpty()]
	[string]$Key = "", # like: "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
	[string]$Value = ""
)
$result = $Null
    switch ($Hive) {
    'LocalMachine' {$Hive = 'HKLM'}
    'CurrentUser' {$Hive = 'HKCU'}
    #'ClassesRoot' {$Hive = 'HKCR'}
    #'CurrentConfig' {$Hive = 'HKCC'}
    #'PerformanceData' {$Hive = 'HKPD'}
    #'Users' {$Hive = 'HKU'}
    }
    
    if (![string]::IsNullOrEmpty($Value)) {$result = Get-ItemPropertyValue -Path ($Hive + ":\" + $Key) -Name $Value}
    else {
        #(Get-Item -Path ($Hive + ":\" + $Key)).foreach({$result += [pscustomobject]@{"property"=$_.PSChildName; "Value" = $_.PSChildValue}})
        Get-Item -Path ($Hive + ":\" + $Key) | Select-Object -ExpandProperty property | ForEach-Object {$result += [pscustomobject]@{"property"=$_; "Value" = (Get-ItemProperty -Path ($Hive + ":\" + $Key) -Name $_).$_}}
    }
$result
} #function
	<#
	MaxConnectionTime
	MaxDisconnectionTime
	MaxIdleTime
	#>
		$w = @()
			$RDPlimits = Get-LocalRegistryValue -ServerName $ServerName -RegValue 'MaxDisconnectionTime'
			if ((!$RDPlimits) -or ([int]$RDPlimits -eq 0)){$w += "<p><div class='warning'>OS: Warning: `t<i>RDP Session MaxDisconnectionTime is not limited $($RDPlimits).</i></div>"}
			$RDPlimits = Get-LocalRegistryValue -ServerName $ServerName -RegValue 'MaxIdleTime'
			if ((!$RDPlimits) -or ([int]$RDPlimits -eq 0)){$w += "<p><div class='warning'>OS: Warning: `t<i>RDP Session MaxIdleTime is not limited $($RDPlimits).</i></div>"}  
			$RDPlimits = Get-LocalRegistryValue -ServerName $ServerName -RegValue 'MaxConnectionTime'
			if ((!$RDPlimits) -or ([int]$RDPlimits -eq 0)){$w += "<p><div class='warning'>OS: Warning: `t<i>RDP Session MaxConnectionTime is not limited $($RDPlimits).</i></div>"}  
			$lousers = [object[]]((quser /server:$ServerName | ForEach-Object { (($_.trim() -replace " {2,}",","))} | ConvertFrom-Csv))
			$qry = 'SELECT * FROM Win32_Process WHERE Name="explorer.exe"'
			$lousers.foreach({ [string]$tn=$_.Username
			    $_.Username = Get-WmiObject -Query $qry -ComputerName $ServerName| ForEach-Object { $_.GetOwner() } | where {$_.User -match $tn } | ForEach-Object {'{0}\{1}' -f $_.Domain, $_.User}
			    if (Is-Admin $tn) {$_.psobject.properties.Add([psnoteproperty]::new("Is Local Admin",$true)); $w += "<p><div class='warning'>OS: Warning: `tHigh privileged account <i>$tn</i> has active session.</div>"} else {$_.psobject.properties.Add([psnoteproperty]::new("Is Local Admin",$false))}
			})
			if (!$lousers) { # if no results from QUSER try to use WMI
				$regexU = '({0})' -f ($ExcludeUsers -join "|")
				$lousers = Get-WmiObject Win32_LoggedOnUser -ComputerName $ServerName | Select-Object -Property * | Select-Object Antecedent -Unique | Where-Object { $_.Antecedent.ToString().Split('"')[1] -ne $ServerName -and $_.Antecedent.ToString().Split('"')[1] -ne "Window Manager" -and $_.Antecedent.ToString().Split('"')[3] -notmatch $ServerName } | ForEach-Object{"{0}\{1}" -f $_.Antecedent.ToString().Split('"')[1],$_.Antecedent.ToString().Split('"')[3]}
				$lousers = $lousers.where{$_ -notmatch $regexU}
				$lousers.foreach({if (Is-Admin $_) {$_.psobject.properties.Add([psnoteproperty]::new("Is Local Admin",$true)); $w += "<p><div class='warning'>OS: Warning: `tHigh privileged account <i>$_</i> has active session.</div>"} else {$_.psobject.properties.Add([psnoteproperty]::new("Is Local Admin",$false))}
				})
			}
		if (!$lousers) {$w += "<p><div class='warning'>OS: Warning: `t<i>No Logged Users detected.</i></div>"}
		$lousers.foreach({ if ((Get-Date - Get-Date($_."LOGON TIME")).TotalMinutes -gt 1440) { $w += "<p><div class='warning'>OS: Warning: `t<i>The user $($_.USERNAME) has old session.</i></div>"} })
		[pscustomobject]@{'Warnings'=$w; 'report'=$lousers}
}
# - STAGE 3 - #
# - Get HW Info
$rWHW = { #run remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$computerBIOS = get-wmiobject Win32_BIOS -ComputerName $ServerName
		$computerSystem = get-wmiobject Win32_ComputerSystem -ComputerName $ServerName | Select-Object -property *
		#$TPMInfo = Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm -ComputerName $ServerName
		$TPMInfo = Get-TPM -ea 0
		if ($TPMInfo) {$TPMEnabled = $TPMInfo.TpmEnabled; $TPMPresent = $TPMInfo.TpmPresent} else {$TPMEnabled = $false; $TPMPresent = $false}
		$SecBOOTEnabled = Confirm-SecureBootUEFI
		#Build the HW info object 
	[void]$r.Add([PSCustomObject]@{ 'Manufacturer' = $computerSystem.Manufacturer; 'Model' = $computerSystem.Model; 'BIOS Vendor' = $computerBIOS.Manufacturer; 'SerialNumber' = $computerBIOS.SerialNumber; 'BIOS Version' = $computerBIOS.SMBIOSBIOSVersion; 'RAM (GB)' = "{0:N1}" -f ($computerSystem.TotalPhysicalMemory/1GB); 'TPM Present' = $TPMPresent; 'TPM Enabled' = $TPMEnabled; 'Secure BOOT' = $SecBOOTEnabled;})
	if (($computerSystem.TotalPhysicalMemory/1GB) -le 8) { $w = "<p><div class='warning'>RAM: Warning: `t<i>The total amount of RAM installed is insufficient.</i></div>" }
	if (($computerSystem.TotalPhysicalMemory/1GB) -le 4) { $w = "<p><div class='warning'>RAM: Error: `t<i>The total amount of RAM installed is low.</i></div>" }
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rCPU = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
	 	$computerCPU = [object[]](get-wmiobject Win32_Processor -ComputerName $ServerName -Property DeviceID, Name, NumberOfCores, NumberOfLogicalProcessors, SocketDesignation, MaxClockSpeed)
		$computerCPU.Foreach({
			[void]$r.Add([PSCustomObject]@{ 'CPU' = $_.Name; 'Socket' = $_.SocketDesignation; 'Cores' = $_.NumberOfCores; 'Logical Processors' = $_.NumberOfLogicalProcessors; 'Freq GHz' = [math]::floor($_.MaxClockSpeed/1024) })
			if ($_.NumberOfLogicalProcessors -le 2) { $w = "<p><div class='warning'>CPU: Warning: `t<i>The number of CPU cores is low.</i></div>" }
		})
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rHDD = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$computerHDD = ([object[]](Get-WmiObject Win32_LogicalDisk -ComputerName $ServerName)).where({$_.Size -gt 0})
		$computerHDD.Foreach({
			[void]$r.Add([PSCustomObject]@{'Drive' = $_.DeviceID; 'Label' = $_.VolumeName; 'Size (GB)' = "{0:N2}" -f ($_.Size/1GB); 'Free (GB)' = "{0:N2}" -f ($_.FreeSpace/1GB); '% Free' = "{0:P2}" -f ($_.FreeSpace/$_.Size);}); 
			if (($_.FreeSpace/1GB) -lt $DriveLowFreeSpaceLimit) {$w +="<p><div class='warning'>OS: Warning: `t<i>Drive free space is low, drive: $_.DeviceID free space: $([math]::ceiling($_.FreeSpace/1GB)) GB.</i></div>"}
		}) 
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 4 - #
# - Get network config - run remotely
$rNET = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$colItems = [object[]](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $ServerName  | Select-Object -Property *)
		$colItems | foreach-object {
		   $ips = $_ | Select-Object -Property @{N='IPAddresses'; E={($_.IPAddress.where({$_ -like '*.*'})) -join ", ::"}};
		   $sns = $_ | Select-Object -Property @{N='IPSubnet'; E={($_.IPSubnet.where({$_ -like '*.*'})) -join ", ::"}}
			$InterfaceIndex = $_.InterfaceIndex; $nls = Get-NetAdapter | Where-Object {$_.InterfaceIndex -eq $InterfaceIndex} | Select-Object -Property Name,LinkSpeed,InterfaceOperationalStatus,MediaConnectionState,VlanID
			$bindings = Get-NetAdapterBinding  * -AllBindings | Where-Object {($_.Name -eq $nls.Name) -and $_.Enabled} ; $bProtocols = $bindings.DisplayName -join ", ::"
			$_.IPAddress.where({$_ -like '*.*'}).foreach({
				if (($_ -NOTMATCH "^192\.168\.") -AND ($_ -NOTMATCH '^172\.(1[6-9]|2[0-9]|3[0-1])\.') -AND ($_ -NOTMATCH "^10\.")) {
					$w +="<p><div class='warning'>LAN: Warning: `t<i>NIC: [$($nls.Name)] has public IP address [$_] binded.</i></div>"; $nip = $_
					$bindings.foreach({if ($_.ComponentID -match "_server|_netbios|_msclient") {$w +="<p><div class='warning'>LAN: Warning: `tNIC: [$($_.Name)] has MS NET protocol [$($_.ComponentID)] binded to the public IP address [$nip].</i></div>"}}) 
				}
			 })
			$DNSConfig = (Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily ipv4).ServerAddresses -join ", ::"
			$aNIC = [PSCustomObject]@{'MAC Address' = [string]$_.MACAddress;'Interface Index' = $_.InterfaceIndex; 'Description' = [string]$_.Description; 'DHCP Enabled' = $_.DHCPEnabled; 'DHCP Server' = $_.DHCPServer; $ips.psobject.Properties.name = $ips.psobject.Properties.value; $sns.psobject.Properties.name = $sns.psobject.Properties.value; 'Default IPGateway' = [string]$_.DefaultIpGateway; "DNS Servers" = $DNSConfig; 'DNS HostName' = [string]$_.DNSHostName; 'DNS Domain' = $_.DNSDomain}
			$nls.PSObject.Properties.ForEach({$aNIC.psobject.properties.Add([psnoteproperty]::new($_.Name,$_.Value)) })
			$aNIC.psobject.properties.Add([psnoteproperty]::new("Binded Protocols",$bProtocols)) 
			$aNIC.psobject.properties.Add([psnoteproperty]::new("Network Profile",(get-NetConnectionProfile -InterfaceIndex $InterfaceIndex).NetworkCategory))
			[void]$r.Add($aNIC)
			if ($nls.MediaConnectionState -ne 'Connected') {$w +="<p><div class='warning'>LAN: Warning: `t<i>NIC: $($aNIC.Name) link is down.</i></div>"}
		}
		#for export multiattrib join @{l="IPAddress";e={$_.IPAddress -join " "}}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 5 - #
# - Get top Processes
$rPRAM = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$TopRAMProc = Get-CimInstance Win32_Process -ComputerName $ServerName | Select-Object -Property * | Sort-Object -Descending -Property WorkingSetSize | Select-Object -Property ProcessId,ProcessName,CommandLine,CreationDate,@{Name="Memory MB"; Expression = {[Math]::Round(($_.WorkingSetSize / 1mb),2)}} -First 5
		$TopRAMProc.foreach({[void]$r.Add($_)})
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rPCPU = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		[int]$LogicalProcessors = 0; ([object[]]( Get-CimInstance -class Win32_processor -ComputerName $ServerName -Property NumberOfLogicalProcessors).NumberOfLogicalProcessors).foreach({$LogicalProcessors += [int]$_})
		$TopCPUProc = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ComputerName $ServerName  -filter '(PercentProcessorTime > 1) AND (NAME <> "_Total") AND (NAME <> "Idle")' | Sort-Object PercentProcessorTime -desc | Select-Object Name,@{Name="Memory MB"; Expression = {[Math]::Round(($_.workingSet / 1mb),0)}},@{Name='CPU Usage'; Expression = {[Math]::Round(($_.PercentProcessorTime / $LogicalProcessors),1)}}  
		$TopCPUProc.foreach({[void]$r.Add($_); if ($_.'CPU Usage' -gt 50) {$w +="<p><div class='warning'>PRC: Warning: `t<i>The Process: $($_.Name) use too much CPU $($_.'CPU Usage').</i></div>"} })
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rPUNS = { # Unsigned running processes : run remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$allPRC = get-process -FileVersionInfo -ea 0 | Select-Object OriginalFilename, FileDescription, CompanyName, FileName -Unique
		foreach ($prc in $allPRC) {
         if ($prc.FileName) {$prcSign = (Get-AuthenticodeSignature -FilePath $prc.FileName -ea SilentlyContinue)}
			if ($prcSign) {
				$prc.psobject.properties.Add([psnoteproperty]::new('SignatureStatusMessage',$prcSign.StatusMessage))
				$prc.psobject.properties.Add([psnoteproperty]::new('SignatureStatus',$prcSign.Status))
				$prc.psobject.properties.Add([psnoteproperty]::new('SignatureSubject',$prcSign.SignerCertificate.Subject))
         }
         else {$prc.psobject.properties.Add([psnoteproperty]::new('SignatureStatus','unknown'))}
			if ($prcSign.Status -ne 'Valid') {[void]$r.Add($($prc | Select-Object OriginalFilename,FileDescription,CompanyName,FileName,SignatureStatus,SignatureSubject))}
		}
		if ($r.count -gt 1) {$w +="<p><div class='warning'>PROC: Warning: `t<i>Some running processes have untrusted signature.</i></div>"}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 6 - #
# - Get Services Anomalies
$rSVC = { # Get Services anomalies : run remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$DomainName = (Get-CimInstance win32_computersystem -ComputerName $ServerName).Domain
		$AllServices = Get-CimInstance -Namespace root\cimv2 -Class Win32_Service -ComputerName $ServerName | Select-Object -Property *
		foreach ($svc in $AllServices) {
			$svc.psobject.properties.Add([psnoteproperty]::new('AssemblyPath',$($svc.PathName -replace '(\s{1,}(\-{1,2}|\/).*){1,}$')))
			$svc.AssemblyPath = $svc.AssemblyPath -replace '"'
			if ((-Not ($svc.AssemblyPath | Test-Path -PathType Leaf)) -and (!$svc.AssemblyPath -match '.exe$')) {$svc.AssemblyPath = ($svc.AssemblyPath + '.exe')}
			if (-Not ($svc.AssemblyPath | Test-Path)) {$w ="<p><div class='warning'>SVC: Warning: `t<i>Service with missed executable was found on the host $ServerName.</i></div>"
				[void]$r.Add($($svc | Select-Object -Property Name,DisplayName,StartMode,State,Status,StartName,PathName,AssemblyPath,SignatureStatusMessage,SignatureStatus,SignatureSubject))
			} #Service Exe not found
		else
		{
			$svcSign = (Get-AuthenticodeSignature -FilePath ($svc.AssemblyPath))
			$svc.psobject.properties.Add([psnoteproperty]::new('SignatureStatusMessage', $svcSign.StatusMessage))
			$svc.psobject.properties.Add([psnoteproperty]::new('SignatureStatus', $svcSign.Status))
			$svc.psobject.properties.Add([psnoteproperty]::new('SignatureSubject', $svcSign.SignerCertificate.Subject))
			#DEBUG
			#$w +="<p>($svc | Select-Object -Property Name,DisplayName,StartMode,State,Status,StartName,PathName,AssemblyPath,SignatureStatusMessage,SignatureStatus)"
		}
		if ((($svc.StartMode -eq "Auto") -and ($svc.State -ne "Running")) -or ($svc.StartName -match $DomainName) -or ($svc.StartName -match $ServerName)) {[void]$r.Add($($svc | Select-Object -Property Name,DisplayName,StartMode,State,Status,StartName,PathName,AssemblyPath,SignatureStatusMessage,SignatureStatus,SignatureSubject))}
		elseif ($svcSign.Status -ne 'Valid') {[void]$r.Add($($svc | Select-Object -Property Name,DisplayName,StartMode,State,Status,StartName,PathName,AssemblyPath,SignatureStatusMessage,SignatureStatus,SignatureSubject))} 
		}  
		if ($r.count -gt 1) {$w +="<p><div class='warning'>SVC: Warning: `t<i>Strange Services detected.</i></div>"} 	
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 7 - #
# - Get last windows update installed
$rWUH = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		[array]$ResultCode = @('Unknown','In Progress','Succeeded','Succeeded With Errors','Failed','Aborted') 
		# Get a WUA Session
		$session = (New-Object -ComObject 'Microsoft.Update.Session')
		$searcher = $session.CreateUpdateSearcher()  
		$historyCount = $searcher.GetTotalHistoryCount() 
		$history = $session.QueryHistory("",0,$historyCount) | Where-Object {![String]::IsNullOrWhiteSpace($_.title)} | ForEach-Object {
			$Result = $ResultCode[$_.ResultCode]
			# Make the properties hidden in com properties visible.
			$_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
			$Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
			$_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
			$_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
			$_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
		}
		#Remove null records and only return the fields we want
		$history | Where-Object {![String]::IsNullOrWhiteSpace($_.title)} | Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber  | Group-Object -Property Product | ForEach-Object {$_.Group | Select-Object -First 1 } | foreach-object {[void]$r.Add($_)}
	   if ($r.count -lt 1) {$w +="<p><div class='warning'>WUH: Warning: `t<i>Unable to get Windows Update History.</i></div>"}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rWUA = { #run remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$session = New-Object -ComObject "Microsoft.Update.Session"
		$updatesearcher = $session.CreateUpdateSearcher()
		$searchresult = $updatesearcher.Search("IsInstalled=0")
		
		foreach ($update in $searchresult.Updates) {
		  $out = New-Object -Type PSObject -Prop @{
		    'Title' =  $update.Title
		    'KB' = $($update.KBArticleIDs)
		  }
		  [void]$r.Add($out)
		}
	if ($r.count -gt 3) {$w +="<p><div class='warning'>WUA: Warning: `t<i>Too much Windows Updates available were not installed.</i></div>"}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 8 - #
# - Get Installed Roles
$rROL = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$ActiveRoles = Get-WindowsFeature -ComputerName $ServerName | Where-Object {$_.InstallState -eq 'Installed'} | Select-Object -property Name,DisplayName,Description,Installed,InstallState,FeatureType,Path,PostConfigurationNeeded 
		$ActiveRoles.foreach({[void]$r.Add($_)})
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 8 - #
# - Get AV Status
function Detect-WindowsAVInstalled { #Detect AV intalled and get basic info
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
	if ((get-wmiobject Win32_ComputerSystem -ComputerName $ServerName).DomainRole -lt 2) { #Client OS
		$AVInstalled = [object[]](Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ComputerName $ServerName) #Check does any AV SW installed
		if ($AVInstalled) { #AV installd, getting basic info
			foreach ($item in $AVInstalled) {
            $hx = '0x{0:x}' -f $item.ProductState; $mid = $hx.Substring(3, 2); $end = $hx.Substring(5)
            if ($mid -match "00|01") { $Enabled = $False; $w += "<p><div class='warning'>WAV: Warning: `t<i>$ServerName has Antivirus $($item.Displayname) disabled.</i></div>" } else { $Enabled = $True }
            if ($end -eq "00") { $UpToDate = $True } else { $UpToDate = $False; $w += "<p><div class='warning'>WAV: Warning: `t<i>$ServerName has Antivirus $($item.Displayname) out of date.</i></div>"  }
				#Collecting results
            [void]$r.Add($($item | Select-Object @{Name='Antivirus Installed'; Expression = { $true} }, Displayname, ProductState, @{Name = "Enabled"; Expression = { $Enabled } }, @{Name = "UpToDate"; Expression = { $UptoDate } }, @{Name = "Path"; Expression = { $_.pathToSignedProductExe } }, Timestamp))
			}
		} #if
		else { #AV SW Not Detected
			$w += "<p><div class='warning'>WAV: Warning: `t<i>$ServerName has no Antivirus installed.</i></div>"
		}
	}
	else { #Server OS
		$WinDefender = Get-WindowsFeature -ComputerName $ServerName | Where-Object {$_.InstallState -eq 'Installed' -and $_.DisplayName -match 'Defender'}
				#Collecting results
      if ($WinDefender) {[void]$r.Add([PSCustomObject]@{'Antivirus Installed'=$true; DisplayName='Windows Defender Antivirus'})}
		else { $Enabled = $False; $w += "<p><div class='warning'>WAV: Warning: `t<i>Windows Defender AV not installed.</i></div>"
		#TODO: try to detect other AV installed
		}
	}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rWDfC = {
		#Todo: Extract from remote session: New-CimSession -ComputerName $ServerName -Name GetWFWRemote
		# Get-MpComputerStatus -CimSession GetWFWRemote
		#Or Invoke-Command -computername $ServerName -scriptblock $ParseWFWRules -JobName "ParseWFWRules" -AsJob
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$WAVStatus = Get-MpComputerStatus | Select-Object -Property AMRunningMode, AMServiceEnabled, AntispywareEnabled, AntispywareSignatureAge, AntivirusEnabled, AntivirusSignatureAge, BehaviorMonitorEnabled, ComputerState, DefenderSignaturesOutOfDate, DeviceControlState, IoavProtectionEnabled, IsTamperProtected, IsVirtualMachine, NISEnabled, NISSignatureAge, OnAccessProtectionEnabled, RealTimeProtectionEnabled, RebootRequired, SmartAppControlState
		if (!$WAVStatus) {$w += "<p><div class='warning'>WAV: Warning: `t<i>Unable to get Windows Defender configuration.</i></div>"}
		[void]$r.Add($WAVStatus)
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rWDfE = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$WAVExclusions = Get-MpPreference | Select-Object -Property Exclusion*
		foreach ($Property in $WAVExclusions.PSObject.Properties) {
			$Property.Value.foreach({if ($_ -match '^[a-zA-Z]+:\\$') {$w += "<p><div class='warning'>WAV: Warning: `t<i>AV exclusion contains some root folder(s).</i></div>"}})
			$Property.Value = ($Property.Value) -join "`n::"
		}
		if (!$WAVExclusions) {$w += "<p><div class='warning'>WAV: Warning: `t<i>Unable to get Windows Defender exclusion list.</i></div>"}
		[void]$r.Add($WAVExclusions)
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 9 - #
$rFWC = { #Get WFW status : run remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		Get-NetFirewallProfile | Select-Object -Property Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,Log* | foreach-object {
		[void]$r.Add($_);
		if (!$_.Enabled) {$w += "<p><div class='warning'>WFW: Warning: `t<i>The firewall profile $($_.Name) is disabled.</i></div>"} 
		}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rFWR = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$WFWRuleGroups = get-NetFireWallRule | Where-Object {$_.Enabled -eq $true -and $_.Action -eq 'Allow'} | Sort-Object -Unique -Property group | Sort-Object -Property Direction
		$WFWRuleGroups.foreach({[void]$r.Add($($_ | Select-Object -Property DisplayGroup,DisplayName,Name,Profile,direction))})
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rFWP = { #Analyze Windows Firewall Rules : run remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		Get-NetFirewallPortFilter | ForEach-Object {
			$fwRule = $_ | Get-NetFirewallRule; $fwapp = ($fwRule | Get-NetFirewallApplicationFilter).Program
			if ($fwRule.Action -eq 'Allow' -and  $fwRule.Enabled -eq $true -and $fwRule.Direction -eq 'Inbound') {$lport = $_.LocalPort; [void]$r.Add(($fwRule | Select-Object -Property DisplayGroup,DisplayName,Profile,direction,@{n='LocalPort';e={$lport}} | Sort-Object -property LocalPort))}
			if ($fwRule.Action -eq 'Allow' -and  $fwRule.Enabled -eq $true -and $fwRule.Direction -eq 'Inbound' -and $_.LocalPort -eq 'Any' -and $_.RemotePort -eq 'Any' -and $fwapp -eq 'Any') {$w += "<p><div class='warning'>WFW: Warning: `t<i>Any-Any firewall rule detected: $($fwRule.DisplayName) ($($fwRule.Profile)).</i></div>"}
		}
		$w = $w | sort-object -Unique
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 10 - #
# - SW inventory
$rAPP = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$keys = '','\Wow6432Node'
		foreach ($key in $keys) {
		      try {
		          $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ServerName)
		          $apps = $reg.OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
		      } catch {
		          continue
		      }
		      foreach ($app in $apps) {
		          $program = $reg.OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
		          $name = $program.GetValue('DisplayName')
					 if (($name -match 'Antivirus')) {$w += "<p><div class='warning'>WAV: Warning: `t<i>There is the $($Name) antivirus is probably installed.</i></div>"}		
		          [void]$r.Add([pscustomobject]@{
		                  DisplayName = $name
		                  DisplayVersion = $program.GetValue('DisplayVersion')
		                  Publisher = $program.GetValue('Publisher')
		                  InstallDate = $program.GetValue('InstallDate')
		                  UninstallString = $program.GetValue('UninstallString')
		                  Bits = $(if ($key -eq '\Wow6432Node') {'32'} else {'64'})
		                  Path = $program.name
		              })
		      }
		}
[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 11 - #
# - EVT LOGs errors & Warning - last 24h.
$rEVTS = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$LastEventsCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "System"; Level = 2; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		if ($LastEventsCount -gt 24) {$w += "<p><div class='warning'>EVT SYS: Warning: `t<i>Too mach Errors in Event Log in last 24h.</i></div>"}
		Get-EventLog -ComputerName $ServerName -LogName "System" -After (Get-Date).AddHours(-24) -Newest $LastEventsCount -EntryType "Error" -Source '*' | Sort-Object -property eventid -Unique | Sort-Object Index -Descending | foreach-object {[void]$r.Add($($_ | Select-Object -Property TimeGenerated,EntryType,EventID,MachineName,Category,Source,Message))}
		$LastEventsCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "System"; Level = 3; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		if ($LastEventsCount -gt 72) {$w += "<p><div class='warning'>EVT SYS: Warning: `t<i>Too mach Warnings in Event Log in last 24h.</i></div>"}
		Get-EventLog -ComputerName $ServerName -LogName "System" -After (Get-Date).AddHours(-24) -Newest $LastEventsCount -EntryType "Warning" -Source '*' | Sort-Object -property eventid -Unique | Sort-Object Index -Descending | foreach-object {[void]$r.Add($($_ | Select-Object -Property TimeGenerated,EntryType,EventID,MachineName,Category,Source,Message))}
		$EVTLogAge = [math]::Ceiling(((Get-Date) - ([DateTime]((Get-WinEvent -ComputerName $ServerName -LogName System -MaxEvents 1 -Oldest).TimeCreated))).TotalDays)
		$w += "<p><div class='warning'>EVT SYS: Warning: `t<i>The SYSTEM log age is $($EVTLogAge) days.</i></div>"
		$EVTLogAge = [math]::Ceiling(((Get-Date) - ([DateTime]((Get-WinEvent -ComputerName $ServerName -LogName Security -MaxEvents 1 -Oldest).TimeCreated))).TotalDays)
		$w += "<p><div class='warning'>EVT SYS: Warning: `t<i>The SECURITY log age is $($EVTLogAge) days.</i></div>"
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rEVTA = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		$LastEventsCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "Application"; Level = 2; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		if ($LastEventsCount -gt 48) {$w += "<p><div class='warning'>EVT APP: Warning: `t<i>Too mach Errors in Event Log in last 24h.</i></div>"}
		Get-EventLog -ComputerName $ServerName -LogName "Application" -After (Get-Date).AddHours(-24) -Newest $LastEventsCount -EntryType "Error" -Source '*' | Sort-Object -property eventid -Unique | Sort-Object Index -Descending | foreach-object {[void]$r.Add($($_ | Select-Object -Property TimeGenerated,EntryType,EventID,MachineName,Category,Source,Message))}	
		$LastEventsCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "Application"; Level = 3; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		if ($LastEventsCount -gt 72) {$w += "<p><div class='warning'>EVT APP: Warning: `t<i>Too mach Warnings in Event Log in last 24h.</i></div>"}
		Get-EventLog -ComputerName $ServerName -LogName "Application" -After (Get-Date).AddHours(-24) -Newest $LastEventsCount -EntryType "Warning" -Source '*' | Sort-Object -property eventid -Unique | Sort-Object Index -Descending | foreach-object {[void]$r.Add($($_ | Select-Object -Property TimeGenerated,EntryType,EventID,MachineName,Category,Source,Message))}
		$EVTLogAge = [math]::Ceiling(((Get-Date) - ([DateTime]((Get-WinEvent -ComputerName $ServerName -LogName Application -MaxEvents 1 -Oldest).TimeCreated))).TotalDays)
		$w += "<p><div class='warning'>EVT SYS: Warning: `t<i>The APPLICATION log age is $($EVTLogAge) days.</i></div>"
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
# - STAGE 12 - #
# - Users & Groups Analysis
$rGRP = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
	if ($ServerName -eq 'localhost') {$ServerName = $Env:Computername} #localhost bug on some systems
	$computer = [ADSI]"WinNT://$ServerName"
	$result = @()
		$Counter = 1
		#Get Local Groups
		foreach($adsiObj in $computer.psbase.children)
		{
		switch -regex($adsiObj.psbase.SchemaClassName)
			{
			"group"
			{
				$group = $adsiObj.name
				$LocalGroup = [ADSI]"WinNT://$ServerName/$group,group"
				$Members = @($LocalGroup.psbase.Invoke("Members"))
				$GName = $group.tostring()
				ForEach ($Member In $Members) {
				$Name = $Member.GetType().InvokeMember("Name", "GetProperty", $Null, $Member, $Null)
				$Path = $Member.GetType().InvokeMember("ADsPath", "GetProperty", $Null, $Member, $Null)
				$isGroup = ($Member.GetType().InvokeMember("Class", "GetProperty", $Null, $Member, $Null) -eq "group")
				If (($Path -like "*/$ServerName/*") -Or ($Path -like "WinNT://NT*")) { $Type = "Local"
				} Else {$Type = "Domain"}
				$result += [PSCustomObject]@{
					Computername = $ServerName
					MemberName = $Name
					PathMember = $Path
					MemeberType = $Type
					ParentGroup = $GName
					isGroupMemeber = $isGroup
					Depth = $Counter
				}
				}
			}
			} #end switch
		} #end foreach
		$result.foreach({[void]$r.Add($($_| select-object Computername, ParentGroup, MemberName, MemeberType, PathMember, isGroupMemeber, Depth))})
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rUSR = {
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
	#Get Local User list
	#Account Disabled	Display Name	Account Name	Inactive Days	Password Expired In
	#Name,Description,PasswordAge,PasswordExpired,Lastlogin
	if ($ServerName -eq 'localhost') {$ServerName = $Env:Computername} #localhost bug on some systems
		$computer = [ADSI]"WinNT://$ServerName"
		$computer.Children | Where-Object {$_.SchemaClassName -eq 'user'} | Foreach-Object {
			$groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)} 
			$AccountDisabled = $false; if (($_.UserFlags[0] -band 2) -eq 2) {$AccountDisabled = $True}
    		[void]$r.Add($($_ | Select-Object @{n='Computername';e={$ServerName}},@{n='Account Active';e={-not $AccountDisabled}},@{n='UserName';e={$_.Name[0]}},@{n='Description';e={$_.Description[0]}},@{n='Last Login';e={If ($_.LastLogin[0] -is [DateTime]) {$_.LastLogin[0]} Else { 'Never logged on' }}},@{n='PasswordAge';e={[Math]::Round($_.PasswordAge[0] / 86400)}},@{n='Groups';e={$groups -join '::'}}))
			if ($_.Name[0] -eq 'Administrator') {
				$w += "<p><div class='warning'>OS: Warning: `t<i>User Administrator was found.</i></div>"
				$adminSID = (New-Object System.Security.Principal.NTAccount($_.Name[0])).Translate([System.Security.Principal.SecurityIdentifier]).value
				if ($adminSID -match '-500$') {$w += "<p><div class='warning'>OS: Error: `t<i>The local Admin account name is ADMINISTRATOR. This Account must be renamed.</i></div>"}
			}
		}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$CRT = { #Certificates Audit -run invoke remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		#Place custom code here
		Get-ChildItem -Recurse Cert:\LocalMachine\My |? {$_.HasPrivateKey -eq $true} | ForEach-Object {
		$crt = $_ | Select-Object -Property @{n='IsTrusted';e={$_.verify()}},@{n='PrivateKeyExportable';e={$_.PrivateKey.CspKeyContainerInfo.Exportable}},Thumbprint,@{n='SubjectName'; e={$_.SubjectName.Name}},@{n='DnsNameList';e={$($_.DnsNameList -join ',:: ')}},Issuer,@{n='EnhancedKeyUsageList';e={$(($_.EnhancedKeyUsageList -join ',:: ') -replace " \(((\d+).)+(\d+)\)")}},NotBefore,NotAfter
		[void]$r.Add($crt)
		if ($crt.PrivateKeyExportable) { $w += "<p><div class='warning'>CER: Error: `t<i>Certificate $($crt.SubjectName) has Private Key Exportable</i>.</div>" }
		if (([datetime]$crt.NotAfter).Ticks -lt (Get-Date).Ticks) { $w += "<p><div class='warning'>CER: Error: `tExpired certificate: <i>$($crt.SubjectName)</i>.</div>" }
		if (([datetime]$crt.NotBefore).Ticks -gt (Get-Date).Ticks) { $w += "<p><div class='warning'>CER: Error: `tPending certificate: <i>$($crt.SubjectName)</i>.</div>" }
	}
	#End Block Code
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$TSK = { #run locally
	param ($ServerName,$TaskIgnorePrincipals)
	$TaskIgnorePrincipalsRX = '({0})' -f ($TaskIgnorePrincipals -join "|")
	$w = @();[Collections.ArrayList]$r=@()
		try { $scheduledtasks = Get-ChildItem "\\$($ServerName)\c$\Windows\System32\Tasks" -Recurse -File -ErrorAction Stop }
    	catch { Write-Warning ("Unable to retrieve Scheduled Tasks list for {0}" -f $ServerName); $scheduledtasks = $null }
    foreach ($task in $scheduledtasks | Sort-Object Name) {
        try { $taskinfo = [xml](Get-Content -Path $task.FullName -ErrorAction stop) }
        catch { Write-Warning ("Could not read {0}" -f $task.FullName); $taskinfo = $null }
        #<RunLevel>HighestAvailable</RunLevel> -and $taskinfo.Task.Principals.Principal.LogonType -ne 'InteractiveToken'
		#Write-Host ("Excluded: `t{0} `ton: `t{1}" -f $TaskIgnorePrincipalsRX, $servername)        
        #[PSCustomObject]@{Server = $Servername; Enabled = $taskinfo.Task.Settings.Enabled; TaskName = $task.Name; RunAsUser = $taskinfo.Task.Principals.Principal.UserId; RunLevel = $taskinfo.Task.Principals.Principal.RunLevel}
		if ($taskinfo.Task.Settings.Enabled -eq 'true' -and $taskinfo.Task.Principals.Principal.RunLevel -eq 'HighestAvailable' `
           -and (($taskinfo.Task.Principals.Principal.GroupId -notmatch $TaskIgnorePrincipalsRX) -and ($taskinfo.Task.Principals.Principal.UserId -notmatch $TaskIgnorePrincipalsRX))
        ) { [void]$r.Add($([PSCustomObject]@{Server = $Servername; Enabled = $taskinfo.Task.Settings.Enabled; TaskName = $task.Name; RunAsUser = $taskinfo.Task.Principals.Principal.UserId; RunLevel = $taskinfo.Task.Principals.Principal.RunLevel; Command = $taskinfo.Task.Actions.Exec.Command})) }
    }
	if ($r.count -gt 1) {$w +="<p><div class='warning'>TSK: Warning: `t<i>Elevated Non-System tasks found.</i></div>"}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}

$SHA = { #Get Shares report - run Remotely !! Method invocation failed because [Selected.Microsoft.Management.Infrastructure.CimInstance] does not contain a method named 'foreach'.
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
	[Collections.ArrayList]$smbSAccess=@(); [Collections.ArrayList]$smbfAccess=@();
	$SmbShares = Get-SmbShare -IncludeHidden
	#SMB Access
	ForEach ($SmbShare in $SmbShares) {
	    $smbsa = Get-SmbShareAccess $smbshare.name | Select-Object @{n='Path';e={$smbshare.path}}, @{n='Description';e={$smbshare.Description}}, Name, AccountName, AccessRight, AccessControlType
        $smbsa.foreach({
			if (($_.AccountName -eq 'Everyone') -and ($_.AccessRight -eq 'Full') -and ($_.AccessControlType -eq 'Allow')) {$w +="<p><div class='warning'>SHA: Error: `t<i>Share $($smbshare.name) has Everyone/FullControll access.</i></div>"}
			if (($_.AccountName -eq 'ANONYMOUS LOGON') -and ($_.AccessRight -eq 'Full') -and ($_.AccessControlType -eq 'Allow')) {$w +="<p><div class='warning'>SHA: Error: `t<i>Share $($smbshare.name) has ANONYMOUS LOGON/FullControll access.</i></div>"}
			if (($_.Path -match "^[a-zA-Z]:\\$") -and ($_.Name -notlike '*$')) {$w +="<p><div class='warning'>SHA: Error: `t<i>The ROOT folder of $($smbshare.Path) is shared.</i></div>"}
			[void]$smbsAccess.Add($_)})
	    if ($smbshare.Path -notlike $null) {
            $smbfacl = (Get-Acl -Path $SmbShare.Path).access | Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited
            $smbfacl.foreach({$_.psobject.properties.Add([psnoteproperty]::new('ShareName',$smbshare.name)); $_.psobject.properties.Add([psnoteproperty]::new('Path',$smbshare.Path)); })
            $smbfacl.foreach({[void]$smbfAccess.Add($_)})
       }
    }
[void]$r.add($smbsAccess); [void]$r.add($smbfAccess) #be aware to expand each array member to output report!
[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$NST = { #Run Remotely!
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
 		$properties = 'Protocol','LocalAddress','LocalPort'
 		$properties += 'RemoteAddress','RemotePort','State','ProcessName','PID'

		netstat -ano | Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object {
		
		 $item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
		     if($item[1] -notmatch '^\[::') {
		        if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
		            $localAddress = $la.IPAddressToString
		            $localPort = $item[1].split('\]:')[-1]
		        }
		        else {
		        $localAddress = $item[1].split(':')[0]
		        $localPort = $item[1].split(':')[-1]
		        } 
		
		        if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
		            $remoteAddress = $ra.IPAddressToString
		            $remotePort = $item[2].split('\]:')[-1]
		        }
		        else{
		            $remoteAddress = $item[2].split(':')[0]
		            $remotePort = $item[2].split(':')[-1]
		        }
		
		        [void]$r.Add($([PSCustomObject]@{
		         PID = $item[-1]
		         ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name
		         Protocol = $item[0]
		         LocalAddress = $localAddress
		         LocalPort = $localPort
		         RemoteAddress =$remoteAddress
		         RemotePort = $remotePort
		         State = if($item[0] -eq 'tcp') {$item[3]} else {$null}
		         } | Select-Object -Property $properties | where {($_.State -notlike $null) -and ($_.Protocol -like 'TCP') -and ($_.LocalAddress -notlike '127.0.0.1') -and ($_.ProcessName -notmatch 'System|Idle') } | sort-object -property LocalPort))
		     }
		 }
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rNTP = { #get time sync config and status - run remotely!
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
        #getting info
        #Check registry items
        $configuredNtpServerNameRegistryPolicy = $null 
        if (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Parameters -PathType Container)
          {
             $configuredNtpServerNameRegistryPolicy = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Parameters -Name 'NtpServer' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NtpServer
             $ConfiguredNTPServerByPolicy = $true; $ConfiguredNTPServerNameRaw = $configuredNtpServerNameRegistryPolicy.Trim()
          }
        else { 
             $ConfiguredNTPServerByPolicy = $false; $ConfiguredNTPServerNameRaw = ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name 'NtpServer').NtpServer).Trim()
          }
        if ($ConfiguredNTPServerNameRaw) { $ConfiguredNTPServerName = $ConfiguredNTPServerNameRaw.Split(' ') -replace ',0x.*' }
        else {$w += "<p><div class='warning'>NTP: Warning: `t<i>Windows Time Service not configured</i></div>"}

        #Get service status
        $NTPServiceStatus = (Get-Service -Name W32Time).Status

        #Get w32tm output
        $w32tmOutput = & 'w32tm' '/query', '/status'

        $sourceNameRaw = $w32tmOutput | Select-String -Pattern '^Source:'

        if ($sourceNameRaw)
        {
            $sourceNameRaw = $sourceNameRaw.ToString().Replace('Source:', '').Trim()
            $SourceName = $sourceNameRaw -replace ',0x.*'
        }
        else
        {
            $w += "<p><div class='warning'>NTP: Error: `t<i>Data from w32tm was not obtained</i></div>"
        }

        $lastTimeSynchronizationDateTimeRaw = $w32tmOutput | Select-String -Pattern '^Last Successful Sync Time:'
        $StatusDateTime = $false
        if ($lastTimeSynchronizationDateTimeRaw)
        {
            $lastTimeSynchronizationDateTimeRaw = $lastTimeSynchronizationDateTimeRaw.ToString().Replace('Last Successful Sync Time:', '').Trim()
            <# Last time synchronization: Test: Date and time #>

            if ($lastTimeSynchronizationDateTimeRaw -eq 'unspecified')
            {
                $w += "<p><div class='warning'>NTP: Error: `t<i>Last time synchronization date and time: Unknown</i></div>"
            }
            else
            {
                $LastTimeSynchronizationDateTime = Get-Date($lastTimeSynchronizationDateTimeRaw)
                $LastTimeSynchronizationElapsedSeconds = [int]((Get-Date) - $LastTimeSynchronizationDateTime).TotalSeconds
                $StatusDateTime = $true
                <# Last time synchronization: Test: Maximum number of seconds #>

                if ($LastTimeSynchronizationElapsedSeconds -eq $null -or $LastTimeSynchronizationElapsedSeconds -lt 0 -or $LastTimeSynchronizationElapsedSeconds -gt 1200)
                {
                    $StatusLastTimeSynchronization = $false
                    $w += "<p><div class='warning'>NTP: Warning: `t<i>Last time synchronization Elapsed: $LastTimeSynchronizationElapsedSeconds seconds</i></div>"
                }
                else { $StatusLastTimeSynchronization = $true }
            }
        }
        else { $w += "<p><div class='warning'>NTP: Error: `t<i> Data from w32tm was not obtained</i></div>" }
			$TimeDiff = @()
			$w32tmOutput = & 'w32tm' '/monitor' '/computers:tik.cesnet.cz,0.cz.pool.ntp.org,ntp.suas.cz'
			$TimeDiffRaw = $w32tmOutput | Select-String -Pattern 'NTP:'
			$TimeDiffRaw.foreach({ if (($_.ToString().Replace('NTP:', '')).Replace('s offset from local clock','').Trim() -match "[+-]?(\d+[\.|\,]\d*|\.\d+)") {$TimeDiff += [int]$matches[0]} }) 
			#$TimeDiff
			$maxTD = ($TimeDiff | ForEach-Object { [Math]::Abs($_) } | Measure-Object -Maximum).Maximum
			foreach ($x in $TimeDiff) { if ([Math]::Abs($x) -eq $maxTD) { $maxTD = $x } }
#Prepare output
	if ([Math]::Abs($maxTD) -gt 19) {$w += "<p><div class='warning'>NTP: Error: `t<i>Time gap between local and global time is high ($maxTD sec.).</i></div>"}
	[void]$r.Add($([PSCustomObject]@{'NTP Service Status' = $NTPServiceStatus; 'Configured NTP Server By Policy' = $ConfiguredNTPServerByPolicy; 'Configured NTP Server Name' = $ConfiguredNTPServerName; 'NTP Source Name'= $SourceName; 'Sync Status' = $StatusDateTime; 'Time Gap with Internet Time (sec.)'=$maxTD; 'Last Time Sync DateTime' = $LastTimeSynchronizationDateTime; 'Time Sync Success' = $StatusLastTimeSynchronization; 'Last Time Sync Elapsed Seconds' = $LastTimeSynchronizationElapsedSeconds;}))
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$rGPO = { #Get GP apply Results - run remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		#Get GPResult output
		$gprxmlfile = ($env:temp + '\' + [System.IO.Path]::GetRandomFileName())
		& 'gpresult' '/Scope', 'Computer', '/x' , $gprxmlfile
		 $results = [xml] (Get-Content $gprxmlfile)
		 $GPOresult = $results.DocumentElement.ComputerResults.GPO | Select-Object Name, Enabled, Filter*, IsValid
		[System.IO.File]::Delete($gprxmlfile)
		$GPOresult.foreach({ [void]$r.Add($_) })
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}
$AZS = { #AZureAD Join State - run remotely
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		[array] $cmdOutput = dsregcmd /status
		if (!($cmdOutput | ?{$_ -match 'TenantName'})) {$w += "<p><div class='warning'>AZ: Info: `t<i>The host is not assigned to any MS365 tenant.</i></div>"}
		[void]$r.Add($([PSCustomObject]@{'TenantName'= ($cmdOutput | ?{$_ -match 'TenantName'}).Split(":")[1].trim();'Device Name'= ($cmdOutput | ?{$_ -match 'Device Name'}).Split(":")[1].trim();'AzureAdJoined'= ($cmdOutput | ?{$_ -match 'AzureAdJoined'}).Split(":")[1].trim();'EnterpriseJoined'= ($cmdOutput | ?{$_ -match 'EnterpriseJoined'}).Split(":")[1].trim();'DomainJoined'= ($cmdOutput | ?{$_ -match 'DomainJoined'}).Split(":")[1].trim();'Virtual Desktop'= ($cmdOutput | ?{$_ -match 'Virtual Desktop'}).Split(":")[1].trim()}))
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}

<# SCRIPTBLOCK Template
$TEMPLATE = { #Change name
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@()
		#Place custom code here
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
}

#>

# - STAGE RUN JOBS - #
<# Exclude when:
		`n`t LUS - Skip Review LoggenOn Users`
		`n`t WHW - Skip HardWare analysis`
		`n`t NET - Skip Network config retrieve`
		`n`t PRC - Skip Processes analysis`
		`n`t APP - Skip Installed Application retrieve`
		`n`t WUS - Skip Windows Update check`
		`n`t WAV - Skip Windows Antivirus check`
		`n`t WFW - Skip Windows Firewall check`
		`n`t SVC - Skip Services Analysis`
		`n`t ROL - Skip Installed Roles enumeration`
		`n`t EVT - Skip Events retrieve`
		`n`t USR - Skip Users and Groups Analysis`
#>
Write-Host "Starting jobs on $($ServerName) at $(Get-Date)" -foregroundcolor yellow
if ($RunTest -contains 'EVT') {
		Start-Job $rEVTS -ArgumentList $ServerName -Name "EVTS" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
		Start-Job $rEVTA -ArgumentList $ServerName -Name "EVTA" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
}
if ($RunTest -contains 'WUS') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {
	Write-Host "Starting local job WUS for $($ServerName) at $(Get-Date)" -foregroundcolor green
	Start-Job -scriptblock $rWUH -Name "WUH" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	Start-Job -scriptblock $rWUA -Name "WUA" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {
	Write-Host "Starting remote job WUS for $($ServerName) at $(Get-Date)" -foregroundcolor yellow
	Invoke-Command -computername $ServerName -scriptblock $rWUH -JobName "WUH" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	Invoke-Command -computername $ServerName -scriptblock $rWUA  -JobName "WUA" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'WFW') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {
	Start-Job -scriptblock $rFWP -Name "FWP" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	Start-Job -scriptblock $rFWR -Name "FWR" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	Start-Job -scriptblock $rFWC -Name "FWC" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {
	Invoke-Command -computername $ServerName -scriptblock $rFWP -JobName "FWP" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	Invoke-Command -computername $ServerName -scriptblock $rFWR -JobName "FWR" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	Invoke-Command -computername $ServerName -scriptblock $rFWC -JobName "FWC" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'LUS') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {	Start-Job -scriptblock $rLUS -ArgumentList $ServerName -Name "LUS" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize }
	else {Invoke-Command -computername $ServerName -scriptblock $rLUS -ArgumentList $ServerName -JobName "LUS" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize } 
}
if ($RunTest -contains 'WHW') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {	Start-Job -scriptblock $rWHW -ArgumentList $ServerName -Name "WHW" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize }
	else { Invoke-Command -computername $ServerName -scriptblock $rWHW -ArgumentList $ServerName -JobName "WHW" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize }
	Start-Job -scriptblock $rCPU -ArgumentList $ServerName -Name "CPU" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	Start-Job -scriptblock $rHDD -ArgumentList $ServerName -Name "HDD" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
}
if ($RunTest -contains 'NET') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $rNET -ArgumentList $ServerName -Name "NET" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $rNET -ArgumentList $ServerName -JobName "NET" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'GPO') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $rGPO -ArgumentList $ServerName -Name "GPO" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $rGPO -ArgumentList $ServerName -JobName "GPO" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'PRC') {
	Start-Job -scriptblock $rPRAM -ArgumentList $ServerName -Name "PRAM" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	Start-Job -scriptblock $rPCPU -ArgumentList $ServerName -Name "PCPU" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $rPUNS -ArgumentList $ServerName -Name "PUNS" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $rPUNS -ArgumentList $ServerName -JobName "PUNS" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'APP') {
	Start-Job -scriptblock $rAPP -ArgumentList $ServerName -Name "APP" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
}
if ($RunTest -contains 'WAV') {
	$AVinfo = Detect-WindowsAVInstalled -ServerName $ServerName
	if ($AVinfo.report.DisplayName -match 'Windows Defender') {
		if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {
		Start-Job -scriptblock $rWDfC -ArgumentList $ServerName -Name "WDfC" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
		Start-Job -scriptblock $rWDfE -ArgumentList $ServerName -Name "WDfE" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
		else {
		Invoke-Command -computername $ServerName -scriptblock $rWDfC -ArgumentList $ServerName -JobName "WDfC" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
		Invoke-Command -computername $ServerName -scriptblock $rWDfE -ArgumentList $ServerName -JobName "WDfE" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	}
	elseif ($Null -eq $AVinfo.results) { # No Ativirus
		[void]$Problems.Add("<p><div class='warning'>WAV: Warning: `t<i>Probably no Antivirus software installed.</i></div>")
	}
	else {[void]$Problems.Add("<p><div class='warning'>WAV: Warning: `t<i>The 3d party Antivirus software installed. Only basic info was got.</i></div>")} # 3d party antivirus detected. Need custom detection routine 
}
if ($RunTest -contains 'SVC') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $rSVC -ArgumentList $ServerName -Name "SVC" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $rSVC -ArgumentList $ServerName -JobName "SVC" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if (($RunTest -contains 'ROL') -and ($computerSystem.DomainRole -ge 2)) {
	Start-Job -scriptblock $rROL -ArgumentList $ServerName -Name "ROL" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
}
if ($RunTest -contains 'USR') {
	Start-Job -scriptblock $rUSR -ArgumentList $ServerName -Name "USR" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize #Run User analysis job
	Start-Job -scriptblock $rGRP -ArgumentList $ServerName -Name "GRP" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize #Run Group analysis job
}
if ($RunTest -contains 'CRT') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $CRT -ArgumentList $ServerName -Name "CRT" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $CRT -ArgumentList $ServerName -JobName "CRT" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'SHA') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $SHA -ArgumentList $ServerName -Name "SHA" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $SHA -ArgumentList $ServerName -JobName "SHA" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'NST') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $NST -ArgumentList $ServerName -Name "NST" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $NST -ArgumentList $ServerName -JobName "NST" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'TSK') {
	Start-Job -scriptblock $TSK -ArgumentList $ServerName,$TaskIgnorePrincipals -Name "TSK" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize
}
if ($RunTest -contains 'NTP') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $rNTP -ArgumentList $ServerName -Name "NTP" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $rNTP -ArgumentList $ServerName -JobName "NTP" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
if ($RunTest -contains 'AZS') {
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $AZS -ArgumentList $ServerName -Name "AZS" | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $AZS -ArgumentList $ServerName -JobName "AZS" -AsJob | select PSBeginTime,location,id,name,State,Error | ft -AutoSize}
}
# - STAGE GETTING JOB OUTPUT - #

Write-Host "Waiting for completed jobs on $($ServerName) at $(Get-Date)" -foregroundcolor yellow
$Watch = [System.Diagnostics.Stopwatch]::StartNew(); $runningmins = $Watch.Elapsed.Minutes
while ($null -ne (Get-Job)) {
		#$host.UI.RawUI.CursorPosition = $origpos; Write-Host $scroll[$idx] -NoNewline; $idx++; if ($idx -ge $scroll.Length) {$idx=0}; Start-Sleep -Milliseconds 100

	$jobsdone = Get-Job | Where-Object { $_.State -eq "Completed" }
	foreach ($jdone in $jobsdone)
	{
		$jout = Receive-Job -Id $jdone.Id
		if (!$jout) {[void]$Problems.Add("<p><div class='warning'>JOB: Warning: `t<i>The JOB $($jdone.Name) on the host $ServerName return no output.</i></div>")}
		if ($null -ne $jout) {
			if ($jdone.Name -like "EVTS") {$SysEvents = $jout}
			if ($jdone.Name -like "EVTA") {$AppEvents = $jout}
			if ($jdone.Name -like "FWC") {$WFWStatus = $jout}
			if ($jdone.Name -like "FWR") {$WFWRules = $jout}
			if ($jdone.Name -like "FWP") {$WFWAllowedPorts = $jout}
			if ($jdone.Name -like "WUH") {$WuaHistory = $jout} # | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
			if ($jdone.Name -like "WUA") {$WuaAvailable = $jout}
			if ($jdone.Name -like "LUS") {$LoggedUsers = $jout}
			if ($jdone.Name -like "WHW") {$HWConfig = $jout}
			if ($jdone.Name -like "CPU") {$CPUConfig = $jout}
			if ($jdone.Name -like "HDD") {$HDDConfig = $jout}
			if ($jdone.Name -like "NET") {$NetConfig = $jout}
			if ($jdone.Name -like "PRAM") {$TopProcRAM = $jout}
			if ($jdone.Name -like "PCPU") {$TopProcCPU = $jout}
			if ($jdone.Name -like "PUNS") {$UnsigProcs = $jout}
			if ($jdone.Name -like "APP") {$AppsInstalled = $jout}
			if ($jdone.Name -like "WDfC") {$WAVConfig = $jout}
			if ($jdone.Name -like "WDfE") {$WAVExc = $jout}
			if ($jdone.Name -like "SVC") {$StrangeServices = $jout}
			if ($jdone.Name -like "ROL") {$ActiveRoles = $jout}
			if ($jdone.Name -like "USR") {$LocalUsers = $jout}
			if ($jdone.Name -like "GRP") {$LocalGroups = $jout}
			if ($jdone.Name -like "CRT") {$Certificates = $jout}
			if ($jdone.Name -like "TSK") {$Tasks = $jout}
			if ($jdone.Name -like "SHA") {$Shares = $jout}
			if ($jdone.Name -like "NST") {$NETStat = $jout}
			if ($jdone.Name -like "NTP") {$NTPStat = $jout}
			if ($jdone.Name -like "GPO") {$GPORes = $jout}
			if ($jdone.Name -like "AZS") {$AZState = $jout}
		}
		Write-Host "The job $($jdone.Name) completed." -foregroundcolor yellow
		Remove-Job -Id $jdone.Id
	}
	if (($Watch.Elapsed.Minutes - $runningmins) -gt 2) {$runningmins = $Watch.Elapsed.Minutes; Write-host "Job(s): $(((Get-Job | Where-Object { $_.State -ne 'Completed' }).Name) -join '; ') are running $($Watch.Elapsed.Minutes) minutes so far.. Waiting for results..." -foregroundcolor yellow}
	if ($Watch.Elapsed.Minutes -gt $JobRunningLimit) {[void]$Problems.Add("<p><div class='warning'>RUNTIME: Warning: `t<i>The JOBs $(((Get-Job | Where-Object { $_.State -ne 'Completed' }).Name) -join '; ') on the host $ServerName are running too long. These jobs where skipped.</i></div>"); $Watch.Stop(); break}
	if (Get-Job | Where-Object { $_.State -eq "Failed" }) {
		(Get-Job | Where-Object { $_.State -eq "Failed" }).foreach({Write-Host ("Job $_.Name was failed with error: " + ($_.ChildJobs[0].JobStateInfo.Reason.Message)) -ForegroundColor Red; [void]$Problems.Add("<p><div class='warning'>RUNTIME: Warning: `t<i>The JOB $($_.Name) on the host $ServerName was failed with error $($_.ChildJobs[0].JobStateInfo.Reason.Message) . This job was skipped.</i></div>")})
		Write-host "Job(s): $(((Get-Job | Where-Object { $_.State -ne 'Failed' }).Name) -join '; ') are failed. Remove these jobs. " -foregroundcolor yellow
		Get-Job | Where-Object { $_.State -eq "Failed" } | Remove-Job -Force
		}
}
$host.UI.RawUI.CursorPosition = $origpos; Write-Host ' '
# - STAGE Report Building - #
#Combine report results to HTML
Write-Host "Combine results and write the report on $($ServerName) at $(Get-Date)" -foregroundcolor yellow

$AZState.Warnings.foreach({[void]$Problems.Add($_)})
if ($AZState.report) { [void]$ReportHTMLArray.Add($($AZState.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Azure AD Join State</H3></td></tr></table>"))}
$LoggedUsers.Warnings.foreach({[void]$Problems.Add($_)})
if ($LoggedUsers.report) { [void]$ReportHTMLArray.Add($($LoggedUsers.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Logged On Users</H3></td></tr></table>"))}
$HWConfig.Warnings.foreach({[void]$Problems.Add($_)})
if ($HWConfig.report) { [void]$ReportHTMLArray.Add($($HWConfig.report | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | SYSTEM HW </H3></td></tr></table>")) }
$CPUConfig.Warnings.foreach({[void]$Problems.Add($_)})
if ($CPUConfig.report) { [void]$ReportHTMLArray.Add($($CPUConfig.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | CPU(s) </H3></td></tr></table>")) }
$HDDConfig.Warnings.foreach({[void]$Problems.Add($_)})
if ($HDDConfig.report) { [void]$ReportHTMLArray.Add($($HDDConfig.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Drives</H3></td></tr></table>")) }
$NTPStat.Warnings.foreach({[void]$Problems.Add($_)})
if ($NTPStat.report) { [void]$ReportHTMLArray.Add($($NTPStat.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | NTP Status</H3></td></tr></table>").Replace("::", "<br/>")) }
$NetConfig.Warnings.foreach({[void]$Problems.Add($_)})
if ($NetConfig.report) { [void]$ReportHTMLArray.Add($($NetConfig.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | NET Config</H3></td></tr></table>").Replace("::", "<br/>")) }
$TopProcRAM.Warnings.foreach({[void]$Problems.Add($_)})
if ($TopProcRAM.report) { [void]$ReportHTMLArray.Add($($TopProcRAM.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | TOP Processes by RAM usage</H3></td></tr></table>")) }
$TopProcCPU.Warnings.foreach({[void]$Problems.Add($_)})
if ($TopProcCPU.report) { [void]$ReportHTMLArray.Add($($TopProcCPU.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | TOP Processes by CPU usage</H3></td></tr></table>")) }
$UnsigProcs.Warnings.foreach({[void]$Problems.Add($_)})
if ($UnsigProcs.report) { [void]$ReportHTMLArray.Add($($UnsigProcs.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Processes with wrong signature</H3></td></tr></table>")) }
$NETStat.Warnings.foreach({[void]$Problems.Add($_)})
if ($NETStat.report) { [void]$ReportHTMLArray.Add($($NETStat.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | NET Stat: Open TCP Ports</H3></td></tr></table>")) }
$StrangeServices.Warnings.foreach({[void]$Problems.Add($_)})
if ($StrangeServices.report) { [void]$ReportHTMLArray.Add($($StrangeServices.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Strange Services</H3></td></tr></table>")) }
$Tasks.Warnings.foreach({[void]$Problems.Add($_)})
if ($Tasks.report) { [void]$ReportHTMLArray.Add($($Tasks.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Custom High Privileged Tasks</H3></td></tr></table>")) }
$Certificates.Warnings.foreach({[void]$Problems.Add($_)})
if ($Certificates.report) { [void]$ReportHTMLArray.Add($($Certificates.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Certificates</H3></td></tr></table>").Replace("::", "<br/>")) }
$GPORes.Warnings.foreach({[void]$Problems.Add($_)})
if ($GPORes.report) { [void]$ReportHTMLArray.Add($($GPORes.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | GPO Application results</H3></td></tr></table>").Replace("::", "<br/>")) }
$LocalUsers.Warnings.foreach({[void]$Problems.Add($_)})
if ($LocalUsers.report) { [void]$ReportHTMLArray.Add($($LocalUsers.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | User Accounts</H3></td></tr></table>").Replace("::", "<br/>")) }
$LocalGroups.Warnings.foreach({[void]$Problems.Add($_)})
if ($LocalGroups.report) { [void]$ReportHTMLArray.Add($($LocalGroups.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Groups</H3></td></tr></table>").Replace("::", "<br/>")) }
$Shares.Warnings.foreach({[void]$Problems.Add($_)})
if ($Shares.report[0]) { [void]$ReportHTMLArray.Add($($Shares.report[0] | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | SMB Shares</H3></td></tr></table>").Replace("::", "<br/>")) }
if ($Shares.report[1]) { [void]$ReportHTMLArray.Add($($Shares.report[1] | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | SMB Shares Access Rights</H3></td></tr></table>").Replace("::", "<br/>")) }
if ($ActiveRoles) {$ActiveRoles.Warnings.foreach({[void]$Problems.Add($_)})}
if ($ActiveRoles.report) { [void]$ReportHTMLArray.Add($($ActiveRoles.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Roles Instaled</H3></td></tr></table>")) }
if ($AVinfo){$AVinfo.Warnings.foreach({[void]$Problems.Add($_)}); [void]$ReportHTMLArray.Add($($AVinfo.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Antivirus status</H3></td></tr></table>"))}
if ($WAVConfig) {	$WAVConfig.Warnings.foreach({[void]$Problems.Add($_)}); [void]$ReportHTMLArray.Add($($WAVConfig.report | Convert-Object2BiArray | Convert-Array2HTML -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Defender Status</H3></td></tr></table>"))}
if ($WAVExc) {	$WAVExc.Warnings.foreach({[void]$Problems.Add($_)}); [void]$ReportHTMLArray.Add($($WAVExc.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Defender Exclusions</H3></td></tr></table>").Replace("::","<br/>"))}
$WFWStatus.Warnings.foreach({[void]$Problems.Add($_)})
if ($WFWStatus.report) { [void]$ReportHTMLArray.Add($($WFWStatus.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Firewall Status</H3></td></tr></table>").Replace("::", "<br/>")) }
$WFWRules.Warnings.foreach({[void]$Problems.Add($_)})
if ($WFWRules.report) { [void]$ReportHTMLArray.Add($($WFWRules.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Firewall Active Rule Groups</H3></td></tr></table>")) }
$WFWAllowedPorts.Warnings.foreach({[void]$Problems.Add($_)})
if ($WFWAllowedPorts.report) { [void]$ReportHTMLArray.Add($($WFWAllowedPorts.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Firewall Allowed Port List</H3></td></tr></table>")) }
$WuaHistory.Warnings.foreach({[void]$Problems.Add($_)})
if ($WuaHistory.report) { [void]$ReportHTMLArray.Add($($WuaHistory.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Update History</H3></td></tr></table>")) }
$WuaAvailable.Warnings.foreach({[void]$Problems.Add($_)})
if ($WuaAvailable.report) { [void]$ReportHTMLArray.Add($($WuaAvailable.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Updates Available</H3></td></tr></table>")) }
$AppsInstalled.Warnings.foreach({[void]$Problems.Add($_)})
if ($AppsInstalled.report) { [void]$ReportHTMLArray.Add($($AppsInstalled.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Installed Applications</H3></td></tr></table>")) }
$SysEvents.Warnings.foreach({[void]$Problems.Add($_)})
if ($SysEvents.report) { [void]$ReportHTMLArray.Add($($SysEvents.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Last 24h. SYSTEM Log Errors & Warnings</H3></td></tr></table>")) }
$AppEvents.Warnings.foreach({[void]$Problems.Add($_)})
if ($AppEvents.report) { [void]$ReportHTMLArray.Add($($AppEvents.report | convertto-html -Fragment -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Last 24h. APPLICATION Log Errors & Warnings</H3></td></tr></table>")) }

#############################################################################
#############################################################################
# - LAST STAGE - #
# Save Report To a File
$ReportHTML = $Header + "<div><table><tr><td><H1>Host <font style='color: green;font-weight: bold;'>$($computerOS.PSComputerName)</font> health report.</H1></td><td style='text-align:right;'>Executed on <i>$ENV:COMPUTERNAME</i> as <i>$ENV:USERNAME</i> at $(get-date -Format s)</td></tr></table>"
if ($Problems) {
	$ReportHTML += "<H2>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Problems found:</H2>"
	$Problems.foreach({$ReportHTML += $_})
}
$ReportHTMLArray.foreach({$ReportHTML += $_})
$ReportHTML += $Footer
#Mark Warining Logins as red
#foreach ($WL in $WarningLogins) { $ReportHTML = $ReportHTML.ToLower() -replace $WL,"<font color='red'>$WL</font>" }
$ReportFile = $ReportFilePath + "\" + $computerOS.PSComputerName + "-HEALTH-REPORT-" + ((Get-Date -Format dd.MM.yy).ToString()) + "-" + ((get-date -Format HH.mm.ss).ToString()) + ".html"
$ReportHTML | Out-File $ReportFile
if (Test-Path -Path $ReportFile -ErrorAction 0) { Write-Host "Report file $ReportFile created successfully."}
else { Write-warning "Report file could not be created." -foregroundColor Magenta }

# Optionaly Send Report by email - $ReportData structure
if ($emailTo -ne "") { #Send Email Report
		$subject = $computerOS.PSComputerName + " Server Health Report"
		$body = $ReportHTML
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
		#Send-MailMessage -To $emailTo -Subject $subject -Body $SessionList -SmtpServer $smtpServer -From $emailFrom -Priority $priority -Encoding ([System.Text.Encoding]::UTF8)
}

[console]::Beep(1000, 300)
Write-Host "All DONE." -foreground Yellow
#Cleaning environment
Get-Job | Remove-Job -force
Get-variable * | Remove-variable -Scope Script -Ea 0