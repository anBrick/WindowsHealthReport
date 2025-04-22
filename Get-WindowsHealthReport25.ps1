<#
to install as task:  .\Get-WindowsHealthReport25.ps1 -Install -ServerName localhost -EmailTo hospimed@arion.cz -HealthOnly -ShowProblems
#>
<# what to detect
HW: 	processor socket/cores, - DONE 
		RAM installed/free, - DONE
		system temperature  - DONE
((Get-WMIObject -Query "SELECT * FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation" -Namespace "root/CIMV2" | Select-Object HighPrecisionTemperature).HighPrecisionTemperature - 2732) / 10.0
		HDD TYPE - DONE
		HDD health (Get-PhysicalDisk), - DONE 
Get-WmiObject -namespace root\wmi -class MSStorageDriver_FailurePredictStatus -ErrorAction Silentlycontinue | Select InstanceName, PredictFailure, Reason
Get-Disk | Get-StorageReliabilityCounter | Select-Object -Property "*"
Get-PhysicalDisk | Select FriendlyName, MediaType
		HDD size/free , - DONE
		CPU utilization - DONE
((Get-WmiObject win32_processor | select LoadPercentage).LoadPercentage)
(((Get-WmiObject win32_processor | select LoadPercentage).LoadPercentage) | Measure-Object -Average).Average
((GET-CIMInstance -class Win32_PerfFormattedData_Counters_ProcessorInformation) | Measure-Object -property PercentProcessorPerformance -Average).average
(Get-CimInstance -ClassName Win32_Processor).LoadPercentage
Get-WmiObject -computer localhost -class win32_processor | Measure-Object -property LoadPercentage -Average | Select-Object -ExpandProperty Average

OS: 	version, -DONE 
		install date, -DONE
		reboot pending, -DONE
		uptime, -DONE
		BootupState, -DONE
		LicenseStatus, -DONE
		Secure BOOT -DONE
		host password age - need to run as system or access to AD... TBD...
Get-date â€“date ([DateTime]::FromFileTime([System.BitConverter]::ToInt64((Get-ItemProperty -path "HKLM:\SECURITY\Policy\Secrets\`$MACHINE.ACC\CupdTime").'(default)',0)))  -Format 'yyyy-MM-dd'

WU: 	queue lenght - DONE

Sec: 	local admin account active - DONE
		unusual local accounts? - DONE
		machine cert expired? - DONE
		admin account password age -DONE
		shares with everyone/FC -DONE	
		AV status - DONE
		Win FW enabled - DONE
		Win FW ANY/ANY rules - DONE
		SMB v1 enabled: (Get-SmbServerConfiguration).EnableSMB1Protocol - run remotely - DONE

RT: 	proceses with wrong signature - DONE
		time gap - DONE
		Strange Services - DONE
		services not running even startup is auto - DONE
		Logged On Users - DONE
		

NET:	internet connection available? -DONE
		has public IP address? -DONE

EVT:	last errors count app/sys/sec - DONE
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
   [string]$EmailFrom = (Get-WmiObject win32_computersystem).DNSHostName + "@" + 'report.' + (Get-WmiObject win32_computersystem).Domain,
  [Parameter(Mandatory = $false,
	HelpMessage = { ("`nEnter an SMTP server address.`n  Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -SMTPServer mail.domain.com`n") })]
   [string]$smtpServer = "localhost",
  [Parameter(Mandatory=$false)]
   [switch]$ShowProblems, # Display verbose information about errors & warnings detected
  [Parameter(Mandatory=$false)]
   [switch]$HealthOnly, # Display breaf health info about each test insted of detailed table
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
		`n`t VOL - Skip Volumes enumeration`
		`n`t EVT - Skip Events retrieve`
		`n`t USR - Skip Users and Groups Analysis`
	   `n`t CRT - Skip Certificates Analysis`
		`n`t TSK - Skip Tasks Analysis`
		`n`t SHA - Skip Shares Analysis`
		`n`t NST - Skip NETStat Analysis`
		`n`t NTP - Skip NTP Status`
		`n`t GPO - Skip GPO Results`
		`n`t AZS - Skip AzureAD Join State check`
 		`n  Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -EmailTo it@domain.com -Ignore APP,WUS,WAV etc.`n")}
 		)]
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
		`n`t VOL - Disk Volumes enumeration`
		`n`t EVT - Events retrieve`
		`n`t USR - Users and Groups Analysis`
	   `n`t CRT - Certificates Analysis`
		`n`t TSK - Tasks Analysis`
		`n`t SHA - Shares Analysis`
		`n`t NST - NETStat Analysis`
		`n`t NTP - NTP Status`
		`n`t GPO - GPO Results`
		`n`t AZS - Do AzureAD Join State check`
 		`n  Usage:  .\") + $myinvocation.MyCommand.Name + (" -ServerName localhost -EmailTo it@domain.com -Include APP,WUS,WAV etc.`n")}
 		)]
	 [Alias('Check')]
	 [String]$Include
)
#############################################################################
#REGION:: Customizable variables. Adjust them for your actual environment
$ScriptDistributionPoints = @('c:\report\',$($ENV:LOGONSERVER + "\NETLOGON\"),"https://raw.githubusercontent.com/anBrick/WindowsHealthReport/main/") ## path for automatic upgrade from
$WorkDir = "$ENV:ALLUSERSPROFILE\Microsoft\Diagnosis\"
$ReportFilePath = [Environment]::GetFolderPath('MyDocuments')
if (($ReportFilePath -match "^[a-zA-Z]:\\$") -or ([string]::IsNullOrEmpty($ReportFilePath.trim()))) {$ReportFilePath = ($ENV:WINDIR + '\LOGS')}
#$WUDepth = 8 # Number of last Windows Update modules installed - not used

$RAMLowFreeLimit = 1 #GB
$JobRunningLimit = 21 # Minutes
$Global:ExcludeUsers = @('^netwrix','^Symantec',"^Health",'\$$',"LOCAL SERVICE",'NETWORK SERVICE','SYSTEM','ANONYMOUS LOGON',"^SQL","^MSOL",'[0-9a-fA-F]{4,}')
$Global:TaskIgnorePrincipals = @('NT AUTHORITY\SYSTEM', 'LocalService', 'LocalSystem', 'LOCAL SERVICE', 'NETWORK SERVICE', 'NT AUTHORITY\SYSTEM', 'SYSTEM', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20')
$Global:IgnoreServices = @('^edgeupdate', '^google', '^map', '^ClamD', '^FreshClam', '^HMWebService', '^IPBAN', '^gupdate', '^RemoteRegistry', '^sppsvc')
$Global:IgnoreCertificates = @()

# - Setup email related variables
$emailpriority = 2 # High = 2, Low = 1, Normal = 0 
$SmtpServerPort = "25"
$EnableSsl = $false
$emailSmtpUser = "username"
$emailSmtpPass = "password"
# - Report html Header
$Header = @"
<!DOCTYPE html><html><head>
<title>$ServerName Health Report</title>
<style>
	body { width:100%; min-width:1024px; padding-left: 12px; padding-right: 10px; font-family: Segoe UI, Verdana, sans-serif, ui-sans-serif, system-ui; font-size:14px; /*font-weight:300;*/ line-height:1.0; color:#222222; background-color:#f4f5f6;}
   strong{ font-weight:600;}
	p.warning { font-family: Segoe UI, sans-serif, ui-sans-serif, system-ui; font-size:12.5px; font-weight: normal; font-stretch: expanded; color:#7B6000; margin-bottom: 2px; margin-top: 0em; margin-left:4px; margin-right:4px; line-height:1.4; background-color:white;}
	p.info { font-family: Segoe UI, sans-serif, ui-sans-serif, system-ui; font-size:12.5px; font-weight: normal; font-stretch: expanded; color:#032282; margin-bottom: 2px; margin-top: 0em; margin-left:4px; margin-right:4px; line-height:1.4; background-color:white;}
	p.error { font-family: Segoe UI, sans-serif, ui-sans-serif, system-ui; font-size:12.5px; font-weight: normal; font-stretch: expanded; color:#7b0000; margin-bottom: 2px; margin-top: 0em; margin-left:4px; margin-right:4px; line-height:1.4; background-color:white;}
	h1{ font-size:17px; font-weight:bold;}
   h2{ font-size:14px; font-weight:normal;}
   h3{ font-size:17px; font-weight:normal; background-color:#66ccee; margin-top:3px; margin-bottom:1px; margin-left:4px; text-align:left;}
   table {border: 0px solid #6E8BB6; background:#f3f3f3; margin-top:0px;}
	table.scope {border-collapse: collapse; border: 0px solid #ffffff; padding:6px; background-color:#66ccee; margin-top:8px; text-align:left;}
	table th { padding:0px; border-collapse: collapse; border: 0px solid #f3f3f3; text-align:left; vertical-align:middle; background-color:#317399; color:white; font-size:14px; font-weight: normal;}
   table td.u { padding:1px; background-color:white; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:grey; margin-left:4px; margin-right:4px;}
   table td.n { padding:1px; background-color:#8AFC95; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:black; margin-left:4px; margin-right:4px;}
   table td.w { padding:1px; background-color:#FEEC6A; border-collapse: collapse; border: 1px solid #FF0000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:red; margin-left:4px; margin-right:4px;}
   table td.e { padding:1px; background-color:#8F4040; border-collapse: collapse; border: 0px solid #FEEC6A; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:#f3f587; margin-left:4px; margin-right:4px;}
	table tr.u { padding:1px; background-color:white; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:grey; margin-left:4px; margin-right:4px;}
   table tr.n { padding:1px; background-color:#8AFC95; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:black; margin-left:4px; margin-right:4px;}
   table tr.w { padding:1px; background-color:#FCEC8A; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:red; margin-left:4px; margin-right:4px;}
   table tr.e { padding:1px; background-color:#530A0A; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:#f3f587; margin-left:4px; margin-right:4px;}
   table tr { padding:1px; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; margin-left:4px; margin-right:4px;}
   .twoColumns { padding: 10px; -webkit-column-count: 2; -webkit-column-rule: 1px solid #6E8BB6; column-count: 2; column-gap: 10px; column-rule: 1px solid #6E8BB6;}
</style>
</head><body>
"@
$Footer = @"
    <div></div><!--End ReportBody--><div>
    <br><center><i>Source script: $($MyInvocation.MyCommand.Path)<br>Report file was saved to $($ReportFilePath)</i></p></center>
    <br><center><i>$(Get-Date -Format "dd/MM/yyyy HH:mm:ss")</i><p style="" font-size:8px;color:#7d9797"">Script Version: 2025.04 | By: Vladislav Jandjuk | Feedback: jandjuk@arion.cz | Git: github.com/anBrick/WindowsHealthReport</p></center>
    <br></div></body></html>
"@
#Other vasr and constants - change it if you know what you do
$ComputerRole = @("Standalone Workstation","Member Workstation","Standalone Server","Member Server","Domain Controller","Domain Controller","Unknown Role")
$OSLicensingStatus = @('Unlicensed','Licensed','OOBGrace','OOTGrace','NonGenuineGrace','Notification','ExtendedGrace','Undefined')
[Collections.ArrayList]$ReportHTMLArray = @()
[Collections.ArrayList]$Problems = @()
$DIAG = @{ }
#End of var area. You have not change the script code below
#############################################################################
#REGION:: ROUTINES
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
}
function Detect-WindowsAVInstalled { #Detect AV intalled and get basic info
	param ($ServerName)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}
	if ((get-wmiobject Win32_ComputerSystem -ComputerName $ServerName).DomainRole -lt 2) { #Client OS
		$AVInstalled = [object[]](Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ComputerName $ServerName) #Check does any AV SW installed
		if ($AVInstalled) { #AV installd, getting basic info
			foreach ($item in $AVInstalled) {
            $hx = '0x{0:x}' -f $item.ProductState; $mid = $hx.Substring(3, 2); $end = $hx.Substring(5)
            if ($mid -match "00|01") { $Enabled = $False; $w += "<div>WAV: Warning: `t<i>$ServerName has Antivirus $($item.Displayname) disabled.</i></div>`r`n" } else { $Enabled = $True }
            if ($end -eq "00") { $UpToDate = $True } else { $UpToDate = $False; $w += "<div>WAV: Warning: `t<i>$ServerName has Antivirus $($item.Displayname) out of date.</i></div>`r`n"  }
				#Collecting results
            [void]$r.Add($($item | Select-Object @{Name='Antivirus Installed'; Expression = { $true} }, Displayname, ProductState, @{Name = "Enabled"; Expression = { $Enabled } }, @{Name = "UpToDate"; Expression = { $UptoDate } }, @{Name = "Path"; Expression = { $_.pathToSignedProductExe } }, Timestamp))
			}
		} #if
		else { #AV SW Not Detected
			$w += "<div>WAV: Warning: `t<i>$ServerName has no Antivirus installed.</i></div>`r`n"
		}
	}
	else { #Server OS
		$WinDefender = Get-WindowsFeature -ComputerName $ServerName | Where-Object {$_.InstallState -eq 'Installed' -and $_.DisplayName -match 'Defender'}
				#Collecting results
      if ($WinDefender) {[void]$r.Add([PSCustomObject]@{'Antivirus Installed'=$true; DisplayName='Windows Defender Antivirus'})}
		else { $Enabled = $False; $w += "<div>WAV: Warning: `t<i>Windows Defender AV not installed.</i></div>`r`n"
		#TODO: try to detect other AV installed
		}
	}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r}
} 
function ConvertTo-HTMLStyle {
	[cmdletbinding()]
	param (
		# Object to colorize
		[parameter(ValueFromPipeline, Mandatory)]
		$InputObj,
		[string]$PreContent
	)
	Begin {
		$HTMLOutput = $null
	}
	Process {
		if (!$InputObj) {return $null}
		$TableHeader = $null
		if (($InputObj -is [array]) -or ($InputObj -is [System.Collections.IDictionary])) {
		$InputObj.foreach({
		switch ($_.DIAG) {
		'ERROR' { $HTMLOutput += ("`r`n<TR class=e>") }
		'WARNING' {$HTMLOutput += ("`r`n<TR class=w>")}
		'NORMAL' {$HTMLOutput += ("`r`n<TR class=n>")}
		'UNKNOWN' {$HTMLOutput += ("`r`n<TR class=u>")}
		default {$HTMLOutput += ("`r`n<TR class=u>")}}
		$_.PSObject.Properties.where({$_.Name -ne 'DIAG'}).FOREACH({ $HTMLOutput += ("<TD class=" + $InputObj.Diag[$InputObj.Diag.Keys -eq $_.Name] + ">" + $([string]$_.Value) + "</TD>")})
		$HTMLOutput += ("</TR>")
		})} else {
			switch ($InputObj.DIAG) {
			'ERROR' { $HTMLOutput += ("`r`n<TR class=e>") }
			'WARNING' {$HTMLOutput += ("`r`n<TR class=w>")}
			'NORMAL' {$HTMLOutput += ("`r`n<TR class=n>")}
			'UNKNOWN' {$HTMLOutput += ("`r`n<TR class=u>")}
			default {$HTMLOutput += ("`r`n<TR class=u>")}}
			$InputObj.PSObject.Properties.where({ $_.Name -ne 'DIAG' }).FOREACH({
					if ($InputObj.Diag) { $HTMLOutput += ("<TD class=" + $InputObj.Diag[$InputObj.Diag.Keys -eq $_.Name] + ">" + $([string]$_.Value) + "</TD>") }
					else { $HTMLOutput += ("<TD class=n>" + $([string]$_.Value) + "</TD>")}
				})
		$HTMLOutput += ("</TR>")
		if (($InputObj -is [array]) -or ($InputObj -is [System.Collections.IDictionary])) {$InputObj[0].PSObject.Properties.where({$_.Name -ne 'DIAG'}).FOREACH({$TableHeader += ("<TH>" + $_.Name + "</TH>")})}
		else {$InputObj.PSObject.Properties.where({$_.Name -ne 'DIAG'}).FOREACH({$TableHeader += ("<TH>" + $_.Name + "</TH>")})}
		$TableHeader += ("</TR>") 
		}
	}
	End {$HTMLOutput =  $PreContent + "`r`n<TABLE><TR>" + $TableHeader + ($HTMLOutput.Replace('<TD class=>', '<TD class=u>')).Replace('::', '<br>') + "`n</TABLE>`r`n"; $HTMLOutput}
}
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
function Color-HState {
	[cmdletbinding()]
	param (
		# Object to colorize
		[parameter(ValueFromPipeline, Mandatory)]
		$HString
	)
	if ([string]::IsNullOrEmpty($HString)){$HString = "Unknown"}
	switch -regex ($HString) {
		'Degraded' { $HTMLOutput = ("<Td class=e>" + $HString + "</td>")}
		'Healthy' { $HTMLOutput = ("<Td class=n>" + $HString + "</td>") }
		'Unhealthy' { $HTMLOutput = ("<Td class=w>" + $HString + "</td>") }
		'UNKNOWN' {$HTMLOutput = ("<Td class=u>" + $HString + "</td>")}
		default {$HTMLOutput = ("<Td class=u>" + $HString + "</td>")}
		}
	$HTMLOutput
}
#function
#REGION:: Prepare ENVIRONMENT
#Create Ignore list from include array
[System.Collections.ArrayList]$RunTest = @('APP', 'AZS', 'CRT', 'EVT', 'GPO', 'LUS', 'NET', 'NTP', 'NST', 'PRC', 'VOL', 'SHA', 'SVC', 'TSK', 'USR', 'WAV', 'WFW', 'WHW', 'WUS')
if ($Include) { $RunTest = $Include -split ','}
if ($Ignore){
	[System.Collections.ArrayList]$it = $Ignore -split ','
	$It.foreach({ $RunTest.Remove($_) })
}
#check Distribution Point for a newer version and upgrade itself...
#Write-Host ('ScripDistributionPoint: {0} | Script Path: {1} | Script Name: {2}' -f $ScriptDistributionPoint, $MyInvocation.MyCommand.Path, $MyInvocation.MyCommand.Name) -BackgroundColor DarkCyan -ForegroundColor Yellow
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
#Check Language mode locally and remotely
if ($ExecutionContext.Sessionstate.LanguageMode -ne 'FullLanguage') {[void]$Problems.Add("<div>RUNTIME: Warning: `t<i>The Local POWERSHELL is not in FULL LANGUAGE MODE. The report will have limited details.</i></div>`r`n")}
$remotesesstion = New-PSSession -ComputerName $ServerName
if ((Invoke-Command -Session $remotesesstion -ScriptBlock { $ExecutionContext.SessionState.LanguageMode }).Value -ne 'FullLanguage') {[void]$Problems.Add("<div>RUNTIME: Warning: `t<i>The POWERSHELL on host $ServerName is not in FULL LANGUAGE MODE. The report will have limited details or unreliable details.</i></div>`r`n")}
Remove-PSSession -Id $remotesesstion.Id
#Verify Escalated execution, if nor try to rise
$RTUser = [Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $RTUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE) { Start-Process powershell.exe "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs; exit}
if ((New-Object Security.Principal.WindowsPrincipal $RTUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE) {Write-Status -Status Error -Message  "U do not hold enough rights, dude. Farewell."; throw}
#############################################################################
#If Powershell is running the 32-bit version on a 64-bit machine, we 
#need to force powershell to run in 64-bit mode .
#############################################################################
if (($pshome -like "*syswow64*") -and ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -like "64*")) {
    Write-Status -Status Warning -Message "Restarting script under 64 bit powershell"
    # relaunch this script under 64 bit shell
    & (join-path ($pshome -replace "syswow64", "sysnative")\powershell.exe) -file $myinvocation.mycommand.Definition @args
    # This will exit the original powershell process. This will only be done in case of an x86 process on a x64 OS.
    exit
}
# Show a brief help message if no parameters passed
if ($PSBoundParameters.Count -lt 1) { Write-host "`nCreate Server Health report and (optionaly) send it by email.`n  Usage:  .\$($myinvocation.MyCommand.Name) -ServerName localhost -EmailTo it@domain.com -Ignore ROL`n" -ForegroundColor Yellow}
$IgnoreParams = 'Install'
Write-Status -Status Information -Message "Prepare environment on $($ServerName) at $(Get-Date)"
#Enabling PSRemote
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ServerName -Concatenate -Force
Enable-WSManCredSSP -Role server -Force
Restart-Service WinRM -Force
#############################################################################
#REGION:: Register System Scheduled Task (switch -INSTALL)
if ($install) {
	Write-Status -Status Information -Message "Install Switch invoked. The script will be registered on $($ServerName) at as SYSTEM task for 06:00 AM every day"
	#copy script to %SystemRoot%
	$scriptpath = $MyInvocation.MyCommand.Path
	try {Copy-Item $scriptpath -Destination $(($env:PSModulePath -split ";").Where({$_ -like "$env:ProgramFiles*"})) -Force; $scriptpath = $(($env:PSModulePath -split ";").Where({$_ -like "$env:ProgramFiles*"}).trim() + '\' + $MyInvocation.myCommand.name) }
	catch {Write-Status -Status Error -Message  "unable to copy script to the %SYSTEMROOT%, running as is."}
	#Create parameters string to path to the script
	if ($PSBoundParameters.ContainsKey('Install')) { $PSBoundParameters.Remove('Install') }
	foreach ($key in $PSBoundParameters.Keys)	{
		if ($key -and ($IgnoreParams -notmatch $key)) { $val = $PSBoundParameters[$key] }
		# Handle different parameter types
		if ($val -is [switch]) { $commandString += " -$key" } # For switch parameters, just include the parameter name
		else { # For other parameters, include both name and value
			if ($val -is [string]) {$commandString += " -$key '$val'"} # Wrap string values in quotes
			else {$commandString += " -$key $val"}
		}
	}
	$reporttask = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $('-NoProfile -NonInteractive -ExecutionPolicy ByPass -command ' + '"& {. ''' + $scriptpath + '''' + $commandString + ';}"')
	$tasktrigger = New-ScheduledTaskTrigger -Daily -At 6am
	Register-ScheduledTask -TaskName "Send-ServerHealthMailReport($($ServerName))" -Action $reporttask -Trigger $tasktrigger -Description "Daily send server health report by email to $($EmailTo) for $($ServerName)" -User "SYSTEM" -RunLevel Highest -Force
}
#############################################################################
#REGION:: Check Networking
# Check Server IP address and issue warning if the public IP is detected
# Test Connection and warn if no responce
if (!(test-connection $ServerName -count 1 -quiet -ErrorAction 0)) {Write-Warning "No responce from the host $ServerName."; [void]$Problems.Add("<div>RUNTIME: Warning: `t<i>No ping responce from the host: $ServerName.</i></div>`r`n")}
$ServerNameIPResolved =  ((Test-Connection $ServerName -count 1 | Select-Object @{Name=$ServerName;Expression={$_.Address}},Ipv4Address).IPV4Address).IPAddressToString
if (($ServerNameIPResolved -NOTMATCH "^169\.254\.") -AND ($ServerNameIPResolved -NOTMATCH "^192\.168\.") -AND ($ServerNameIPResolved -NOTMATCH "^172\.(1[6-9]|2[0-9]|3[0-1])\.") -AND ($ServerNameIPResolved -NOTMATCH "^10\.") -AND ($ServerNameIPResolved -NOTMATCH "^127\.0\.0")) {
	Write-Warning "The IP Address for host $ServerName is resolved to Public v4 IP [$ServerNameIPResolved]. Report could may be proceeded incorrectly."; [void]$Problems.Add("<div>RUNTIME: Warning: `t<i>The IP Address for host $ServerName is resolved to Public v4 IP [$ServerNameIPResolved]. Report could not be proceeded correctly.</i></div>`r`n")
	#try to obtain Host local IP 
	$HostIpv4Addresses = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ServerName -filter 'IPEnabled="True"' | Select-Object -ExpandProperty IPAddress | Where-Object{$_ -notmatch ':'}
	$HostIpv4Addresses.foreach({if (($_ -MATCH "^192\.168\.") -or ($_ -MATCH "^172\.(1[6-9]|2[0-9]|3[0-1])\.") -or ($_ -MATCH "^10\.")) {$ServerName = $_} 
	else {
		[void]$Problems.Add("<div>NET: Warning: `t<i>The host has Public IP v4 address assigned: [$_].</i></div>`r`n")
		
	}})
}
$HostName = (Get-WmiObject win32_computersystem -ComputerName $ServerName).Name
try {$InternetInfo = Invoke-RestMethod "http://ipinfo.io/json" | Select-Object ip,hostname,city,region,country}
catch {[void]$Problems.Add("<div>NET: Warning: `t<i>The host has probably no internet access.</i></div>`r`n")}
if (($emailFrom -notmatch '^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$') -and ($InternetInfo)) { $EmailFrom = $InternetInfo.hostname -replace '^(.*?)\.', '${1}@' }
$InternetInfo | Add-Member -MemberType NoteProperty -Name "DIAG" -Value (@{ 'hostname' = 'n' })
#############################################################################
#REGION:: get HOST Name and Domain
	Write-Verbose "We are running on $ServerName and getting report for the $HostName..."
	$DomainName = ((Get-WmiObject win32_computersystem -ComputerName $ServerName).Domain -Split "\.")[0]
	Write-Verbose "Host Name is : $HostName ; Local Domain is : $DomainName"
	$DCName = (Get-WmiObject -Class win32_ntdomain -Filter "DomainName = '$DomainName'" -ComputerName $ServerName).DomainControllerName
	if (!$DCName) {[void]$Problems.Add("<div>LAN: Info: `t<i>Workgroup Environment.</i></div>`r`n")}
	Write-Verbose "DC Name is $DCName"
#############################################################################
#REGION:: Get HOST Win OS Info
	$computerSystem = get-wmiobject Win32_ComputerSystem -ComputerName $ServerName | Select-Object -property *
	if ($computerSystem.DomainRole -lt 2) {[void]$Problems.Add("<div>OS: Warning: `t<i>Target OS is not Server OS. Result may not be reliable.</i></div>`r`n"); $DIAG.Add('Role', 'w')}
	$computerOS = get-wmiobject Win32_OperatingSystem -ComputerName $ServerName | Select-Object -property *
	if ([math]::ceiling((NEW-TIMESPAN -Start (Get-CimInstance -ComputerName $ServerName Win32_OperatingSystem).InstallDate -end (get-date)).days /365) -gt 4) {[void]$Problems.Add("<div>OS: Warning: `t<i>This OS installation is too old.</i></div>`r`n"); $DIAG.Add('Installed', 'w')}
	if ([math]::ceiling($computerOS.FreePhysicalMemory /1MB) -lt $RAMLowFreeLimit) {[void]$Problems.Add("<div>OS: Warning: `t<i>Low Free RAM: $([math]::ceiling($computerOS.FreePhysicalMemory /1MB)) GB.</i></div>`r`n"); $DIAG.Add('Free RAM (GB)', 'w')}
	$HostOSinfo = [PSCustomObject]@{'DIAG'=$DIAG; 'Installed' = ([Management.ManagementDateTimeConverter]::ToDateTime($computerOS.InstallDate)).ToString("dd.MM.yyyy"); 'PCName' = $computerOS.PSComputerName; 'Role' = $ComputerRole[$computerSystem.DomainRole]; 'Domain' = $DomainName; 'Note' = $computerOS.Description; 'BootTime' = ([Management.ManagementDateTimeConverter]::ToDateTime($computerOS.LastBootUpTime)).ToString("dd.MM.yyyy"); 'BootupState' = $computerSystem.BootupState; 'OS' = $computerOS.caption; 'SP' = $computerOS.ServicePackMajorVersion; 'Owner' = $computerOS.RegisteredUser; "Free RAM (GB)" = [math]::ceiling($computerOS.FreePhysicalMemory /1MB); 'WinDir' = $computerOS.WindowsDirectory; 'OS Lang' = [System.Globalization.CultureInfo]::GetCultureInfo([int]$computerOS.OSLanguage).DisplayName; 'Reboot Pending' = (Get-PendingRebootState -ServerName $ServerName) }
	if (!$HostOSinfo) {[void]$Problems.Add("<div>OS: <b>Error:</b> `t<i>No Access to WMI at $ServerName.</i></div>`r`n"); }
	if ($HostOSinfo.'Reboot Pending') {[void]$Problems.Add("<div>OS: Warning: `t<i>OS Reboot Pending.</i></div>`r`n"); $HostOSinfo.DIAG.Add('Reboot Pending','w')}
	if ((new-timespan -Start (([Management.ManagementDateTimeConverter]::ToDateTime($computerOS.LastBootUpTime))) -End (Get-Date)).Days -le 1) {[void]$Problems.Add("<div>OS: Warning: `t<i>Host was restarted in last 24h.</i></div>`r`n"); $HostOSinfo.DIAG.Add('BootTime','w')}
	$OSLicensing = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ComputerName $ServerName | Where-Object { $_.PartialProductKey } | Select-Object Name, Description, LicenseStatus
	if ($OSLicensing.LicenseStatus -ne 1) {[void]$Problems.Add("<div>OS: <b>Error:</b> `t<i>The licensing status: $($OSLicensingStatus[$OSLicensing.LicenseStatus]) is not normal.</i></div>`r`n"); $OSLicensing.psobject.properties.Add([psnoteproperty]::new('DIAG',@{'LicenseStatus'='e'})); $OSLicensing.psobject.properties.Add([psnoteproperty]::new('HState','Unhealthy'))} else { $OSLicensing.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'LicenseStatus' = 'n' }));$OSLicensing.psobject.properties.Add([psnoteproperty]::new('HState','Healthy'))}
#############################################################################
#REGION:: MODULES - CODE TO RUN as JOBS
$rWHW = { #HW info : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'; 
		$computerBIOS = get-wmiobject Win32_BIOS -ComputerName $ServerName
		$computerSystem = get-wmiobject Win32_ComputerSystem -ComputerName $ServerName | Select-Object -property *
		$SecBOOTEnabled = Confirm-SecureBootUEFI
		$SysTemperature = ((Get-WMIObject -ComputerName $ServerName -Query "SELECT * FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation" -Namespace "root/CIMV2" | Select-Object HighPrecisionTemperature).HighPrecisionTemperature - 2732) / 10.0
	if (($computerSystem.TotalPhysicalMemory/1GB) -le 8) { $w = "<div>RAM: Warning: `t<i>The total amount of RAM installed is insufficient.</i></div>`r`n"; $DIAG.Add('RAM (GB)', 'w'); $HState = 'Degraded'}
	if (($computerSystem.TotalPhysicalMemory/1GB) -le 4) { $w = "<div>RAM: <b>Error:</b> `t<i>The total amount of RAM installed is low.</i></div>`r`n"; $DIAG.Add('RAM (GB)', 'e'); $HState = 'Unhealthy' }
	if (($SysTemperature) -gt 40) { $w += "<div>Cooling: <b>Error:</b> `t<i>The system temperature is high.</i></div>`r`n"; $DIAG.Add('System Temperature', 'e'); $HState = 'Degraded' }
	elseif (($SysTemperature) -gt 30) { $w += "<div>Cooling: Warning: `t<i>The system temperature is ubnormal.</i></div>`r`n"; $DIAG.Add('System Temperature', 'w'); $HState = 'Unhealthy' }
	if (!$SecBOOTEnabled) { $w += "<div>OS: Warning: `t<i>Secure boot</i> is not enabled.</div>"; $DIAG.Add('Secure BOOT', 'w'); $HState = 'Unhealthy' }
		#Build the HW info object 
	[void]$r.Add([PSCustomObject]@{'DIAG'=$DIAG; 'Manufacturer' = $computerSystem.Manufacturer; 'Model' = $computerSystem.Model; 'BIOS Vendor' = $computerBIOS.Manufacturer; 'SerialNumber' = $computerBIOS.SerialNumber; 'BIOS Version' = $computerBIOS.SMBIOSBIOSVersion; 'System Temperature' = $SysTemperature;'RAM (GB)' = "{0:N1}" -f ($computerSystem.TotalPhysicalMemory/1GB); 'Secure BOOT' = $SecBOOTEnabled;})
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rCPU = { #CPU info : run local or remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'; $CPUCores = 0;
		$CPULoad = [math]::ceiling(((Get-CimInstance -ComputerName $ServerName -ClassName Win32_Processor).LoadPercentage | Measure-Object -Average).Average)
		if (($CPULoad) -gt 90) { $w += "<div>CPU: <b>Error:</b> `t<i>CPU load is high.</i></div>`r`n"; $DIAG.Add('CPU Load', 'e'); $HState = 'Degraded' }
		elseif (($CPULoad) -gt 70) { $w += "<div>CPU: Warning: `t<i>CPU load is ubnormal.</i></div>`r`n"; $DIAG.Add('CPU Load', 'w'); $HState = 'Unhealthy' }
	 	$computerCPU = [object[]](get-wmiobject Win32_Processor -ComputerName $ServerName -Property DeviceID, Name, NumberOfCores, NumberOfLogicalProcessors, SocketDesignation, MaxClockSpeed)
		$computerCPU.Foreach({
			$CPUCores += $_.NumberOfLogicalProcessors
			[void]$r.Add([PSCustomObject]@{'DIAG'=$DIAG; 'CPU' = $_.Name; 'Socket' = $_.SocketDesignation; 'Cores' = $_.NumberOfCores; 'Logical Processors' = $_.NumberOfLogicalProcessors; 'Freq GHz' = [math]::floor($_.MaxClockSpeed/1024) ; 'CPU Load' = $CPULoad})
		})
		if ($CPUCores -le 4) { $w += "<div>CPU: Warning: `t<i>The number of CPU cores: $CPUCores is low.</i></div>`r`n"; $DIAG.Add('Logical Processors', 'w'); $HState = 'Unhealthy' }
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rHDD = { #HDD State : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
		$PhisicalDrive = [object[]](Get-PhysicalDisk | select-Object -Property FriendlyName,Model,HealthStatus,OperationalStatus,PhysicalLocation,SerialNumber,Size,BusType,DeviceId,MediaType,SpindleSpeed,Usage)
	$PhisicalDrive.Foreach({
			$DIAG = @{ }
			if (($_.OperationalStatus) -ne 'OK') {$w +="<div>DRIVE: <b>Error:</b> `t<i>Drive: $_.FriendlyName operational status is $_.OperationalStatus.</i></div>`r`n"; $DIAG.Add('OperationalStatus', 'e'); $HState = 'Degraded'} else { $DIAG.Add('OperationalStatus', 'n'); $HState = 'Healthy'}
			if (($_.HealthStatus) -ne 'Healthy') {$w +="<div>DRIVE: <b>Error:</b> `t<i>Drive: $_.FriendlyName health status is $_.HealthStatus.</i></div>`r`n"; $DIAG.Add('HealthStatus', 'e'); $HState = 'Degraded'} else { $DIAG.Add('HealthStatus', 'n'); $HState = 'Healthy'}
			[void]$r.Add([PSCustomObject]@{'DIAG'=$DIAG; 'DeviceId'=$_.DeviceId;'Model'=$_.Model;'Name'=$_.FriendlyName;'SerialNumber'=$_.SerialNumber;'MediaType'=$_.MediaType;'SpindleSpeed'=$_.SpindleSpeed;'BusType'=$_.BusType;'PhysicalLocation'=$_.PhysicalLocation;'Size (GB)' = "{0:N2}" -f ($_.Size/1GB);'OperationalStatus'=$_.OperationalStatus;'HealthStatus'=$_.HealthStatus;'Usage'=$_.Usage;});
		}) 
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rVOL = { #Vol space : run remotely
	param ($ServerName,$IgnoreList)
	$DriveLowFreeSpaceLimit = 18 # GB
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
		$LogicalDrive = ([object[]](Get-WmiObject Win32_LogicalDisk -ComputerName $ServerName)).where({($_.Size -gt 0) -and ($_.DriveType -eq 3) })
	$LogicalDrive.Foreach({
			$DIAG = @{ }
			if (([math]::ceiling($_.FreeSpace/1GB) -lt ($DriveLowFreeSpaceLimit/2)) -and ([math]::ceiling($_.FreeSpace/$_.Size*100) -lt 25)) {$w += "<div>VOL: <b>Error:</b> `tDrive free space is very low, drive: <i>$($_.DeviceID) free space: $([math]::ceiling($_.FreeSpace/1GB)) GB.</i></div>`r`n"; $DIAG ='Error'; $HState = 'Degraded'}
		 	elseif (([math]::ceiling($_.FreeSpace/1GB) -lt $DriveLowFreeSpaceLimit) -and ([math]::ceiling($_.FreeSpace/$_.Size*100) -lt 25)) {$w += "<div>VOL: Warning: `tDrive free space is low, drive: <i>$($_.DeviceID) free space: $([math]::ceiling($_.FreeSpace/1GB)) GB.</i></div>`r`n"; $DIAG ='Warning'; $HState = 'Unhealthy' }
         else { $DIAG = 'NORMAL'; $HState = 'Healthy'}
		 [void]$r.Add([PSCustomObject]@{'DIAG'=$DIAG; 'Drive' = $_.DeviceID; 'Label' = $_.VolumeName; 'Size (GB)' = "{0:N2}" -f ($_.Size/1GB); 'Free (GB)' = "{0:N2}" -f ($_.FreeSpace/1GB); '% Free' = "{0:P0}" -f ($_.FreeSpace/$_.Size);}); 
		}) 	
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}	
$AZS = { #AZureAD Join State : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
	try
	{
		[array]$cmdOutput = dsregcmd /status
		if ($cmdOutput) { $AZStatus = [PSCustomObject]@{ 'DIAG' = @{ 'TenantName' = 'n' }; 'TenantName' = ($cmdOutput | Where-Object{ $_ -match 'TenantName' }).Split(":")[1].trim(); 'Device Name' = ($cmdOutput | Where-Object{ $_ -match 'Device Name' }).Split(":")[1].trim(); 'AzureAdJoined' = ($cmdOutput | Where-Object{ $_ -match 'AzureAdJoined' }).Split(":")[1].trim(); 'EnterpriseJoined' = ($cmdOutput | Where-Object{ $_ -match 'EnterpriseJoined' }).Split(":")[1].trim(); 'DomainJoined' = ($cmdOutput | Where-Object{ $_ -match 'DomainJoined' }).Split(":")[1].trim(); 'Virtual Desktop' = ($cmdOutput | Where-Object{ $_ -match 'Virtual Desktop' }).Split(":")[1].trim() } }
	}
	catch { }
	try {
		$cmdOutput = & 'C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe' show # | findstr /C:"Agent Status"
		# $stats.split()[-1] -eq 'Connected'
		if ($cmdOutput)
		{
			$AZStatus = [PSCustomObject]@{ 'DIAG' = @{ }; 'Tenant ID' = ($cmdOutput | Where-Object{ $_ -match 'Tenant ID' }).Split(":")[1].trim(); 'Resource Name' = ($cmdOutput | Where-Object{ $_ -match 'Resource Name' }).Split(":")[1].trim(); 'Agent Status' = ($cmdOutput | Where-Object{ $_ -match 'Agent Status' }).Split(":")[1].trim(); 'Agent Last Heartbeat' = ($cmdOutput | Where-Object{ $_ -match 'Agent Last Heartbeat' }).Split(":")[1].trim(); 'Agent Error Details' = ($cmdOutput | Where-Object{ $_ -match 'Agent Error Details' }).Split(":")[1].trim(); 'GC Service (gcarcservice)' = ($cmdOutput | Where-Object{ $_ -match 'gcarcservice' }).Split(":")[1].trim() }
			if ($AZStatus.'Agent Status' -ne 'Connected') { $AZStatus.DIAG.Add('Agent Status', 'w'); $w += "<div>AZ: Warning: `t<i>Connection to Azure is not estableshed.</i></div>`r`n"; $HState = 'Unhealthy'  }
			if (([math]::ceiling((New-TimeSpan -end (Get-Date) -Start ([DateTime]::ParseExact($AZStatus.'Agent Last Heartbeat', 'yyyy-MM-ddTHH', $null))).TotalHours)) -gt 2) { $AZStatus.DIAG.Add('Agent Last Heartbeat', 'w'); $w += "<div>AZ: Warning: `t<i>Azure Agent connection is delayed.</i></div>`r`n"; $HState = 'Unhealthy'  }
			if (([math]::ceiling((New-TimeSpan -end (Get-Date) -Start ([DateTime]::ParseExact($AZStatus.'Agent Last Heartbeat', 'yyyy-MM-ddTHH', $null))).TotalHours)) -gt 3) { $AZStatus.DIAG.Add('Agent Last Heartbeat', 'e'); $w += "<div>AZ: <b>Error:</b> `t<i>Last Azure Agent connection long ago.</i></div>`r`n"; $HState = 'Degraded' }
			if (![string]::IsNullOrEmpty($AZStatus.'Agent Error Details')) { $AZStatus.DIAG.Add('Agent Error Details', 'e'); $w += "<div>AZ: <b>Error:</b> `t<i>Error in Azure Agent.</i></div>`r`n"; $HState = 'Degraded' }
			if ($AZStatus.'GC Service (gcarcservice)' -ne 'running') { $AZStatus.DIAG.Add('GC Service (gcarcservice)', 'e'); $w += "<div>AZ: <b>Error:</b> `t<i>Azure Agent Service is not running.</i></div>`r`n"; $HState = 'Degraded' }
		}
	}
	catch { }
	if (!$AZStatus) { $w += "<div>AZ: Info: `t<i>The host is not assigned to any MS365 tenant.</i></div>`r`n" }
	else { [void]$r.Add($AZStatus)}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rWUA = { #WUpdate queue : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@(); $DIAG = 'UNKNOWN'; $HState = 'Healthy'
		$session = New-Object -ComObject "Microsoft.Update.Session"
		$updatesearcher = $session.CreateUpdateSearcher()
		$searchresult = $updatesearcher.Search("IsInstalled=0")
		foreach ($update in $searchresult.Updates) {
		  if ($update.Title -match 'Security') {$w +="<div>WUA: Warning: `t<i>KB$($update.KBArticleIDs)</i> : Security patch is ready to install.</div>`r`n"; $DIAG ='Warning'; $HState = 'Unhealthy' }
		  [void]$r.Add($([PSCustomObject]@{ 'DIAG' = $DIAG; 'Title' = $update.Title; 'KB' = $($update.KBArticleIDs); }))
		}
	if ($r.count -gt 4) {$w += "<div>WUA: Warning: `tMany Windows Updates available were not installed: <i>$($r.count).</i></div>`r`n"; $DIAG = 'Warning'; $HState = 'Unhealthy' }
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rPUNS = { # Unsigned running processes : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
		$allPRC = get-process -FileVersionInfo -ErrorAction 0 | Select-Object OriginalFilename, FileDescription, CompanyName, FileName -Unique
		foreach ($prc in $allPRC) {
         if ($prc.FileName) {$prcSign = (Get-AuthenticodeSignature -FilePath $prc.FileName -ErrorAction SilentlyContinue)}
			if ($prcSign) {
				$prc.psobject.properties.Add([psnoteproperty]::new('SignatureStatusMessage',$prcSign.StatusMessage))
				$prc.psobject.properties.Add([psnoteproperty]::new('SignatureSubject',$prcSign.SignerCertificate.Subject))
         }
         else {$prc.psobject.properties.Add([psnoteproperty]::new('SignatureStatusMessage','unsigned'))}
			if ($prcSign.Status -ne 'Valid') {
				$prc.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'SignatureStatusMessage' = 'e' })); $HState = 'Degraded'
				[void]$r.Add($($prc | Select-Object DIAG, OriginalFilename, FileDescription, CompanyName, FileName, SignatureStatusMessage, SignatureSubject))
				$w += "<div>PROC: Warning: `t<i>$($prc.Filename)</i> : Running process has wrong signature.</div>`r`n";
			}
		}
		if ($r.count -gt 1) { $HState = 'Unhealthy' }
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rNTP = { #get time sync config and status : run remotely!
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
        #getting info
        #Check registry items
        $configuredNtpServerNameRegistryPolicy = $null 
        if (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Parameters -PathType Container) {
             $configuredNtpServerNameRegistryPolicy = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Parameters -Name 'NtpServer' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NtpServer
             $ConfiguredNTPServerByPolicy = $true; $ConfiguredNTPServerNameRaw = $configuredNtpServerNameRegistryPolicy.Trim()
          }
        else { 
             $ConfiguredNTPServerByPolicy = $false; $ConfiguredNTPServerNameRaw = ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name 'NtpServer').NtpServer).Trim()
          }
        if ($ConfiguredNTPServerNameRaw) { $ConfiguredNTPServerName = $ConfiguredNTPServerNameRaw.Split(' ') -replace ',0x.*' }
        else {$w += "<div>NTP: Warning: `t<i>Windows Time Service not configured</i></div>`r`n"; $DIAG.Add('Configured NTP Server Name', 'w'); $HState = 'Unhealthy' }

        #Get service status
        $NTPServiceStatus = (Get-Service -Name W32Time).Status
        #Get w32tm output
        $w32tmOutput = & 'w32tm' '/query', '/status'

        $sourceNameRaw = $w32tmOutput | Select-String -Pattern '^Source:'
        if ($sourceNameRaw) {
            $sourceNameRaw = $sourceNameRaw.ToString().Replace('Source:', '').Trim()
            $SourceName = $sourceNameRaw -replace ',0x.*'
        }
        else {$w += "<div>NTP: <b>Error:</b> `t<i>Data from w32tm was not obtained</i></div>`r`n"; $DIAG.Add('NTP Source Name', 'e'); $HState = 'Degraded'}

        $lastTimeSynchronizationDateTimeRaw = $w32tmOutput | Select-String -Pattern '^Last Successful Sync Time:'
        $StatusDateTime = $false
        if ($lastTimeSynchronizationDateTimeRaw) {
            $lastTimeSynchronizationDateTimeRaw = $lastTimeSynchronizationDateTimeRaw.ToString().Replace('Last Successful Sync Time:', '').Trim()
            <# Last time synchronization: Test: Date and time #>
            if ($lastTimeSynchronizationDateTimeRaw -eq 'unspecified') {$w += "<div>NTP: <b>Error:</b> `t<i>Last time synchronization date and time: Unknown</i></div>`r`n"; $DIAG.Add('Last Time Sync DateTime', 'e'); $HState = 'Degraded'}
            else {
                $LastTimeSynchronizationDateTime = Get-Date($lastTimeSynchronizationDateTimeRaw)
                $LastTimeSynchronizationElapsedSeconds = [int]((Get-Date) - $LastTimeSynchronizationDateTime).TotalSeconds
                $StatusDateTime = $true
                <# Last time synchronization: Test: Maximum number of seconds #>
                if ($LastTimeSynchronizationElapsedSeconds -eq $null -or $LastTimeSynchronizationElapsedSeconds -lt 0 -or $LastTimeSynchronizationElapsedSeconds -gt 1200) {
                    $StatusLastTimeSynchronization = $false
                    $w += "<div>NTP: Warning: `t<i>Last time synchronization Elapsed: $LastTimeSynchronizationElapsedSeconds seconds</i></div>`r`n"; $HState = 'Unhealthy'; $DIAG.Add('Last Time Sync Elapsed Seconds', 'w')
                }
                else { $StatusLastTimeSynchronization = $true }
            }
        }
        else { $w += "<div>NTP: <b>Error:</b> `t<i> Data from w32tm was not obtained</i></div>`r`n"; $DIAG.Add('NTP Service Status', 'e'); $HState = 'Degraded' }
			$TimeDiff = @()
			$w32tmOutput = & 'w32tm' '/monitor' '/computers:tik.cesnet.cz,0.cz.pool.ntp.org,ntp.suas.cz'
			$TimeDiffRaw = $w32tmOutput | Select-String -Pattern 'NTP:'
			$TimeDiffRaw.foreach({ if (($_.ToString().Replace('NTP:', '')).Replace('s offset from local clock','').Trim() -match "[+-]?(\d+[\.|\,]\d*|\.\d+)") {$TimeDiff += [int]$matches[0]} }) 
			#$TimeDiff
			$maxTD = ($TimeDiff | ForEach-Object { [Math]::Abs($_) } | Measure-Object -Maximum).Maximum
			foreach ($x in $TimeDiff) { if ([Math]::Abs($x) -eq $maxTD) { $maxTD = $x } }
#Prepare output
	if ([Math]::Abs($maxTD) -gt 19) {$w += "<div>NTP: <b>Error:</b> `t<i>Time gap between local and global time is high ($maxTD sec.).</i></div>`r`n"; $DIAG.Add('Time Gap with Internet Time (sec.)', 'e'); $HState = 'Degraded'}
	[void]$r.Add($([PSCustomObject]@{'DIAG'=$DIAG; 'NTP Service Status' = $NTPServiceStatus; 'Configured NTP Server By Policy' = $ConfiguredNTPServerByPolicy; 'Configured NTP Server Name' = $ConfiguredNTPServerName; 'NTP Source Name'= $SourceName; 'Sync Status' = $StatusDateTime; 'Time Gap with Internet Time (sec.)'=$maxTD; 'Last Time Sync DateTime' = $LastTimeSynchronizationDateTime; 'Time Sync Success' = $StatusLastTimeSynchronization; 'Last Time Sync Elapsed Seconds' = $LastTimeSynchronizationElapsedSeconds;}))
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rSVC = { # Get Services anomalies : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
		$DomainName = (Get-CimInstance win32_computersystem -ComputerName $ServerName).Domain
		$AllServices = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_Service -ComputerName $ServerName | Select-Object -Property * | Where-Object { $_.Name -notmatch ('({0})' -f ($IgnoreList -join "|")) }
	foreach ($svc in $AllServices) {
		$DIAG = @{ }
			$svc.psobject.properties.Add([psnoteproperty]::new('AssemblyPath',$($svc.PathName -replace '(\s{1,}(\-{1,2}|\/).*){1,}$')))
			$svc.AssemblyPath = $svc.AssemblyPath -replace '"'
			$svc.psobject.properties.Add([psnoteproperty]::new('DIAG', $DIAG))
			if ((-Not ($svc.AssemblyPath | Test-Path -PathType Leaf)) -and (!$svc.AssemblyPath -match '.exe$')) {$svc.AssemblyPath = ($svc.AssemblyPath + '.exe')}
			if (-Not ($svc.AssemblyPath | Test-Path)) {$w += "<div>SVC: Warning: `t<i>$($svc.Name)</i> : Service with missed executable.</div>`r`n"; $HState = 'Unhealthy' ; $svc.DIAG.Add('AssemblyPath', 'w')
				[void]$r.Add($($svc | Select-Object -Property DIAG,Name,DisplayName,StartMode,State,Status,StartName,PathName,AssemblyPath,SignatureStatusMessage,SignatureSubject))
			} #Service Exe not found
			else {
				$svcSign = (Get-AuthenticodeSignature -FilePath ($svc.AssemblyPath))
				$svc.psobject.properties.Add([psnoteproperty]::new('SignatureStatusMessage', $svcSign.StatusMessage))
				$svc.psobject.properties.Add([psnoteproperty]::new('SignatureSubject', $svcSign.SignerCertificate.Subject))
				#DEBUG
				#$w +="<p>($svc | Select-Object -Property Name,DisplayName,StartMode,State,Status,StartName,PathName,AssemblyPath,SignatureStatusMessage,SignatureStatus)"
			}
			if ((($svc.StartMode -eq "Auto") -and ($svc.State -ne "Running"))) {$svc.DIAG.Add('State', 'e'); $w += "<div>SVC: <b>Error:</b> `t<i>$($svc.Name)</i> : Service is configured for Automatic start but not running.</i></div>`r`n"; $HState = 'Degraded'; [void]$r.Add($($svc | Select-Object -Property DIAG,Name,DisplayName,StartMode,State,Status,StartName,PathName,AssemblyPath,SignatureStatusMessage,SignatureSubject))}
		elseif ($svcSign.Status -ne 'Valid') { $svc.DIAG.Add('SignatureStatusMessage', 'w'); [void]$r.Add($($svc | Select-Object -Property DIAG, Name, DisplayName, StartMode, State, Status, StartName, PathName, AssemblyPath, SignatureStatusMessage, SignatureSubject)); $w += "<div>SVC: Warning: `t<i>$($svc.Name)</i> : Service has wrong signature.</div>`r`n";}
		elseif (($svc.StartName -match $DomainName) -or ($svc.StartName -match $ServerName)) { $svc.DIAG.Add('StartName', 'w'); [void]$r.Add($($svc | Select-Object -Property DIAG, Name, DisplayName, StartMode, State, Status, StartName, PathName, AssemblyPath, SignatureStatusMessage, SignatureSubject)) }
	}
	if ($r.count -gt 1) {$HState = 'Unhealthy' }
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rLUS = { #Get Logged ON Users : RUN Remotely		
	param ($ServerName,$IgnoreList)
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
		$w = @(); $HState = 'Healthy'
			$lousers = [object[]]((quser /server:$ServerName | ForEach-Object { (($_.trim() -replace " {2,}",","))} | ConvertFrom-Csv))
			$qry = 'SELECT * FROM Win32_Process WHERE Name="explorer.exe"'
			$lousers.foreach({ [string]$tn=$_.Username
			    $_.Username = Get-WmiObject -Query $qry -ComputerName $ServerName| ForEach-Object { $_.GetOwner() } | Where-Object {$_.User -match $tn } | ForEach-Object {'{0}\{1}' -f $_.Domain, $_.User}
			    if ([string]::IsNullOrEmpty($_.Username)) {$_.Username = $tn}
			    if (Is-Admin $tn) {$_.psobject.properties.Add([psnoteproperty]::new("Is Local Admin",$true)); $_.psobject.properties.Add([psnoteproperty]::new("DIAG",'WARNING')); $w += "<div>OS: Warning: `tHigh privileged account <i>$tn</i> has active session.</div>"; $HState = 'Unhealthy'} else {$_.psobject.properties.Add([psnoteproperty]::new("Is Local Admin",$false))}
			})
			if (!$lousers) { # if no results from QUSER try to use WMI
				$regexU = '({0})' -f ($Global:ExcludeUsers -join "|")
				$lousers = Get-WmiObject Win32_LoggedOnUser -ComputerName $ServerName | Select-Object -Property * | Select-Object Antecedent -Unique | Where-Object { $_.Antecedent.ToString().Split('"')[1] -ne $ServerName -and $_.Antecedent.ToString().Split('"')[1] -ne "Window Manager" -and $_.Antecedent.ToString().Split('"')[3] -notmatch $ServerName } | ForEach-Object{"{0}\{1}" -f $_.Antecedent.ToString().Split('"')[1],$_.Antecedent.ToString().Split('"')[3]}
				$lousers = $lousers.where{$_ -notmatch $regexU}
				$lousers.foreach({if (Is-Admin $_) {$_.psobject.properties.Add([psnoteproperty]::new("Is Local Admin",$true)); $_.psobject.properties.Add([psnoteproperty]::new("DIAG",'WARNING')); $w += "<div>OS: Warning: `tHigh privileged account <i>$_</i></div> has active session."; $HState = 'Unhealthy' } else {$_.psobject.properties.Add([psnoteproperty]::new("Is Local Admin",$false))}
				})
			}
		if ($lousers) {$w += "<div>OS: Warning: `t<i>Active User's sesstions detected.</i></div>`r`n"; $HState = 'Unhealthy' }
		$lousers.foreach({ if ((Get-Date - Get-Date($_."LOGON TIME")).TotalMinutes -gt 1440) { $w += "<div>OS: Warning: `t<i>The user $($_.USERNAME) has old session.</i></div>`r`n"; $HState = 'Unhealthy' ; $_.DIAG = 'WARNING'} })
		[pscustomobject]@{'Warnings'=$w; 'report'=$lousers; 'HState'= $HState}
}
$rUSR = { #Get Local Users anomalies : run locally
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
	#Get Local User list
	#Account Disabled	Display Name	Account Name	Inactive Days	Password Expired In
	#Name,Description,PasswordAge,PasswordExpired,Lastlogin
	if ($ServerName -eq 'localhost') {$ServerName = $Env:Computername} #localhost bug on some systems
		$computer = [ADSI]"WinNT://$ServerName"
		$computer.Children | Where-Object {$_.SchemaClassName -eq 'user'} | Foreach-Object {
			$groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)} 
			$AccountDisabled = $false; if (($_.UserFlags[0] -band 2) -eq 2) {$AccountDisabled = $True}
			if ($_.Name[0] -eq 'Administrator') {
				$w += "<div>OS: Warning: `t<i>User Administrator was found.</i></div>`r`n"; $HState = 'Unhealthy' 
				$adminSID = (New-Object System.Security.Principal.NTAccount($_.Name[0])).Translate([System.Security.Principal.SecurityIdentifier]).value
				if (($adminSID -match '-500$') -and (!$AccountDisabled)) {$w += "<div>USR: <b>Error:</b> `t<i>The local Admin account name is ADMINISTRATOR and it is NOT DISABLED. This Account must be renamed or disabled.</i></div>`r`n"; $HState = 'Degraded'; $DIAG.Add('UserName', 'e')}
				elseif (($adminSID -match '-500$') -and ($_.Name[0] -notmatch 'admin')) {$w += "<div>USR: Warning: `t<i>Abnormal Local Admin account found: $($_.Name[0]).</i></div>`r`n"; $HState = 'Unhealthy' ; $DIAG.Add('UserName', 'w')}
				elseif ($adminSID -match '-500$') {$LocalAdminCount +=1}
    		[void]$r.Add($($_ | Select-Object @{n='DIAG';e={$DIAG}}, @{n='Computername';e={$ServerName}},@{n='Account Active';e={-not $AccountDisabled}},@{n='UserName';e={$_.Name[0]}},@{n='Description';e={$_.Description[0]}},@{n='Last Login';e={If ($_.LastLogin[0] -is [DateTime]) {$_.LastLogin[0]} Else { 'Never logged on' }}},@{n='PasswordAge';e={[Math]::Round($_.PasswordAge[0] / 86400)}},@{n='Groups';e={$groups -join '::'}}))
			}
		}
	if ($LocalAdminCount -gt 2) {$w += "<div>USR: Warning: `t<i>Too much high priviledged account found.</i></div>`r`n"; $HState = 'Unhealthy' } 
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$CRT = { #Certificates Audit : run remotely
	param ($ServerName,$IgnoreList)
	$w = @(); [Collections.ArrayList]$r = @(); $DIAG = @{ }; $HState = 'Healthy'
	$HostLANDNSName = (Get-WmiObject win32_computersystem -ComputerName $ServerName).Name + '.' + (Get-WmiObject -ComputerName $ServerName win32_computersystem).Domain
	$IgnoreList += $HostLANDNSName
		Get-ChildItem -Recurse Cert:\LocalMachine\My |Where-Object {($_.HasPrivateKey -eq $true) -and ($_.Subject -notmatch ('({0})' -f ($IgnoreList -join "|")))} | ForEach-Object {
		$crt = $_ | Select-Object -Property @{ n = 'DIAG'; e= { $DIAG } }, @{ n = 'IsTrusted'; e = { $_.verify() } } , @{ n = 'PrivateKeyExportable'; e = { $_.PrivateKey.CspKeyContainerInfo.Exportable } }, Thumbprint, @{ n = 'SubjectName'; e = { $_.SubjectName.Name } }, @{ n = 'DnsNameList'; e = { $($_.DnsNameList -join ',:: ') } }, Issuer, @{ n = 'EnhancedKeyUsageList'; e = { $(($_.EnhancedKeyUsageList -join ',:: ') -replace " \(((\d+).)+(\d+)\)") } }, NotBefore, NotAfter
		if (([datetime]$crt.NotAfter).Ticks -lt (Get-Date).Ticks) { $w += "<div>CER: <b>Error:</b> `tExpired certificate: <i>$($crt.SubjectName).</i></div>`r`n"; $crt.DIAG.Add('NotAfter', 'e') }
			elseif (([datetime]$crt.NotBefore).Ticks -gt (Get-Date).Ticks) { $w += "<div>CER: <b>Error:</b> `tPending certificate: <i>$($crt.SubjectName).</i></div>`r`n"; $HState = 'Unhealthy' ; $crt.DIAG.Add('NotBefore', 'e') }
			else { $crt.DIAG = @{ } }
			if ($crt.DIAG.Count -gt 0) {[void]$r.Add($crt)}
	}
	#End Block Code
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$SHA = { #Get Shares report - run Remotely !! Method invocation failed because [Selected.Microsoft.Management.Infrastructure.CimInstance] does not contain a method named 'foreach'.
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
	$SmbShares = Get-SmbShare -IncludeHidden | select-Object -property Name,Path,Volume,Description | Where-Object {$_.path -match '\\'}
	#SMB Access
	ForEach ($SmbShare in $SmbShares)
	{
		$DIAG = @{ }
		$smbsa = Get-SmbShareAccess -Name $smbshare.name | Select-Object @{ n = 'DIAG'; e = { $DIAG } }, @{ n = 'Path'; e = { $smbshare.path } }, @{ n = 'Description'; e = { $smbshare.Description } }, Name, AccountName, AccessRight, AccessControlType | ForEach-Object {
			$_.DIAG = @{ };
			if (($_.AccountName -eq 'Everyone') -and ($_.AccessRight -eq 'Full') -and ($_.AccessControlType -eq 'Allow')) {$w += "<div>SHA: <b>Error:</b> `tShare <i>$($smbshare.name)</i> has Everyone/FullControll access.</div>`r`n"; $HState = 'Unhealthy'; $_.DIAG.Add('AccountName', 'w')}
			if (($_.AccountName -eq 'ANONYMOUS LOGON') -and ($_.AccessRight -eq 'Full') -and ($_.AccessControlType -eq 'Allow')) {$w += "<div>SHA: <b>Error:</b> `tShare <i>$($smbshare.name)</i> has ANONYMOUS LOGON/FullControll access.</div>`r`n"; $HState = 'Unhealthy'; $_.DIAG.Add('AccountName', 'e')}
			if (($_.Path -match "^[a-zA-Z]:\\$") -and ($_.Name -notlike '*$')) {$w += "<div>SHA: Warning: `tThe ROOT folder of <i>$($smbshare.Path)</i> is shared.</div>`r`n"; $HState = 'Degraded'; $_.DIAG.Add('Path', 'w')}
			if (($_.Path -notmatch '^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\?)*$') -and (![string]::IsNullOrEmpty($_.Path))) {$w += "<div>SHA: Warning: `tNon common path: <i>$($smbshare.Path)</i> is shared.</div>`r`n"; $HState = 'Unhealthy' ; $_.DIAG.Add('Path', 'w')}
	    	if ($_.DIAG.count -gt 0) {[void]$r.add($_)}
			}
    }
    if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {$w +="<div>SHA: Warning: `t<i>SMB V1 protocol Enabled</i></div>`r`n"}
[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rWDf = { #Get WindowsDefender AV config : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy';
		$WAVStatus = Get-MpComputerStatus | Select-Object -Property AMRunningMode, AMServiceEnabled, ComputerState, DefenderSignaturesOutOfDate, IsTamperProtected, RealTimeProtectionEnabled
	if (!$WAVStatus) { $w += "<div>WAV: Warning: `t<i>Unable to get Windows Defender configuration.</i></div>`r`n"; $DIAG.Add('WAVStatus', 'e'); $HState = 'Unknown' }
	elseif ($WAVStatus.AMRunningMode -ne 'Normal') { $w += "<div>WAV: <b>Error:</b> `t<i>Windows Defender degraded.</i></div>`r`n"; $HState = 'Degraded'; $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'AMRunningMode'='w' })) }
	elseif (!$WAVStatus.AMServiceEnabled) { $w += "<div>WAV: <b>Error:</b> `t<i>Windows Defender service is not enabled.</i></div>`r`n"; $HState = 'Degraded'; $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'AMServiceEnabled'='e' })) }
	elseif ($WAVStatus.DefenderSignaturesOutOfDate) { $w += "<div>WAV: Warning: `t<i>Windows Defender signatures is outdated.</i></div>`r`n"; $HState = 'Unhealthy' ; $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'DefenderSignaturesOutOfDate'='w' }))}
		$WAVExclusions = Get-MpPreference | Select-Object -Property Exclusion*
		foreach ($Property in $WAVExclusions.PSObject.Properties) {
			$Property.Value.foreach({if ($_ -match '^[a-zA-Z]+:\\$') {$w += "<div>WAV: Warning: `t<i>AV exclusion contains some root folder(s).</i></div>`r`n"; $HState = 'Unhealthy' ; $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG',@{ $Property.Value = 'w' }))}})
			$Property.Value = ($Property.Value) -join "`n<br>"
			$WAVStatus.psobject.properties.Add([psnoteproperty]::new($Property.Name,$Property.Value))
		}
		if (($WAVStatus.DIAG.count -gt 0) -and $WAVStatus) {[void]$r.Add($WAVStatus)}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rFWC = { #Get WFW status : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
		Get-NetFirewallProfile | Select-Object -Property Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,Log* | foreach-object {
		if (!$_.Enabled) {$w += "<div>WFW: <b>Error:</b> `tThe firewall profile <i>$($_.Name)</i> is disabled.</div>`r`n"; $HState = 'Degraded'; $_.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'Enabled' = 'e' }))}
		if ($_.DIAG.Count -gt 0) {[void]$r.Add($_)} 
		}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rFWP = { #Analyze Windows Firewall Rules : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
		Get-NetFirewallPortFilter | ForEach-Object {
			$fwRule = $_ | Get-NetFirewallRule; $fwapp = ($fwRule | Get-NetFirewallApplicationFilter).Program
			if ($fwRule.Action -eq 'Allow' -and  $fwRule.Enabled -eq $true -and $fwRule.Direction -eq 'Inbound' -and $_.LocalPort -eq 'Any' -and $_.RemotePort -eq 'Any' -and $fwapp -eq 'Any') {
			$w += "<div>WFW: Warning: `tAny-Any firewall rule detected: <i>$($fwRule.DisplayName) ($($fwRule.Profile)).</i></div>`r`n"; $HState = 'Unhealthy' ; $fwRule.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'DisplayName' = 'e' }))
			$lport = $_.LocalPort; [void]$r.Add(($fwRule | Select-Object -Property DIAG,DisplayGroup,DisplayName,Profile,direction,@{n='LocalPort';e={$lport}} | Sort-Object -property LocalPort))
			}
		}
		$w = $w | sort-object -Unique
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rEVT = { #Get Event Log Errors count - run locally
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
		$SysErrEvCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "System"; Level = 2; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		$SysWarEvCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "System"; Level = 3; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		$SecErrEvCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "Security"; Level = 2; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		$SecWarEvCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "Security"; Level = 3; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		$AppErrEvCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "Application"; Level = 2; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		$AppWarEvCount = (Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "Application"; Level = 3; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }).count
		
		$APPEVTLogAge = [math]::Floor(((Get-Date) - ([DateTime]((Get-WinEvent -ComputerName $ServerName -LogName Application -MaxEvents 1 -Oldest).TimeCreated))).TotalDays)
		$SYSEVTLogAge = [math]::Floor(((Get-Date) - ([DateTime]((Get-WinEvent -ComputerName $ServerName -LogName System -MaxEvents 1 -Oldest).TimeCreated))).TotalDays)
		$SECEVTLogAge = [math]::Floor(((Get-Date) - ([DateTime]((Get-WinEvent -ComputerName $ServerName -LogName Security -MaxEvents 1 -Oldest).TimeCreated))).TotalDays)

		if ($AppErrEvCount -gt 48) {$w += "<div>EVT APP: Warning: `t<i>Too mach Errors in App Event Log in last 24h.</i></div>`r`n"; $DIAG.Add('App Errors', 'e'); $HState = 'Unhealthy' }		
		if ($AppWarEvCount -gt 72) {$w += "<div>EVT APP: Warning: `t<i>Too mach Warning in App Event Log in last 24h.</i></div>`r`n"; $DIAG.Add('App Warnings', 'w')}
		if ($SysErrEvCount -gt 24) {$w += "<div>EVT SYS: Warning: `t<i>Too mach Errors in SYSTEM Event Log in last 24h.</i></div>`r`n"; $DIAG.Add('System Erros', 'e'); $HState = 'Unhealthy' }
		if ($SysWarEvCount -gt 72) {$w += "<div>EVT SYS: Warning: `t<i>Too mach Warnings in SYSTEM Event Log in last 24h.</i></div>`r`n"; $DIAG.Add('System Warnings', 'w')}
		if ($SecErrEvCount -gt 24) {$w += "<div>EVT SEC: Warning: `t<i>Too mach Errors in SECURITY Event Log in last 24h.</i></div>`r`n"; $DIAG.Add('Security Errors', 'e'); $HState = 'Degraded'}
		if ($SecWarEvCount -gt 72) {$w += "<div>EVT SEC: Warning: `t<i>Too mach Warnings in SECURITY Event Log in last 24h.</i></div>`r`n"; $DIAG.Add('Security Warnings', 'w')}
		if ($SYSEVTLogAge -lt 7) {$w += "<div>EVT SYS: Warning: `tThe SYSTEM log age is <i>$($SYSEVTLogAge)</i> days.</div>`r`n"; $DIAG.Add('System Age', 'w')}
		if ($SECEVTLogAge -lt 7) {$w += "<div>EVT SYS: Warning: `tThe SECURITY log age is <i>$($SECEVTLogAge)</i> days.</div>`r`n"; $DIAG.Add('Security Age', 'w'); $HState = 'Unhealthy' }
		if ($APPEVTLogAge -lt 7) {$w += "<div>EVT SYS: Warning: `tThe Application log age is <i>$($APPEVTLogAge)</i> days.</div>`r`n"; $DIAG.Add('App Age', 'w')}
		[void]$r.Add([pscustomobject]@{'DIAG'=$DIAG; 'System Erros'=$SysErrEvCount; 'System Warnings'=$SysWarEvCount; 'System Age'=$SYSEVTLogAge; 'Security Errors'=$SecErrEvCount; 'Security Warnings'=$SecWarEvCount; 'Security Age'=$SECEVTLogAge; 'App Errors'=$AppErrEvCount; 'App Warnings'=$AppWarEvCount; 'App Age'=$APPEVTLogAge;}) 
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rEVTv = { #Get Event Log Errors verbosely - run locally
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}
#collect syslog events
    $erevs = Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "System"; Level = 2; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }
    $erevsco = $erevs | Group-Object -Property Id
    $erevs | Sort-Object -property id -Unique | foreach-object {$eid = $_.ID;[void]$r.Add($($_ | Select-Object -Property @{n='LOG';e={"System"}},TimeCreated,ID,ProviderName,Message,@{n='Count';e={($erevsco | ?{$_.Name -eq $eid}).Count}},@{n='DIAG';e={$DIAG}} ))}
#collect seclog events
    $erevs = Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "Security"; Level = 2; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }
    $erevsco = $erevs | Group-Object -Property Id
    $erevs | Sort-Object -property id -Unique | foreach-object {$eid = $_.ID;[void]$r.Add($($_ | Select-Object -Property @{n='LOG';e={"Security"}},TimeCreated,ID,ProviderName,Message,@{n='Count';e={($erevsco | ?{$_.Name -eq $eid}).Count}},@{n='DIAG';e={$DIAG}} ))}
#collect applog events
    $erevs = Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $ServerName -FilterHashtable @{ LogName = "Application"; Level = 2; StartTime = (Get-Date).AddHours(-24) } | Where-Object { ($_.ProviderName -like '*') }
    $erevsco = $erevs | Group-Object -Property Id
    $erevs | Sort-Object -property id -Unique | foreach-object {$eid = $_.ID;[void]$r.Add($($_ | Select-Object -Property @{n='LOG';e={"Application"}},TimeCreated,ID,ProviderName,Message,@{n='Count';e={($erevsco | ?{$_.Name -eq $eid}).Count}},@{n='DIAG';e={$DIAG}} ))}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
#############################################################################
#############################################################################
#REGION:: EXECUING TESTS
Write-Status -Status Information -Message "Starting jobs on $($ServerName) at $(Get-Date)"
if ($RunTest -contains 'EVT') {
		Start-Job $rEVT -ArgumentList $ServerName -Name "EVT" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
		Start-Job $rEVTv -ArgumentList $ServerName -Name "EVTV" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
} #OK
if ($RunTest -contains 'WUS') {
	Write-Status -Status Information -Message "Starting job Windows Update State for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {
	Start-Job -scriptblock $rWUA -Name "WUA" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
	else {
	Invoke-Command -computername $ServerName -scriptblock $rWUA  -JobName "WUA" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
}
if ($RunTest -contains 'WFW') {
	Write-Status -Status Information -Message "Starting job Windows Firewall State for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {
	Start-Job -scriptblock $rFWP -Name "FWP" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
	Start-Job -scriptblock $rFWC -Name "FWC" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
	else {
	Invoke-Command -computername $ServerName -scriptblock $rFWP -JobName "FWP" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
	Invoke-Command -computername $ServerName -scriptblock $rFWC -JobName "FWC" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
}
if ($RunTest -contains 'LUS') {
	Write-Status -Status Information -Message "Starting job Active User's Sessions for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {	Start-Job -scriptblock $rLUS -ArgumentList $ServerName -Name "LUS" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize }
	else {Invoke-Command -computername $ServerName -scriptblock $rLUS -ArgumentList $ServerName -JobName "LUS" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize } 
}
if ($RunTest -contains 'WHW') {
	Write-Status -Status Information -Message "Starting job Detect Hardware for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {	
		Start-Job -scriptblock $rWHW -ArgumentList $ServerName -Name "WHW" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize 
		Start-Job -scriptblock $rCPU -ArgumentList $ServerName -Name "CPU" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
		Start-Job -scriptblock $rHDD -ArgumentList $ServerName -Name "HDD" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize		
		Start-Job -scriptblock $rVOL -ArgumentList $ServerName -Name "VOL" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
		}
	else { 
	Invoke-Command -computername $ServerName -scriptblock $rWHW -ArgumentList $ServerName -JobName "WHW" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize 
	Invoke-Command -computername $ServerName -scriptblock $rCPU -ArgumentList $ServerName -JobName "CPU" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
	Invoke-Command -computername $ServerName -scriptblock $rHDD -ArgumentList $ServerName -JobName "HDD" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
	Invoke-Command -computername $ServerName -scriptblock $rVOL -ArgumentList $ServerName -JobName "VOL" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize
	}

}
if ($RunTest -contains 'WAV') {
	Write-Status -Status Information -Message "Starting job Windows Antivirus State for $($ServerName) at $(Get-Date)"
	$AVinfo = Detect-WindowsAVInstalled -ServerName $ServerName
	if ($AVinfo.report.DisplayName -match 'Windows Defender') {
		if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1"))
		{
			Start-Job -scriptblock $rWDf -ArgumentList $ServerName -Name "WDf" | Select-Object PSBeginTime, location, id, name, State, Error | Format-Table -AutoSize
		}
		else { Invoke-Command -computername $ServerName -scriptblock $rWDf -ArgumentList $ServerName -JobName "WDf" -AsJob | Select-Object PSBeginTime, location, id, name, State, Error | Format-Table -AutoSize }
	}
	elseif ($Null -eq $AVinfo.results)
	{
		# No Ativirus
		[void]$Problems.Add("<div>WAV: Warning: `t<i>Probably no Antivirus software installed.</i></div>`r`n")
	}
	else { [void]$Problems.Add("<div>WAV: Warning: `t<i>The 3d party Antivirus software installed. Only basic info was got.</i></div>`r`n") } # 3d party antivirus detected. Need custom detection routine 
}
if ($RunTest -contains 'SVC') {
	Write-Status -Status Information -Message "Starting job Windows Services State for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $rSVC -ArgumentList $ServerName,$Global:IgnoreServices -Name "SVC" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
	else { Invoke-Command -computername $ServerName -scriptblock $rSVC -ArgumentList $ServerName, $Global:IgnoreServices -JobName "SVC" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
}
if ($RunTest -contains 'USR') {
	Write-Status -Status Information -Message "Starting job Local Users for $($ServerName) at $(Get-Date)"
	Start-Job -scriptblock $rUSR -ArgumentList $ServerName, $Global:ExcludeUsers -Name "USR" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize #Run User analysis job
}
if ($RunTest -contains 'CRT') {
	Write-Status -Status Information -Message "Starting job Certificates for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $CRT -ArgumentList $ServerName -Name "CRT" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $CRT -ArgumentList $ServerName -JobName "CRT" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
}
if ($RunTest -contains 'SHA') {
	Write-Status -Status Information -Message "Starting job Shares for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $SHA -ArgumentList $ServerName -Name "SHA" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $SHA -ArgumentList $ServerName -JobName "SHA" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
}
if ($RunTest -contains 'NTP') {
	Write-Status -Status Information -Message "Starting job Internet Time for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $rNTP -ArgumentList $ServerName -Name "NTP" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $rNTP -ArgumentList $ServerName -JobName "NTP" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
}
if ($RunTest -contains 'AZS') {
	Write-Status -Status Information -Message "Starting job Azure Join State for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) {Start-Job -scriptblock $AZS -ArgumentList $ServerName -Name "AZS" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
	else {Invoke-Command -computername $ServerName -scriptblock $AZS -ArgumentList $ServerName -JobName "AZS" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
}
if ($RunTest -contains 'PRC') {
	Write-Status -Status Information -Message "Starting job Windows Processes for $($ServerName) at $(Get-Date)"
	if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1")) { Start-Job -scriptblock $rPUNS -ArgumentList $ServerName, $Global:TaskIgnorePrincipals -Name "PUNS" | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
	else { Invoke-Command -computername $ServerName -scriptblock $rPUNS -ArgumentList $ServerName, $Global:TaskIgnorePrincipals -JobName "PUNS" -AsJob | Select-Object PSBeginTime,location,id,name,State,Error | Format-Table -AutoSize}
}

#############################################################################
#REGION:: COLLECTING RESULTS
Write-Status -Status Information -Message "Waiting for completed jobs on $($ServerName) at $(Get-Date)"
$Watch = [System.Diagnostics.Stopwatch]::StartNew(); $runningmins = $Watch.Elapsed.Minutes
while ($null -ne (Get-Job)) {
		#$host.UI.RawUI.CursorPosition = $origpos; Write-Host $scroll[$idx] -NoNewline; $idx++; if ($idx -ge $scroll.Length) {$idx=0}; Start-Sleep -Milliseconds 100

	$jobsdone = Get-Job | Where-Object { $_.State -eq "Completed" }
	foreach ($jdone in $jobsdone)
	{
		$jout = Receive-Job -Id $jdone.Id
		if (!$jout) {[void]$Problems.Add("<div>JOB: Warning: `t<i>The JOB $($jdone.Name) on the host $ServerName return no output.</i></div>`r`n")}
		if ($null -ne $jout) {
			if (!([string]::IsNullOrEmpty($jout.Warnings))) {$jout.Warnings = $jout.Warnings | Sort-Object -Unique; }
			if ($jdone.Name -like "EVT") {$SysEvents = $jout}
			if ($jdone.Name -like "EVTV") {$SysEventsVer = $jout}
			if ($jdone.Name -like "FWC") {$WFWStatus = $jout}
			if ($jdone.Name -like "FWR") {$WFWRules = $jout}
			if ($jdone.Name -like "WUA") {$WuaAvailable = $jout}
			if ($jdone.Name -like "LUS") {$LoggedUsers = $jout}
			if ($jdone.Name -like "WHW") {$HWConfig = $jout}
			if ($jdone.Name -like "CPU") {$CPUConfig = $jout}
			if ($jdone.Name -like "HDD") {$HDDConfig = $jout}
			if ($jdone.Name -like "PUNS") {$UnsigProcs = $jout}
			if ($jdone.Name -like "WDf") {$WAVConfig = $jout}
			if ($jdone.Name -like "SVC") {$StrangeServices = $jout}
			if ($jdone.Name -like "USR") {$LocalUsers = $jout}
			if ($jdone.Name -like "CRT") {$Certificates = $jout}
			if ($jdone.Name -like "SHA") {$Shares = $jout}
			if ($jdone.Name -like "NTP") {$NTPStat = $jout}
			if ($jdone.Name -like "AZS") {$AZState = $jout}
			if ($jdone.Name -like "VOL") {$VOLstate = $jout}
		}
		Write-Status -Status Information -Message "The job $($jdone.Name) completed."
		Remove-Job -Id $jdone.Id
	}
	if (($Watch.Elapsed.Minutes - $runningmins) -gt 2) {$runningmins = $Watch.Elapsed.Minutes; Write-Status -Status Warning -Message "Job(s): $(((Get-Job | Where-Object { $_.State -ne 'Completed' }).Name) -join '; ') are running $($Watch.Elapsed.Minutes) minutes so far.. Waiting for results..."}
	if ($Watch.Elapsed.Minutes -gt $JobRunningLimit) {[void]$Problems.Add("<div>RUNTIME: Warning: `t<i>The JOBs $(((Get-Job | Where-Object { $_.State -ne 'Completed' }).Name) -join '; ') on the host $ServerName are running too long. These jobs where skipped.</i></div>`r`n"); $Watch.Stop(); break}
	if (Get-Job | Where-Object { $_.State -eq "Failed" }) {
		(Get-Job | Where-Object { $_.State -eq "Failed" }).foreach({Write-Status -Status Error -Message ("Job $_.Name was failed with error: " + ($_.ChildJobs[0].JobStateInfo.Reason.Message)); [void]$Problems.Add("<div>RUNTIME: Warning: `t<i>The JOB $($_.Name) on the host $ServerName was failed with error $($_.ChildJobs[0].JobStateInfo.Reason.Message) . This job was skipped.</i></div>`r`n")})
		Write-Status -Status Error -Message "Job(s): $(((Get-Job | Where-Object { $_.State -ne 'Failed' }).Name) -join '; ') are failed. Remove these jobs. "
		Get-Job | Where-Object { $_.State -eq "Failed" } | Remove-Job -Force
		}
}
#############################################################################
#REGION:: BUILD REPORT
Write-Status -Status Information -Message "Combine results and write the report on $($ServerName) at $(Get-Date)"
	
[void]$ReportHTMLArray.Add($($HostOSinfo | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Operating System </H3></td></tr></table>"))
if ($LoggedUsers.report) { [void]$ReportHTMLArray.Add($($LoggedUsers.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Logged On Users</H3></td></tr></table>"))}
if ($SysEvents.report) { [void]$ReportHTMLArray.Add($($SysEvents.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Last 24h. Event Log Errors & Warnings</H3></td></tr></table>")) }
if ($SysEventsVer.report) { [void]$ReportHTMLArray.Add($($SysEventsVer.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Last 24h. Event Log Errors List</H3></td></tr></table>")) }
if ($HWConfig.report) { [void]$ReportHTMLArray.Add($($HWConfig.report | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | SYSTEM HW </H3></td></tr></table>")) }
#REPLACE convertto-html !!!
$AZState.Warnings.foreach({[void]$Problems.Add($_)})
if ($AZState.report) { [void]$ReportHTMLArray.Add($($AZState.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Azure AD Join State</H3></td></tr></table>"))}	
$LoggedUsers.Warnings.foreach({[void]$Problems.Add($_)})
$HWConfig.Warnings.foreach({[void]$Problems.Add($_)})
$CPUConfig.Warnings.foreach({[void]$Problems.Add($_)})
if ($CPUConfig.report) { [void]$ReportHTMLArray.Add($($CPUConfig.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | CPU(s) </H3></td></tr></table>")) }
$HDDConfig.Warnings.foreach({[void]$Problems.Add($_)})
if ($HDDConfig.report) { [void]$ReportHTMLArray.Add($($HDDConfig.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Drives</H3></td></tr></table>")) }
$VOLstate.Warnings.foreach({[void]$Problems.Add($_)})
if ($VOLstate.report) { [void]$ReportHTMLArray.Add($($VOLstate.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Volumes</H3></td></tr></table>")) }
$NTPStat.Warnings.foreach({[void]$Problems.Add($_)})
if ($NTPStat.report) { [void]$ReportHTMLArray.Add($($NTPStat.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | NTP Status</H3></td></tr></table>").Replace("::", "<br/>")) }
$UnsigProcs.Warnings.foreach({[void]$Problems.Add($_)})
if ($UnsigProcs.report) { [void]$ReportHTMLArray.Add($($UnsigProcs.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Processes with wrong signature</H3></td></tr></table>")) }
$StrangeServices.Warnings.foreach({[void]$Problems.Add($_)})
if ($StrangeServices.report) { [void]$ReportHTMLArray.Add($($StrangeServices.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Strange Services</H3></td></tr></table>")) }
$LocalUsers.Warnings.foreach({[void]$Problems.Add($_)})
if ($LocalUsers.report) { [void]$ReportHTMLArray.Add($($LocalUsers.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | User Accounts</H3></td></tr></table>").Replace("::", "<br/>")) }
$Certificates.Warnings.foreach({[void]$Problems.Add($_)})
if ($Certificates.report) { [void]$ReportHTMLArray.Add($($Certificates.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Certificates</H3></td></tr></table>").Replace("::", "<br/>")) }
$Shares.Warnings.foreach({[void]$Problems.Add($_)})
if ($Shares.report) { [void]$ReportHTMLArray.Add($($Shares.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | SMB Shares</H3></td></tr></table>").Replace("::", "<br/>")) }
if ($AVinfo){$AVinfo.Warnings.foreach({[void]$Problems.Add($_)}); [void]$ReportHTMLArray.Add($($AVinfo.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Antivirus status</H3></td></tr></table>"))}
if ($WAVConfig) {	$WAVConfig.Warnings.foreach({[void]$Problems.Add($_)}); if ($WAVConfig.report) {[void]$ReportHTMLArray.Add($($WAVConfig.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Defender Status</H3></td></tr></table>"))}}
$WFWStatus.Warnings.foreach({[void]$Problems.Add($_)})
if ($WFWStatus.report) { [void]$ReportHTMLArray.Add($($WFWStatus.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Firewall Status</H3></td></tr></table>").Replace("::", "<br/>")) }
$WuaAvailable.Warnings.foreach({[void]$Problems.Add($_)})
if ($WuaAvailable.report) { [void]$ReportHTMLArray.Add($($WuaAvailable.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Updates Available</H3></td></tr></table>")) }
$SysEvents.Warnings.foreach({[void]$Problems.Add($_)})
$SysEventsVer.Warnings.foreach({[void]$Problems.Add($_)})
[void]$ReportHTMLArray.Add($($OSLicensing | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Operating System Licensing State</H3></td></tr></table>"))
[void]$ReportHTMLArray.Add($($InternetInfo | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Internet Connection info </H3></td></tr></table>"))
#############################################################################
#REGION:: SAVE & SEND REPORT
$ReportHTML = $Header + "<div><table><tr><td><H1>Host <font style='color: green;font-weight: bold;'>$($computerOS.PSComputerName)</font> health report.</H1></td><td style='text-align:right;'>Executed on <i>$ENV:COMPUTERNAME</i> as <i>$ENV:USERNAME</i> at $(get-date -Format s)</td></tr></table>"
if ($Problems -and $ShowProblems) {
	$ReportHTML += "<H2>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Problems found:</H2></div><div class='twoColumns'>`n<table width=90%><tr>`n"
	$Problems.foreach({
		if ($_ -match "Error:"){$EReportHTML += "" + ($_ -replace "<div>","<div>") + "`n"}
		elseif ($_ -match "Warning:") {$WReportHTML += "" + ($_ -replace "<div>","<div>") + "`n"}
		else {$EReportHTML += "" + ($_ -replace "<div>","<div>") + "`n"}
	})
	$ReportHTML += "<td class=e>" + $EReportHTML + "</td><td class=w>" + $WReportHTML + "</td>" + "</tr></table></div>`n"
}
if (!$HealthOnly) {$ReportHTMLArray.foreach({$ReportHTML += $_})} #Save full report
else { #save only Healthy/unhealthy status
	$ReportHTML += $($HostOSinfo | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Operating System </H3></td></tr></table>")
	$ReportHTML += "<table class=health><tr><td><H2>HOST: <font color=green>$($HostName) </font> | Event Log </H2></td>" + (Color-HState $SysEvents.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Hardware </H2></td>" + (Color-HState $HWConfig.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | CPU </H2></td>" + (Color-HState $CPUConfig.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Drives </H2></td>" + (Color-HState $HDDConfig.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Volumes </H2></td>" + (Color-HState $VOLstate.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Network Time </H2></td>" + (Color-HState $NTPStat.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Running Processes </H2></td>" + (Color-HState $UnsigProcs.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Services </H2></td>" + (Color-HState $StrangeServices.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Active Sessions </H2></td>" + (Color-HState $LoggedUsers.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | User Accounts </H2></td>" + (Color-HState $LocalUsers.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Certificates </H2></td>" + (Color-HState $Certificates.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | SMB Shares </H2></td>" + (Color-HState $Shares.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Antimalware </H2></td>" + (Color-HState $AVinfo.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Windows Defender </H2></td>" + (Color-HState $WAVConfig.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Windows Firewall </H2></td>" + (Color-HState $WFWStatus.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Windows Updates </H2></td>" + (Color-HState $WuaAvailable.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Operating System Licensing </H2></td>" + (Color-HState $OSLicensing.HState) + "</tr>"
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Azure </H2></td>" + (Color-HState $AZState.HState) + "</tr></table>"
	$ReportHTML += $($SysEventsVer.report | ConvertTo-HTMLStyle -PreContent "<table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Last 24h. Event Log Errors List</H3></td></tr></table>")
}
$ReportHTML += $Footer
#Mark Warining Logins as red
#foreach ($WL in $WarningLogins) { $ReportHTML = $ReportHTML.ToLower() -replace $WL,"<font color='red'>$WL</font>" }
$ReportFile = $ReportFilePath + "\" + $computerOS.PSComputerName + "-HEALTH-REPORT-" + ((Get-Date -Format dd.MM.yy).ToString()) + "-" + ((get-date -Format HH.mm.ss).ToString()) + ".html"
$ReportHTML | Out-File $ReportFile
if (Test-Path -Path $ReportFile -ErrorAction 0) { Write-Status -Status Information -Message "Report file $ReportFile created successfully."}
else { Write-warning "Report file could not be created." -foregroundColor Magenta }

# Optionaly Send Report by email - $ReportData structure
if ($emailTo -ne "") { #Send Email Report
		$subject = $computerOS.PSComputerName + " Server Health Report | " + ((Get-Date -Format dd.MM.yy).ToString()) + " " + ((get-date -Format HH.mm.ss).ToString())
		$body = $ReportHTML
		$ToDomain = $emailTo.Split("@")[1]
		if (!([System.Net.Sockets.TcpClient]::new().ConnectAsync($smtpServer, $SmtpServerPort).Wait(600)))
		{
			$DomainSMTPServer = (Resolve-DnsName -Name $ToDomain -Type MX).NameExchange
			if ($NULL -ne $DomainSMTPServer) { $smtpServer = $DomainSMTPServer }
		}
		if ([System.Net.Sockets.TcpClient]::new().ConnectAsync($smtpServer, $SmtpServerPort).Wait(600)) {
		Write-Status -Status Information -Message "Sending report to $($emailTo) by SMTP:$smtpServer"
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
		else {Write-Status -Status Error -Message "No SMTP servers available"}		
}

#############################################################################
#REGION:: Cleaning environment
Get-Job | Remove-Job -force
Get-variable * | Remove-variable -Scope Script -ErrorAction 0
#############################################################################
#REGION:: DONE
Write-Status -Status Information -Message "All DONE."
[console]::Beep(1000, 300)
#############################################################################