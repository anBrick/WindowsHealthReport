<#
To install as the task RUN:  .\Get-WindowsHealthReport25.ps1 -Install -ServerName localhost -EmailTo hospimed@arion.cz -HealthOnly -ShowProblems
#>
<#
What's new 2026: Reputation Engine integration
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
   [switch]$ShowProblems, # Display verbose information about errors & warnings detected (retired)
  [Parameter(Mandatory=$false)]
   [switch]$NoProblems, # Omit verbose information about errors & warnings detected 
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
	:root{ --ok:#16a34a; --warn:#f59e0b; --err:#dc2626; --info:#2563eb; --bg:#f1f5f9; --card:#ffffff; --text:#0f172a; --muted:#64748b; --border:#e2e8f0;}
	body { width:100%; min-width:1024px; padding-left: 12px; padding-right: 10px; font-family: Segoe UI, Verdana, sans-serif, ui-sans-serif, system-ui; font-size:14px; /*font-weight:300;*/ line-height:1.0; color:#222222; background-color:#f4f5f6;}
   strong{ font-weight:600;}
	p.warning { font-family: Segoe UI, sans-serif, ui-sans-serif, system-ui; font-size:12.5px; font-weight: normal; font-stretch: expanded; color:#7B6000; margin-bottom: 2px; margin-top: 0em; margin-left:4px; margin-right:4px; line-height:1.4; background-color:white;}
	p.info { font-family: Segoe UI, sans-serif, ui-sans-serif, system-ui; font-size:12.5px; font-weight: normal; font-stretch: expanded; color:#032282; margin-bottom: 2px; margin-top: 0em; margin-left:4px; margin-right:4px; line-height:1.4; background-color:white;}
	p.error { font-family: Segoe UI, sans-serif, ui-sans-serif, system-ui; font-size:12.5px; font-weight: normal; font-stretch: expanded; color:#7b0000; margin-bottom: 2px; margin-top: 0em; margin-left:4px; margin-right:4px; line-height:1.4; background-color:white;}
	h1{ font-size:17px; font-weight:bold; color:white; background-color:black;}
   h2{ font-size:14px; font-weight:normal;}
   h3{ font-size:17px; font-weight:normal; margin-top:3px; margin-bottom:1px; margin-left:4px; text-align:left;}
	.card{ background:var(--card); border-radius:12px; padding:18px; margin-bottom:20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1), 0 4px 6px rgba(0,0,0,0.05);}
   table {border: 0px solid #6E8BB6; background:#f3f3f3; margin-top:0px;}
	table.scope {border-collapse: collapse; border: 0px solid #ffffff; padding:8px; background-color:#f9faff; margin-top:8px; text-align:left;}
	table th { padding:4px; border-collapse: collapse; border: 0px solid #4c62b5; text-align:left; vertical-align:middle; background-color:#2563eb; color:white; font-size:14px; font-weight: normal;}
   table tr { padding:1px; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; margin-left:4px; margin-right:4px;}
   table tr.u { padding:1px; background-color:white; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:grey; margin-left:4px; margin-right:4px;}
   table tr.n { padding:1px; background-color:#8AFC95; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:black; margin-left:4px; margin-right:4px;}
   table tr.w { padding:1px; background-color:#FCEC8A; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:red; margin-left:4px; margin-right:4px;}
   table tr.e { padding:1px; background-color:#530A0A; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:#f3f587; margin-left:4px; margin-right:4px;}
   table td.dae { padding:15px; background-color:#dc2626; border-collapse: collapse; border: 0px solid #dc2626; text-align:left; vertical-align:middle; font-size:24px; font-family: system-ui, system-ui; color:white; margin-left:4px; margin-right:4px;}   
   table td.daw { padding:15px; background-color:#f59e0b; border-collapse: collapse; border: 0px solid #f59e0b; text-align:left; vertical-align:middle; font-size:24px; font-family: system-ui, system-ui; color:white; margin-left:4px; margin-right:4px;}
   table td.dan { padding:15px; background-color:#2563eb; border-collapse: collapse; border: 0px solid #2563eb; text-align:left; vertical-align:middle; font-size:24px; font-family: system-ui, system-ui; color:white; margin-left:4px; margin-right:4px;}
   table td.daef13 { padding:8px; background-color:#dc2626; border-collapse: collapse; border: 0px solid #dc2626; text-align:left; vertical-align:top; font-size:13px; font-family: system-ui, system-ui; color:white; margin-left:4px; margin-right:4px;}   
   table td.dawf13 { padding:8px; background-color:#f59e0b; border-collapse: collapse; border: 0px solid #f59e0b; text-align:left; vertical-align:top; font-size:13px; font-family: system-ui, system-ui; color:white; margin-left:4px; margin-right:4px;}
   table td.danf13 { padding:8px; background-color:#2563eb; border-collapse: collapse; border: 0px solid #2563eb; text-align:left; vertical-align:top; font-size:13px; font-family: system-ui, system-ui; color:white; margin-left:4px; margin-right:4px;}
   table td.u { padding:4px; background-color:white; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:grey; margin-left:4px; margin-right:4px;}
   table td.n { padding:4px; background-color:#8AFC95; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:black; margin-left:4px; margin-right:4px;}
   table td.w { padding:4px; background-color:#FEEC6A; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:red; margin-left:4px; margin-right:4px;}
   table td.e { padding:4px; background-color:#8F4040; border-collapse: collapse; border: 0px solid #000000; text-align:left; vertical-align:middle; font-size:12px; font-family: system-ui, system-ui; color:#f3f587; margin-left:4px; margin-right:4px;}
   .twoColumns { padding: 10px; -webkit-column-count: 2; -webkit-column-rule: 1px solid #6E8BB6; column-count: 2; column-gap: 10px; column-rule: 1px solid #6E8BB6;}
</style>
</head><body>
"@
$Footer = @"
    <div></div><!--End ReportBody--><div>
    <br><center><i>Source script: $($MyInvocation.MyCommand.Path)<br>Report file was saved to $($ReportFilePath)</i></p></center>
    <br><center><i>$(Get-Date -Format "dd/MM/yyyy HH:mm:ss")</i><p style="" font-size:8px;color:#7d9797"">Script Version: 2026.02 | By: Vladislav Jandjuk | Feedback: jandjuk@o30.cz | Git: github.com/anBrick/WindowsHealthReport</p></center>
    <br></div></body></html>
"@
#Other vasr and constants - change it if you know what you do
$ComputerRole = @("Standalone Workstation","Member Workstation","Standalone Server","Member Server","Domain Controller","Domain Controller","Unknown Role")
$OSLicensingStatus = @('Unlicensed','Licensed','OOBGrace','OOTGrace','NonGenuineGrace','Notification','ExtendedGrace','Undefined')
$ReportHTMLArray = [System.Collections.Generic.List[string]]::new()
$Problems = [System.Collections.Generic.List[string]]::new()
$DIAG = @{ }
#End of var area. You have not change the script code below
#############################################################################
#REGION:: ReputationEngine Class definition
<#
ReputationEngine.ps1
Version: 2.9 (Refactored: bug fixes, performance improvements, code quality)

Changes from 2.8:
  - [FIX]  PresenceScoreThreshold now persisted and restored on deserialization
  - [FIX]  ShouldRemove: removed redundant/inverted Score check (MinScoreToKeep removed)
  - [FIX]  UpdatePresence: Get-Date called once per invocation to avoid timestamp drift
  - [FIX]  GetOrCreate: TrustBias typed as [int] to prevent arithmetic errors on null/string input
  - [PERF] Cleanup: replaced O(n²) array += with Generic List
  - [PERF] Cleanup: only runs every $CleanupIntervalSaves saves, not on every Save()
  - [QUAL] Magic numbers moved into ReputationConfig (EmaAlpha, DeviationThreshold, BaseScore, etc.)
  - [QUAL] Key derivation extracted to ReputationRecord.GetKey() — no more 3x duplication
  - [QUAL] TrustBias clamp limits moved into ReputationConfig
  - [QUAL] Save() returns [bool] so callers can detect failures
  - [QUAL] BatchReconcile: absent-item marking extracted to private MarkAbsentItems()
#>

# ================= CONFIG =================
class ReputationConfig {
    [int]$MaxMissCount              = 10
    [int]$MaxAgeDays                = 30
    [int]$MinPresenceScore          = -40

    # Score calculation
    [int]$BaseScore                 = 50
    [double]$EmaAlpha               = 0.1
    [double]$DeviationThreshold     = 0.15
    [int]$PresenceScoreWeight       = 2
    [int]$DeviationPenalty          = 30

    # TrustBias clamping
    [int]$MinTrustBias              = -40
    [int]$MaxTrustBias              = 30

    # How many Save() calls between automatic Cleanup() runs (0 = every save)
    [int]$CleanupIntervalSaves      = 5
}

# ================= RECORD =================
class ReputationRecord {
    [string]$Hash
    [string]$ID
    [datetime]$FirstSeen
    [datetime]$LastSeen
    [datetime]$LastObserved
    [bool]$IsPresent
    [int]$PresenceScore             = 0
    [int]$PresenceScoreThreshold    = 20
    [double]$BaselineValue          = 0
    [double]$LastValue              = 0
    [int]$BaselineSamples           = 0
    [double]$LastDeviationWeighted  = 0
    [int]$Score                     = 0

    ReputationRecord([string]$Hash, [string]$ID) {
        $now = Get-Date
        $this.Hash           = $Hash
        $this.ID             = $ID
        $this.FirstSeen      = $now
        $this.LastSeen       = $now
        $this.LastObserved   = $now
        $this.IsPresent      = $true
        $this.PresenceScore  = 1
    }

    # Canonical key: prefer Hash, fall back to ID
    [string] GetKey() {
        return $(if ($this.Hash) { $this.Hash } else { $this.ID })
    }

    [void] UpdatePresence([bool]$Present) {
        $now = Get-Date          # capture once to avoid timestamp drift
        $this.LastObserved = $now
        $this.IsPresent    = $Present

        if ($Present) {
            $this.LastSeen = $now
            if ($this.PresenceScore -lt $this.PresenceScoreThreshold) {
                $this.PresenceScore++
            }
        }
        else {
            if ($this.PresenceScore -gt -($this.PresenceScoreThreshold)) {
                $this.PresenceScore -= 2
            }
        }
    }

    [bool] ShouldRemove([ReputationConfig]$cfg) {
        $now = Get-Date
        if ($this.PresenceScore -le $cfg.MinPresenceScore)         { return $true }
        if ($this.LastSeen -lt $now.AddDays(-$cfg.MaxAgeDays))     { return $true }
        return $false
    }

    [void] UpdateValue([double]$Value, [double]$MaxValue, [ReputationConfig]$cfg) {
        $this.LastValue = $Value

        if ($this.BaselineSamples -eq 0) {
            $this.BaselineValue   = $Value
            $this.BaselineSamples = 1
            return
        }

        $this.BaselineValue = ($cfg.EmaAlpha * $Value) + ((1 - $cfg.EmaAlpha) * $this.BaselineValue)
        $this.BaselineSamples++

        if ($MaxValue -gt 0 -and $this.BaselineValue -ne 0) {
            $percent    = [math]::Abs($Value - $this.BaselineValue) / $this.BaselineValue
            $sizeFactor = [math]::Log10($MaxValue + 1)
            $this.LastDeviationWeighted = $percent * $sizeFactor
        }
    }

    [int] CalculateScore([ReputationConfig]$cfg) {
        $result  = $cfg.BaseScore
        $result += $this.PresenceScore * $cfg.PresenceScoreWeight

        if ($this.LastDeviationWeighted -gt $cfg.DeviationThreshold) {
            $result -= $cfg.DeviationPenalty
        }

        $result     = [math]::Max(0, [math]::Min(100, $result))
        $this.Score = $result
        return $result
    }
}

# ================= CATALOG =================
class ReputationCatalog {
    [string]$Path
    [string]$BackupPath
    [hashtable]$Data
    [ReputationConfig]$Config

    hidden [int]$_saveCount = 0

    ReputationCatalog([string]$Path) {
        $this.Path       = $Path
        $this.BackupPath = "$Path.bak"
        $this.Config     = [ReputationConfig]::new()
        $this.Initialize()
    }

    [void] Cleanup() {
        $keysToRemove = [System.Collections.Generic.List[string]]::new()

        foreach ($key in $this.Data.Keys) {
            if ($this.Data[$key].ShouldRemove($this.Config)) {
                $keysToRemove.Add($key)
            }
        }

        foreach ($k in $keysToRemove) {
            Write-Verbose "Removing stale record: $k"
            $this.Data.Remove($k)
        }
    }

    [void] Initialize() {
        $folder = Split-Path $this.Path
        if (!(Test-Path $folder)) { New-Item $folder -ItemType Directory -Force | Out-Null }

        if (Test-Path $this.Path) {
            try {
                $raw = Import-Clixml $this.Path
                if ($raw -isnot [hashtable]) { throw "Invalid catalog format" }

                $this.Data = @{}
                foreach ($key in $raw.Keys) {
                    $r   = $raw[$key]
                    $obj = [ReputationRecord]::new($r.Hash, $r.ID)

                    $obj.FirstSeen              = $r.FirstSeen
                    $obj.LastSeen               = $r.LastSeen
                    $obj.LastObserved           = $r.LastObserved
                    $obj.IsPresent              = $r.IsPresent
                    $obj.PresenceScore          = $r.PresenceScore
                    $obj.PresenceScoreThreshold = $r.PresenceScoreThreshold   # FIX: was missing in 2.8
                    $obj.BaselineValue          = $r.BaselineValue
                    $obj.LastValue              = $r.LastValue
                    $obj.BaselineSamples        = $r.BaselineSamples
                    $obj.LastDeviationWeighted  = $r.LastDeviationWeighted
                    $obj.Score                  = $r.Score

                    $this.Data[$key] = $obj
                }
            }
            catch {
                Write-Warning "Catalog invalid or unreadable ($_). Reinitializing."
                $this.Data = @{}
                $this.Save() | Out-Null
            }
        }
        else {
            $this.Data = @{}
            $this.Save() | Out-Null
        }
    }

    # Returns $true on success, $false on failure so callers can react
    [bool] Save() {
        $this._saveCount++
        $interval = $this.Config.CleanupIntervalSaves
        if ($interval -le 0 -or ($this._saveCount % $interval) -eq 0) {
            $this.Cleanup()
        }

        $temp = "$($this.Path).tmp"
        try {
            if (Test-Path $this.Path) {
                Copy-Item $this.Path $this.BackupPath -Force
            }
            $this.Data | Export-Clixml $temp -ErrorAction Stop
            Move-Item $temp $this.Path -Force
            return $true
        }
        catch {
            Write-Warning "Save failed ($_). Attempting backup restore."
            if (Test-Path $this.BackupPath) {
                Copy-Item $this.BackupPath $this.Path -Force
            }
            return $false
        }
        finally {
            if (Test-Path $temp) { Remove-Item $temp -Force -ErrorAction SilentlyContinue }
        }
    }

    [ReputationRecord] GetOrCreate([string]$Hash, [string]$ID, [int]$TrustBias) {
        $key = if ($Hash) { $Hash } else { $ID }

        if (-not $this.Data.ContainsKey($key)) {
            $rec       = [ReputationRecord]::new($Hash, $ID)
            $TrustBias = [math]::Max($this.Config.MinTrustBias, [math]::Min($this.Config.MaxTrustBias, $TrustBias))
            if ($TrustBias -ne 0) { $rec.PresenceScore = [int]($TrustBias / 2) }
            $this.Data[$key] = $rec
        }

        return $this.Data[$key]
    }
}

# ================= ENGINE =================
class ReputationEngine {
    [ReputationCatalog]$Catalog

    ReputationEngine([string]$CatalogPath) {
        $this.Catalog = [ReputationCatalog]::new($CatalogPath)
    }

    [object[]] BatchReconcile([object[]]$Items) {
        $seen   = [System.Collections.Generic.HashSet[string]]::new()
        $output = [System.Collections.Generic.List[object]]::new()
        $cfg    = $this.Catalog.Config

        foreach ($i in $Items) {
            $bias = if ($null -ne $i.TrustBias) { [int]$i.TrustBias } else { 0 }
            $rec  = $this.Catalog.GetOrCreate($i.Hash, $i.ID, $bias)

            $seen.Add($rec.GetKey()) | Out-Null
            $rec.UpdatePresence($true)

            if ($null -ne $i.Value) {
                $max = if ($null -ne $i.MaxValue) { [double]$i.MaxValue } else { 0 }
                $rec.UpdateValue([double]$i.Value, $max, $cfg)
            }

            $score = $rec.CalculateScore($cfg)
            $i | Add-Member -NotePropertyName ReputationScore -NotePropertyValue $score -Force
				$i | Add-Member -NotePropertyName ReputationIsPresent -NotePropertyValue $true  -Force
            $output.Add($i)
        }

        $this.MarkAbsentItems($seen, $output, $cfg)
        return $output.ToArray()
    }

    # Marks catalog entries not seen in this batch as absent
    hidden [void] MarkAbsentItems(
        [System.Collections.Generic.HashSet[string]]$seen,
        [System.Collections.Generic.List[object]]$output,
        [ReputationConfig]$cfg
    ) {
        # Snapshot keys to avoid issues if Data is modified during iteration
        $allKeys = @($this.Catalog.Data.Keys)

        foreach ($key in $allKeys) {
            if ($seen.Contains($key)) { continue }

            $rec   = $this.Catalog.Data[$key]
            $rec.UpdatePresence($false)
            $score = $rec.CalculateScore($cfg)

            $output.Add([pscustomobject]@{
                Hash                = $rec.Hash
                ID                  = $rec.ID
                ReputationScore     = $score
                ReputationIsPresent = $false
            })
        }
    }

    # Returns $true on success
    [bool] Save() {
        return $this.Catalog.Save()
    }
}

#ENDREGION:: ReputationEngine Class
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
        #[System.Net.IPAddress]::Parse($ServerName)
        $ServerName = ([System.Net.Dns]::GetHostEntry($ServerName)).HostName
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
    <#
    .SYNOPSIS
    Determines whether a remote (or local) Windows machine is pending a reboot, using registry flags.

    .DESCRIPTION
    Queries a series of well-known registry keys and values that Windows (and ConfigMgr) set
    when a reboot is required. Stops as soon as any one indicator is found.

    .PARAMETER ServerName
    The target computer (defaults to the local machine).

    .OUTPUTS
    [bool]  Returns $true if any reboot-pending flag is detected; otherwise $false.

    .EXAMPLE
    Get-PendingRebootState -ServerName DC01 -Verbose
    #>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipelineByPropertyName)]
		[ValidateNotNullOrEmpty()]
		[string]$ServerName = $env:COMPUTERNAME
	)
	
	# Define all registry checks in one place:
	$tests = @(
		@{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'; Name = 'RebootPending' }
		@{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'; Name = 'RebootInProgress' }
		@{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'; Name = 'RebootRequired' }
		@{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'; Name = 'PackagesPending' }
		@{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'; Name = 'PostRebootReporting' }
		@{ Path = 'SYSTEM\CurrentControlSet\Control\Session Manager'; Name = 'PendingFileRenameOperations' }
		@{ Path = 'SYSTEM\CurrentControlSet\Control\Session Manager'; Name = 'PendingFileRenameOperations2' }
		@{ Path = 'SOFTWARE\Microsoft\Updates'; Name = 'UpdateExeVolatile' }
		@{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Name = 'DVDRebootSignal' }
		@{ Path = 'SOFTWARE\Microsoft\ServerManager\CurrentRebootAttemps'; Name = $null }
		@{ Path = 'SYSTEM\CurrentControlSet\Services\Netlogon'; Name = 'JoinDomain' }
		@{ Path = 'SYSTEM\CurrentControlSet\Services\Netlogon'; Name = 'AvoidSpnSet' }
		# ConfigMgr client flag
		@{ Path = 'SOFTWARE\Microsoft\CCMSetup'; Name = 'RebootRequested' }
		# Feature-On-Demand / DISM
		@{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\AdvancedInstall'; Name = 'RebootPending' }
		# Device migration
		@{ Path = 'SYSTEM\CurrentControlSet\Control\DeviceMigration'; Name = 'PendingDeviceMigration' }
		
		# Custom script: Active vs. Current ComputerName mismatch
		@{Script = {
				try{
					$acn = Get-RemoteRegistryValue -ServerName $ServerName -Key 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Value 'ComputerName'
					$ccn = Get-RemoteRegistryValue -ServerName $ServerName -Key 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Value 'ComputerName'
					return ($acn -and $ccn -and ($acn -ne $ccn))
				}
				catch{Write-Verbose "ComputerName mismatch check failed: $_"; return $false}
			}
		}
		
		# Custom script: Windows Update Services\Pending has >0 values
		@{Script = {
			try{
					$pnd = Get-RemoteRegistryValue -ServerName $ServerName -Key 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending'
					return ($pnd -and $pnd.ValueCount -gt 0)
				}
				catch{Write-Verbose "Pending services check failed: $_";return $false}
			}
		}
	)
	
	foreach ($test in $tests){
		if ($test.Script){
			if (& $test.Script){Write-Verbose 'Reboot-pending indicator found by script test.'; return $true}
		}
		else{
			try{
				# Does the key exist?
				$keyObj = Get-RemoteRegistryValue -ServerName $ServerName -Key $test.Path -ErrorAction Stop
				if ($keyObj){
					if ($test.Name){
						$val = Get-RemoteRegistryValue -ServerName $ServerName -Key $test.Path -Value $test.Name -ErrorAction Stop
						if ($null -ne $val){Write-Verbose "Found '$($test.Name)' under '$($test.Path)'.";return $true}
					}
					else{Write-Verbose "Found key '$($test.Path)'.";return $true}
				}
			}
			catch{Write-Verbose "Registry test failed for '$($test.Path)\$($test.Name)': $_"}
		}
	}
	Write-Verbose 'No reboot-pending indicators detected.';return $false
}

function Detect-WindowsAVInstalled{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$ServerName
	)
	
	begin { $W = [System.Collections.Generic.List[string]]::new(); [Collections.ArrayList]$r = @(); $DIAG = @{ } }
	process{
		try{
			$sys = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ServerName -ErrorAction Stop
			$isServer = $sys.DomainRole -ge 2
		}
		catch{
			$W.Add("<div>WAV: Error: `t<i>Unable to query system info on $ServerName : $_</i></div>`r`n")
			return [pscustomobject]@{ 'Warnings' = $W; 'Report' = $r }
		}
		if (-not $isServer){
			try { $avProducts = [object[]](Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ComputerName $ServerName -ErrorAction Stop) }
			catch{
				$W.Add("<div>WAV: Error: `t<i>Unable to query antivirus info on $ServerName : $_</i></div>`r`n")
				return [pscustomobject]@{ 'Warnings' = $W; 'Report' = $r }
			}
			if ($avProducts){
				foreach ($product in $avProducts){
					$state = [int]$product.ProductState
					$enabled = ($state -band 0x10) -ne 0
					$upToDate = ($state -band 0x100) -eq 0
					
					if (-not $Enabled) { $W.Add("<div>WAV: Warning: `t<i>$ServerName has Antivirus $($product.DisplayName) disabled.</i></div>`r`n") }
					if (-not $upToDate) { $W.Add("<div>WAV: Warning: `t<i>$ServerName has Antivirus $($product.DisplayName) out of date.</i></div>`r`n") }
					
					[void]$r.Add($($product | Select-Object @{ Name = 'Antivirus Installed'; Expression = { $true } }, DisplayName, ProductState, @{ Name = "Enabled"; Expression = { $Enabled } }, @{ Name = "UpToDate"; Expression = { $upToDate } }, @{ Name = "Path"; Expression = { $_.pathToSignedProductExe } }, Timestamp))
				} #foreach
			}
			else { $Enabled = $False; $W.Add("<div>WAV: Warning: `t<i>$ServerName has no Antivirus installed.</i></div>`r`n") }
		}
		else{
			#server OS
			try { $defender = Get-WindowsFeature -ComputerName $ServerName -ErrorAction Stop | Where-Object { $_.Name -match "Defender" } }
			catch{
				$W.Add("<div>WAV: Error: `t<i>Unable to query Windows Defender state on $ServerName : $_</i></div>`r`n")
				return [pscustomobject]@{ 'Warnings' = $W; 'Report' = $r }
			}
			if ($defender -and $defender.Installed) { $Enabled = $true; [void]$r.Add([PSCustomObject]@{ 'Antivirus Installed' = $true; DisplayName = $Defender.DisplayName }) }
			else { $Enabled = $False; $W.Add("<div>WAV: Warning: `t<i>$($Defender.DisplayName) AV not installed.</i></div>`r`n") }
		}
		
		[pscustomobject]@{ 'Warnings' = $W; 'Report' = $r }
	}
}

function ConvertTo-HTMLStyle {
	[cmdletbinding()]
	param (
		# Object to colorize
		[parameter(ValueFromPipeline, Mandatory)]
		$InputObj,
		[string]$PreContent
	)
	Begin {$HTMLOutput = $null}
	Process {
		if (!$InputObj) {return $null}
		$TableHeader = $null
		if (($InputObj -is [array]) -or ($InputObj -is [System.Collections.IDictionary])) {
		$InputObj.foreach({
		switch -regex ($_.DIAG) {
		'^E' {$HTMLOutput += ("`r`n<TR class=e>")}
		'^W' {$HTMLOutput += ("`r`n<TR class=w>")}
		'^N' {$HTMLOutput += ("`r`n<TR class=n>")}
		'^U' {$HTMLOutput += ("`r`n<TR class=u>")}
		default {$HTMLOutput += ("`r`n<TR class=u>")}}
		$_.PSObject.Properties.where({$_.Name -ne 'DIAG'}).FOREACH({ $HTMLOutput += ("<TD class=" + $InputObj.Diag[$InputObj.Diag.Keys -eq $_.Name] + ">" + $([string]$_.Value) + "</TD>")})
		$HTMLOutput += ("</TR>")
		})} else {
			switch -regex ($InputObj.DIAG) {
			'^E' {$HTMLOutput += ("`r`n<TR class=e>")}
			'^W' {$HTMLOutput += ("`r`n<TR class=w>")}
			'^N' {$HTMLOutput += ("`r`n<TR class=n>")}
			'^U' {$HTMLOutput += ("`r`n<TR class=u>")}
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
	End {
		$HTMLOutput =  $PreContent + "`r`n<TABLE><TR>" + $TableHeader + ($HTMLOutput.Replace('<TD class=>', '<TD class=u>')).Replace('::', '<br>') + "`n</TABLE>`r`n";
		if ($PreContent -match '(?i)^\s*<div\b') {$HTMLOutput += '</div>'}  # auto add closing DIV
		$HTMLOutput
	}
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
	# Log source for Application Event Log
	$source = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.PSCommandPath)
	if ([string]::IsNullOrEmpty($source)) {$source = [IO.Path]::GetFileNameWithoutExtension($PSCommandPath)}
	if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {[System.Diagnostics.EventLog]::CreateEventSource($source, "Application")} #register EvtLog Source
	Write-EventLog -LogName Application -Source $source -EntryType $Status -EventID 34343 -Message $(( '{0} Runtime message:: {1}') -f $MyInvocation.myCommand.name,$Message) -ea 0 
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
#############################################################################
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
	try {Invoke-WebRequest -Uri $($ScriptDistributionPoint + $MyInvocation.myCommand.name) -UseDefaultCredentials -OutFile $UpdatesFile
		Write-Status -Status Information -Message "New version downloaded from $($ScriptDistributionPoint + $MyInvocation.myCommand.name), begin updating itself."
	}
	catch {Write-Status -Status Error -Message "ERROR $_ : Unable to downlaod updates from $($ScriptDistributionPoint + $MyInvocation.myCommand.name), running as local version."}
	if (Test-Path $UpdatesFile) {
		Unblock-File $UpdatesFile -ea 0
		try {Copy-Item $UpdatesFile -Destination $($MyInvocation.MyCommand.Path) -Force;
			Write-Status -Status Information -Message "New version installed to $($MyInvocation.MyCommand.Path)."
		}
		catch {Write-Status -Status Error -Message "ERROR $_ : Unable to uplaod updates to $($MyInvocation.MyCommand.Path), update failed."}
		Remove-Item $UpdatesFile -ea 0
	}
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
#Check Language mode locally and remotely
if ($ExecutionContext.Sessionstate.LanguageMode -ne 'FullLanguage') {$Problems.Add("<div>RUNTIME: Warning: `t<i>The Local POWERSHELL is not in FULL LANGUAGE MODE. The report will have limited details.</i></div>`r`n"); Write-Status -Status Warning -Message  "Warning: POWERSHELL is not in FULL LANGUAGE MODE. The report will have limited details."}
try {
	$remotesesstion = New-PSSession -ComputerName $ServerName
	if ((Invoke-Command -Session $remotesesstion -ScriptBlock { $ExecutionContext.SessionState.LanguageMode }).Value -ne 'FullLanguage') {$Problems.Add("<div>RUNTIME: Warning: `t<i>The POWERSHELL on host $ServerName is not in FULL LANGUAGE MODE. The report will have limited details or unreliable details.</i></div>`r`n")}
	Remove-PSSession -Id $remotesesstion.Id
} catch {$Problems.Add("<div>RUNTIME: Warning: `t<i>Remote Powershell Invokation failure to $ServerName.</i></div>`r`n")}
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
#REGION TEMPORARY CHANGES:: replace target email address for report task if it is jandjuk@arion.cz to beta@arion.cz
# Old and new email addresses
$oldEmail = "jandjuk@arion.cz"
$newEmail = "beta@arion.cz"

# Get all scheduled tasks
$tasks = Get-ScheduledTask

foreach ($task in $tasks) {
    # Export the task XML
    $xml = (Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath) -join "`n"

    # Check if XML contains the old email
    if ($xml -match [regex]::Escape($oldEmail)) {
        Write-Output "Updating task: $($task.TaskPath)$($task.TaskName)"

        # Replace the old email with the new one
        $newXml = $xml -replace [regex]::Escape($oldEmail), $newEmail

        # Re-register the task with the modified XML
        $newXml | Register-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Force
    }
}

#############################################################################
#REGION:: Check Networking
# Check Server IP address and issue warning if the public IP is detected
# Test Connection and warn if no responce
if (!(test-connection $ServerName -count 1 -quiet -ErrorAction 0)) {Write-Warning "No responce from the host $ServerName."; $Problems.Add("<div>RUNTIME: Warning: `t<i>No ping responce from the host: $ServerName.</i></div>`r`n")}
$ServerNameIPResolved =  ((Test-Connection $ServerName -count 1 | Select-Object @{Name=$ServerName;Expression={$_.Address}},Ipv4Address).IPV4Address).IPAddressToString
if (($ServerNameIPResolved -NOTMATCH "^169\.254\.") -AND ($ServerNameIPResolved -NOTMATCH "^192\.168\.") -AND ($ServerNameIPResolved -NOTMATCH "^172\.(1[6-9]|2[0-9]|3[0-1])\.") -AND ($ServerNameIPResolved -NOTMATCH "^10\.") -AND ($ServerNameIPResolved -NOTMATCH "^127\.0\.0")) {
	Write-Warning "The IP Address for host $ServerName is resolved to Public v4 IP [$ServerNameIPResolved]. Report could may be proceeded incorrectly."; $Problems.Add("<div>RUNTIME: Warning: `t<i>The IP Address for host $ServerName is resolved to Public v4 IP [$ServerNameIPResolved]. Report could not be proceeded correctly.</i></div>`r`n")
	#try to obtain Host local IP 
	$HostIpv4Addresses = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ServerName -filter 'IPEnabled="True"' | Select-Object -ExpandProperty IPAddress | Where-Object{$_ -notmatch ':'}
	$HostIpv4Addresses.foreach({if (($_ -MATCH "^192\.168\.") -or ($_ -MATCH "^172\.(1[6-9]|2[0-9]|3[0-1])\.") -or ($_ -MATCH "^10\.")) {$ServerName = $_} 
	else {
		$Problems.Add("<div>NET: Warning: `t<i>The host has Public IP v4 address assigned: [$_].</i></div>`r`n")
	}})
}
#Get NIC Config
$NICConfig = @();
$opt = New-CimSessionOption -Protocol Dcom
$s = New-CimSession -ComputerName $ServerName -SessionOption $opt
$nic = Get-CimInstance -CimSession $s -ClassName Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select GUID,Name,ServiceName,MACAddress,Speed
$IPConfig = Get-CimInstance -CimSession $s -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | Select Description,IPAddress,MACAddress,DHCPEnabled
$VLANs = Get-CimInstance -CimSession $s -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapterAdvancedPropertySettingData -Filter "RegistryKeyword LIKE '%Vlan%'" | Where-Object {$_.DisplayName -match 'vlan\s*id'} | Select InterfaceDescription,DisplayName,DisplayValue
foreach ($n in $nic) {
    $i = $IPConfig | Where-Object {$_.MACAddress -eq $n.MACAddress}
    $v = $VLANs  | Where-Object {$_.InterfaceDescription -match $n.name}
    $NICConfig += [PSCustomObject]@{
        Server      = $ServerName
        Name        = $n.Name
        MACAddress  = $n.MACAddress
        ID          = 'NIC:{0}\{1}' -f $ServerName, $n.Name
        HASH        = 'NIC:{0}\{1}' -f $ServerName, $n.MACAddress
        ServiceName = $n.ServiceName
        DHCPEnabled = $i.DHCPEnabled
        SpeedGbps   = [math]::Round($n.Speed / 1000000000, 2)
        IPAddresses = [PSCustomObject]@{
                        IPv4 = $i.IPAddress | Where-Object {([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'}
                        IPv6 = $i.IPAddress | Where-Object {([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetworkV6'}
                      }
        "VLAN ID"   = $v.DisplayValue
		  Message = '<div>NIC: Info:	The Host <i>{0}</i> has network connection via: <i>{1}</i></div>' -f $ServerName, $n.Name
    }
}

$HostName = (Get-WmiObject win32_computersystem -ComputerName $ServerName).Name
try {$InternetInfo = Invoke-RestMethod "http://ipinfo.io/json" | Select-Object ip,hostname,city,region,country}
catch {$Problems.Add("<div>NET: Warning: `t<i>The host has probably no internet access.</i></div>`r`n")}
if (($emailFrom -notmatch '^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$') -and ($InternetInfo)) { $EmailFrom = $InternetInfo.hostname -replace '^(.*?)\.', '${1}@' }
$InternetInfo | Add-Member -MemberType NoteProperty -Name "DIAG" -Value (@{ 'hostname' = 'n' })
#############################################################################
#REGION:: get HOST Name and Domain
	Write-Verbose "We are running on $ServerName and getting report for the $HostName..."
	$DomainName = ((Get-WmiObject win32_computersystem -ComputerName $ServerName).Domain -Split "\.")[0]
	Write-Verbose "Host Name is : $HostName ; Local Domain is : $DomainName"
	$DCName = (Get-WmiObject -Class win32_ntdomain -Filter "DomainName = '$DomainName'" -ComputerName $ServerName).DomainControllerName
	if (!$DCName) {$Problems.Add("<div>LAN: Info: `t<i>Workgroup Environment.</i></div>`r`n")}
	Write-Verbose "DC Name is $DCName"
#############################################################################
#REGION:: Get HOST Win OS Info
	$computerSystem = get-wmiobject Win32_ComputerSystem -ComputerName $ServerName | Select-Object -property *
	if ($computerSystem.DomainRole -lt 2) {$Problems.Add("<div>OS: Warning: `t<i>Target OS is not Server OS. Result may not be reliable.</i></div>`r`n"); $DIAG.Add('Role', 'w')}
	$computerOS = get-wmiobject Win32_OperatingSystem -ComputerName $ServerName | Select-Object -property *
	if ([math]::ceiling((NEW-TIMESPAN -Start (Get-CimInstance -ComputerName $ServerName Win32_OperatingSystem).InstallDate -end (get-date)).days /365) -gt 4) {$Problems.Add("<div>OS: Warning: `t<i>This OS installation is too old.</i></div>`r`n"); $DIAG.Add('Installed', 'w')}
	if ([math]::ceiling($computerOS.FreePhysicalMemory /1MB) -lt $RAMLowFreeLimit) {$Problems.Add("<div>OS: Warning: `t<i>Low Free RAM: $([math]::ceiling($computerOS.FreePhysicalMemory /1MB)) GB.</i></div>`r`n"); $DIAG.Add('Free RAM (GB)', 'w')}
	$HostOSinfo = [PSCustomObject]@{'DIAG'=$DIAG; 'Installed' = ([Management.ManagementDateTimeConverter]::ToDateTime($computerOS.InstallDate)).ToString("dd.MM.yyyy"); 'PCName' = $computerOS.PSComputerName; 'Role' = $ComputerRole[$computerSystem.DomainRole]; 'Domain' = $DomainName; 'Note' = $computerOS.Description; 'BootTime' = ([Management.ManagementDateTimeConverter]::ToDateTime($computerOS.LastBootUpTime)).ToString("dd.MM.yyyy"); 'BootupState' = $computerSystem.BootupState; 'OS' = $computerOS.caption; 'SP' = $computerOS.ServicePackMajorVersion; 'Owner' = $computerOS.RegisteredUser; "Free RAM (GB)" = [math]::ceiling($computerOS.FreePhysicalMemory /1MB); 'WinDir' = $computerOS.WindowsDirectory; 'OS Lang' = [System.Globalization.CultureInfo]::GetCultureInfo([int]$computerOS.OSLanguage).DisplayName; 'Reboot Pending' = (Get-PendingRebootState -ServerName $ServerName) }
	if (!$HostOSinfo) {$Problems.Add("<div>OS: <b>Error:</b> `t<i>No Access to WMI at $ServerName.</i></div>`r`n"); }
	if ($HostOSinfo.'Reboot Pending') {$Problems.Add("<div>OS: Warning: `t<i>OS Reboot Pending.</i></div>`r`n"); $HostOSinfo.DIAG.Add('Reboot Pending','w')}
	if ((new-timespan -Start (([Management.ManagementDateTimeConverter]::ToDateTime($computerOS.LastBootUpTime))) -End (Get-Date)).Days -le 1) {$Problems.Add("<div>OS: Warning: `t<i>Host was restarted in last 24h.</i></div>`r`n"); $HostOSinfo.DIAG.Add('BootTime','w')}
	$OSLicensing = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ComputerName $ServerName | Where-Object { $_.PartialProductKey } | Select-Object Name, Description, LicenseStatus
	if ($OSLicensing.LicenseStatus -ne 1) {$Problems.Add("<div>OS: <b>Error:</b> `t<i>The licensing status: $($OSLicensingStatus[$OSLicensing.LicenseStatus]) is not normal.</i></div>`r`n"); $OSLicensing.psobject.properties.Add([psnoteproperty]::new('DIAG',@{'LicenseStatus'='e'})); $OSLicensing.psobject.properties.Add([psnoteproperty]::new('HState','Unhealthy'))} else { $OSLicensing.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'LicenseStatus' = 'n' }));$OSLicensing.psobject.properties.Add([psnoteproperty]::new('HState','Healthy'))}
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
		$PhisicalDrive = [object[]](Get-PhysicalDisk | select-Object -Property UniqueId,FriendlyName,Model,HealthStatus,OperationalStatus,PhysicalLocation,SerialNumber,Size,BusType,DeviceId,MediaType,SpindleSpeed,Usage)
	$PhisicalDrive.Foreach({
			$DIAG = @{ }
			if (($_.OperationalStatus) -ne 'OK'){
				$w += [pscustomobject]@{
					ID = "HDRIVE:$ServerName`\$_.FriendlyName"
					Hash = "HDRIVE:$ServerName`\$_.UniqueId"
					TrustBias = -20
					Message = "<div>DRIVE: <b>Error:</b> `t<i>Drive: $_.FriendlyName operational status is $_.OperationalStatus.</i></div>`r`n"
				}
				$HState = 'Degraded'
			}
			else { $DIAG.Add('OperationalStatus', 'n'); $HState = 'Healthy' }
			if (($_.HealthStatus) -ne 'Healthy'){
				$w += [pscustomobject]@{
					ID = "HDRIVE:$ServerName`\$_.FriendlyName"
					Hash = "HDRIVE:$ServerName`\$_.UniqueId"
					TrustBias = -20
					Message = "<div>DRIVE: <b>Error:</b> `t<i>Drive: $_.FriendlyName health status is $_.HealthStatus.</i></div>`r`n"
				}
				$DIAG.Add('HealthStatus', 'e'); $HState = 'Degraded'
			}
			else { 
				$w += [pscustomobject]@{
					ID = "HDRIVE:$ServerName`\$_.FriendlyName"
					Hash = "HDRIVE:$ServerName`\$_.UniqueId"
					TrustBias = -10
					Message = "<div>DRIVE: <b>Info:</b> `t<i>Drive: $_.FriendlyName health status is $_.HealthStatus.</i></div>`r`n"
				}
				$DIAG.Add('HealthStatus', 'n'); $HState = 'Healthy' 
			}
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
			$ovol = [pscustomobject]@{
					ID = "VOLUME:$ServerName`\$_.VolumeName"
					Hash = "VOLUME:$ServerName`\$_.DeviceID"
					Value = $_.FreeSpace
					MaxValue = $_.Size}
			if (([math]::ceiling($_.FreeSpace/1GB) -lt ($DriveLowFreeSpaceLimit/2)) -and ([math]::ceiling($_.FreeSpace/$_.Size * 100) -lt 25)){
				$ovol | Add-Member -NotePropertyName TrustBias -NotePropertyValue -40 -Force
				$ovol | Add-Member -NotePropertyName Message -NotePropertyValue "<div>VOL: <b>Error:</b> `tDrive free space is very low, drive: <i>$($_.DeviceID) free space: $([math]::ceiling($_.FreeSpace/1GB)) GB.</i></div>`r`n" -Force
				$DIAG ='Error'; $HState = 'Degraded'}
			elseif (([math]::ceiling($_.FreeSpace/1GB) -lt $DriveLowFreeSpaceLimit) -and ([math]::ceiling($_.FreeSpace/$_.Size * 100) -lt 25)){
				$ovol | Add-Member -NotePropertyName TrustBias -NotePropertyValue -30 -Force
				$ovol | Add-Member -NotePropertyName Message -NotePropertyValue "<div>VOL: Warning: `tDrive free space is low, drive: <i>$($_.DeviceID) free space: $([math]::ceiling($_.FreeSpace/1GB)) GB.</i></div>`r`n" -Force
				$DIAG ='Warning'; $HState = 'Unhealthy' }
         else { 
				$ovol | Add-Member -NotePropertyName TrustBias -NotePropertyValue -1 -Force
				$ovol | Add-Member -NotePropertyName Message -NotePropertyValue "<div>VOL: Info: `tDrive: <i>$($_.DeviceID) free space: $([math]::ceiling($_.FreeSpace/1GB)) GB.</i></div>`r`n" -Force
				$DIAG = 'NORMAL'; $HState = 'Healthy'
			}
			$w += $ovol
		 [void]$r.Add([PSCustomObject]@{'DIAG'=$DIAG; 'Drive' = $_.DeviceID; 'Label' = $_.VolumeName; 'Size (GB)' = "{0:N2}" -f ($_.Size/1GB); 'Free (GB)' = "{0:N2}" -f ($_.FreeSpace/1GB); '% Free' = "{0:P0}" -f ($_.FreeSpace/$_.Size);}); 
		}) 	
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}	
$AZS = { #AZureAD Join State : run remotely
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
	try {	[array]$cmdOutput = dsregcmd /status}
	catch { }
	if ($cmdOutput) { $AZStatus = [PSCustomObject]@{ 'DIAG' = @{ 'TenantName' = 'n' }; 'TenantName' = ($cmdOutput | Where-Object{ $_ -match 'TenantName' }).Split(":")[1].trim(); 'Device Name' = ($cmdOutput | Where-Object{ $_ -match 'Device Name' }).Split(":")[1].trim(); 'AzureAdJoined' = ($cmdOutput | Where-Object{ $_ -match 'AzureAdJoined' }).Split(":")[1].trim(); 'EnterpriseJoined' = ($cmdOutput | Where-Object{ $_ -match 'EnterpriseJoined' }).Split(":")[1].trim(); 'DomainJoined' = ($cmdOutput | Where-Object{ $_ -match 'DomainJoined' }).Split(":")[1].trim(); 'Virtual Desktop' = ($cmdOutput | Where-Object{ $_ -match 'Virtual Desktop' }).Split(":")[1].trim() } }
	try {	$cmdOutput = & 'C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe' show } # | findstr /C:"Agent Status" 
	catch { }
		# $stats.split()[-1] -eq 'Connected'
		if ($cmdOutput){
			$AZStatus = [PSCustomObject]@{ 'DIAG' = @{ }; 'Tenant ID' = ($cmdOutput | Where-Object{ $_ -match 'Tenant ID' }).Split(":")[1].trim(); 'Resource Name' = ($cmdOutput | Where-Object{ $_ -match 'Resource Name' }).Split(":")[1].trim(); 'Agent Status' = ($cmdOutput | Where-Object{ $_ -match 'Agent Status' }).Split(":")[1].trim(); 'Agent Last Heartbeat' = ($cmdOutput | Where-Object{ $_ -match 'Agent Last Heartbeat' }).Split(":")[1].trim(); 'Agent Error Details' = ($cmdOutput | Where-Object{ $_ -match 'Agent Error Details' }).Split(":")[1].trim(); 'GC Service (gcarcservice)' = ($cmdOutput | Where-Object{ $_ -match 'gcarcservice' }).Split(":")[1].trim() }
			if ($AZStatus.'Agent Status' -ne 'Connected') { $AZStatus.DIAG.Add('Agent Status', 'w'); $w += "<div>AZ: Warning: `t<i>Connection to Azure is not estableshed.</i></div>`r`n"; $HState = 'Unhealthy'  }
			if (([math]::ceiling((New-TimeSpan -end (Get-Date) -Start ([DateTime]::ParseExact($AZStatus.'Agent Last Heartbeat', 'yyyy-MM-ddTHH', $null))).TotalHours)) -gt 2) { $AZStatus.DIAG.Add('Agent Last Heartbeat', 'w'); $w += "<div>AZ: Warning: `t<i>Azure Agent connection is delayed.</i></div>`r`n"; $HState = 'Unhealthy'  }
			if (([math]::ceiling((New-TimeSpan -end (Get-Date) -Start ([DateTime]::ParseExact($AZStatus.'Agent Last Heartbeat', 'yyyy-MM-ddTHH', $null))).TotalHours)) -gt 3) { $AZStatus.DIAG.Add('Agent Last Heartbeat', 'e'); $w += "<div>AZ: <b>Error:</b> `t<i>Last Azure Agent connection long ago.</i></div>`r`n"; $HState = 'Degraded' }
			if (![string]::IsNullOrEmpty($AZStatus.'Agent Error Details')) { $AZStatus.DIAG.Add('Agent Error Details', 'e'); $w += "<div>AZ: <b>Error:</b> `t<i>Error in Azure Agent.</i></div>`r`n"; $HState = 'Degraded' }
			if ($AZStatus.'GC Service (gcarcservice)' -ne 'running') { $AZStatus.DIAG.Add('GC Service (gcarcservice)', 'e'); $w += "<div>AZ: <b>Error:</b> `t<i>Azure Agent Service is not running.</i></div>`r`n"; $HState = 'Degraded' }
		}
	
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
	$w = [System.Collections.ArrayList]::new();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
	function Get-RunningProcesses {
	# Run as Administrator for full data
	$ServerName = (Get-WmiObject win32_computersystem).Name
	# Function: SHA256
	function Get-FileHashSafe($path){
	    try {(Get-FileHash -Algorithm SHA256 -Path $path -ErrorAction Stop).Hash}
	    catch { $null }
	}
	# Function: Signature
	function Get-SignatureSafe($path){
	    try {(Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop).Status}
	    catch { $null }
	}
	# Cache UWP packages into fast lookup table
	$appxLookup = @{}; Get-AppxPackage -AllUsers | ForEach-Object {if ($_.InstallLocation) {$appxLookup[$_.InstallLocation.ToLower()] = $_.PackageFamilyName}}
	# Cache all processes
	$procs = Get-CimInstance Win32_Process
	# Create PID lookup for parent (FAST)
	$parentLookup = @{}; foreach ($p in $procs) {$parentLookup[$p.ProcessId] = $p.Name}
	# Get owner info only once
	$ownerCache = @{}
	foreach ($p in $procs) {
	    $owner = $p | Invoke-CimMethod GetOwner -ErrorAction SilentlyContinue
	    if ($owner.User) {$ownerCache[$p.ProcessId] = "$($owner.Domain)\$($owner.User)"}
	    else {$ownerCache[$p.ProcessId] = "SYSTEM"}
	}
	# Main loop
	foreach ($p in $procs) {
	    $pkg = ""; $path = $p.ExecutablePath; $fdesc = $null; $fcompany = $null
	    # FAST UWP detection
	    if ($path -and (Test-Path $path)){
	        $pathLower = $path.ToLower()
	        $fvi = (Get-Item $pathLower).VersionInfo
	        $fdesc = $fvi.FileDescription
	        $fcompany = $fvi.CompanyName
	        foreach ($key in $appxLookup.Keys){ if ($pathLower.StartsWith($key)){$pkg = $appxLookup[$key]; break} }
	    }
	    $hash = if ($path) { Get-FileHashSafe $path } else {$p.Name}
	    $sig  = if ($path) { Get-SignatureSafe $path } else {$null}
	    [PSCustomObject]@{
	        Name        = $p.Name
	        ID         = $p.Name
	        ParentName  = $parentLookup[$p.ParentProcessId]
	        User        = $ownerCache[$p.ProcessId]
	        Type        = if ($pkg) { "UWP" } elseif ($path) { "Win32" } else { "System" }
	        PackageName = $pkg
	        FileName        = $path
	        FileDescription = $fdesc
	        CompanyName     = $fcompany
	        Hash = $hash
	        SignatureStatus = $sig
	        CommandLine = $p.CommandLine
	    }
	}
	} #function
	$unsignedProcesses = Get-RunningProcesses | Where-Object { ($_.SignatureStatus -ne 'valid') -and (![string]::IsNullOrEmpty($_.FileName)) } | Select-Object Name, PackageName, Type, User, @{ Name = 'ID'; Expression = { "PROCESS:$ServerName`\$($_.ID)" } }, Hash, FileName, FileDescription, CompanyName, SignatureStatus, @{ Name = 'TrustBias'; Expression = { -30 } }, @{ Name = 'DIAG'; Expression = { @{ SignatureStatus = 'e' } } }, @{ Name = 'Message'; Expression = { "<div>PROC: Warning: `t<i>$($_.Name) [$($_.Filename)]</i> : Running process has wrong signature.</div>`r`n" } }
	$hiddenProcesses = Get-RunningProcesses | Where-Object { [string]::IsNullOrEmpty($_.FileName) } | Select-Object Name, PackageName, Type, User, @{ Name = 'ID'; Expression = { "PROCESS:$ServerName`\$($_.ID)" } }, Hash, FileName, FileDescription, CompanyName, SignatureStatus, @{ Name = 'TrustBias'; Expression = { -30 } }, @{ Name = 'DIAG'; Expression = { @{ SignatureStatus = 'e' } } }, @{ Name = 'Message'; Expression = { "<div>PROC: Warning: `t<i>$($_.Name) </i> : Running process has hidden executable.</div>`r`n" } }
	$w.AddRange(@($unsignedProcesses | Select-Object ID, Hash, FileName, TrustBias, Message))
	$w.AddRange(@($hiddenProcesses | Select-Object ID, Hash, FileName, TrustBias, Message))
	$r.AddRange(@($unsignedProcesses | Where-Object {$_.Type -ne 'System'} | Select-Object Name,PackageName,Type,User,FileName,FileDescription,CompanyName,SignatureStatus,DIAG))
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
function Get-ExecutablePath {
    param ( [string]$InputString )
    # Case 1: String starts with a quote - extract quoted content
    if ($InputString -match '^"') {
        $pattern = '\"([^\"]+)\"'
        $match = [regex]::Match($InputString, $pattern)
		if ($match.Success) { return $match.Groups[1].Value }
    }
    # Case 2: Look for an executable path pattern (handles spaces without quotes)
    elseif ($InputString -match '(^[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\.exe)') { return $matches[1] }
    # Case 3: Simple space-separated first part (fallback)
    else {
        $pattern = '^([^\s]+)'
        $match = [regex]::Match($InputString, $pattern)
        if ($match.Success) { return $match.Groups[1].Value }
    }
    # Return empty string if no match found
    return ""
}

function Get-FileHashSafe($path){
    try {(Get-FileHash -Algorithm SHA256 -Path $path -ErrorAction Stop).Hash}
    catch { $null }
}
# Function: Signature
function Get-SignatureSafe($path){
    try {(Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop)}
    catch { $null }
}

	$w = @(); [Collections.ArrayList]$r = @(); $DIAG = @{ }; $HState = 'Healthy'
	$DomainName = (Get-CimInstance win32_computersystem -ComputerName $ServerName).Domain
	$pattern = if ($IgnoreList.Count -gt 0) {$IgnoreList -join '|'} else { $null }
    $AllServices = Get-CimInstance Win32_Service -ComputerName $ServerName | Where-Object { -not $pattern -or $_.Name -notmatch $pattern }
	foreach ($svc in $AllServices)
	{
		$DIAG = @{}; $svc.psobject.properties.Add([psnoteproperty]::new('DIAG', $DIAG))
        $svc.psobject.properties.Add([psnoteproperty]::new('AssemblyPath', $(Get-ExecutablePath $svc.PathName)))
        #$svc | select DisplayName, AssemblyPath
        $fhash = Get-FileHashSafe $svc.AssemblyPath
			$wsvc = [pscustomobject]@{
				ID   = "SERVICE:$ServerName`:$($svc.DisplayName)"
				Hash = $(if ($fhash) {$fhash} else {"SERVICE:$ServerName`:$($svc.Name)"})
				TrustBias = 41
				Message = "<div>SVC: Info: `tService registered: <i>$($svc.Name)</i></div>`r`n"
			}
		if (![string]::IsNullOrEmpty($svc.AssemblyPath) -and $svc.AssemblyPath -notmatch '\.exe$') { $svc.AssemblyPath += '.exe'}
		if (![string]::IsNullOrEmpty($svc.AssemblyPath) -and !(Test-Path -LiteralPath $svc.AssemblyPath -PathType Leaf)) { $wsvc.TrustBias = -30; $wsvc.Message = "<div>SVC: Warning: `t<i>$($svc.Name)</i> : Service with missed executable.</div>`r`n"
			$HState = 'Unhealthy'; $svc.DIAG.Add('AssemblyPath', 'w')
			[void]$r.Add($($svc | Select-Object -Property DIAG, Name, DisplayName, StartMode, State, Status, StartName, PathName, AssemblyPath, SignatureStatusMessage, SignatureSubject))
		} #Service Exe not found
		elseif (!([string]::IsNullOrEmpty($svc.AssemblyPath))) {
			$svcSign = Get-SignatureSafe $svc.AssemblyPath
			$svc.psobject.properties.Add([psnoteproperty]::new('SignatureStatusMessage', [regex]::Match($svcSign.StatusMessage, '^.*?[.!?](?=\s|$)').Value))
			$subject = if ($svcSign.SignerCertificate) { $svcSign.SignerCertificate.Subject } else { "Signature is absent" }
			$svc.psobject.properties.Add([psnoteproperty]::new('SignatureSubject', $subject))
		}
		else {
			$wsvc.TrustBias = -30; $wsvc.Message = "<div>SVC: Warning: `t<i>$($svc.Name)</i> : Service with undefined executable.</div>`r`n"
			$HState = 'Unhealthy'; $svc.DIAG.Add('AssemblyPath', 'w')
			[void]$r.Add($($svc | Select-Object -Property DIAG, Name, DisplayName, StartMode, State, Status, StartName, PathName, AssemblyPath, SignatureStatusMessage, SignatureSubject))
		}
		if ((($svc.StartMode -eq "Auto") -and ($svc.State -ne "Running"))) {
			$svc.DIAG.Add('State', 'e');
			$wsvc.TrustBias = -30; $wsvc.Message = "<div>SVC: <b>Error:</b> `t<i>$($svc.Name)</i> : Service is configured for Automatic start but not running.</div>`r`n"
			$HState = 'Degraded'; [void]$r.Add($($svc | Select-Object -Property DIAG, Name, DisplayName, StartMode, State, Status, StartName, PathName, AssemblyPath, SignatureStatusMessage, SignatureSubject)) 
		}
		elseif ($svcSign -and $svcSign.Status -ne 'Valid') {
			 $svc.DIAG.Add('SignatureStatusMessage', 'w'); [void]$r.Add($($svc | Select-Object -Property DIAG, Name, DisplayName, StartMode, State, Status, StartName, PathName, AssemblyPath, SignatureStatusMessage, SignatureSubject)); $wsvc.TrustBias = -30; $wsvc.Message = "<div>SVC: Warning: `t<i>$($svc.Name)</i> : Service has wrong signature.</div>`r`n"; 
		}
		elseif (($svc.StartName -match $DomainName) -or ($svc.StartName -match $ServerName)) { 
			$svc.DIAG.Add('StartName', 'w'); [void]$r.Add($($svc | Select-Object -Property DIAG, Name, DisplayName, StartMode, State, Status, StartName, PathName, AssemblyPath, SignatureStatusMessage, SignatureSubject)) 
		}
		$w += $wsvc
	}
	if ($r.count -gt 0) { $HState = 'Unhealthy' }
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
	function Is-Admin	{
		#test does the user hold the high privilege on local system
		param (
			[Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)]
			[string]$UserName
		)
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$userprincipal = ([System.DirectoryServices.AccountManagement.UserPrincipal]) -as [type]
		$up = $userprincipal::FindByIdentity([system.DirectoryServices.Accountmanagement.contextType]::Domain, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)
		if ($up){
			try {
				$ID = New-Object Security.Principal.WindowsIdentity -ArgumentList $up.SamAccountName
				$ID.Claims.Value.Contains('S-1-5-32-544')
			}
			catch { $null }
		}
		else{
			try {
				$up = $userprincipal::FindByIdentity([System.DirectoryServices.AccountManagement.ContextType]::Machine, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)
				$up.GetGroups().sid.Value.Contains('S-1-5-32-544')
			}
			catch { $null }
		}
	}
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy'
	#Get Local User list
	#Account Disabled	Display Name	Account Name	Inactive Days	Password Expired In
	#Name,Description,PasswordAge,PasswordExpired,Lastlogin
	if ($ServerName -eq 'localhost') {$ServerName = $Env:Computername} #localhost bug on some systems
	$computer = [ADSI]"WinNT://$ServerName"
	$LocalAdminCount = 0
	$computer.Children | Where-Object { $_.SchemaClassName -eq 'user' } | Foreach-Object {
		$groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
		$AccountDisabled = $false; if (($_.UserFlags[0] -band 2) -eq 2) { $AccountDisabled = $True }
		$accountSID = (New-Object System.Security.Principal.NTAccount($_.Name[0])).Translate([System.Security.Principal.SecurityIdentifier]).value
		$IsPUA = Is-Admin -UserName $_.Name[0]
		$cUser = $_ #temporary var to use in switch statement
		switch -regex ($_.Name[0]) {
			'Administrator' {
				if (($accountSID -match '-500$') -and (!$AccountDisabled)) { $msg= "<div>USR: <b>Error:</b> `t<i>The local Admin account name is ADMINISTRATOR and it is ACTIVE. This Account must be renamed or disabled.</i></div>`r`n"; $TrustBias = -30; $HState = 'Degraded'; $DIAG = 'Error' }
				else {$msg = "<div>USR: Warning: `t<i>User Administrator was found.</i></div>`r`n"; $TrustBias = -20; if ($HState -ne 'Degraded') {$HState = 'Unhealthy'}}
				$w += [pscustomobject]@{ID="USER:$ServerName`\$cUser.Name[0]";Hash=$accountSID;TrustBias=$TrustBias;Message=$msg}
				[void]$r.Add($($cUser | Select-Object @{ n = 'DIAG'; e = { $DIAG } }, @{ n = 'Computername'; e = { $ServerName } }, @{ n = 'Account Active'; e = { -not $AccountDisabled } }, @{ n = 'UserName'; e = { $cUser.Name[0] } }, @{ n = 'Description'; e = { $cUser.Description[0] } }, @{ n = 'Last Login'; e = { If ($cUser.LastLogin[0] -is [DateTime]) { $cUser.LastLogin[0] } Else { 'Never logged on' } } }, @{ n = 'PasswordAge'; e = { [Math]::Round($cUser.PasswordAge[0] / 86400) } }, @{ n = 'Groups'; e = { $groups -join '::' } }))
				}
			'Guest' {
				if (($accountSID -match '-501$') -and (!$AccountDisabled)){
					$w += [pscustomobject]@{ID="USER:$ServerName`\$cUser.Name[0]";Hash=$accountSID;TrustBias=-30;Message="<div>USR: <b>Error:</b> `t<i>The local Guest account name is GUEST and it is ACTIVE.</i></div>`r`n"}; $HState = 'Degraded'; $DIAG = 'Error';
					[void]$r.Add($($cUser | Select-Object @{ n = 'DIAG'; e = { $DIAG } }, @{ n = 'Computername'; e = { $ServerName } }, @{ n = 'Account Active'; e = { -not $AccountDisabled } }, @{ n = 'UserName'; e = { $cUser.Name[0] } }, @{ n = 'Description'; e = { $cUser.Description[0] } }, @{ n = 'Last Login'; e = { If ($cUser.LastLogin[0] -is [DateTime]) { $cUser.LastLogin[0] } Else { 'Never logged on' } } }, @{ n = 'PasswordAge'; e = { [Math]::Round($cUser.PasswordAge[0] / 86400) } }, @{ n = 'Groups'; e = { $groups -join '::' } }))
				}
			}
			default {
				if ($IsPUA) {
					if ($cUser.Name[0] -notmatch 'admin') { $w += [pscustomobject]@{ID="USER:$ServerName`\$cUser.Name[0]";Hash=$accountSID;TrustBias=-30;Message="<div>USR: Warning: `t<i>Abnormal Admin account found: $($cUser.Name[0]).</i></div>`r`n"}}
					$LocalAdminCount += 1; $DIAG = 'Warning'; if ($HState -ne 'Degraded') {$HState = 'Unhealthy'}
					[void]$r.Add($($cUser | Select-Object @{ n = 'DIAG'; e = { $DIAG } }, @{ n = 'Computername'; e = { $ServerName } }, @{ n = 'Account Active'; e = { -not $AccountDisabled } }, @{ n = 'UserName'; e = { $cUser.Name[0] } }, @{ n = 'Description'; e = { $cUser.Description[0] } }, @{ n = 'Last Login'; e = { If ($cUser.LastLogin[0] -is [DateTime]) { $cUser.LastLogin[0] } Else { 'Never logged on' } } }, @{ n = 'PasswordAge'; e = { [Math]::Round($cUser.PasswordAge[0] / 86400) } }, @{ n = 'Groups'; e = { $groups -join '::' } }))}
					}
				}
			} #foreach
	if ($LocalAdminCount -gt 3) {$w += [pscustomobject]@{ID="USER:$ServerName`\Local Admins Accounts";Hash=($ServerName + "\localadmins");TrustBias=-40;Message="<div>USR: Warning: `t<i>Too much high priviledged account found.</i></div>`r`n"};
   if ($HState -ne 'Degraded') {$HState = 'Unhealthy'} } 
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$CRT = { #Certificates Audit : run remotely
	param ($ServerName,$IgnoreList)
	$w = @(); [Collections.ArrayList]$r = @(); $DIAG = @{ }; $HState = 'Healthy'
	$HostLANDNSName = (Get-WmiObject win32_computersystem -ComputerName $ServerName).Name + '.' + (Get-WmiObject -ComputerName $ServerName win32_computersystem).Domain
	$IgnoreList += $HostLANDNSName
		Get-ChildItem -Recurse Cert:\LocalMachine\My |Where-Object {($_.HasPrivateKey -eq $true) -and ($_.Subject -notmatch ('({0})' -f ($IgnoreList -join "|")))} | ForEach-Object {
		$crt = $_ | Select-Object -Property @{ n = 'DIAG'; e= { $DIAG } }, @{ n = 'IsTrusted'; e = { $_.verify() } } , @{ n = 'PrivateKeyExportable'; e = { $_.PrivateKey.CspKeyContainerInfo.Exportable } }, Thumbprint, @{ n = 'SubjectName'; e = { $_.SubjectName.Name } }, @{ n = 'DnsNameList'; e = { $($_.DnsNameList -join ',:: ') } }, Issuer, @{ n = 'EnhancedKeyUsageList'; e = { $(($_.EnhancedKeyUsageList -join ',:: ') -replace " \(((\d+).)+(\d+)\)") } }, NotBefore, NotAfter
		if (([datetime]$crt.NotAfter).Ticks -lt (Get-Date).Ticks) { $w += [pscustomobject]@{ID="CERTIFICATE:$ServerName`\$crt.SubjectName";Hash=$crt.Thumbprint;TrustBias=-30;Message="<div>CER: <b>Error:</b> `tExpired certificate: <i>$($crt.SubjectName).</i></div>`r`n"}; $HState = 'Degraded'; $crt.DIAG.Add('NotAfter', 'e') }
			elseif (([datetime]$crt.NotBefore).Ticks -gt (Get-Date).Ticks) { $w += [pscustomobject]@{ID="CERTIFICATE:$ServerName`\$crt.SubjectName";Hash=$crt.Thumbprint;TrustBias=-20;Message="<div>CER: <b>Error:</b> `tPending certificate: <i>$($crt.SubjectName).</i></div>`r`n"}; $HState = if ($HState -ne 'Degraded') {'Unhealthy'} ; $crt.DIAG.Add('NotBefore', 'e') }
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
			if (($_.AccountName -eq 'Everyone') -and ($_.AccessRight -eq 'Full') -and ($_.AccessControlType -eq 'Allow')) {$w += [pscustomobject]@{ID="SHARE:$ServerName`\$smbshare.name";Hash=$smbshare.path;TrustBias=-30;Message="<div>SHA: <b>Error:</b> `tShare <i>$($smbshare.name)</i> has Everyone/FullControll access.</div>`r`n"}; $HState = 'Unhealthy'; $_.DIAG.Add('AccountName', 'w')}
			if (($_.AccountName -eq 'ANONYMOUS LOGON') -and ($_.AccessRight -eq 'Full') -and ($_.AccessControlType -eq 'Allow')) {$w += [pscustomobject]@{ID="SHARE:$ServerName`\$smbshare.name";Hash=$smbshare.path;TrustBias=-30;Message="<div>SHA: <b>Error:</b> `tShare <i>$($smbshare.name)</i> has ANONYMOUS LOGON/FullControll access.</div>`r`n"}; $HState = 'Unhealthy'; $_.DIAG.Add('AccountName', 'e')}
			if (($_.Path -match "^[a-zA-Z]:\\$") -and ($_.Name -notlike '*$')) {$w += [pscustomobject]@{ID="SHARE:$ServerName`\$smbshare.name";Hash=$smbshare.path;TrustBias=-30;Message="<div>SHA: Warning: `tThe ROOT folder of <i>$($smbshare.Path)</i> is shared.</div>`r`n"}; $HState = 'Degraded'; $_.DIAG.Add('Path', 'w')}
			if (($_.Path -notmatch '^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\?)*$') -and (![string]::IsNullOrEmpty($_.Path))) {$w += [pscustomobject]@{ID="SHARE:$ServerName`\$smbshare.name";Hash=$smbshare.path;TrustBias=-30;Message="<div>SHA: Warning: `tNon common path: <i>$($smbshare.Path)</i> is shared.</div>`r`n"}; $HState = 'Unhealthy' ; $_.DIAG.Add('Path', 'w')}
	    	if ($_.DIAG.count -gt 0) {[void]$r.add($_)}
			}
    }
    if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {$w +="<div>SHA: Warning: `t<i>SMB V1 protocol Enabled</i></div>`r`n"}
[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$OLDrWDf = { 
	param ($ServerName,$IgnoreList)
	$w = @();[Collections.ArrayList]$r=@();$DIAG=@{}; $HState = 'Healthy';
		$WAVStatus = Get-MpComputerStatus | Select-Object -Property AMRunningMode, AMServiceEnabled, ComputerState, DefenderSignaturesOutOfDate, IsTamperProtected, RealTimeProtectionEnabled
	if (!$WAVStatus) { $w += [pscustomobject]@{ID="AV:$ServerName`\DefenderUnknown";Hash="AV:$ServerName`\DefenderUnknown";TrustBias=-20;Message="<div>WAV: Warning: `t<i>Unable to get Windows Defender configuration.</i></div>`r`n"}; $WAVStatus = New-Object PSObject;  $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'WAVStatus' = 'e' })); $HState = 'Unknown' }
	elseif ($WAVStatus.AMRunningMode -ne 'Normal') { $w += [pscustomobject]@{ID="AV:$ServerName`\DefenderDegraded";Hash="AV:$ServerName`\DefenderDegraded";TrustBias=-30;Message="<div>WAV: <b>Error:</b> `t<i>Windows Defender degraded.</i></div>`r`n"}; $HState = 'Degraded'; $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'AMRunningMode' = 'w' })) }
	elseif (!$WAVStatus.AMServiceEnabled) { $w += [pscustomobject]@{ID="AV:$ServerName`\DefenderDisabled";Hash="AV:$ServerName`\DefenderDisabled";TrustBias=-30;Message="<div>WAV: <b>Error:</b> `t<i>Windows Defender service is not enabled.</i></div>`r`n"}; $HState = 'Degraded'; $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'AMServiceEnabled' = 'e' })) }
	elseif ($WAVStatus.DefenderSignaturesOutOfDate) { $w += [pscustomobject]@{ID="AV:$ServerName`\DefenderSignaturesOutOfDate";Hash="AV:$ServerName`\DefenderSignaturesOutOfDate";TrustBias=-30;Message="<div>WAV: Warning: `t<i>Windows Defender signatures are outdated.</i></div>`r`n"}; $HState = 'Unhealthy'; $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG', @{ 'DefenderSignaturesOutOfDate' = 'w' })) }
	$WAVExclusions = Get-MpPreference | Select-Object -Property Exclusion*
		foreach ($Property in $WAVExclusions.PSObject.Properties) {
			$Property.Value.foreach({
				if ($_ -match '^[a-zA-Z]+:\\$') {$w += [pscustomobject]@{ID="AV:$ServerName`\$_";Hash="AV:$ServerName`\$_";TrustBias=-30;Message="<div>WAV: Warning: `t<i>AV exclusion contains root folder: $($_).</i></div>`r`n"}; $HState = 'Unhealthy' ; $WAVStatus.psobject.properties.Add([psnoteproperty]::new('DIAG',@{ $Property.Value = 'w' }))}
				else {$w += [pscustomobject]@{ID="AV:$ServerName`\$_";Hash="AV:$ServerName`\$_";TrustBias=-20;Message="<div>WAV: Warning: `t<i>AV exclusion: $($_).</i></div>`r`n"}}
			}) #foreach
			$Property.Value = ($Property.Value) -join "`n<br>"
			$WAVStatus.psobject.properties.Add([psnoteproperty]::new($Property.Name,$Property.Value))
		}
	if ($WAVStatus) {[void]$r.Add($WAVStatus)}
	[pscustomobject]@{'Warnings'=$w; 'report'=$r; 'HState'= $HState}
}
$rWDf = {#Get WindowsDefender AV config : run remotely
	param ($ServerName,$IgnoreList)
	$w = @(); $r = [Collections.ArrayList]::new(); $HState = 'Healthy'
	$WAVStatus = Get-MpComputerStatus | Select-Object AMRunningMode,AMServiceEnabled,ComputerState,DefenderSignaturesOutOfDate,IsTamperProtected,RealTimeProtectionEnabled
	if (!$WAVStatus){
		$w += [pscustomobject]@{
		ID="AV:$ServerName`\DefenderUnknown"
		Hash="AV:$ServerName`\DefenderUnknown"
		TrustBias=-20
		Message="<div>WAV: Warning: `t<i>Unable to get Windows Defender configuration.</i></div>`r`n"
		}
		$WAVStatus=[pscustomobject]@{}; $HState='Unknown'
	}
	$WAVStatus | Add-Member DIAG @{} -Force
	# Exclusions
	$WAVExclusions = Get-MpPreference | Select-Object Exclusion*
	foreach ($Property in $WAVExclusions.PSObject.Properties){
		foreach ($item in @($Property.Value)){
			if ($item -match '^[a-zA-Z]+:\\$'){
				$w += [pscustomobject]@{
				ID="AV:$ServerName`\$item"
				Hash="AV:$ServerName`\$item"
				TrustBias=-30
				Message="<div>WAV: Error: `t<i>AV exclusion contains root folder: $item.</i></div>`r`n"
				}
			$HState='Unhealthy'
			$WAVStatus.DIAG[$Property.Name]='e'
			}
			else{
				$w += [pscustomobject]@{
				ID="AV:$ServerName`\$item"
				Hash="AV:$ServerName`\$item"
				TrustBias=-20
				Message="<div>WAV: Warning: `t<i>Exclusion: $item.</i></div>`r`n"
				}
			}
		}
	$joined=@($Property.Value)-join "`n<br>"
	$WAVStatus | Add-Member $Property.Name $joined -Force
	}
	[void]$r.Add($WAVStatus)
	[pscustomobject]@{Warnings=$w;report=$r;HState=$HState}
} #Get WinDefender Excl
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
    param ($ServerName, $IgnoreList)

    $warnings = New-Object System.Collections.Generic.HashSet[string]; $report   = New-Object System.Collections.Generic.List[object]; $HState   = 'Healthy'
# netsh is available on ALL Windows versions, fast, no CIM class issues
$raw = netsh advfirewall firewall show rule name=all dir=in verbose 2>$null
# Parse rule blocks
$blocks = ($raw -join "`n") -split '(?=Rule Name:)'

foreach ($block in $blocks) {
    if ($block -notmatch 'Rule Name:') { continue }

    # Only Enabled + Inbound + Allow
    if ($block -notmatch 'Enabled:\s+Yes')          { continue }
    if ($block -notmatch 'Direction:\s+In')          { continue }
    if ($block -notmatch 'Action:\s+Allow')          { continue }

    # Extract fields
    $name     = if ($block -match 'Rule Name:\s+(.+)')        { $Matches[1].Trim() } else { '' }
	 $description  = if ($block -match 'Description:\s+(.+)')  { $Matches[1].Trim() } else { '' }
    $group    = if ($block -match 'Grouping:\s+(.+)')         { $Matches[1].Trim() } else { '' }
    $profile  = if ($block -match 'Profiles:\s+(.+)')         { $Matches[1].Trim() } else { '' }
    $localPort= if ($block -match 'LocalPort:\s+(.+)')        { $Matches[1].Trim() } else { 'Any' }
    $remPort  = if ($block -match 'RemotePort:\s+(.+)')       { $Matches[1].Trim() } else { 'Any' }
    $program  = if ($block -match 'Program:\s+(.+)')          { $Matches[1].Trim() } else { 'Any' }

    $isAnyApp = ($program -eq 'Any' -or $program -eq '')

    if ((localPort -eq 'Any') -and ($remPort -eq 'Any') -and $isAnyApp) {
			$warnings.Add([pscustomobject]@{
				ID="WFW:$ServerName`\$name"
				Hash="WFW:$ServerName`\$name"
				TrustBias=-30
				Message="<div>WFW: Warning:`tAny-Any firewall rule detected: <i>$name ($profile).</i></div>`r`n"
				}
        	)

        $HState = 'Unhealthy'

        $report.Add([pscustomobject]@{
            DIAG         = @{ DisplayName = $name }
            DisplayGroup = $group
            DisplayName  = $name
				Description	 = $description
            Profile      = $profile
            Direction    = 'Inbound'
            LocalPort    = $localPort
				Program 		 = $program
        })
    }
}

[pscustomobject]@{
    Warnings = $warnings
    Report   = $report
    HState   = $HState
}
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
	if (($AVinfo.report.DisplayName -match 'Windows') -or ($AVinfo.report.DisplayName -match 'Microsoft')) {
		if (($ServerName -eq "localhost") -or ($ServerName -eq "127.0.0.1"))
		{
			Start-Job -scriptblock $rWDf -ArgumentList $ServerName -Name "WDf" | Select-Object PSBeginTime, location, id, name, State, Error | Format-Table -AutoSize
		}
		else { Invoke-Command -computername $ServerName -scriptblock $rWDf -ArgumentList $ServerName -JobName "WDf" -AsJob | Select-Object PSBeginTime, location, id, name, State, Error | Format-Table -AutoSize }
	}
	elseif ($Null -eq $AVinfo.report)
	{
		# No Ativirus
		$Problems.Add("<div>WAV: Warning: `t<i>Probably no Antivirus software installed.</i></div>`r`n")
	}
	else { $Problems.Add("<div>WAV: Warning: `t<i>The 3d party Antivirus software installed. Only basic info was got.</i></div>`r`n") } # 3d party antivirus detected. Need custom detection routine 
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
		if (!$jout) {$Problems.Add("<div>JOB: Warning: `t<i>The JOB $($jdone.Name) on the host $ServerName return no output.</i></div>`r`n")}
		if ($null -ne $jout) {
#			if ($null -ne $jout.Warnings) {$jout.Warnings = $jout.Warnings | Sort-Object -Unique; }
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
	if ($Watch.Elapsed.Minutes -gt $JobRunningLimit) {$Problems.Add("<div>RUNTIME: Warning: `t<i>The JOBs $(((Get-Job | Where-Object { $_.State -ne 'Completed' }).Name) -join '; ') on the host $ServerName are running too long. These jobs where skipped.</i></div>`r`n"); $Watch.Stop(); break}
	if (Get-Job | Where-Object { $_.State -eq "Failed" }) {
		(Get-Job | Where-Object { $_.State -eq "Failed" }).foreach({Write-Status -Status Error -Message ("Job $_.Name was failed with error: " + ($_.ChildJobs[0].JobStateInfo.Reason.Message)); $Problems.Add("<div>RUNTIME: Warning: `t<i>The JOB $($_.Name) on the host $ServerName was failed with error $($_.ChildJobs[0].JobStateInfo.Reason.Message) . This job was skipped.</i></div>`r`n")})
		Write-Status -Status Error -Message "Job(s): $(((Get-Job | Where-Object { $_.State -ne 'Failed' }).Name) -join '; ') are failed. Remove these jobs. "
		Get-Job | Where-Object { $_.State -eq "Failed" } | Remove-Job -Force
		}
}
#############################################################################
#REGION:: Initialize Reputation Engine. need each engine for each sensors type i.e. processes, volumes, drives, users, AV Exclusions etc.
$PRCREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-PRC-REPUTATION_CATALOG" + ".XML"))
$SVCREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-SVC-REPUTATION_CATALOG" + ".XML"))
$HDDREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-HDD-REPUTATION_CATALOG" + ".XML"))
$VOLREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-VOL-REPUTATION_CATALOG" + ".XML"))
$USRREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-USR-REPUTATION_CATALOG" + ".XML"))
$AVEREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-AVE-REPUTATION_CATALOG" + ".XML"))
$NICREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-NIC-REPUTATION_CATALOG" + ".XML"))
$CRTREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-CRT-REPUTATION_CATALOG" + ".XML"))
$SHAREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-SHA-REPUTATION_CATALOG" + ".XML"))
$WFWREEngine = [ReputationEngine]::new(($ReportFilePath + "\" + $computerOS.PSComputerName + "-WFW-REPUTATION_CATALOG" + ".XML"))
#############################################################################
#REGION:: RE Processing Function (reuse for different items type)
function EvaluateRE([object[]]$Items,[ReputationEngine]$REngine){
	if ($Items) {
    $OutputItems = [System.Collections.Generic.List[object]]::new()
    $Items = @($REngine.BatchReconcile($Items))
    foreach($item in $Items){
			if (($item.ReputationScore -lt 40) -or ($item.PresenceScore -eq 1)){$OutputItems.Add($item.Message)}
			elseif ((-not $item.ReputationIsPresent) -and (![string]::IsNullOrEmpty($item.ID))) {$OutputItems.Add("<div>---: Warning: `t<i>$($item.id)</i> is missing.</div>`r`n" )}
    }
    $REngine.Save() | out-null
    $OutputItems.ToArray()
	}
	else {$null} 
} #return array of warning messages based on Reputation ENgine diagnostics
#############################################################################
#REGION:: BUILD REPORT
Write-Status -Status Information -Message "Combine results and write the report on $($ServerName) at $(Get-Date)"
	
[void]$ReportHTMLArray.Add($($HostOSinfo | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Operating System </H3></td></tr></table>"))
if ($LoggedUsers.report) { [void]$ReportHTMLArray.Add($($LoggedUsers.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Logged On Users</H3></td></tr></table>"))}
if ($SysEvents.report) { [void]$ReportHTMLArray.Add($($SysEvents.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Last 24h. Event Log Errors & Warnings</H3></td></tr></table>")) }
if ($SysEventsVer.report) { [void]$ReportHTMLArray.Add($($SysEventsVer.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Last 24h. Event Log Errors List</H3></td></tr></table>")) }
if ($HWConfig.report) { [void]$ReportHTMLArray.Add($($HWConfig.report | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | SYSTEM HW </H3></td></tr></table>")) }
#
if ($NICConfig) { [void]$ReportHTMLArray.Add($($NICConfig | Select-Object -Property Name,MACAddress,ServiceName,DHCPEnabled,SpeedGbps,"VLAN ID",@{Name='IPv4';Expression={$_.IPAddresses.IPv4 -join ', '}},@{Name='IPv6';Expression={$_.IPAddresses.IPv6 -join ', '}}  | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Network Config </H3></td></tr></table>")) }
$Problems.AddRange([string[]]@(EvaluateRE $NICConfig $NICREEngine)) #new 2026 > utilize ReputationEngine
$Problems.AddRange([string[]]@($AZState.Warnings))
if ($AZState.report) { [void]$ReportHTMLArray.Add($($AZState.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Azure AD Join State</H3></td></tr></table>"))}	
$Problems.AddRange([string[]]@($LoggedUsers.Warnings))
$Problems.AddRange([string[]]@($HWConfig.Warnings))
$Problems.AddRange([string[]]@($CPUConfig.Warnings))
if ($CPUConfig.report) { [void]$ReportHTMLArray.Add($($CPUConfig.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | CPU(s) </H3></td></tr></table>")) }
$Problems.AddRange([string[]]@(EvaluateRE $HDDConfig.Warnings $HDDREEngine)) #new 2026 > utilize ReputationEngine
if ($HDDConfig.report) { [void]$ReportHTMLArray.Add($($HDDConfig.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Drives</H3></td></tr></table>")) }
$Problems.AddRange([string[]]@(EvaluateRE $VOLstate.Warnings $VOLREEngine)) #new 2026 > utilize ReputationEngine
if ($VOLstate.report) { [void]$ReportHTMLArray.Add($($VOLstate.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Volumes</H3></td></tr></table>")) }
$Problems.AddRange([string[]]@($NTPStat.Warnings))
if ($NTPStat.report) { [void]$ReportHTMLArray.Add($($NTPStat.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | NTP Status</H3></td></tr></table>").Replace("::", "<br/>")) }
#############################################################################
$Problems.AddRange([string[]]@(EvaluateRE $UnsigProcs.Warnings $PRCREEngine)) #new 2026 > utilize ReputationEngine
#############################################################################
if ($UnsigProcs.report) { [void]$ReportHTMLArray.Add($($UnsigProcs.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Processes with wrong signature</H3></td></tr></table>")) }
$Problems.AddRange([string[]]@(EvaluateRE $StrangeServices.Warnings $SVCREEngine)) #new 2026 > utilize ReputationEngine
#$Problems.AddRange([string[]]@($StrangeServices.Warnings))
if ($StrangeServices.report) { [void]$ReportHTMLArray.Add($($StrangeServices.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Strange Services</H3></td></tr></table>")) }
$Problems.AddRange([string[]]@(EvaluateRE $LocalUsers.Warnings $USRREEngine)) #new 2026 > utilize ReputationEngine
if ($LocalUsers.report) { [void]$ReportHTMLArray.Add($($LocalUsers.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Unsettling User Accounts</H3></td></tr></table>").Replace("::", "<br/>")) }
$Problems.AddRange([string[]]@(EvaluateRE $Certificates.Warnings $CRTREEngine)) #new 2026 > utilize ReputationEngine
if ($Certificates.report) { [void]$ReportHTMLArray.Add($($Certificates.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Certificates</H3></td></tr></table>").Replace("::", "<br/>")) }
$Problems.AddRange([string[]]@(EvaluateRE $Shares.Warnings $SHAREEngine)) #new 2026 > utilize ReputationEngine
if ($Shares.report) { [void]$ReportHTMLArray.Add($($Shares.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | SMB Shares</H3></td></tr></table>").Replace("::", "<br/>")) }
if ($AVinfo){$Problems.AddRange([string[]]@($AVinfo.Warnings)); [void]$ReportHTMLArray.Add($($AVinfo.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Antivirus status</H3></td></tr></table>"))}
if ($WAVConfig) { 
#	$WAVConfig.Warnings | Select-Object -first 6 | Format-Table -autosize
	$Problems.AddRange([string[]]@(EvaluateRE $WAVConfig.Warnings $AVEREEngine));if ($WAVConfig.report) {[void]$ReportHTMLArray.Add($($WAVConfig.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Defender Status</H3></td></tr></table>"))}}
$Problems.AddRange([string[]]@(EvaluateRE $WFWStatus.Warnings $WFWREEngine)) #new 2026 > utilize ReputationEngine
if ($WFWStatus.report) { [void]$ReportHTMLArray.Add($($WFWStatus.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Firewall Status</H3></td></tr></table>").Replace("::", "<br/>")) }
$Problems.AddRange([string[]]@($WuaAvailable.Warnings))
if ($WuaAvailable.report) { [void]$ReportHTMLArray.Add($($WuaAvailable.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Windows Updates Available</H3></td></tr></table>")) }
$Problems.AddRange([string[]]@($SysEvents.Warnings))
$Problems.AddRange([string[]]@($SysEventsVer.Warnings))
[void]$ReportHTMLArray.Add($($OSLicensing | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Operating System Licensing State</H3></td></tr></table>"))
[void]$ReportHTMLArray.Add($($InternetInfo | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Internet Connection info </H3></td></tr></table>"))
#############################################################################
#REGION:: SAVE & SEND REPORT
$ReportHTML = $Header + "<div><table><tr><td><H1>Host <font style='color: green;font-weight: bold;'>$($computerOS.PSComputerName)</font> health report.</H1></td><td style='text-align:right;'>Executed on <i>$ENV:COMPUTERNAME</i> as <i>$ENV:USERNAME</i> at $(get-date -Format s)</td></tr></table>"

$Problems.where({$_ -notmatch '(Warning:|Error:)'}) #debug

if ($Problems -and ($ShowProblems -or !$NoProblems)) {
	$Problems = $Problems.where({![string]::IsNullOrEmpty($_)}) | Sort-Object -Unique
	#$Problems.where({$_ -match "Error:"})
	#$Problems.where({$_ -match "Warning:"})
	
	$ReportHTML += '<table width=98%><tr><td class=dae>Errors: <br>{0}</td><td class=daw>Warnings: <br>{1}</td><td class=dan>Notifications: <br>{2}</td></tr></table>' -f $($Problems.where({$_ -match "Error:"}).count),$($Problems.where({$_ -match "Warning:"}).count),$($Problems.where({$_ -notmatch '(Warning:|Error:)'}).count)
	$ReportHTML += "<H2>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Problems found:</H2></div>`n"
	$EReportHTML = [string]::Join([Environment]::NewLine,$Problems.Where({$_.IndexOf('error:',[StringComparison]::OrdinalIgnoreCase) -ge 0}))
	$WReportHTML = [string]::Join([Environment]::NewLine,$Problems.Where({$_.IndexOf('warning:',[StringComparison]::OrdinalIgnoreCase) -ge 0}))
	$NReportHTML = [string]::Join([Environment]::NewLine,$Problems.Where({$_ -notmatch '(Warning:|Error:)'}))
	$ReportHTML += "<div class='twoColumns'><table width=98%><tr><td class=daef13>" + $EReportHTML + "</td><td class=dawf13>" + $WReportHTML + "</td><td class=danf13>" + $NReportHTML + "</td>" + "</tr></table></div>`n"
}
if (!$HealthOnly) {$ReportHTML += [string]::Join([Environment]::NewLine, $ReportHTMLArray)} #Save full report
else { #save only Healthy/unhealthy status
	$ReportHTML += $($HostOSinfo | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($HostName) </font> | Operating System </H3></td></tr></table></div>")
	$ReportHTML += "<div class=card><table class=health><tr><td><H2>HOST: <font color=green>$($HostName) </font> | Event Log </H2></td>" + (Color-HState $SysEvents.HState) + "</tr>"
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
	$ReportHTML += "<tr><td><H2>HOST: <font color=green>$($HostName) </font> | Azure </H2></td>" + (Color-HState $AZState.HState) + "</tr></table></div>"
	$ReportHTML += $($SysEventsVer.report | ConvertTo-HTMLStyle -PreContent "<div class=card><table class=scope><tr><td><H3>HOST: <font color=green>$($computerOS.PSComputerName) </font> | Last 24h. Event Log Errors List</H3></td></tr></table></div>")
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
		$emailMessage.SubjectEncoding = [System.Text.Encoding]::UTF8
		$emailMessage.BodyEncoding = [System.Text.Encoding]::UTF8
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