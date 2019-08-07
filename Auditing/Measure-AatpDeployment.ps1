<#
 .Version: 1.5
 .Author: Andrew Harris
 .Twitter: ciberresponce
 .Email: aharri@microsoft.com
 .Blog: https://aka.ms/andrew
 
 .Description
  This script will:
    - Discover all Domain Controllers
    - Evaluate Azure ATP or ATA on the DCs in regard to their audit settings
 
  ATA v1.7 requires event ID 4776.  However, v1.8+ and Azure ATP require more event ID's to augment
    ATA's ability to help protect the environment. As a result, ATA's Lieghtweight Gateway (LWGW)
    will automatically push events to the ATA Center. This process does not ensure the proper
    Advanced Audit settings are turned on for the respective DCs. In addition, this process is not
    automated for DC's whose traffic is covered by a Gateway (and not a LWGW)
#>

# Version to test against
param(
  [Parameter(Mandatory=$false)]
  [ValidateSet("1.9", "1.8", "1.7", "AATP")]
  [string]
  $Version = "AATP",

  [Parameter(Mandatory=$false)]
  [int]
  $RunJobsThrottle = 10,

  [Parameter(Mandatory=$false)]
  [string]
  $Fqdn = $null
)

$LiteralPath = Resolve-Path .
If(Test-Path $LiteralPath\Results -PathType Container){
  #do nothing
}
Else{
  New-Item -ItemType Directory -Path "$LiteralPath\Results" -Force | Out-Null
}

If(Test-Path $LiteralPath\Transcript -PathType Container){
  #do nothing
}
Else{
  New-Item -ItemType Directory -Path "$LiteralPath\Transcript" -Force | Out-Null
}

Start-Transcript -Path "$LiteralPath\Transcript\AtaPostDep-Transcript_$(get-date -Format "MM-dd-yyyy_hh.mm.ss").rtf" | Out-Null

Write-Output "Literal Path: $LiteralPath"
Write-Host "[!!] Executing from: $LiteralPath" -ForegroundColor Yellow
Write-Host "[!!] Transcript plus results will be based on this execution point`n`n" -ForegroundColor Yellow
Write-Host "[+] Setting up Environment..." -ForegroundColor Green

If ($PSVersionTable.PSVersion.Major -lt 3){
  Write-Error "Need to be PowerShell v3 or higher. Please upgrade to use this script"
  exit
}

Import-Module .\HelperModules\Get-AuditPolicyCompliance.psm1

$Host.UI.RawUI.WindowTitle = "$($Host.UI.RawUI.WindowTitle.split(':')[0]) : ATA Post-Deployment Compliance Measurement"

Write-Host "`n
   ###        ###    ########## #######           
  ## ##      ## ##       ##     ##    ##    
 ##   ##    ##   ##      ##     ##   ###
##     ##  ##     ##     ##     ######  
#########  #########     ##     ##        DC Advanced Audit Setings
##     ##  ##     ##     ##     ##            Assessment Tool
##     ##  ##     ##     ##     ##            
`n`n`n"
Write-Host "[+] Starting ATA Post-Deployment Audit Settings Assessment Tool" -ForegroundColor Green
Write-Host "[+] Environment successfully created" -ForegroundColor Green
Write-Host "[+] Detecting Domain Controllers..." -ForegroundColor Green
Write-Host "[!] Assessing Environment against version: $Version" -ForegroundColor Yellow

$configurationContainer = ([adsi] "LDAP://RootDSE").Get("ConfigurationNamingContext")
$partitions = ([adsi] "LDAP://CN=Partitions,$configurationContainer").psbase.children
$DCs = @()
foreach($partition in $partitions) {
 if($partition.netbiosName -ne ""){
  $partitionDN=$partition.ncName
  $dcContainer=[adsi] "LDAP://ou=domain controllers,$partitionDN"
  $DCs += $dcContainer.psbase.children
 }
}
[int]$DCCount = ($DCs.dNSHostName).Count
Write-Host "`t[-] Discovered $DCCount Domain Controllers" -ForegroundColor Green

# if given a Fqdn, only pull DCs from that domain
if ($Fqdn){
  Write-Host "`t[-] Filtering for DCs in: $Fqdn" -ForegroundColor Yellow
  $DomainDN = "DC=$($Fqdn.replace(".",",DC="))"
  $DCs = $DCs | Where-Object { $_.distinguishedName -match "OU=Domain Controllers,$DomainDN" }
  [int]$DCCount = ($DCs.dNSHostName).Count
  Write-Host "[+] Inspecting $DCCount Domain Controllers" -ForegroundColor Green
}

$DCs = @($DCs.dNSHostName)

$i = 0

$DcJobs = @()
foreach  ($DC in $DCs){
  $runningJob = @(Get-Job | Where-Object { $_.State -eq 'Running'})
  #if using all RunJob capacity (default to 10), wait for a job to fill up
  if ($runningJob.Count -ge $RunJobsThrottle){
    $runningJob | Wait-Job -Any | Out-Null
  }
  #this gets passed to only when RunJobs count is lower then threshold, thus we can start another!
  $i+=1
  $PercentComplete = $i / $DCCount * 100
  $newjob = Start-Job -Name $DC -FilePath .\HelperModules\DCScriptBlock.ps1 -ArgumentList @($DC, $LiteralPath, $Version)
  $DcJobs += $newjob
  Write-Progress -Activity "Querying Domain Controllers" -Status "Percentage complete: $PercentComplete" -PercentComplete $PercentComplete
}
$DCResults = Get-Job | Wait-Job | Receive-Job
Write-Host "[+] Completed scans against reachable DCs" -ForegroundColor Green

#Create CSV Output
$DCResults | Select-Object DC_FQDN, OverallStatus, isSensor, AdvancedAuditForce, AuditSettingsOverall, AuditSettingsCredVal, AuditSettingsSecGroupMgt | `
  Export-Csv -Path "$LiteralPath\Results\Assessment-$(get-date -Format "MM-dd-yyyy").csv" -Encoding ASCII -NoTypeInformation

Stop-Transcript
$DCResults | Select-Object DC_FQDN, OverallStatus, isSensor, AuditSettingsOverall, AuditSettingsCredVal, AuditSettingsSecGroupMgt | Format-Table
Pause