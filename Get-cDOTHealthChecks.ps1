<#
.SYNOPSIS
  Get-cDOTHealthChecks.ps1 performs a health check on NetApp Data ONTAP storage cluster.

.DESCRIPTION
   The following tasks are performed by this script

   Get Last Weekly ASUP status for all nodes in the cluster
   Get Cluster nodes Health Status
   Get Cluster HA Information
   Get Uptime of all nodes
   Get Aggregates where state is not online
   Get EMS logs (EMERGENCY, ALERT) in last two hours
   Check for Broken Disks
   Get Snapmirror Status where Lag Time is more than 30 minutes
   Check for Volumes with used Capacity more than 95%
   Check for Volumes with inodes used more than 75%
   Check Volumes with Max AutoSize Used more than 80% (i.e. UsedSize/MaxAutoSize > 80%)
   Check Interfaces which are not on home node or home port
   Check Unhealthy Interface Groups
   Send email to Recepients with data collected by this script

   This script has been successfully tested on DATA ONTAP 9.1P5

.PARAMETER UserName
  Username to connect to storage cluster
  
.PARAMETER Password
  Password to authenticate the user credentials
  
.PARAMETER Cluster
  Cluster Name or IP address

.INPUTS
  The script requires PSLogging Module to be present on the Windows host.
  PSLogging Module v2.5.2 can be downloaded from below link

  https://www.powershellgallery.com/packages/PSLogging/2.5.2

.OUTPUTS
  The script log file is stored in E:\ssh\308143\cDOT-HealthChecks\<Cluster-name>.log

.NOTES
  Version:        1.1
  Author:         Nitish Chopra
  Creation Date:  20/10/2017
  Purpose/Change: Automate Weekly Health Checks

.EXAMPLE
  PS E:\ssh\308143> .\Get-cDOTHealthChecks.ps1 -Cluster au2004npsc001
#>
#---------------------------------------------------------[Script Parameters]------------------------------------------------------
Param (
  #Script parameters go here
  [Parameter(Mandatory=$true,ValueFromPipeline=$True,HelpMessage="Enter the Location of file with storage clusters")] 
  [string]$Cluster,
  [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage="Get Date and Time for the Log File")]
  [string]$timer = (Get-Date -Format yyyy-MM-dd-hhmm)
)
#----------------------------------------------------------[Declarations]----------------------------------------------------------
#Script Version
$sScriptVersion = '1.1'

#Log File Info
$sLogPath = 'E:\ssh\308143\cDOT-HealthChecks'
$scriptPath = 'E:\ssh\308143'
$sLogName = $Cluster+"-"+$timer+".log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName
$PSLoggingModulePath = "E:\ssh\308143\Modules\PSLogging"
#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Check-LoadedModule {
  Param(
    [parameter(Mandatory = $true)]
    [string]$ModuleName
  )
  Begin {
    Write-LogInfo -LogPath $sLogFile -Message ("Importing Module: " + $ModuleName)
  }
  Process {
    $LoadedModules = Get-Module | Select Name
    if ($LoadedModules -notlike "*$ModuleName*") {
      try {
        Import-Module -Name $ModuleName -ErrorAction Stop
      }
      catch {
        Write-LogError -LogPath $sLogFile -Message "Could not find the Module on this system. Error importing Module" -ExitGracefully
        Break
      }
    }
  }
  End {
    If ($?) {
      Write-LogInfo -LogPath $sLogFile -Message ("Module " +$ModuleName + " is imported Successfully")
      Write-LogInfo -LogPath $sLogFile -Message ' ' 
    }
  }
}
function convertDateTime ($UnixDate) {
  [TimeZone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($UnixDate))
}
function Connect-Cluster {
  Param (
    [parameter(Mandatory = $true)]
    [string]$strgCluster
  )
  Begin {
    Write-LogInfo -LogPath $sLogFile -Message ("Connecting to storage cluster " + $strgCluster)
  }  
  Process {  
    try {
      #Add-NcCredential -Name $strgCluster -Credential $ControllerCredential
      Connect-nccontroller -Name $strgCluster -Credential $ControllerCredential -HTTPS -Timeout 600000 -ErrorAction Stop | Out-Null 
    }
    catch {
      Write-LogError -LogPath $sLogFile -Message ("Failed Connecting to Cluster " + $strgCluster + " : $_.") -ExitGracefully
      Break
    }
  }
  End {
    If ($?) {
      Write-LogInfo -LogPath $sLogFile -Message ' '
      Write-LogInfo -LogPath $sLogFile -Message ("Connected to " + $strgCluster)
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}
Function Import-Credentials{
   <#
   .SYNOPSIS
   This function decrypts registry key values.
   .DESCRIPTION
   Used Microsoft's DPAPI to decrypt binary values.
   .PARAMETER
   RegistryPath Accepts a String containing the registry path.
   .PARAMETER
   RegistryPath Accepts a String containing the registry path.
   .EXAMPLE
   Import-Credentials -registryPath "HKLM\Software\Scripts" -registryValue "Value"
   .NOTES
   The example provided decryptes the value of the registry key "HKLM\Software\Scripts\Value"
   Credentials can only be decrypted by the same user account that was used to export them.
   See the Microsoft DPAPI documentation for further information
   .LINK
   http://msdn.microsoft.com/en-us/library/ms995355.aspx
   http://msdn.microsoft.com/en-us/library/system.security.cryptography.protecteddata.aspx
   #>
   [CmdletBinding()]
   Param(
      [Parameter(Position=0,
         Mandatory=$True,
         ValueFromPipeLine=$True,
         ValueFromPipeLineByPropertyName=$True)]
      [String]$registryPath,
      [Parameter(Position=1,
         Mandatory=$True,
         ValueFromPipeLine=$True,
         ValueFromPipeLineByPropertyName=$True)]
      [String]$registryValue
   )
   #'---------------------------------------------------------------------------
   #'Decrypt value from binary registry key
   #'---------------------------------------------------------------------------
   $keyPath = "HKLM\$registryPath\$registryValue"
   Try{
      [void][System.Reflection.Assembly]::LoadWithPartialName("System.Security")
      $secret    = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registryPath).GetValue($registryValue)
      $decrypted = [System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($secret, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
   }Catch{
      Write-Warning -Message $("Failed Reading Registry Key ""$keyPath"". Error " + $_.Exception.Message)
      $decrypted = ""
   }
   Return $decrypted;
}
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
#Set Error Action to Silently Continue
[String]$registryPath = "Software\NetApp\Scripts\Syslog";
[String]$username     = Import-Credentials -registryPath $registryPath -registryValue "Key"
[String]$password     = Import-Credentials -registryPath $registryPath -registryValue "Value"
$ssPassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$ControllerCredential = New-Object System.Management.Automation.PsCredential($username,$ssPassword)
#-----------------------------------------------------------[Execution]------------------------------------------------------------
Import-Module $PSLoggingModulePath
Start-Log -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion

#Import Modules
Check-LoadedModule DataONTAP

#Script Execution goes here
# Connect to Cluster
Connect-Cluster $Cluster

# Get the nodes in the cluster
$nodes = (get-ncnode).Node 

# Get Last Weekly ASUP status
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'
Write-LogInfo -LogPath $sLogFile -Message ("Get Last Weekly ASUP status for nodes")
foreach ($node in $nodes) { 
  #Write-LogInfo -LogPath $sLogFile -Message ("Get Last Weekly ASUP status for node: " + $node)
  $asupHistory = Get-NcAutoSupportHistory -Query @{
                                                   Subject = "WEEKLY_LOG";
                                                   Destination = "http";
                                                   NodeName = "$node";
                                                   }
  $max = ($asupHistory | Measure-Object -Property SeqNum -Maximum).Maximum
  $status = $asupHistory | Where-Object {$_.SeqNum -eq $max} | Select NodeName,SeqNum,Subject,Status,@{Name="DateTime";Expression={convertDateTime -UnixDate $_.GenerationTimestamp}} | Format-Table | Out-String
  
  Write-LogInfo -LogPath $sLogFile -Message $status
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Get Cluster nodes Health Status
Write-LogInfo -LogPath $sLogFile -Message 'Get Cluster nodes Health Status'
try {
  $nodesHealth = Get-NcClusterNode | select NodeName,IsNodeHealthy | Out-String
  Write-LogInfo -LogPath $sLogFile -Message $nodesHealth
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Cannot Get Cluster Nodes Health Status: $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Get Cluster HA Information
Write-LogInfo -LogPath $sLogFile -Message 'Get Cluster HA Info'
try {
  #$haInfo = Get-NcClusterHaInfo | Out-String
  $haInfo = Get-NcClusterHaInfo | select Node,NodeState,TakeOverEnabled,TakeoverState,GivebackState | out-String
  Write-LogInfo -LogPath $sLogFile -Message $haInfo
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Cannot Get Cluster HA Info: $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Get Node Uptime
Write-LogInfo -LogPath $sLogFile -Message 'Get Uptime of Nodes'
Write-LogInfo -LogPath $sLogFile -Message ' '
foreach ($node in $nodes) {
  try {
    $upTime = “$node, Node Uptime: {0:dd} days, {0:hh} hours, {0:mm} minutes” -f (Get-NcNode -node $node).NodeUptimeTS
    $upTime = $upTime | Out-String
    Write-LogInfo -LogPath $sLogFile -Message $upTime
  }
  catch {
    Write-LogError -LogPath $sLogFile -Message “Cannot Get Uptime of Node $node : $_.” -ExitGracefully $False
  }
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Get Aggregates where state is not online
Write-LogInfo -LogPath $sLogFile -Message 'Get list of offline Aggregates'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $offlineAggrs = Get-NcAggr | ? {$_.State -ne "online"}
  If([string]::IsNULLOrEmpty($offlineAggrs)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** ALL AGGREGATES ARE ONLINE ***'
  }
  else {
    $offAggrs = $offlineAggrs | out-String
    Write-LogInfo -LogPath $sLogFile -Message $offAggrs
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Cannot Get offline Aggregates: $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Analyze EMS logs (EMERGENCY, ALERT)
Write-LogInfo -LogPath $sLogFile -Message 'Get EMS LOGS for past 2 hour'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $emsLogs = Get-NcEmsMessage -Severity emergency,alert -StartTime (Get-Date).AddHours(-2)
  If([string]::IsNULLOrEmpty($emsLogs)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** NO CRITICAL ALERTS found in EMS LOGS ***'
  }
  else {
    $emsLogs = $emsLogs | out-String
    Write-LogInfo -LogPath $sLogFile -Message $emsLogs
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Failed Querying EMS Logs : $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Check for Broken Disks
Write-LogInfo -LogPath $sLogFile -Message 'Check for Broken Disks'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $FailedDiskTemplate = Get-NcDisk -Template
  Initialize-NcObjectProperty -Object $FailedDiskTemplate -Name DiskRaidInfo
  $FailedDiskTemplate.DiskRaidInfo.ContainerType = "broken"
  $FailedDisks = Get-NcDisk -Query $FailedDiskTemplate

  If([string]::IsNULLOrEmpty($FailedDisks)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** NO BROKEN Disks in the cluster ***'
  }
  else {
    $FailedDisks = $FailedDisks | out-String
    Write-LogInfo -LogPath $sLogFile -Message $FailedDisks
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Failed Querying Broken Disks : $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Check Snapmirror Status
Write-LogInfo -LogPath $sLogFile -Message 'Check Snapmirror DP Relations where Lag Time is more than 30 minutes'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $getSMStatus = Get-NcSnapmirror -Query @{RelationshipType = "data_protection"} `
                                  | Where-Object {$_.LagTime -gt 1800} `
                                  | Select-Object SourceLocation,DestinationLocation, `
                                  @{ 'N'="Lag TimeMinutes"; 'E'={ [Math]::Round($_.LagTime / 60, 2) } },Schedule,RelationshipStatus `
                                  | Format-Table -AutoSize |out-string

  If([string]::IsNULLOrEmpty($getSMStatus)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** NO Snapmirror DP Relations with Lag Time more than 30 minutes ***'
  }
  else {
    Write-LogInfo -LogPath $sLogFile -Message $getSMStatus
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Failed Querying Snapmirror Status : $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Check for Volumes with used Capacity more than 95%
Write-LogInfo -LogPath $sLogFile -Message 'Check Volumes with Used Capacity more than 95%'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $volumeCapacity = Get-NcVol | Where-Object {$_.Used -ge 95} | select Name,Used
  If([string]::IsNULLOrEmpty($volumeCapacity)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** All Volumes under 95% Used Capacity ***'
  }
  else {
    $volumeCapacity = $volumeCapacity | out-String
    Write-LogInfo -LogPath $sLogFile -Message $volumeCapacity
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Failed Querying Snapmirror Status : $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Check for Volumes with inodes used more than 75%
Write-LogInfo -LogPath $sLogFile -Message 'Check Volumes with inodes used more than 75%'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $inodesPcUsed = Get-NcVol | Select-Object Name,@{Name="pcInodesUsed"; Expression={(100*$_.FilesUsed) / $_.FilesTotal -as [INT]}} `
                            | sort-object -descending pcInodesUsed `
                            | Where-Object {$_.pcInodesUsed -gt 75} `
                            | Format-Table @{Name="VolumeName"; Expression={$_.Name}; Width=30},@{Name="%InodesUsed"; Expression={$_.pcInodesUsed}; Width=15} `
                            | Out-String

  If([string]::IsNULLOrEmpty($inodesPcUsed)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** No Volume has inodes used more than 75% ***'
  }
  else {
    Write-LogInfo -LogPath $sLogFile -Message $inodesPcUsed
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Failed Querying inodes Status : $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Check for Max AutoSize Used %
Write-LogInfo -LogPath $sLogFile -Message 'Check Volumes with Max AutoSize Used more than 80%'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $maxAutoSizeUsed = Get-NcVol | Where-Object { ("{0:N2}" -f ($_.VolumeSpaceAttributes.SizeUsed/$_.VolumeAutosizeAttributes.MaximumSize)) -gt 0.8 } `
                               |Select-Object Vserver,Name, `
                               @{Name='Type'; Expression={$_.VolumeIdAttributes.Type}}, `
                               @{Name='MaxAutoSizeUsed(%)'; Expression={[Math]::Round(($_.VolumeSpaceAttributes.SizeUsed/$_.VolumeAutosizeAttributes.MaximumSize * 100), 2)}} `
                               | Format-Table -AutoSize `
                               | Out-String

  If([string]::IsNULLOrEmpty($maxAutoSizeUsed)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** No Volume has Max AutoSize Used more than 80% ***'
  }
  else {
    Write-LogInfo -LogPath $sLogFile -Message $maxAutoSizeUsed
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Failed Querying Volume AutoSize Status : $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Check Interfaces which are not home
Write-LogInfo -LogPath $sLogFile -Message 'Check NOT HOME Interfaces'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $notHomeInterface = Get-NcNetInterface -Query @{ IsHome = $false } | select InterfaceName,OpStatus,Vserver,Address
  If([string]::IsNULLOrEmpty($notHomeInterface)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** All INTERFACES ARE ON Home NODE and Home PORT ***'
  }
  else {
    $notHomeInterface = $notHomeInterface | out-String
    Write-LogInfo -LogPath $sLogFile -Message $notHomeInterface
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Failed Querying Not Home Interfaces : $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

# Check Unhealthy Interface Groups
Write-LogInfo -LogPath $sLogFile -Message 'Check Unhealthy Interface Groups'
Write-LogInfo -LogPath $sLogFile -Message ' '
try {
  $Ifgrps = Get-NcNetPortIfgrp | where {$_.PortParticipation -eq "partial" -or $_.PortParticipation -eq "none"} | select Node,IfgrpName,Mode,PortParticipation,Ports,UpPorts
  If([string]::IsNULLOrEmpty($Ifgrps)) {
    Write-LogInfo -LogPath $sLogFile -Message '*** All INTERFACE GROUPS are HEALTHY ***'
  }
  else {
    $Ifgrps = $Ifgrps | out-String
    Write-LogInfo -LogPath $sLogFile -Message $Ifgrps
  }
}
catch {
  Write-LogError -LogPath $sLogFile -Message “Failed Querying Not Home Interfaces : $_.” -ExitGracefully $False
}
Write-LogInfo -LogPath $sLogFile -Message '***************************************************************************************************'

Start-Sleep -Seconds 5
if (Test-Path $sLogFile) {
    [string]$mailbody = "Weekly Health Check Report for cluster: " + $Cluster
    Send-Log -LogPath $sLogFile -SMTPServer "appsmtp.lab.local" -EmailFrom "Automated_Reports@lab.local" -EmailTo "user1@lab.local, nitish.chopra@lab.local" -EmailSubject $mailbody -Verbose
    Stop-Log -LogPath $sLogFile
}
###### END ######