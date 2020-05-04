<#
.SYNOPSIS
  The tool helps collecting log files, configuration files, Windows Event Logs of YSoft SafeQ 6 or YSoft SafeQ 5.

.DESCRIPTION
  The tool identifies YSoft SafeQ installation and collects all possible log files and configuration.
  The tool collects information from Windows Event Viewer.
  The tool collects information from Windows System Information
  The tool collects data for defined period of time (see $LogAge parameter). E.g. if the issue happened 3 hours ago, you would collect data from the last 4-5 hours to ensure that all data for analysis are available.
  The tool collects only data from the server where the command was triggered for the past X hours (see $LogAge parameter). In case other servers may be involved (Management Server, CBPR Client, Authentication against SPOC group, etc.) data from all affected servers has to be provided.
    - for instance an authentication issue on an MFD managed by a SPOC group hidden behind a virtual IP address of load balancer occurs; log files from all servers in the SPOC group as well as from the Management servers has to be provided.
    - log files must cover the date and time of the occurrence
  
  The script must be launched using PowerShell as an Administrator
  Additional data such as "Support information" (YSoft SafeQ Management web interface > Dashboard > Click "Support information" > Click "Download support information"), screenshots and so on are to be collected manually.

.PARAMETER LogAge
  Defines the period for how how many hours the log files will be collected from now to the past (default configuration is past 24 hours)
  
.PARAMETER RootCollectionPath
  Defines the folder where on the server would you like to store the data (by default a new folder will be created on the desktop)

.NOTES
  Version:        1.08
  Author:         YSoft
  Creation Date:  04/05/2020

.EXAMPLE
  Run Windows PowerShell as an administrator and launch the command as follows:
  C:\Users\Administrator\Downloads> .\SQ_Collect_Logs.ps1
#>

#-----------------------------------------------------------[Parameters]-----------------------------------------------------------

# Set the log age to gather in hours (Default: $LogAge = '24')
$LogAge = '24'

# Log collection folder (Default: $RootCollectionPath = "$($env:USERPROFILE)\Desktop")
# Example : $RootCollectionPath = "C:\Temp"
$RootCollectionPath = "$($env:USERPROFILE)\Desktop"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Prepare the log collection folder
$IPaddress = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.DefaultIPGateway -ne $null}).IPAddress | Select-Object -First 1
$FolderName = "$((Get-Date).ToString("yyyyMMddHHmm"))_$($env:COMPUTERNAME)_$($IPaddress)_YSoftDiagData"
$DataDest = "$($RootCollectionPath)\$($FolderName)"

# Define the services
$Services = Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services | ? {(($_.Name.Split('\') | Select-Object -Last 1) -like "YSoft*") -or (($_.Name.Split('\') | Select-Object -Last 1) -like "YSQ*")} | % {
    Get-ItemProperty $_.PsPath | ? {
         $_.PSChildName -ne "YSoftEtcd" `
    -and $_.PSChildName -ne "YSoftSQ-LDAP" `
    -and $_.PSChildName -ne "YSoftSQ-JSDL" `
    -and $_.PSChildName -ne "YSoftSafeQLDAPReplicator" `
    -and $_.PSChildName -ne "YSoftSafeQCMLDBS" `
    -and $_.PSChildName -ne "YSoftWeb"
    }
}

# Define the configuration files
$ConfFiles = New-Object PSObject -Property @{

    "YSoftSQ-Management"     = "conf\*.properties","tomcat\conf\*.xml"
    "YSoftIms"               = "application.properties"
    "YSoftPGSQL"             = "*.conf"
    "YSoftSQ-SPOC"           = "conf\modules\*.conf","conf\*.drl","conf\remoteConfImg.xml"
    "YSoftSQ-SPOCGS"         = "config\distServer.conf","config\spoc-cluster-jgroups-TCP.xml","config\spoc-replication-cluster-configuration.xml"
    "YSoftSQ-EUI"            = "conf\*.xml"
    "YSoftSQ-TS"             = "TerminalServer.exe.config"
    "YSoftSQ-FSP"            = "service\*.config"
    "YSoftSQ-WPS"            = "WpsService.exe.config"
    "YSoftSQ-MPS"            = "Service\conf\*.config"
    "YSoftSQ-MIG"            = "bin\MigService.exe.config","bin\services\MdnsService.xml"
    "YSoftPS"                = "ps-conf\*.properties","ysoft\*.properties","conf\*.xml"
    "YSoftSQ-JOB-SERVICE"    = "configuration\*.json"

    "YSoftSafeQCML"          = "conf\*.conf","conf\*.drl","tomcat\conf\*.xml"
    "YSoftMobilePrintServer" = "Service\conf\*.config"
    "YSoftPaymentSystem"     = "ps-conf\*.properties","ysoft\*.properties","conf\*.xml"
    "YSQpostgres"            = "*.conf"
    "YSoftSafeQORS"          = "conf\modules\*.conf","conf\*.drl","conf\remoteConfImg.xml"
}

$SrvPaths = @()
$CnfPaths = @()

'Copying the configuration files' | Out-Host
ForEach ($Service in $Services) {
    $SrvPath = $Service.ImagePath.Split()[0].Trim('`"')
    $SrvPath = $SrvPath.Substring(0,$SrvPath.LastIndexOf("\")) -Replace ("\\?bin\\?","") -Replace ("\\?tomcat\\?","") -Replace ("\\Service\\?","") -Replace ("PGSQL","PGSQL-data")
    $SrvPaths += $SrvPath

    ForEach ($SrvName in $ConfFiles.PSObject.Properties.Name) {
        If ($Service.PSChildName -eq $SrvName) {
            ForEach ($SrvPth in $SrvPath) {
                ForEach ($CnfName in $ConfFiles.$SrvName) {
                    If ((Test-Path "$($SrvPth)\$($CnfName)")) {
                        $CnfPaths = Get-ChildItem -Path "$($SrvPath)\$($CnfName)"
                        ForEach ($CnfPath in $CnfPaths) {
                            $DirectoryName = $CnfPath.DirectoryName -replace ("\w:\\","")
                            $Destination = "$DataDest\$DirectoryName"
                            If (!(Test-Path $Destination)) {
                                New-Item -Path $Destination -ItemType Directory | Out-Null
                            }
                            Copy-Item $CnfPath -Destination $Destination
                        }
                    }
                }
            }
        }
    }
}

'Copying the log files' | Out-Host
$LogPaths = @()
$LogList = @()
ForEach ($SrvPath in $SrvPaths) {
    $LogList += Get-ChildItem -Path $SrvPath | ? {($_.Length -gt 0) -and ($_.extension -eq ".log")}
    $LogPaths += Get-ChildItem -Path $SrvPath -Directory | ? {$_.Name -match ".*(log|logs)$"} | Select-Object -ExpandProperty FullName
}

ForEach ($LogPath in $LogPaths) {
    $LogList += Get-ChildItem -Path $LogPath | ? {($_.Length -gt 0) -and ($_.extension -in ".log",".zip")}
}

$Patterns = @()
ForEach ($Log in $LogList) {
    If ($Log.BaseName -match "\.") {  
        $Patterns += ($Log.BaseName -Split ('\.'))[0]
    } Elseif ($Log.BaseName -match "postgresql") {
        $Patterns += ($Log.BaseName -Split ('\-'))[0]
    } Else {
        $Patterns += $Log.BaseName
    }
}
$Patterns = $Patterns | Select-Object -Unique

$LastLogs = @()
ForEach ($Pattern in $Patterns) {
    $LastLogs += $LogList | ? {$_.BaseName -match "$Pattern"} | Sort-Object LastWriteTime -Descending | Select-Object -First 2
}
$LogsToCopy = $LogList | ? {$_.LastWriteTime -gt (Get-Date).AddHours(-$LogAge) -or $_ -in $LastLogs}

ForEach ($LogToCopy in $LogsToCopy) {
    $DirectoryName = $LogToCopy.DirectoryName -replace ("\w:\\","")
    $Destination = "$DataDest\$DirectoryName"
    If (!(Test-Path $Destination)) {
        New-Item -Path $Destination -ItemType Directory | Out-Null
    }
    Copy-Item $LogToCopy.FullName -Destination $Destination
}

'Getting the Windows Event Logs' | Out-Host
Get-EventLog Application -After (Get-Date).AddHours(-$LogAge) | Format-Table -wrap -auto | Out-File $DataDest\EventLog_Application.txt
Get-EventLog System -After (Get-Date).AddHours(-$LogAge) | Format-Table -wrap -auto | Out-File $DataDest\EventLog_System.txt

'Getting the System Info' | Out-Host
systeminfo | Out-File $DataDest\SystemInfo.txt

'Listing details about available memory dumps' | Out-Host
$hprof = Get-ChildItem -Path ([regex]::split($SrvPaths, '(\w:\\\w+\s?\w\\)')[1]) -Filter *.hprof -Recurse
If (![string]::IsNullOrEmpty($hprof)) {
    $hprof | Format-Table -Property FullName, Length, LastWriteTime -AutoSize | Out-File $DataDest\HeapDump_List.txt
}

'Extracting archived logs' | Out-Host
$ZipFiles = Get-ChildItem -Path $DataDest -Recurse | Where-Object {$_.Name -match '.zip'}
If ($ZipFiles) {
  ForEach ($ZipFile in $ZipFiles) {
    Expand-Archive -Path $($ZipFile.FullName) -DestinationPath $($ZipFile.Directory.FullName)
    Remove-Item -Path $ZipFile.FullName
  }
}

'Compressing the files' | Out-Host
Compress-Archive -Path $DataDest -DestinationPath "$($DataDest).zip"
Remove-Item -Path $DataDest -Recurse -Force

Write-Output ""
Write-Output "Work done, the output is in $($DataDest).zip"
Write-Output 'Feel free to close the script'
Read-Host