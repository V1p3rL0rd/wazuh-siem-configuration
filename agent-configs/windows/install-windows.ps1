<#
.SYNOPSIS
    Baseline Wazuh Agent Deployment Script for Windows Server
.DESCRIPTION
    Downloads and installs Wazuh Agent silently, applies optimized baseline ossec.conf,
    and starts the Wazuh service.
.PARAMETER WazuhManager
    IP address or FQDN of the Wazuh Manager (e.g. "192.0.2.10" or "wazuh.example.com").
.PARAMETER AgentName
    Custom name for the agent (defaults to $env:COMPUTERNAME).
.PARAMETER AgentVersion
    Wazuh Agent version (must be <= manager version). Defaults to WAZUH_VERSION from the repository .env.
.PARAMETER AgentGroup
    Optional agent group assigned at enrollment (must exist on the manager).
.PARAMETER InstallSysmon
    Optional switch to install Microsoft Sysmon alongside Wazuh.
.EXAMPLE
    .\install-windows.ps1 -WazuhManager "192.0.2.10"
    .\install-windows.ps1 -WazuhManager "wazuh.example.com" -AgentVersion "4.14.5" -AgentGroup "windows-server"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$WazuhManager,

    [Parameter(Mandatory = $false)]
    [string]$AgentName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [string]$AgentVersion,

    [Parameter(Mandatory = $false)]
    [string]$AgentGroup,

    [Parameter(Mandatory = $false)]
    [switch]$InstallSysmon
)

$ErrorActionPreference = "Stop"

# Ensure RunAs Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be executed in an elevated Administrator PowerShell session."
    exit 1
}

# Auto-detect Wazuh Manager IP/FQDN from .env if not supplied
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFileCandidates = @((Join-Path $scriptDir "..\..\.env"))
if (-not $AgentVersion) {
    foreach ($candidate in $envFileCandidates) {
        if (Test-Path $candidate) {
            $verLine = Select-String -Path $candidate -Pattern "^WAZUH_VERSION=(.+)$" | Select-Object -Last 1
            if ($verLine) { $AgentVersion = $verLine.Matches[0].Groups[1].Value.Trim("'`" "); break }
        }
    }
}
$AgentVersion = "$AgentVersion".TrimStart("v")
if ($AgentVersion -notmatch '^\d+\.\d+\.\d+$') {
    Write-Error "Agent version is not set. Pass -AgentVersion (must not be newer than the manager, e.g. 4.14.5)."
    exit 1
}

if (-not $WazuhManager) {
    $possibleEnv = Join-Path $scriptDir "..\..\.env"
    if (Test-Path $possibleEnv) {
        $envLines = Get-Content $possibleEnv
        foreach ($line in $envLines) {
            if ($line -match "^WAZUH_SERVER_IP=(.+)$" -or $line -match "^WAZUH_SERVER_FQDN=(.+)$") {
                $WazuhManager = $matches[1].Trim("'`"")
                if ($WazuhManager) { break }
            }
        }
    }
}

if (-not $WazuhManager) {
    $WazuhManager = Read-Host "Wazuh Manager IP or FQDN"
}

if (-not $WazuhManager) {
    Write-Error "Please supply -WazuhManager parameter (e.g. -WazuhManager '192.0.2.10' or 'wazuh.example.com')."
    exit 1
}

$workDir = "$env:TEMP\WazuhInstall"
if (-not (Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir | Out-Null
}

# Optional Sysmon installation
if ($InstallSysmon) {
    Write-Host "==> Checking and installing Sysmon..." -ForegroundColor Cyan
    $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
    $sysmonConfigFile = Join-Path $scriptDir "sysmonconfig.xml"

    if (-not $sysmonService) {
        $sysmonZip = Join-Path $workDir "Sysmon.zip"
        $sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
        Write-Host "Downloading Sysmon from Sysinternals..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip

        Expand-Archive -Path $sysmonZip -DestinationPath "$workDir\Sysmon" -Force
        $sysmonExe = "$workDir\Sysmon\Sysmon64.exe"
        $sig = Get-AuthenticodeSignature -FilePath $sysmonExe
        if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Microsoft") {
            Write-Error "Sysmon64.exe signature is not a valid Microsoft signature ($($sig.Status)). Aborting."
            exit 1
        }

        if (Test-Path $sysmonConfigFile) {
            Write-Host "Installing Sysmon with custom configuration..."
            Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i `"$sysmonConfigFile`"" -Wait
        } else {
            Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i" -Wait
        }
    } else {
        Write-Host "Sysmon service is already running." -ForegroundColor Green
    }
}

Write-Host "==> [1/3] Downloading Wazuh Agent MSI..." -ForegroundColor Cyan
$wazuhMsi = Join-Path $workDir "wazuh-agent.msi"
$wazuhMsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$AgentVersion-1.msi"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $wazuhMsiUrl -OutFile $wazuhMsi
$msiSig = Get-AuthenticodeSignature -FilePath $wazuhMsi
if ($msiSig.Status -ne "Valid" -or $msiSig.SignerCertificate.Subject -notmatch "Wazuh") {
    Write-Error "Wazuh MSI signature is not valid ($($msiSig.Status)). Aborting."
    exit 1
}

Write-Host "==> [2/3] Installing Wazuh Agent silently..." -ForegroundColor Cyan
$msiArgs = "/i `"$wazuhMsi`" /q WAZUH_MANAGER=`"$WazuhManager`" WAZUH_AGENT_NAME=`"$AgentName`""
if ($AgentGroup) { $msiArgs += " WAZUH_AGENT_GROUP=`"$AgentGroup`"" }
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru

if ($process.ExitCode -ne 0) {
    Write-Error "Wazuh Agent MSI installation failed with exit code $($process.ExitCode)."
    exit 1
}

Write-Host "==> [3/3] Applying baseline ossec.conf..." -ForegroundColor Cyan
$wazuhInstallDir = "${env:ProgramFiles(x86)}\ossec-agent"
if (-not (Test-Path $wazuhInstallDir)) {
    $wazuhInstallDir = "$env:ProgramFiles\ossec-agent"
}

$localOssecConf = Join-Path $scriptDir "ossec.conf"
$targetOssecConf = Join-Path $wazuhInstallDir "ossec.conf"

if (Test-Path $localOssecConf) {
    $confContent = Get-Content $localOssecConf -Raw
    $confContent = $confContent.Replace("<WAZUH_MANAGER_IP>", $WazuhManager)
    # UTF-8 without BOM (Windows PowerShell 5.1 "Set-Content -Encoding UTF8" writes a BOM)
    [System.IO.File]::WriteAllText($targetOssecConf, $confContent, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Baseline ossec.conf applied successfully." -ForegroundColor Green
}

Write-Host "Restarting Wazuh service..." -ForegroundColor Cyan
# Service name is WazuhSvc (display name "Wazuh")
$svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $svc) { $svc = Get-Service -DisplayName "Wazuh" -ErrorAction SilentlyContinue }
if (-not $svc) {
    Write-Error "Wazuh agent service not found after installation."
    exit 1
}
Restart-Service -Name $svc.Name -Force
Start-Sleep -Seconds 5
$svc.Refresh()
if ($svc.Status -ne "Running") {
    Write-Error "Wazuh agent service is $($svc.Status). Check $wazuhInstallDir\ossec.log"
    exit 1
}

Write-Host "==> Wazuh Agent $AgentVersion deployed as '$AgentName' (manager: $WazuhManager)." -ForegroundColor Green
$svc
