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
    Wazuh Agent version (must be <= manager version). Defaults to WAZUH_VERSION from .env, else 4.9.2.
.PARAMETER InstallSysmon
    Optional switch to install Microsoft Sysmon alongside Wazuh.
.EXAMPLE
    .\install-windows.ps1 -WazuhManager "192.0.2.10"
    .\install-windows.ps1 -WazuhManager "wazuh.example.com"
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
    $AgentVersion = "4.9.2"
    foreach ($candidate in $envFileCandidates) {
        if (Test-Path $candidate) {
            $verLine = Select-String -Path $candidate -Pattern "^WAZUH_VERSION=(.+)$" | Select-Object -Last 1
            if ($verLine) { $AgentVersion = $verLine.Matches[0].Groups[1].Value.Trim("'`" "); break }
        }
    }
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
Invoke-WebRequest -Uri $wazuhMsiUrl -OutFile $wazuhMsi

Write-Host "==> [2/3] Installing Wazuh Agent silently..." -ForegroundColor Cyan
$msiArgs = "/i `"$wazuhMsi`" /q WAZUH_MANAGER=`"$WazuhManager`" WAZUH_AGENT_NAME=`"$AgentName`""
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
    Set-Content -Path $targetOssecConf -Value $confContent -Encoding UTF8
    Write-Host "Baseline ossec.conf applied successfully." -ForegroundColor Green
}

Write-Host "Restarting Wazuh service..." -ForegroundColor Cyan
Restart-Service -Name "Wazuh" -Force

Write-Host "==> Wazuh Agent successfully deployed and connected to $WazuhManager as '$AgentName'!" -ForegroundColor Green
Get-Service -Name "Wazuh"
