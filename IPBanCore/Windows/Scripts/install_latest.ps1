#
# One click install script for IPBan for Windows
# (c) 2011-Present Digital Ruby, LLC
# https://ipban.com
#
# PowerShell minimum version: 5.1
# Update PowerShell: https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-windows?view=powershell-5.1
#
# Please run from an admin powershell prompt the following:
# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DigitalRuby/IPBan/master/IPBanCore/Windows/Scripts/install_latest.ps1'))
#
# Should you ever wish to update IPBan, just re-run this script and it will auto-update and preserve your ipban.sqlite and ipban.config files!
#
# To uninstall, run this same script with an argument of uninstall
# To install a specific version, pass it as the fifth argument or use -version (ex. 4.0.0)
#

param
(
    [Parameter(Mandatory=$False, Position = 0)]
    [String] $uninstall,

    [Parameter(Mandatory=$False, Position = 1)]
    [Boolean] $silent = $False,

    [Parameter(Mandatory=$False, Position = 2)]
    [Boolean] $autostart = $True,

    [Parameter(Mandatory=$False, Position = 3)]
    [ValidateSet("delayed-auto", "auto")]
    [String] $startupType = "delayed-auto",

    [Parameter(Mandatory=$False, Position = 4)]
    [String] $version
)

if ($PSVersionTable.PSVersion.Major -lt 5)
{
    Write-Output "This script requires powershell 5.1 or greater"
    exit -1
}

$ProgressPreference = "SilentlyContinue"
$INSTALL_PATH = "C:\Program Files\IPBan"
$SERVICE_NAME = "IPBan"
$ErrorActionPreference = "Stop"
$tempPath = [System.IO.Path]::GetTempPath()
[bool] $isUninstall = ($uninstall -eq "u" -or $uninstall -eq "uninstall")

$CONFIG_FILE = "$INSTALL_PATH\ipban.config"
$INSTALL_EXE = "$INSTALL_PATH\DigitalRuby.IPBan.exe"

# Remove existing service
if (Get-Service $SERVICE_NAME -ErrorAction SilentlyContinue)
{
    Write-Output "Removing existing service"
    try { Stop-Service -Name $SERVICE_NAME -Force } catch {}
    & sc.exe delete $SERVICE_NAME
}

# Remove or backup existing install
if (Test-Path -Path $INSTALL_PATH)
{
    Write-Output "Removing existing directory at $INSTALL_PATH"

    if ($isUninstall -eq $False)
    {
        foreach ($file in @("ipban.config","ipban.override.config","ipban.sqlite","nlog.config"))
        {
            if (Test-Path "$INSTALL_PATH\$file")
            {
                Copy-Item "$INSTALL_PATH\$file" $tempPath
            }
        }
    }
    else
    {
        Remove-Item "$INSTALL_PATH" -Force -Recurse
        Write-Output "IPBan is fully uninstalled from this system"
        exit 0
    }
}

# Create install dir
New-Item -Type Directory -Path $INSTALL_PATH -ErrorAction SilentlyContinue

# Get release
if ([string]::IsNullOrWhiteSpace($version))
{
    $ReleaseAssets = Invoke-RestMethod "https://api.github.com/repos/DigitalRuby/IPBan/releases/latest"
}
else
{
    $versionTag = $version.Replace('.', '_')
    $ReleaseAssets = Invoke-RestMethod "https://api.github.com/repos/DigitalRuby/IPBan/releases/tags/$versionTag"
}

if ([System.Environment]::Is64BitOperatingSystem)
{
    $url = ($ReleaseAssets.assets | Where-Object { $_.name -match "\-Windows\-x64" }).browser_download_url
}
else
{
    $url = ($ReleaseAssets.assets | Where-Object { $_.name -match "\-Windows\-x86" }).browser_download_url
}

if ([string]::IsNullOrWhiteSpace($version))
{
    Write-Output "Downloading latest ipban from $url"
}
else
{
    Write-Output "Downloading ipban version $version from $url"
}

$ZipFile = "$INSTALL_PATH\IPBan.zip"

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest -Uri $url -OutFile $ZipFile

# Extract
Expand-Archive -LiteralPath $ZipFile -DestinationPath $INSTALL_PATH -Force
Remove-Item -Force $ZipFile

# Restore configs
foreach ($file in @("ipban.config","ipban.override.config","ipban.sqlite","nlog.config"))
{
    if (Test-Path "$tempPath\$file")
    {
        Copy-Item "$tempPath\$file" "$INSTALL_PATH"
        Remove-Item "$tempPath\$file"
    }
}

# Enable audit policy
& auditpol.exe /set /category:"{69979849-797A-11D9-BED3-505054503030}" /success:enable /failure:enable
& auditpol.exe /set /category:"{69979850-797A-11D9-BED3-505054503030}" /success:enable /failure:enable

# Handle startupType logic
if ($silent -eq $True)
{
    if ([string]::IsNullOrEmpty($startupType))
    {
        $startupType = "delayed-auto"
    }
}
elseif ([string]::IsNullOrEmpty($startupType))
{
    Write-Host "`n"
    Write-Host "Select the services startup type:"
    Write-Host '1. delayed-auto'
    Write-Host '2. auto'

    do
    {
        $choice = Read-Host "Enter selection"
        switch ($choice)
        {
            "1" { $startupType = "delayed-auto" }
            "2" { $startupType = "auto" }
        }
    } while ($startupType -notin @("delayed-auto","auto"))
}

# Create service
$binPath = "`"$INSTALL_EXE`""

Write-Output "Creating service..."
& sc.exe create $SERVICE_NAME binPath= $binPath start= $startupType

if ($autostart)
{
    Write-Output "Starting service..."
    Start-Service $SERVICE_NAME
}

Write-Output "IPBan installation complete."