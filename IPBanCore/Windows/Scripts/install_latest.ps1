#
# One click install script for IPBan for Windows
# (c) 2011-Present Digital Ruby, LLC
# https://www.digitalruby.com
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
#

param
(
	[Parameter(Mandatory=$False, Position = 0)]
	[String] $uninstall,
	[Parameter(Mandatory=$False, Position = 1)]
	[Boolean] $silent = $False,
	[Parameter(Mandatory=$False, Position = 2)]
	[Boolean] $autostart = $True
)

if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1))
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

if (Get-Service $SERVICE_NAME -ErrorAction SilentlyContinue)
{
    # create install path, ensure clean slate
    Write-Output "Removing existing service"
    try
    {
        Stop-Service -Name $SERVICE_NAME -Force
    }
    catch
    {
    }
    & sc.exe delete $SERVICE_NAME
}

if (Test-Path -Path $INSTALL_PATH)
{
    Write-Output "Removing existing directory at $INSTALL_PATH"
    if ($isUninstall -eq $False)
    {
        if (Test-Path "$INSTALL_PATH\ipban.config")
        {
            copy-item "$INSTALL_PATH\ipban.config" $tempPath
        }
        if (Test-Path "$INSTALL_PATH\ipban.override.config")
        {
            copy-item "$INSTALL_PATH\ipban.override.config" $tempPath
        }
        if (Test-Path "$INSTALL_PATH\ipban.sqlite")
        {
            copy-item "$INSTALL_PATH\ipban.sqlite" $tempPath
        }
		if (Test-Path "$INSTALL_PATH\nlog.config")
        {
            copy-item "$INSTALL_PATH\nlog.config" $tempPath
        }
    }
	else
	{
		Remove-Item "$INSTALL_PATH" -Force -Recurse 
		Write-Output "IPBan is fully uninstalled from this system"
		exit 0
	}
}

# download zip file
New-Item -Type Directory -path $INSTALL_PATH -ErrorAction SilentlyContinue
$ReleaseAssets = Invoke-RestMethod "https://api.github.com/repos/DigitalRuby/IPBan/releases/latest"
if ([System.Environment]::Is64BitOperatingSystem)
{
    $url        = ($ReleaseAssets.assets | ? name -Match "\-Windows\-x64").browser_download_url
} else {
    $url        = ($ReleaseAssets.assets | ? name -Match "\-Windows\-x86").browser_download_url
}
Write-Output "Downloading ipban from $Url"
$ZipFile = "$INSTALL_PATH\IPBan.zip"

# Forcing the Invoke-RestMethod PowerShell cmdlet to use TLS 1.2 to avoid error "The request was aborted: Could not create SSL/TLS secure channel."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $ZipFile 

# extract zip file, cleanup zip file
Expand-Archive -LiteralPath $ZipFile -DestinationPath $INSTALL_PATH -Force
Remove-Item -Force $ZipFile

# copy back over the config and db file
if (Test-Path -Path "$tempPath\ipban.config")
{
    copy-Item "$tempPath\ipban.config" "$INSTALL_PATH"
    remove-Item "$tempPath\ipban.config"
}
if (Test-Path -Path "$tempPath\ipban.override.config")
{
    copy-Item "$tempPath\ipban.override.config" "$INSTALL_PATH"
    remove-Item "$tempPath\ipban.override.config"
}
if (Test-Path -Path "$tempPath\ipban.sqlite")
{
    copy-Item "$tempPath\ipban.sqlite" "$INSTALL_PATH"
    remove-Item "$tempPath\ipban.sqlite"
}
if (Test-Path -Path "$tempPath\nlog.config")
{
    copy-Item "$tempPath\nlog.config" "$INSTALL_PATH"
    remove-Item "$tempPath\nlog.config"
}

# ensure audit policy is logging
& auditpol.exe /set /category:"{69979849-797A-11D9-BED3-505054503030}" /success:enable /failure:enable
& auditpol.exe /set /category:"{69979850-797A-11D9-BED3-505054503030}" /success:enable /failure:enable

# create service
& sc.exe create IPBAN type= own start= delayed-auto binPath= $INSTALL_EXE DisplayName= $SERVICE_NAME
& sc.exe description IPBAN "Automatically builds firewall rules for abusive login attempts: https://github.com/DigitalRuby/IPBan"
& sc.exe failure IPBAN reset= 9999 actions= "restart/60000/restart/60000/restart/60000"
if ($autostart -eq $True)
{
	Start-Service IPBAN
}
else
{
	Write-Output "IPBAN Service is in stopped state, you must start it manually."
}

if ($silent -eq $False)
{
    # open config
    Write-Output "Opening config file, make sure to whitelist your trusted ip addresses!"
    & notepad $CONFIG_FILE
}
