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
	[Parameter(Mandatory=$False, Position = 0)] [String]$uninstall
)

if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1))
{
    & echo "This script requires powershell 5.1 or greater"
    exit -1
}

$VERSION_DOTS = "1.7.0"
$VERSION_UNDERSCORES = $VERSION_DOTS -replace "\.","_"
$FILE_NAME = "IPBan-Windows-x64_$VERSION_UNDERSCORES.zip"
$INSTALL_PATH = "C:/Program Files/IPBan"
$SERVICE_NAME = "IPBan"
$ErrorActionPreference = "Stop"
$tempPath = [System.IO.Path]::GetTempPath()
[bool] $isUninstall = ($uninstall -eq "u" -or $uninstall -eq "uninstall")

if ([System.Environment]::Is64BitOperatingSystem -ne $True)
{
    $FILE_NAME = "IPBan-Windows-x86_$VERSION_UNDERSCORES.zip"
}

$CONFIG_FILE = "$INSTALL_PATH/ipban.config"
$INSTALL_EXE = "$INSTALL_PATH/DigitalRuby.IPBan.exe"

if (Get-Service $SERVICE_NAME -ErrorAction SilentlyContinue)
{
    # create install path, ensure clean slate
    & echo "Removing existing service"
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
    & echo "Removing existing directory at $INSTALL_PATH"
    if ($isUninstall -eq $False)
    {
        if (Test-Path "$INSTALL_PATH/ipban.config")
        {
            copy "$INSTALL_PATH/ipban.config" $tempPath
        }
        if (Test-Path "$INSTALL_PATH/ipban.override.config")
        {
            copy "$INSTALL_PATH/ipban.override.config" $tempPath
        }
        if (Test-Path "$INSTALL_PATH/ipban.sqlite")
        {
            copy "$INSTALL_PATH/ipban.sqlite" $tempPath
        }
    }
    & cmd.exe /c rd /s /q $INSTALL_PATH
}

if ($isUninstall -eq $True)
{
    & echo "IPBan is fully uninstalled from this system"
    exit
}

# download zip file
& mkdir -p $INSTALL_PATH
$Url = "https://github.com/DigitalRuby/IPBan/releases/download/$VERSION_DOTS/$FILE_NAME"
& echo "Downloading ipban from $Url"
$ZipFile = "$INSTALL_PATH/IPBan.zip"

# Forcing the Invoke-RestMethod PowerShell cmdlet to use TLS 1.2 to avoid error "The request was aborted: Could not create SSL/TLS secure channel."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $ZipFile 

# extract zip file, cleanup zip file
Expand-Archive -LiteralPath $ZipFile -DestinationPath $INSTALL_PATH
Remove-Item -Force $ZipFile

# copy back over the config and db file
if (Test-Path -Path "$tempPath/ipban.config")
{
    & copy "$tempPath/ipban.config" "$INSTALL_PATH"
    & rm "$tempPath/ipban.config"
}
if (Test-Path -Path "$tempPath/ipban.override.config")
{
    & copy "$tempPath/ipban.override.config" "$INSTALL_PATH"
    & rm "$tempPath/ipban.override.config"
}
if (Test-Path -Path "$tempPath/ipban.sqlite")
{
    & copy "$tempPath/ipban.sqlite" "$INSTALL_PATH"
    & rm "$tempPath/ipban.sqlite"
}

# ensure audit policy is logging
& auditpol.exe /set /category:"{69979849-797A-11D9-BED3-505054503030}" /success:enable /failure:enable
& auditpol.exe /set /category:"{69979850-797A-11D9-BED3-505054503030}" /success:enable /failure:enable

# create service
& sc.exe create IPBAN type= own start= delayed-auto binPath= $INSTALL_EXE DisplayName= $SERVICE_NAME
& sc.exe description IPBAN "Automatically builds firewall rules for abusive login attempts: https://github.com/DigitalRuby/IPBan"
& sc.exe failure IPBAN reset= 9999 actions= "restart/60000/restart/60000/restart/60000"
& sc.exe start IPBAN

# open config
& echo "Opening config file, make sure to whitelist your trusted ip addresses!"
& notepad $CONFIG_FILE
