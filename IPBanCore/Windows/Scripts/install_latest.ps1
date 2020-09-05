param
(
	[Parameter(Mandatory=$False, Position = 0)] [String]$uninstall
)

$VERSION_DOTS = "1.5.7"
$VERSION_UNDERSCORES = $VERSION_DOTS -replace "\.","_"
$FILE_NAME = "IPBan-Windows-x64_$VERSION_UNDERSCORES.zip"
$INSTALL_PATH = "C:/Program Files/IPBan"
$INSTALL_EXE = "$INSTALL_PATH/DigitalRuby.IPBan.exe"
$CONFIG_FILE = "$INSTALL_PATH/ipban.config"
$SERVICE_NAME = "IPBan"

if (Get-Service $SERVICE_NAME -ErrorAction SilentlyContinue)
{
    # create install path, ensure clean slate
    & echo "Removing existing service"
    Stop-Service -Name $SERVICE_NAME -Force
    & sc.exe delete $SERVICE_NAME
}
if (Test-Path -Path $INSTALL_PATH)
{
    & echo "Removing existing directory at $INSTALL_PATH"
    & cmd.exe /c rd /s /q $INSTALL_PATH
}

if ($uninstall -eq "u" -or $uninstall -eq "uninstall")
{
    & echo "IPBan is fully uninstalled from this system"
    exit
}

# download zip file
& mkdir -p $INSTALL_PATH
$Url = "https://github.com/DigitalRuby/IPBan/releases/download/$VERSION_DOTS/$FILE_NAME"
& echo "Downloading ipban from $Url"
$ZipFile = "$INSTALL_PATH/IPBan.zip"
Invoke-WebRequest -Uri $Url -OutFile $ZipFile 

# extract zip file, cleanup zip file
Expand-Archive -LiteralPath $ZipFile -DestinationPath $INSTALL_PATH
Remove-Item -Force $ZipFile

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
