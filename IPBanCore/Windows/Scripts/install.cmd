REM Make sure to extract service files to c:/ipban first!
auditpol.exe /set /category:"{69979849-797A-11D9-BED3-505054503030}" /success:enable /failure:enable
auditpol.exe /set /category:"{69979850-797A-11D9-BED3-505054503030}" /success:enable /failure:enable
sc.exe create IPBAN type= own start= delayed-auto binPath= c:/ipban/DigitalRuby.IPBan.exe DisplayName= "IPBan Service"
sc.exe description IPBAN "Automatically builds firewall rules for abusive login attempts: https://github.com/DigitalRuby/IPBan"
sc.exe failure IPBAN reset= 9999 actions= "restart/60000/restart/60000/restart/60000"
sc.exe start IPBAN
