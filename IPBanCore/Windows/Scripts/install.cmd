REM Make sure to extract service files to c:/ipban first!
sc.exe create IPBAN type= own start= delayed-auto binPath= c:/ipban/DigitalRuby.IPBan.exe DisplayName= "IPBan Service"
sc.exe description IPBAN "Automatically builds firewall rules for abusive login attempts: https://github.com/DigitalRuby/IPBan"
sc.exe start IPBAN
