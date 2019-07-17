sc create IpBan type= own start= auto binPath= %~dp0DigitalRuby.IPBan.exe DisplayName= "IP Ban Service"
sc config IPBan depend= EventLog