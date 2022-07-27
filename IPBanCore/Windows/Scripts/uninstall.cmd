sc.exe stop IPBAN
sc.exe delete IPBAN
if not exist "C:\ipban" mkdir "C:\ipban"
if not exist "C:\Program Files\IPBan" mkdir "C:\Program Files\IPBan"
rmdir /s /q c:\ipban
rmdir /s /q "C:\Program Files\IPBan"
