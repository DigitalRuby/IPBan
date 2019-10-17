IPBan Service
-----
[![Build Status](https://dev.azure.com/DigitalRuby/DigitalRuby/_apis/build/status/DigitalRuby_IPBan?branchName=master)](https://dev.azure.com/DigitalRuby/DigitalRuby/_build/latest?definitionId=4&branchName=master)

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

<a href="https://email.digitalruby.com/SubscribeInitial/IPBan">Sign up for the IPBan Mailing List</a>

Please visit <a href='https://ipban.com'>https://ipban.com</a> to learn about IPBan Pro, the best way to secure your Windows and Linux servers from botnets, brute force attacks and hackers.

You can also visit the ipban discord at https://discord.gg/sHCUHH3 to chat with me or other IPBan users.

**Requirements**
- IPBan requires .NET core 3.0 SDK to build and debug code. For an IDE, I suggest Visual Studio Community 2019 for Windows, or VS code for Linux. All are free. You can build a self contained executable to eliminate the need for dotnet core on the server machine, or just download the precompiled binaries.
- Running and/or debugging code requires that you run your IDE or terminal as administrator or root.
- Officially supported platforms: Windows 8.1 or newer (x86, x64), Windows Server 2012 or newer (x86, x64), Linux Ubuntu 16.04+ or equivelant (x64). Windows Server 2008 will work with some tweaks, but it is basically at end of life, so no longer officially supported.
- Mac OS X not supported at this time.

**Features**
- Auto ban ip addresses on Windows and Linux by detecting failed logins from event viewer and/or log files. On Linux, SSH is watched by default. On Windows, RDP, OpenSSH, VNC, MySQL, SQL Server and Exchange are watched. More applications can easily be added via config file.
- Highly configurable, many options to determine failed login count threshold, time to ban, etc.
- Make sure to check out the DigitalRuby.IPBan.dll.config file (in the IPBanCore project) for configuration options, each option is documented with comments.
- Banning happens basically instantly for event viewer. For log files, you can set how often it polls for changes.
- Very fast - I've optimized and tuned this code since 2012. The bottleneck is pretty much always the firewall implementation, not this code.
- Unban ip addresses easily by placing an unban.txt file into the service folder with each ip address on a line to unban.
- Works with ipv4 and ipv6 on all platforms.
- Please visit the wiki at https://github.com/DigitalRuby/IPBan/wiki for lots more documentation.

**Download**

- Official download link is: https://github.com/DigitalRuby/IPBan/releases
- Legacy download link: https://www.digitalruby.com/download/ipban-software-download/.

Install
------

Please note that for IPBan Pro, you can find install instructions at https://ipban.com/Docs/Install. These install instructions are for the free IPBan version.

**Windows**
- For Windows, IPBan is supported on Windows Server 2012 or equivalent or newer. Windows Server 2008 does a poor job of logging ip addresses and is end of life. Windows XP and Server 2003 are NOT supported.
- Extract the IPBan.zip (inside is IPBanWindows.zip) file to a place on your computer. Right click on all the extracted files and select properties. Make sure to select "unblock" if the option is available.  You can use the [Unblock-File](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-6) utility with an **elevated** PowerShell to unblock all files in the IPBan directory:
```
dir C:\path\to\ipban | Unblock-File
```
- You *MUST* make this change to the local security policy to ensure ip addresses show up: 
Change Local Security Policy -> Local Policies -> Audit Policy and turn failure logging on for "audit account logon events" and "audit logon events".
From an admin command prompt:

```
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
```

- It is highly recommended to disable NTLM logins and only allow NTLM2 logins. Use secpol -> local policies -> security options -> network security restrict ntlm incoming ntlm traffic -> deny all accounts.
- To install as a Windows service use the [sc command](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) and run the following in an elevated command window:
```
sc.exe create IPBAN type= own start= delayed-auto binPath= c:\path\to\service\DigitalRuby.IPBan.exe DisplayName= IPBAN
sc.exe description IPBAN "Automatically builds firewall rules for abusive login attempts: https://github.com/DigitalRuby/IPBan"
sc.exe start IPBAN
```
or with Powershell use the command [New-Service](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-service) and run the following in an elevated powershell window:
```powershell
New-Service -Name "IPBAN" -BinaryPathName "c:\path\to\service\DigitalRuby.IPBan.exe" -StartupType automatic -DisplayName "IPBAN" -Description "Automatically builds firewall rules for abusive login attempts: https://github.com/DigitalRuby/IPBan"
Get-WmiObject win32_service -Filter "name='IPBAN'"
Start-Service IPBAN
sc.exe config IPBAN start= delayed-auto
```
- On Windows, the service MUST be set to start as delayed automatic, otherwise the service will crash upon machine reboot.
- The service needs file system, event viewer and firewall access, so running as a privileged account is required.
- To run as a console app, simply run DigitalRuby.IPBan.exe and watch console output.
- On some Windows versions, NLA will default to on. This may lock you out of remote desktop, so turn this option off if needed.
- NLA is not supported with IPBan on Windows Server 2012 or older. You must use Windows Server 2016 or newer if you want NLA. Failed logins do not log properly with NLA on the older Windows editions, regardless of any settings, registry or group policy changes.
- On Windows Small Business Server 2011 (and probably earlier) and Windows Server running Exchange, with installed PowerShell v.2 that does not know Unblock-File command, and newer version can’t be installed (as some scripts for managing OWA stop working correctly). Easier way is to manually unblock downloaded ZIP file and then unzip content.
- On Windows Server running Exchange, it is impossible to disable NTLM (deny all clients in Security restrict ntlm incoming ntlm traffic) as then Outlook on client computers permanently asks users for entering username and password. To workaround this, set LAN Manager authenticating level in Security Optins of Local Policies to "Send NTLMv2 response only. Refuse LM & NTLM". There is one small issue – when somebody tries to login with an undefined username, the log does not contain an IP address. Not sure why Microsoft can't log an ip address properly.
- If using Exchange, disabling app pool 'MSExchangeServicesAppPool' can eliminate quite a lot of problems in the event viewer with ip addresses not being logged.

**Linux**

- Build and run and debug code with Visual Studio code
	- This shell script runs vscode as root:
	- `sudo mount -t vboxsf ipban ~/Desktop/ipban` # only needed if you are in a Virtual Box VM and have setup a shared folder to Windows
	- `sudo code --user-data-dir="/tmp/vscode-root"`
- IPBan is currently supported on Ubuntu 16.04 or newer and Debian 9 or newer. IPSet and IPTables are required and installed automatically if needed.
- Easy one click install:
```
sudo -i; bash <(wget -qO- https://raw.githubusercontent.com/DigitalRuby/IPBan/master/Linux/Scripts/Install.sh)
```
- Change config file as desired, changes will be picked up automatically, press Ctrl-X to save.

Other Information
------

**Analytics**

To disable anonymously sending banned ip addresses to the global ipban database, set UseDefaultBannedIPAddressHandler to false in the config file.

**About Me**

I'm Jeff Johnson and I created IPBan to block hackers out because Windows (and Linux quite frankly) does a horrible job of this by default and performance suffers as hackers try to breach your remote desktop, SSH, SMTP, etc. IPBan gets them in the block rule of the firewall where they belong.

Please visit <a href='https://ipban.com'>https://ipban.com</a> for additional updates, news, additional software and more.

I do consulting and contracting if you need extra customizations for this software.

Donations are accepted, any amount is appreciated, I work on this project for free to benefit the world.

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

Jeff Johnson, CEO/CTO  
Digital Ruby, LLC  
https://www.digitalruby.com  
support@digitalruby.com


