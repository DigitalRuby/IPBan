IPBan Service
-----
[![Build Status](https://dev.azure.com/DigitalRuby/DigitalRuby/_apis/build/status/DigitalRuby_IPBan?branchName=master)](https://dev.azure.com/DigitalRuby/DigitalRuby/_build/latest?definitionId=4&branchName=master)

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

<a href="https://email.digitalruby.com/SubscribeInitial/IPBan">Sign up for the IPBan Mailing List</a>

Please visit <a href='https://ipban.com'>https://ipban.com</a> to learn about IPBan Pro, the best way to secure your Windows and Linux servers from botnets, brute force attacks and hackers.

**Requirements**
- IPBan requires .NET core 2.2 SDK to build and debug code. For an IDE, I suggest Visual Studio Community 2017 (2019+ recommended) for Windows or MAC, or VS code for Linux. All are free. You can build a self contained executable to eliminate the need for dotnet core on the server machine, or just download the precompiled binaries.
- Running and/or debugging code requires that you run your IDE or terminal as administrator or root.
- Officially supported platforms: Windows 8.1 or newer (x86, x64), Windows Server 2008 or newer (x86, x64), Linux Ubuntu 16.04+ or equivelant (x64).
- Mac OS X not supported at this time.

**Features**
- Auto ban ip addresses on Windows and Linux by detecting failed logins from event viewer and/or log files (SSH, FTP, SMTP, etc.)
- Highly configurable, many options to determine failed login count threshold, time to ban, etc.
- Make sure to check out the DigitalRuby.IPBan.dll.config file for configuration options, each option is documented with comments.
- Banning happens basically instantly for event viewer. For log files, you can set how often it polls for changes.
- Very fast - I've optimized and tuned this code since 2012. The bottleneck is pretty much always the firewall implementation, not this code.
- Unban ip addresses easily by placing an unban.txt file into the service folder with each ip address on a line to unban.
- See the app.config file for a complete list of options, each property is well documented. There are lots of them.
- Works with ipv4 and ipv6 on all platforms.

**Download**

- Official download link is: https://github.com/DigitalRuby/IPBan/releases
- Legacy download link: https://www.digitalruby.com/download/ipban-software-download/.

**Windows**
- For Windows, IPBan is supported on Windows Server 2008 or equivalent or newer (Server 2012+ recommended). Windows Server 2008 does a poor job of logging ip addresses. Windows XP and Server 2003 are NOT supported.
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

- For Windows Server 2008 or equivalent, you should disable NTLM logins and only allow NTLM2 logins. On Windows Server 2008, there is no way to get the ip address of NTLM logins. Use secpol -> local policies -> security options -> network security restrict ntlm incoming ntlm traffic -> deny all accounts.
- To install as a Windows service use the [sc command](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) and run the following in an elevated command window:
```
sc create IPBAN type= own start= delayed-auto binPath= c:\path\to\service\DigitalRuby.IPBan.exe DisplayName= IPBAN
sc description IPBAN "Automatically builds firewall rules for abusive login attempts: https://github.com/DigitalRuby/IPBan"
sc start IPBAN
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
- On Windows Small Business Server 2011 (and probably earlier) and Windows Server running Exchange, with installed PowerShell v.2 that does not know Unblock-File command, and newer version can’t be installed (as some scripts for managing OWA stop working correctly). Easier way is to manually unblock downloaded ZIP file and then unzip content.
- On Windows Server running Exchange, it is impossible to disable NTLM (deny all clients in Security restrict ntlm incoming ntlm traffic) as then Outlook on client computers permanently asks users for entering username and password. To workaround this, set LAN Manager authenticating level in Security Optins of Local Policies to "Send NTLMv2 response only. Refuse LM & NTLM". There is one small issue – when somebody tries to login with an undefined username, the log does not contain an IP address. Not sure why Microsoft can't log an ip address properly.
- If using Exchange, disabling app pool 'MSExchangeServicesAppPool' can eliminate quite a lot of problems in the event viewer with ip addresses not being logged.

**Linux**

- Build and run and debug code with Visual Studio code
	- This shell script runs vscode as root:
	- sudo mount -t vboxsf ipban ~/Desktop/ipban # only needed if you are in a Virtual Box VM and have setup a shared folder to Windows
	- sudo code --user-data-dir="/tmp/vscode-root"
- IPBan is currently supported on all Linux that have iptables and ipset installed.
- SSH into your server as root. If using another admin account name, substitute all root user instances with your account name.
- Install dependencies:
```
sudo apt-get install iptables
sudo apt-get install ipset
sudo apt-get update
```
- mkdir /opt/ipban
- Extract the IPBan.zip file (inside is IPBanLinux.zip) folder and use SSH to copy files to /opt/ipban. Plenty of free SSH GUI out there if you want that.
- chmod +x /opt/ipban/DigitalRuby.IPBan (makes sure the DigitalRuby.IPBan executable has execute permissions)
- Create service:
```
sudo nano /lib/systemd/system/ipban.service
```
- Paste in these contents:
```
[Unit]
Description=IPBan Service
After=network.target

[Service]
ExecStart=/opt/ipban/DigitalRuby.IPBan
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
- Save service file (Ctrl-X)
- Start the service:
```
sudo systemctl daemon-reload 
sudo systemctl start ipban
sudo systemctl enable ipban
systemctl status ipban
```

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


