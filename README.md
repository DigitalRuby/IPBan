IPBan Service
-----
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

**Requirements**
- IPBan requires .NET core 2.2 SDK and Visual Studio 2017 or newer to build from source. You can build a self contained executable to eliminate the need for dotnet core on the server machine, or just download the precompiled binaries.
- Supported platforms: Windows (x86, x64), Linux (x64).
- Mac OS X not officially supported at this time, but you can try your luck it should work in theory.

**Instructions**

- Official download link is http://www.digitalruby.com/download/ipban-software-download/ or https://github.com/jjxtra/IPBan/releases.
- Make sure to look at the config file for configuration options, each are documented with comments.
- Here is a regex that matches any 32 bit ip address, useful if you need to add a new block option in the config file: 

```
(?<ipaddress>^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$)
```

**Windows**
- For Windows, IPBan is supported on Windows Server 2008 or equivalent or newer. Windows XP and Server 2003 are NOT supported.
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
sc create IPBAN type= own start= auto binPath= c:\path\to\service\IPBan.exe DisplayName= IPBAN
sc description IPBAN "Automatically builds firewall rules for abusive login attempts: https://github.com/DigitalRuby/IPBan"
```
The service needs file system, event viewer and firewall access, so please run as SYSTEM to ensure permissions.  Running "sc" as described above in an elevated command prompt will install the service using the local SYSTEM account.
- To run as a console app, simply run IPBan.exe and watch console output.
- If you want to run and debug code in Visual Studio, make sure to run Visual Studio as administrator. Visual Studio 2017 or newer is required, along with .net core 2.1.1. Community edition is free.
- On some Windows versions, NLA will default to on. This will lock you out of remote desktop, so make sure to turn this option off. 
 
**Linux**

- IPBan is currently supported on ubuntu 16.X - 18.X. For other Linux or MAC, you may need to adjust some of the instructions and add config file entries for the appropriate log files to parse.
- SSH into your server as root. If using another admin account name, substitute all root user instances with your account name.
- Install dependencies:
```
sudo apt-get install iptables
sudo apt-get install ipset
sudo apt-get install vsftpd
sudo apt-get update
```
- mkdir /root/IPBan
- Extract the IPBan.zip file (inside is IPBanLinux.zip) folder and use ftp to copy files to /root/IPBan
- chmod +x ./root/IPBan/IPBan (makes sure the IPBan executable has execute permissions)
- Create service:
```
sudo nano /lib/systemd/system/IPBan.service
```
- Paste in these contents:
```
[Unit]
Description=IPBan Service
After=network.target

[Service]
ExecStart=/root/IPBan/IPBan
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
- Save service file (Ctrl-X)
- Start the service:
```
sudo systemctl daemon-reload 
sudo systemctl enable IPBan
sudo systemctl start IPBan
systemctl status IPBan
```

**About Me**

I'm Jeff Johnson and I created IPBan to block hackers out because Windows (and Linux quite frankly) does a horrible job of this by default and performance suffers as hackers try to breach your remote desktop or SSH. IPBan gets them in the block rule of the firewall where they belong.

Please visit http://www.digitalruby.com/securing-your-windows-dedicated-server/ for more information about this program.

I do consulting and contracting if you need extra customizations for this software.

Donations are accepted, any amount is appreciated, I work on this project for free to benefit the world.

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

Jeff Johnson, CEO/CTO  
Digital Ruby, LLC  
http://www.digitalruby.com  
support@digitalruby.com


