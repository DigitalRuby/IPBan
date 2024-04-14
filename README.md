# IPBan - Free software to block out attackers quickly and easily on Linux and Windows

[![Github Sponsorship](.github/github_sponsor_btn.svg)](https://github.com/sponsors/jjxtra)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)
[![Build Status](https://dev.azure.com/DigitalRuby/DigitalRuby/_apis/build/status/DigitalRuby_IPBan?branchName=master)](https://dev.azure.com/DigitalRuby/DigitalRuby/_build/latest?definitionId=4&branchName=master)

## Helpful Links

- Get a discount on IPBan Pro by visiting <a href='https://ipban.com/upgrade-to-ipban-pro/'>https://ipban.com/upgrade-to-ipban-pro/</a>.
- <a href='https://ipthreat.net/integrations/ipban'>Integrate IPBan with IPThreat</a>, a 100% free to use website and service of community submitted bad ip addresses.  Help make the Internet safer and join hundreds of other like minded users.
- You can also visit the ipban discord at https://discord.gg/GRmbCcKFNR to chat with other IPBan users.
- <a href="https://ipban.com/newsletter">Sign up for the IPBan Mailing List</a>

## Requirements

- IPBan free version requires .NET 6 SDK to build and debug code. For an IDE, I suggest Visual Studio Community for Windows, or VS code for Linux. All are free. You can build a self contained executable to eliminate the need for dotnet core on the server machine, or just download the precompiled binaries in releases.
- Running and/or debugging code requires that you run your IDE or terminal as administrator or root.
- Officially supported platforms:
	- Windows 8.1 or newer (x86, x64)
	- Windows Server 2016 or newer (x86, x64)
	- Linux Ubuntu x64 (requires firewalld)
	- Linux Debian x64 (requires firewalld)
	- Linux CentOS x64 (requires firewalld)
	- Linux RedHat x64 (requires firewalld)
	- Mac OS X not supported at this time

## Features

- Auto ban ip addresses by detecting failed logins from event viewer and/or log files. On Linux, SSH is watched by default. On Windows, RDP, OpenSSH, VNC, MySQL, SQL Server, Exchange, SmarterMail, MailEnable are watched. More applications can easily be added via config file.
- Additional recipes for event viewer and log files are here: https://github.com/DigitalRuby/IPBan/tree/master/Recipes
- Highly configurable, many options to determine failed login count threshold, time to ban, etc.
- Make sure to check out the ipban.config file (formerly named DigitalRuby.IPBan.dll.config, see IPBanCore project) for configuration options, each option is documented with comments.
- Banning happens basically instantly for event viewer. For log files, you can set how often it polls for changes.
- Very fast - I've optimized and tuned this code since 2012. The bottleneck is pretty much always the firewall implementation, not this code.
- Unban ip addresses easily by placing an unban.txt file into the service folder with each ip address on a line to unban.
- Works with ipv4 and ipv6 on all platforms.
- Please visit the wiki at https://github.com/DigitalRuby/IPBan/wiki for lots more documentation.

 ## Download

- Official download link is: https://github.com/DigitalRuby/IPBan/releases

## Install

Please note that for IPBan Pro, you can find install instructions at https://ipban.com/ipban-pro-install-instructions/. These install instructions here on github are for the free IPBan version.

### **Windows**

- IPBan is supported on Windows Server 2016 and Windows 10, or newer.
- Fail2Ban but for Windows!
- Easy one click install, open admin powershell and run:
```
$ProgressPreference = 'SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DigitalRuby/IPBan/master/IPBanCore/Windows/Scripts/install_latest.ps1'))
```
Note: Powershell 5.1 or greater is required.

***Additional Windows Notes***
- Windows Server 2012 is no longer supported as of October 2023. Please upgrade to a different operating system that is actually supported by Microsoft.
- Please ensure your server and clients are patched before making the above change: https://support.microsoft.com/en-us/help/4093492/credssp-updates-for-cve-2018-0886-march-13-2018. You need to manually edit group policy as specified in the link.
![](IPBan/img/WindowsCredSSP.png)
- On Windows Server running Exchange, it is impossible to disable NTLM (deny all clients in Security restrict ntlm incoming ntlm traffic) as then Outlook on client computers permanently asks users for entering username and password. To workaround this, set LAN Manager authenticating level in Security Options of Local Policies to "Send NTLMv2 response only. Refuse LM & NTLM". There is one small issue – when somebody tries to login with an undefined username, the log does not contain an IP address. Not sure why Microsoft can't log an ip address properly.
- If using Exchange, disabling app pool 'MSExchangeServicesAppPool' can eliminate quite a lot of problems in the event viewer with ip addresses not being logged.
- Uninstaller: https://github.com/DigitalRuby/IPBan/blob/master/IPBanCore/Windows/Scripts/uninstall.cmd

### Linux

Easy one click install:
```
sudo -i; bash <(wget -qO- https://raw.githubusercontent.com/DigitalRuby/IPBan/master/IPBanCore/Linux/Scripts/Install.sh)
```

Uninstall: `sudo systemctl stop ipban; sudo systemctl disable ipban; sudo rm /opt/ipban -r`

## Other Information

<a href="https://ipban.com/newsletter">Sign up for the IPBan Mailing List</a>

## Upgrade

Get a discount on IPBan Pro by visiting <a href='https://ipban.com/upgrade-to-ipban-pro/'>https://ipban.com/upgrade-to-ipban-pro/</a>.

## Other Services

<a href='https://ipthreat.net/integrations/ipban'>Integrate IPBan with IPThreat</a>, a 100% free to use website and service. Unlike some other sites and services that use community contributed data, IPThreat does not charge subscription fees.

## Analytics

To disable anonymously sending banned ip addresses to the global ipban database, set UseDefaultBannedIPAddressHandler to false in the config file.

## Dontations

If the free IPBan has helped you and you feel so inclined, please consider donating...

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

Jeff Johnson, CEO/CTO  
Digital Ruby, LLC  
https://www.digitalruby.com  
support@digitalruby.com


