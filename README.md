Windows IPBan Service
-----
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

**Instructions**

- Ensure .NET framework 4.5 or newer is installed. Then extract the .zip file download to a place on your computer. Right click on all the extracted files and select properties. Make sure to select "unblock" if the option is available.
- You *MUST* make this change to the local security policy to ensure ip addresses show up: 
Change Local Security Policy -> Local Policies -> Audit Policy and turn failure logging on for "audit account logon events" and "audit logon events".
From an admin command prompt: auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
- To run as a Windows service run "sc create IPBAN type= own start= auto binPath= c:\path\to\service\ipban.exe DisplayName= IPBAN". The service needs file system, event viewer and firewall access, so please run as SYSTEM to ensure permissions.
- Make sure to look at the config file for configuration options.
- To run as a console app, simply run IPBAN.EXE and watch console output.
- If you want to run and debug code in Visual Studio, make sure to run Visual Studio as administrator. Visual Studio 2017 or newer is required. Community edition is free.
- Here is a regex that matches any 32 bit ip address, useful if you need to add a new block option in the config file: 
(?<ipaddress>^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$)

**About Me**

I'm Jeff Johnson and I created IPBan to block hackers out because Windows does a horrible job of this by default and performance suffers as hackers try to breach your remote desktop. IPBan gets them in the block rule of the firewall where they belong.

Please visit http://www.digitalruby.com/securing-your-windows-dedicated-server/ for more information about this program.

I do consulting and contracting if you need extra customizations for this software.

Donations are accepted, any amount is appreciated, I work on this project for free to benefit the world.

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

Jeff Johnson, CEO/CTO  
Digital Ruby, LLC  
http://www.digitalruby.com  
support@digitalruby.com


