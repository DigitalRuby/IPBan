Windows IPBan Service
-----
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

Extract files to a place on your computer. Right click on all the extracted files and select properties. Make sure to select "unblock" if the option is available.

To run as a Windows service run "sc create IPBAN type= own start= auto binPath= c:\path\to\service\ipban.exe DisplayName= IPBAN". The service writes a log file to the same directory as the service, so run as SYSTEM to ensure permissions.

Make sure to look at the config file for configuration options.

To debug as a console app, simply run IPBAN.EXE and watch console output.

Make sure you are logging failed login attempts via local security policy / audit policy.

You *MUST* make this change to the local security policy to ensure ip addresses show up: 
Change Local Security Policy -> Local Policies -> Audit Policy and turn failure logging on for "audit account logon events" and "audit logon events".
From an admin command prompt: auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable

If you still don't see ip addresses being logged, do the following:

- Make sure to read this stackoverflow thread about ip addresses not getting logged: http://stackoverflow.com/questions/1734635/event-logging-ipaddress-does-not-always-resolve
- Network security: LAN Manager authentication level -- Send NTLMv2 response only. Refuse LM & NTLM
- Network security: Restrict NTLM: Audit Incoming NTLM Traffic -- Enable auditing for all accounts
- Network security: Restrict NTLM: Incoming NTLM traffic -- Allow all accounts
- Do not allow for passwords to be saved -- Enabled
- Prompt for credentials on the client computer -- Enabled

If you want to run in Visual Studio, make sure to run Visual Studio as administrator.

For reference, here is a regex that matches any 32 bit ip address:
(?<ipaddress>^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$)

Please visit http://www.digitalruby.com/securing-your-windows-dedicated-server/ for more information about this program.

I do consulting and contracting if you need extra customizations for this software.

Enjoy!

Donations are accepted, any amount is appreciated, I work on this project for free to benefit the world.

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7EJ3K33SRLU9E)

-Jeff Johnson, CEO/CTO Digital Ruby, LLC
http://www.digitalruby.com
email: support@digitalruby.com

