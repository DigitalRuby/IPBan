<p>Domino is a web server provided by IBM.</p>
<p>Example log file paths are:</p>

```
C:/Domino-LOG/**/*.log
C:/Program Files/IBM/Domino/data/IBM_TECHNICAL_SUPPORT/**/*.log
```

Example failed login regex:

```
^((?<date>.*?(?:AM|PM))\s*(?:SMTP\sServer:\sAuthentication\sfailed\sfor\suser\s(?<username>[^;]+?)\s*;.*?(?<ipaddress>\d{1.3}\.\d{1.3}\. \d{1,3}\.\d{1,3})$)|(TLS\/SSL\s+connection\s*(?<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[(]\d+[)]\s*[-][>]\s*\d{1,3}\.\d{1,3}\. \d{1,3}\.\d{1,3}[(]\d+[)]\s*failed\swith.*$)|(SMTP\sServer\s*[[][^\]]*[\]]\sConnection\sfrom\s[[](?<ipaddress>\d{1,3}\.\d{1,3}\. \d{1,3}\.\d{1,3})[\]]\srejected\sfor\spolicy\sreasons.*?$))|((?<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?HTTP\/1\.1["]\s401.*$))
```

You have to configure the Domino server to write the Domlog ( what the weblog is HTTP / HTTPS ) also in a text file and name the location. The other logfile is the so-called console log of Domino and this is written by default in the IBM Tech directory.
Also you can / must configure Domino to select what is logged in the console to fit the regex.

Example Domino logs:

```
console.log:

09/09/2020 01:37:38 AM  SMTP Server [1D44:0658-0C6C] Connection from [xxx.xxx.xxx.xxx] rejected for policy reasons. IP address of connecting host not found in reverse DNS lookup.
09/09/2020 01:37:39 AM  SMTP Server: Authentication failed for user nologin ; connecting host xxx.xxx.xxx.xxx
09/09/2020 03:09:39 PM  SMTP Server: Authentication failed for user selling@your.domain.com ; connecting host xxx.xxx.xxx.xxx
09/09/2020 06:05:17 AM  TLS/SSL connection xxx.xxx.xxx.xxx(32318) -> 127.0.0.1(443) failed with rejected SSLv3 connection
09/09/2020 06:05:48 AM  TLS/SSL connection xxx.xxx.xxx.xxx(36376) -> 127.0.0.1(443) failed with no supported ciphers

Domlog:

xxx.xxx.xxx.xxx your.domain.com "Karl Killer" [15/Sep/2020:14:28:30 +0000] "GET /log.nsf HTTP/1.1" 401 184 "" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0" 0 "" "C:/Program Files/IBM/Domino/data/log.nsf"
```

Thanks to `Uwe Sartorius` for the domino integration guide!
