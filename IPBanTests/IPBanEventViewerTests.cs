/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://www.digitalruby.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanEventViewerTests : IIPBanDelegate
    {
        private readonly Dictionary<string, int> successEvents = new();

        private IPBanService service;

        [SetUp]
        public void Setup()
        {
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            service.IPBanDelegate = this;
            service.Firewall.Truncate();
        }

        [TearDown]
        public void TearDown()
        {
            IPBanService.DisposeIPBanTestService(service);
            successEvents.Clear();
        }

        /*
        private void TestRemoteDesktopAttemptWithIPAddress(string ipAddress, int count)
        {
            string xml = string.Format(@"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>{0}</Data><Data Name='IpPort'>52813</Data></EventData></Event>", ipAddress);

            while (count-- > 0)
            {
                service.EventViewer.ProcessEventViewerXml(xml);
            }
        }
        */

        [Test]
        public void TestEventViewer()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return;
            }

            // event viewer xml and expected ipaddress,username,source,[0 = failed login, 1 = successful login]
            // value can be "x" if parse fail
            var xmlTestStrings = new KeyValuePair<string, string>[]
            {
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}'/><EventID>140</EventID><Version>0</Version><Level>3</Level><Task>4</Task><Opcode>14</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2020-05-30T21:35:42.077609500Z'/><EventRecordID>3230629</EventRecordID><Correlation ActivityID='{F4201097-CCED-4F8B-BC9A-6E34FC360000}'/><Execution ProcessID='2084' ThreadID='6188'/><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>my.domain.com</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='IPString'>212.92.107.115</Data></EventData><RenderingInfo Culture='en-US'><Message>A connection from the client computer with an IP address of 212.92.107.115 failed because the user name or password is not correct.</Message><Level>Warning</Level><Task>RemoteFX module</Task><Opcode>ProtocolExchange</Opcode><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Provider></Provider><Keywords></Keywords></RenderingInfo></Event>",
                    "212.92.107.115,,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2021-04-07T15:59:41.8109921Z' /><EventRecordID>13384143</EventRecordID><Correlation ActivityID='{1be9c669-2b89-0002-9ac6-e91b892bd701}' /><Execution ProcessID='888' ThreadID='9132' /><Channel>Security</Channel><Computer>BF-mymedia</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>administrator</Data><Data Name='TargetDomainName'></Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>-</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>41.42.43.44</Data><Data Name='IpPort'>0</Data></EventData></Event>",
                    "41.42.43.44,administrator,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4653</EventID><Version>0</Version><Level>0</Level><Task>12547</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2020-07-10T17:20:06.687103300Z' /><EventRecordID>100095994</EventRecordID><Correlation ActivityID='{5108737F-4EB9-0001-8473-0851B94ED601}' /><Execution ProcessID='660' ThreadID='124' /><Channel>Security</Channel><Computer>MYVPN.MYCPU</Computer><Security /></System><EventData><Data Name='LocalMMPrincipalName'>-</Data><Data Name='RemoteMMPrincipalName'>-</Data><Data Name='LocalAddress'>88.88.88.81</Data><Data Name='LocalKeyModPort'>4500</Data><Data Name='RemoteAddress'>88.88.88.82</Data><Data Name='RemoteKeyModPort'>4500</Data><Data Name='KeyModName'>%%8222</Data><Data Name='FailurePoint'>%%8199</Data><Data Name='FailureReason'>Negotiation timed out</Data><Data Name='MMAuthMethod'>%%8194</Data><Data Name='State'>%%8202</Data><Data Name='Role'>%%8205</Data><Data Name='MMImpersonationState'>%%8217</Data><Data Name='MMFilterID'>54919761</Data><Data Name='InitiatorCookie'>db55d3767e51b422</Data><Data Name='ResponderCookie'>0000000000000000</Data></EventData></Event>",
                    "88.88.88.82,,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='VisualSVN Server 3.9' /><EventID Qualifiers='0'>1004</EventID><Level>2</Level><Task>2</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2020-04-12T19:52:33.000000000Z' /><EventRecordID>134854</EventRecordID><Channel>VisualSVNServer</Channel><Computer>server.domain-net.com</Computer><Security /></System><EventData><Data>user root: (OS 1326) Der Benutzername oder das Kennwort ist falsch.</Data><Data>123.123.123.124</Data></EventData></Event>",
                    "123.123.123.124,root,SVN,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='RemoteAccess' /><EventID Qualifiers='0'>20271</EventID><Level>3</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2020-03-06T11:47:14.000000000Z' /><EventRecordID>440917</EventRecordID><Channel>System</Channel><Computer>server.domain-net.com</Computer><Security /></System><EventData><Data>{NA}</Data><Data>Admin</Data><Data>123.123.123.123</Data><Data>Die Remoteverbindung wurde verweigert, weil die angegebene Kombination aus Benutzername und Kennwort nicht erkannt wird oder das ausgewählte Authentifizierungsprotokoll nicht für den RAS-Server zulässig ist.</Data><Data>0x10</Data><Binary>B3020000</Binary></EventData></Event>",
                    "123.123.123.123,Admin,RRAS,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='RemoteAccess' /><EventID Qualifiers='0'>20271</EventID><Level>3</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2020-03-23T19:40:08.225301000Z' /><EventRecordID>32407</EventRecordID><Channel>System</Channel><Computer>MYCOMPUTER.MYDOMAIN.local</Computer><Security /></System><EventData><Data>{NA}</Data><Data>corinne</Data><Data>11.12.13.15</Data><Data>The remote connection was denied because the user name and password combination you provided is not recognized, or the selected authentication protocol is not permitted on the remote access server.</Data><Data>0x10</Data><Binary>B3020000</Binary></EventData></Event>",
                    "11.12.13.15,corinne,RRAS,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>6272</EventID><Version>1</Version><Level>0</Level><Task>12552</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2019-12-13T19:48:39.420098200Z' /><EventRecordID>276341076</EventRecordID><Correlation /><Execution ProcessID='616' ThreadID='3956' /><Channel>Security</Channel><Computer>MYSUBDOMAIN.MYDOMAIN.local</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-2216450734-2288107589-99135520-4696</Data><Data Name='SubjectUserName'>mydomain\username</Data><Data Name='SubjectDomainName'>L1S</Data><Data Name='FullyQualifiedSubjectUserName'>MYSUBDOMAIN.MYDOMAIN.local/username</Data><Data Name='SubjectMachineSID'>S-1-0-0</Data><Data Name='SubjectMachineName'>-</Data><Data Name='FullyQualifiedSubjectMachineName'>-</Data><Data Name='MachineInventory'>-</Data><Data Name='CalledStationID'>192.168.21.49</Data><Data Name='CallingStationID'>98.196.175.165</Data><Data Name='NASIPv4Address'>192.168.21.49</Data><Data Name='NASIPv6Address'>-</Data><Data Name='NASIdentifier'>nasid</Data><Data Name='NASPortType'>Virtual</Data><Data Name='NASPort'>7</Data><Data Name='ClientName'>clientname</Data><Data Name='ClientIPAddress'>192.168.21.49</Data><Data Name='ProxyPolicyName'>Microsoft Routing and Remote Access Service Policy</Data><Data Name='NetworkPolicyName'>PolicyCorp</Data><Data Name='AuthenticationProvider'>Windows</Data><Data Name='AuthenticationServer'>MYSUBDOMAIN.MYDOMAIN.local</Data><Data Name='AuthenticationType'>EAP</Data><Data Name='EAPType'>Microsoft: Secured password (EAP-MSCHAP v2)</Data><Data Name='AccountSessionIdentifier'>353238</Data><Data Name='QuarantineState'>Full Access</Data><Data Name='QuarantineSessionIdentifier'>-</Data><Data Name='LoggingResult'>Accounting information was written to the local log file.</Data></EventData></Event>",
                    "98.196.175.165,username,RRAS,1"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQL$SERVER' /><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2020-04-16T13:56:01.660102100Z' /><EventRecordID>24234250</EventRecordID><Channel>Application</Channel><Computer>CPU1</Computer><Security /></System><EventData><Data>sa</Data><Data>Reason: Failed to open the explicitly specified database 'db'.</Data><Data>[CLIENT: 173.10.24.145]</Data><Binary>184800000E00000015000000430065006E0050006F0069006E00740056004D0031005C00430045004E0050004F0049004E0054000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "x"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2020-03-04T20:58:52.555949300Z'/><EventRecordID>38600046</EventRecordID><Correlation ActivityID='{75ECDDC3-EDB3-0003-CBDD-EC75B3EDD501}'/><Execution ProcessID='696' ThreadID='4092'/><Channel>Security</Channel><Computer>MYCOMPUTER</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>administrator</Data><Data Name='TargetDomainName'></Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>-</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>33.32.31.30</Data><Data Name='IpPort'>51292</Data></EventData></Event>",
                    "33.32.31.30,administrator,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2020-04-05T19:12:41.597844900Z' /><EventRecordID>295694367</EventRecordID><Correlation ActivityID='{9EF3A62A-06BB-0005-46A6-F39EBB06D601}' /><Execution ProcessID='728' ThreadID='18912' /><Channel>Security</Channel><Computer>srv-xch03.example.com</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SRV-XCH03$</Data><Data Name='SubjectDomainName'>EXAMPLE</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>testuser</Data><Data Name='TargetDomainName'>example.com</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>8</Data><Data Name='LogonProcessName'>Advapi</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>SRV-XCH03</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x23b0</Data><Data Name='ProcessName'>C:\Windows\System32\inetsrv\w3wp.exe</Data><Data Name='IpAddress'>21.25.29.33</Data><Data Name='IpPort'>1765</Data></EventData></Event>",
                    "21.25.29.33,testuser,IIS,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQL$INSTANCENAME' /><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2020-03-04T19:40:23.065120000Z' /><EventRecordID>16022222</EventRecordID><Channel>Application</Channel><Computer>MyVM1</Computer><Security /></System><EventData><Data>sa</Data><Data>Reason: Password did not match that for the login provided.</Data><Data>[CLIENT: 2.92.13.221]</Data><Binary>184800000E00000015000000430065006E0050006F0069006E00740056004D0031005C00430045004E0050004F0049004E0054000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "2.92.13.221,sa,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2020-03-04T09:54:40.262696500Z' /><EventRecordID>3588211</EventRecordID><Correlation ActivityID='{8bc80487-e7d1-0002-8a04-c88bd1e7d501}' /><Execution ProcessID='144' ThreadID='1580' /><Channel>Security</Channel><Computer>FAILED_SERVER_NAME</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>FAILED_USER_NAME</Data><Data Name='TargetDomainName'>FAILED_DOMAIN_NAME</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>FAILED_WORK_STATION_NAME</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>100.101.102.103</Data><Data Name='IpPort'>0</Data></EventData></Event>",
                    "100.101.102.103,FAILED_USER_NAME,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PostgreSQL' /><EventID Qualifiers='0'>0</EventID><Level>4</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2020-01-26T09:49:25.000000000Z' /><EventRecordID>3649448</EventRecordID><Channel>Application</Channel><Computer>COMPUTER_NAME</Computer><Security /></System><EventData><Data>2020-01-26 04:49:25 -05 LOG: conexión recibida: host=33.55.77.99 port=59368</Data></EventData></Event>",
                    "33.55.77.99,,PostgreSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2020-03-02T20:51:32.557777800Z' /><EventRecordID>278832</EventRecordID><Correlation ActivityID='{01CF6159-F0D1-0002-6361-CF01D1F0D501}' /><Execution ProcessID='656' ThreadID='3396' /><Channel>Security</Channel><Computer>Abeilles-SRV.Abeilles.local</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>ABEILLES-SRV$</Data><Data Name='SubjectDomainName'>ABEILLES</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-668249714-2975252900-182073203-500</Data><Data Name='TargetUserName'>administrateur</Data><Data Name='TargetDomainName'>ABEILLES</Data><Data Name='TargetLogonId'>0x2c83b3</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>ABEILLES-SRV</Data><Data Name='LogonGuid'>{F56C817A-B94F-73E3-E9BE-07A9AFFB8844}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x4b0</Data><Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data><Data Name='IpAddress'>74.76.76.76</Data><Data Name='IpPort'>0</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>%%1843</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event>",
                    "74.76.76.76,administrateur,RDP,1"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4624</EventID><Version>1</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2019-06-13T14:35:04.718125000Z' /><EventRecordID>14296</EventRecordID><Correlation /><Execution ProcessID='480' ThreadID='7692' /><Channel>Security</Channel><Computer>ns524406</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>CPU4406$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-549477949-4172057549-3284972235-1005</Data><Data Name='TargetUserName'>rdpuser</Data><Data Name='TargetDomainName'>CPU4406</Data><Data Name='TargetLogonId'>0x1d454067</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>CPU4406</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc38</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>44.55.66.77</Data><Data Name='IpPort'>0</Data><Data Name='ImpersonationLevel'>%%1833</Data></EventData></Event>",
                    "44.55.66.77,rdpuser,RDP,1"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER' /><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2018-07-23T05:02:39.000000000Z' /><EventRecordID>3423</EventRecordID><Channel>Application</Channel><Computer>ns524406</Computer><Security /></System><EventData><Data>sa</Data><Data>Reason: An error occurred while evaluating the password.</Data><Data>[CLIENT: 61.62.63.64]</Data><Binary>184800000E000000090000004E0053003500320034003400300036000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "61.62.63.64,sa,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}'/><EventID>139</EventID><Version>0</Version><Level>3</Level><Task>4</Task><Opcode>14</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-06-26T01:37:02.869748200Z'/><EventRecordID>42406434</EventRecordID><Correlation ActivityID='{F420C8AD-71D8-43BE-86ED-D02442380000}'/><Execution ProcessID='3660' ThreadID='243736'/><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>cpu0</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='ResultCode'>0x80090302</Data><Data Name='IPString'>185.209.0.22</Data></EventData></Event>",
                    "185.209.0.22,,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}'/><EventID>131</EventID><Version>0</Version><Level>4</Level><Task>4</Task><Opcode>15</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-06-26T01:53:56.457887700Z'/><EventRecordID>42406524</EventRecordID><Correlation ActivityID='{F420D573-5248-42DC-BCE2-CBC44FE80000}'/><Execution ProcessID='3660' ThreadID='2708'/><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>cpu1</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='ConnType'>TCP</Data><Data Name='ClientIP'>66.5.4.3:56461</Data></EventData></Event>",
                    "x"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}'/><EventID>131</EventID><Version>0</Version><Level>4</Level><Task>4</Task><Opcode>15</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-05-04T01:54:27.116318900Z'/><EventRecordID>2868163</EventRecordID><Correlation ActivityID='{F420C0F6-FAFD-4D94-B102-B3A142DF0000}'/><Execution ProcessID='1928' ThreadID='2100'/><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>KAU-HOST-03</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='ConnType'>TCP</Data><Data Name='ClientIP'>203.171.54.90:54511</Data></EventData></Event>",
                    "x"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='ASP.NET 2.0.50727.0'/><EventID Qualifiers='32768'>1309</EventID><Level>3</Level><Task>3</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2014-07-10T23:37:57.000Z'/><EventRecordID>196334166</EventRecordID><Channel>Application</Channel><Computer>SERVIDOR</Computer><Security/></System><EventData><Data>3005</Data><Data>Excepci?n no controlada.</Data><Data>11/07/2014 1:37:57</Data><Data>10/07/2014 23:37:57</Data><Data>2b4bdc4736fe40f9af42fce697b8acc7</Data><Data>9</Data><Data>7</Data><Data>0</Data><Data>/LM/W3SVC/44/ROOT-1-130495088933270000</Data><Data>Full</Data><Data>/</Data><Data>C:\Inetpub\vhosts\cbhermosilla.es\httpdocs\</Data><Data>SERVIDOR</Data><Data></Data><Data>116380</Data><Data>w3wp.exe</Data><Data>SERVIDOR\IWPD_36(cbhermosill)</Data><Data>HttpException</Data><Data>No se pueden validar datos. (le français [lə fʁɑ̃sɛ] ( listen) or la langue française [la lɑ̃ɡ fʁɑ̃sɛz])" + "\x0001" + @"汉语 / 漢語 --:" + "\x0013" + @":--汉语 / 漢語</Data><Data>http://cbhermosilla.es/ScriptResource.axd?d=sdUSoDA_p4m7C8RvW7GhwLy4-JvXN1IcbzfRDWczGaZK4pT_avDiah8wSHZqBBjyvhhqa0cQYI_FWQYwCqlPsA8BsjFn19zRsw08qPt-rkQyZ6ODPVJ_Dp7CuLQKGPn6lQd-SOyyiu0VTTAgMiLVZqD6__M1&amp;t=635057131997880000</Data><Data>/ScriptResource.axd</Data><Data>66.249.76.207</Data><Data></Data><Data>False</Data><Data></Data><Data>SERVIDOR\IWPD_36(cbhermosill)</Data><Data>7</Data><Data>SERVIDOR\IWPD_36(cbhermosill)</Data><Data>False</Data><Data>   en System.Web.Configuration.MachineKeySection.EncryptOrDecryptData(Boolean fEncrypt, Byte[] buf, Byte[] modifier, Int32 start, Int32 length, IVType ivType, Boolean useValidationSymAlgo, Boolean signData) en System.Web.Configuration.MachineKeySection.EncryptOrDecryptData(Boolean fEncrypt, Byte[] buf, Byte[] modifier, Int32 start, Int32 length, IVType ivType, Boolean useValidationSymAlgo) en System.Web.UI.Page.DecryptStringWithIV(String s, IVType ivType) en System.Web.UI.Page.DecryptString(String s)</Data></EventData></Event>",
                    "x"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>99.99.99.99</Data><Data Name='IpPort'>52813</Data></EventData></Event>",
                    "99.99.99.99,forex,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>127.0.0.1</Data><Data Name='IpPort'>52813</Data></EventData></Event>",
                    "127.0.0.1,forex,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2012-04-05T20:26:30.000000000Z'/><EventRecordID>408488</EventRecordID><Channel>Application</Channel><Computer>dallas</Computer><Security/></System><EventData><Data>sa1</Data><Data> Reason: Could not find a login matching the name provided.</Data><Data> [CLIENT: 99.99.99.100]</Data><Binary>184800000E00000007000000440041004C004C00410053000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "99.99.99.100,sa1,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER' /><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2020-06-03T18:29:05.369181500Z' /><EventRecordID>303418</EventRecordID><Channel>Application</Channel><Computer>MYDOMAIN.MYDOMAINHOST.local</Computer><Security /></System><EventData><Data>sa</Data><Data>Reason: An error occurred while evaluating the password.</Data><Data>[CLIENT: 155.155.155.155]</Data><Binary>184800000E0000000B0000004200540043004F005200440042003000310030000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "155.155.155.155,sa,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2012-04-05T20:26:30.000000000Z'/><EventRecordID>408488</EventRecordID><Channel>Application</Channel><Computer>dallas</Computer><Security/></System><EventData><Data>sa1</Data><Data> Reason: Could not find a login matching the name provided.</Data><Data> [CLIENT: 0.0.0.0]</Data><Binary>184800000E00000007000000440041004C004C00410053000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "0.0.0.0,sa1,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>99.99.99.98</Data><Data Name='IpPort'>52813</Data></EventData></Event>",
                    "99.99.99.98,forex,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>5152</EventID><Version>0</Version><Level>0</Level><Task>12809</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2013-07-23T22:33:04.141430800Z' /><EventRecordID>4892828</EventRecordID><Correlation /><Execution ProcessID='4' ThreadID='72' /><Channel>Security</Channel><Computer>MYCOMPUTER</Computer><Security /></System><EventData><Data Name='ProcessId'>0</Data><Data Name='Application'>-</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>37.140.141.29</Data><Data Name='SourcePort'>32480</Data><Data Name='DestAddress'>196.22.190.33</Data><Data Name='DestPort'>80</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>689661</Data><Data Name='LayerName'>%%14597</Data><Data Name='LayerRTID'>13</Data></EventData></Event>",
                    "37.140.141.29,,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>5152</EventID><Version>0</Version><Level>0</Level><Task>12809</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2013-07-24T11:09:21.153847400Z'/><EventRecordID>4910290</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='76'/><Channel>Security</Channel><Computer>MYCOMPUTER</Computer><Security/></System><EventData><Data Name='ProcessId'>4</Data><Data Name='Application'>System</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>82.61.45.195</Data><Data Name='SourcePort'>3079</Data><Data Name='DestAddress'>196.22.190.31</Data><Data Name='DestPort'>445</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>755725</Data><Data Name='LayerName'>%%14610</Data><Data Name='LayerRTID'>44</Data></EventData></Event>",
                    "82.61.45.195,,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12809</Task><Opcode>0</Opcode><Keywords>0x8010000000000001</Keywords><TimeCreated SystemTime='2013-07-24T11:24:51.369052700Z'/><EventRecordID>4910770</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='88'/><Channel>Security</Channel><Computer>MYCOMPUTER</Computer><Security/></System><EventData><Data Name='ProcessId'>2788</Data><Data Name='Application'>\device\harddiskvolume2\program files (x86)\rhinosoft.com\serv-u\servudaemon.exe</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>37.235.53.240</Data><Data Name='SourcePort'>39058</Data><Data Name='DestAddress'>196.22.190.31</Data><Data Name='DestPort'>21</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>780480</Data><Data Name='LayerName'>%%14610</Data><Data Name='LayerRTID'>44</Data></EventData></Event>",
                    "x"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2014-08-25T09:11:06.000000000Z'/><EventRecordID>116411121</EventRecordID><Channel>Application</Channel><Computer>s16240956</Computer><Security/></System><EventData><Data>sa</Data><Data> Raison : impossible de trouver une connexion correspondant au nom fourni.</Data><Data> [CLIENT : 218.10.17.192]</Data><Binary>184800000E0000000A0000005300310036003200340030003900350036000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "218.10.17.192,sa,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSExchangeTransport' /><EventID Qualifiers='32772'>1035</EventID><Level>3</Level><Task>1</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2015-06-08T08:13:12.000000000Z' /><EventRecordID>667364</EventRecordID><Channel>Application</Channel><Computer>DC.sicoir.local</Computer><Security /></System><EventData><Data>LogonDenied</Data><Data>Default DC</Data><Data>Ntlm</Data><Data>212.48.88.133</Data></EventData></Event>",
                    "212.48.88.133,,MSExchange,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER' /><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2015-09-10T14:20:42.000000000Z' /><EventRecordID>4439286</EventRecordID><Channel>Application</Channel><Computer>DSVR018379</Computer><Security /></System><EventData><Data>sa</Data><Data>Reason: Password did not match that for the login provided.</Data><Data>[CLIENT: 222.186.61.16]</Data><Binary>184800000E0000000B00000044005300560052003000310038003300370039000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "222.186.61.16,sa,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2017-08-09T11:06:11.486303500Z' /><EventRecordID>17925</EventRecordID><Correlation ActivityID='{A7FB7D60-01E0-0000-877D-FBA7E001D301}' /><Execution ProcessID='648' ThreadID='972' /><Channel>Security</Channel><Computer>DESKTOP-N8QJFLU</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>steven.universe</Data><Data Name='TargetDomainName'>VENOM</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>SP-W7-PC</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>37.191.115.2</Data><Data Name='IpPort'>0</Data></EventData></Event>",
                    "37.191.115.2,steven.universe,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}' /><EventID>140</EventID><Version>0</Version><Level>3</Level><Task>4</Task><Opcode>14</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2016-11-13T11:52:25.314996400Z' /><EventRecordID>1683867</EventRecordID><Correlation ActivityID='{F4204608-FB58-4924-A3D9-B8A1B0870000}' /><Execution ProcessID='2920' ThreadID='4104' /><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>SERVER</Computer><Security UserID='S-1-5-20' /></System><EventData><Data Name='IPString'>1.2.3.4</Data></EventData></Event>",
                    "1.2.3.4,,RDP,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER' /><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2017-11-25T02:03:39.164598300Z' /><EventRecordID>19044</EventRecordID><Channel>Application</Channel><Computer>srv01</Computer><Security /></System><EventData><Data>sa</Data><Data>Raison : le mot de passe ne correspond pas à la connexion spécifiée.</Data><Data> [CLIENT : 196.65.47.84]</Data><Binary>184800000E0000000D00000053004500520056004500550052002D0043004F004E0047000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "196.65.47.84,sa,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH' Guid='{C4B57D35-0636-4BC3-A262-370F249F9802}' /><EventID>4</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-07-23T09:21:59.867239200Z' /><EventRecordID>1369</EventRecordID><Correlation /><Execution ProcessID='7964' ThreadID='696' /><Channel>OpenSSH/Operational</Channel><Computer>ns524406</Computer><Security UserID='S-1-5-18' /></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Connection closed by 185.222.211.58 port 49448 [preauth]</Data></EventData></Event>",
                    "185.222.211.58,,SSH,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH' Guid='{C4B57D35-0636-4BC3-A262-370F249F9802}' /><EventID>4</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2019-03-26T00:58:31.360472700Z' /><EventRecordID>247502</EventRecordID><Correlation /><Execution ProcessID='4944' ThreadID='6160' /><Channel>OpenSSH/Operational</Channel><Computer>ns524406</Computer><Security UserID='S-1-5-18' /></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Accepted password for success_user from 88.88.88.88 port 12345 ssh2 </Data></EventData></Event>",
                    "88.88.88.88,success_user,SSH,1"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH' Guid='{C4B57D35-0636-4BC3-A262-370F249F9802}' /><EventID>4</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2019-04-13T10:03:30.415041300Z' /><EventRecordID>257875</EventRecordID><Correlation /><Execution ProcessID='5424' ThreadID='6272' /><Channel>OpenSSH/Operational</Channel><Computer>ns524406</Computer><Security UserID='S-1-5-18' /></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Failed password for invalid user root from 192.169.217.183 port 43716 ssh2</Data></EventData></Event>",
                    "192.169.217.183,root,SSH,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH' Guid='{C4B57D35-0636-4BC3-A262-370F249F9802}' /><EventID>4</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-07-23T09:21:59.867239200Z' /><EventRecordID>1369</EventRecordID><Correlation /><Execution ProcessID='7964' ThreadID='696' /><Channel>OpenSSH/Operational</Channel><Computer>ns524406</Computer><Security UserID='S-1-5-18' /></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Did not receive identification string from 70.91.222.121</Data></EventData></Event>",
                    "70.91.222.121,,SSH,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH' Guid='{C4B57D35-0636-4BC3-A262-370F249F9802}' /><EventID>4</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-07-23T09:21:59.867239200Z' /><EventRecordID>1369</EventRecordID><Correlation /><Execution ProcessID='7964' ThreadID='696' /><Channel>OpenSSH/Operational</Channel><Computer>ns524406</Computer><Security UserID='S-1-5-18' /></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Disconnected from 188.166.71.236 port 44510 [preauth]</Data></EventData></Event>",
                    "188.166.71.236,,SSH,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='tvnserver' /><EventID Qualifiers='2'>258</EventID><Level>3</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2019-05-14T14:22:32.337254800Z' /><EventRecordID>9961</EventRecordID><Channel>Application</Channel><Computer>MyCPU</Computer><Security /></System><EventData><Data>Authentication failed from 104.248.243.148</Data></EventData></Event>",
                    "104.248.243.148,,VNC,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='tvnserver' /><EventID Qualifiers='2'>257</EventID><Level>3</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2019-05-14T14:22:32.337254800Z' /><EventRecordID>9961</EventRecordID><Channel>Application</Channel><Computer>MyCPU</Computer><Security /></System><EventData><Data>Authentication passed by 24.42.43.14</Data></EventData></Event>",
                    "24.42.43.14,,VNC,1"
                ),
                // https://github.com/DigitalRuby/IPBan/issues/65
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2019-10-03T14:58:10.000000000Z'/><EventRecordID>252736</EventRecordID><Channel>Application</Channel><Computer>MyComputer</Computer><Security/></System><EventData><Data>U$er_Name,To Be-Found !</Data><Data> Raison : impossible de trouver une connexion correspondant au nom fourni.</Data><Data> [CLIENT : 11.20.30.40]</Data><Binary>184800000E000000090000004E0053003500320034003400300036000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "11.20.30.40,U$er_Name,To Be-Found !,MSSQL,0"
                ),
                new
                (
                    @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQL$SQLEXPRESS'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2019-10-09T13:49:38.389639000Z'/><EventRecordID>599309</EventRecordID><Channel>Application</Channel><Computer>MyComputer</Computer><Security/></System><EventData><Data>sa</Data><Data> Raison : le mot de passe ne correspond pas à la connexion spécifiée.</Data><Data> [CLIENT : 11.0.0.1]</Data><Binary>184800000E000000090000004E0053003500320034003400300036000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                    "11.0.0.1,sa,MSSQL,0"
                )
            };
            for (int i = 0; i < 5; i++)
            {
                foreach (KeyValuePair<string, string> xml in xmlTestStrings)
                {
                    IPAddressLogEvent result = service.EventViewer.ProcessEventViewerXml(xml.Key);
                    string expectedInfo = (result is null ? "x" : ((result.IPAddress ?? string.Empty) + "," + (result.UserName ?? string.Empty) + "," +
                        (result.Source ?? string.Empty) + "," + (result.Type == IPAddressEventType.FailedLogin ? "0" : (result.Type == IPAddressEventType.SuccessfulLogin ? "1" : "2"))));
                    Assert.AreEqual(xml.Value, expectedInfo);
                }
                service.RunCycleAsync().Sync();

                // pretend enough time has passed to not batch the login attempts
                IPBanService.UtcNow += TimeSpan.FromSeconds(10.0);
            }

            string[] blockedIPAddresses = service.Firewall.EnumerateBannedIPAddresses().ToArray();
            string[] expected = new string[]
            {
                "1.2.3.4",
                "2.92.13.221",
                "11.0.0.1",
                "11.20.30.40",
                "11.12.13.15",
                "21.25.29.33",
                "33.32.31.30",
                "33.55.77.99",
                "37.140.141.29",
                "37.191.115.2",
                "41.42.43.44",
                "61.62.63.64",
                "70.91.222.121",
                "82.61.45.195",
                "88.88.88.82",
                "99.99.99.98",
                "99.99.99.99",
                "99.99.99.100",
                "100.101.102.103",
                "104.248.243.148",
                "123.123.123.123",
                "123.123.123.124",
                "155.155.155.155",
                "185.209.0.22",
                "185.222.211.58",
                "188.166.71.236",
                "192.169.217.183",
                "196.65.47.84",
                "212.48.88.133",
                "212.92.107.115",
                "218.10.17.192",
                "222.186.61.16"
            };
            Array.Sort(blockedIPAddresses);
            Array.Sort(expected);
            if (expected.Length != blockedIPAddresses.Length)
            {
                Assert.Fail("Failed to block ips: " + string.Join(", ", expected.Except(blockedIPAddresses)));
            }
            Assert.AreEqual(expected, blockedIPAddresses);
            Assert.AreEqual(5, successEvents.Count);
            Assert.AreEqual(5, successEvents["24.42.43.14_VNC_"]);
            Assert.AreEqual(5, successEvents["44.55.66.77_RDP_rdpuser"]);
            Assert.AreEqual(5, successEvents["74.76.76.76_RDP_administrateur"]);
            Assert.AreEqual(5, successEvents["88.88.88.88_SSH_success_user"]);
            Assert.AreEqual(5, successEvents["98.196.175.165_RRAS_username"]);
        }

        void IDisposable.Dispose() => GC.SuppressFinalize(this);

        Task IIPBanDelegate.IPAddressBanned(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp, bool banned)
        {
            return Task.CompletedTask;
        }

        Task IIPBanDelegate.LoginAttemptFailed(string ip, string source, string userName, string machineGuid, string osName, string osVersion, int count, DateTime timestamp)
        {
            return Task.CompletedTask;
        }

        Task IIPBanDelegate.LoginAttemptSucceeded(string ip, string source, string userName, string machineGuid, string osName, string osVersion, int count, DateTime timestamp)
        {
            string key = ip + "_" + (source?.ToString()) + "_" + (userName?.ToString());
            successEvents.TryGetValue(key, out int count2);
            successEvents[key] = ++count2;
            return Task.CompletedTask;
        }

        void IIPBanDelegate.Start(IIPBanService service)
        {

        }

        Task IIPBanDelegate.Update()
        {
            return Task.CompletedTask;
        }

        /*
        /// <summary>
        /// Test all entries in the event viewer that match config
        /// </summary>
        public void TestAllEntries()
        {
            int count = 0;
            try
            {
                TimeSpan timeout = TimeSpan.FromMilliseconds(20.0);
                string queryString = GetEventLogQueryString(null);
                EventLogQuery query = new EventLogQuery(null, PathType.LogName, queryString)
                {
                    Session = new EventLogSession("localhost")
                };
                EventLogReader reader = new EventLogReader(query);
                EventRecord record;
                while ((record = reader.ReadEvent(timeout)) != null)
                {
                    if (++count % 100 == 0)
                    {
                        Console.Write("Count: {0}    \r", count);
                    }
                    ProcessEventViewerXml(record.ToXml());
                }
                service.RunCycle();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex.Message);
            }
            Console.WriteLine("Tested {0} entries        ", count);
        }
        */
    }
}