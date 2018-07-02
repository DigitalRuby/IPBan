using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;

namespace IPBan
{
    public class IPBanWindowsEventViewer : IUpdater
    {
        private static readonly Regex invalidXmlRegex = new Regex(@"(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\uFEFF\uFFFE\uFFFF]", RegexOptions.Compiled);

        private IIPBanService service;
        private EventLogQuery query;
        private EventLogWatcher watcher;
        private string previousQueryString;

        public IPBanWindowsEventViewer(IIPBanService service)
        {
            this.service = service;
            service.AddUpdater(this);
            Update();
        }

        public void Update()
        {
            SetupEventLogWatcher();
        }

        public void Dispose()
        {
            query = null;
            if (watcher != null)
            {
                watcher.Dispose();
                watcher = null;
                service.RemoveUpdater(this);
            }
        }

        private void ProcessIPAddressAndUserName(string ipAddress, string userName, XmlDocument doc)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
            {
                return;
            }

            XmlNode userNameNode = doc.SelectSingleNode("//Data[@Name='TargetUserName']");
            if (userNameNode != null)
            {
                userName = (string.IsNullOrWhiteSpace(userName) ? userNameNode.InnerText.Trim() : userName);
            }

            Log.Write(NLog.LogLevel.Info, "*LOGIN FAIL* IP: {0}, USER: {1}", ipAddress, userName);
            service.AddPendingIPAddressAndUserName(ipAddress, userName);
        }

        private void ExtractIPAddressAndUserNameFromXml(XmlDocument doc, out string ipAddress, out string userName)
        {
            XmlNode keywordsNode = doc.SelectSingleNode("//Keywords");
            string keywordsText = keywordsNode.InnerText;
            if (keywordsText.StartsWith("0x"))
            {
                keywordsText = keywordsText.Substring(2);
            }
            ulong keywordsULONG = ulong.Parse(keywordsText, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            ipAddress = userName = null;

            if (keywordsNode != null)
            {
                // we must match on keywords
                foreach (ExpressionsToBlockGroup group in service.Config.GetGroupsMatchingKeywords(keywordsULONG))
                {
                    foreach (ExpressionToBlock expression in group.Expressions)
                    {
                        // find all the nodes, try and get an ip from any of them, all must match
                        XmlNodeList nodes = doc.SelectNodes(expression.XPath);

                        if (nodes.Count == 0)
                        {
                            Log.Write(NLog.LogLevel.Info, "No nodes found for xpath {0}", expression.XPath);
                            ipAddress = null;
                            break;
                        }

                        // if there is a regex, it must match
                        if (string.IsNullOrWhiteSpace(expression.Regex))
                        {
                            // count as a match, do not modify the ip address if it was already set
                            Log.Write(NLog.LogLevel.Info, "No regex, so counting as a match");
                        }
                        else
                        {
                            bool foundMatch = false;

                            // try and find an ip from any of the nodes
                            foreach (XmlNode node in nodes)
                            {
                                // if we get a match, stop checking nodes
                                if ((foundMatch = IPBanService.GetIPAddressAndUserNameFromRegex(expression.RegexObject, node.InnerText, ref ipAddress, ref userName)))
                                {
                                    break;
                                }
                            }

                            if (!foundMatch)
                            {
                                // match fail, null out ip, we have to match ALL the nodes or we get null ip and do not ban
                                Log.Write(NLog.LogLevel.Info, "Regex {0} did not match any nodes with xpath {1}", expression.Regex, expression.XPath);
                                ipAddress = null;
                                break;
                            }
                        }
                    }

                    if (ipAddress != null)
                    {
                        break;
                    }
                    ipAddress = userName = null; // set null for the next node attempt
                }
            }
        }

        private XmlDocument ParseXml(string xml)
        {
            xml = invalidXmlRegex.Replace(xml, string.Empty);
            XmlTextReader reader = new XmlTextReader(new StringReader(xml))
            {
                Namespaces = false
            };
            XmlReader outerReader = XmlReader.Create(reader, new XmlReaderSettings { CheckCharacters = false });
            XmlDocument doc = new XmlDocument();
            doc.Load(outerReader);

            return doc;
        }

        private void EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e != null && e.EventRecord != null)
                {
                    EventRecord rec = e.EventRecord;
                    string xml = null;
                    try
                    {
                        xml = rec.ToXml();
                    }
                    catch
                    {
                    }
                    if (xml != null)
                    {
                        ProcessEventViewerXml(xml);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Exception(ex);
            }
        }

        private string GetEventLogQueryString()
        {
            int id = 0;
            string queryString = "<QueryList>";
            foreach (ExpressionsToBlockGroup group in service.Config.Expressions.Groups)
            {
                if (Environment.OSVersion.Version.Major > group.MinimumWindowsMajorVersion ||
                    (Environment.OSVersion.Version.Major >= group.MinimumWindowsMajorVersion && Environment.OSVersion.Version.Minor >= group.MinimumWindowsMinorVersion))
                {
                    ulong keywordsDecimal = ulong.Parse(group.Keywords.Substring(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
                    queryString += "<Query Id='" + (++id).ToString() + "' Path='" + group.Path + "'><Select Path='" + group.Path + "'>*[System[(band(Keywords," + keywordsDecimal.ToString() + "))]]</Select></Query>";
                }
            }
            queryString += "</QueryList>";

            return queryString;
        }

        private void SetupEventLogWatcher()
        {
            try
            {
                string queryString = GetEventLogQueryString();
                if (queryString != previousQueryString)
                {
                    watcher?.Dispose();
                    query = new EventLogQuery(null, PathType.LogName, queryString);
                    watcher = new EventLogWatcher(query);
                    watcher.EventRecordWritten += EventRecordWritten;
                    watcher.Enabled = true;
                    previousQueryString = queryString;
                }
            }
            catch (Exception ex)
            {
                Log.Exception("Failed to create event viewer watcher", ex);
            }
        }

        private void TestRemoteDesktopAttemptWithIPAddress(string ipAddress, int count)
        {
            string xml = string.Format(@"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>{0}</Data><Data Name='IpPort'>52813</Data></EventData></Event>", ipAddress);

            while (count-- > 0)
            {
                ProcessEventViewerXml(xml);
            }
        }

        /// <summary>
        /// Process event viewer XML
        /// </summary>
        /// <param name="xml">XML</param>
        public void ProcessEventViewerXml(string xml)
        {
            Log.Write(NLog.LogLevel.Info, "Processing xml: {0}", xml);

            XmlDocument doc = ParseXml(xml);
            ExtractIPAddressAndUserNameFromXml(doc, out string ipAddress, out string userName);
            ProcessIPAddressAndUserName(ipAddress, userName, doc);
        }

        /// <summary>
        /// Run tests
        /// </summary>
        public void RunTests()
        {
            string[] xmlTestStrings = new string[]
            {
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}'/><EventID>139</EventID><Version>0</Version><Level>3</Level><Task>4</Task><Opcode>14</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-06-26T01:37:02.869748200Z'/><EventRecordID>42406434</EventRecordID><Correlation ActivityID='{F420C8AD-71D8-43BE-86ED-D02442380000}'/><Execution ProcessID='3660' ThreadID='243736'/><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>cpu0</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='ResultCode'>0x80090302</Data><Data Name='IPString'>185.209.0.22</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}'/><EventID>131</EventID><Version>0</Version><Level>4</Level><Task>4</Task><Opcode>15</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-06-26T01:53:56.457887700Z'/><EventRecordID>42406524</EventRecordID><Correlation ActivityID='{F420D573-5248-42DC-BCE2-CBC44FE80000}'/><Execution ProcessID='3660' ThreadID='2708'/><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>cpu1</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='ConnType'>TCP</Data><Data Name='ClientIP'>66.5.4.3:56461</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}'/><EventID>131</EventID><Version>0</Version><Level>4</Level><Task>4</Task><Opcode>15</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2018-05-04T01:54:27.116318900Z'/><EventRecordID>2868163</EventRecordID><Correlation ActivityID='{F420C0F6-FAFD-4D94-B102-B3A142DF0000}'/><Execution ProcessID='1928' ThreadID='2100'/><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>KAU-HOST-03</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='ConnType'>TCP</Data><Data Name='ClientIP'>203.171.54.90:54511</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='ASP.NET 2.0.50727.0'/><EventID Qualifiers='32768'>1309</EventID><Level>3</Level><Task>3</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2014-07-10T23:37:57.000Z'/><EventRecordID>196334166</EventRecordID><Channel>Application</Channel><Computer>SERVIDOR</Computer><Security/></System><EventData><Data>3005</Data><Data>Excepci?n no controlada.</Data><Data>11/07/2014 1:37:57</Data><Data>10/07/2014 23:37:57</Data><Data>2b4bdc4736fe40f9af42fce697b8acc7</Data><Data>9</Data><Data>7</Data><Data>0</Data><Data>/LM/W3SVC/44/ROOT-1-130495088933270000</Data><Data>Full</Data><Data>/</Data><Data>C:\Inetpub\vhosts\cbhermosilla.es\httpdocs\</Data><Data>SERVIDOR</Data><Data></Data><Data>116380</Data><Data>w3wp.exe</Data><Data>SERVIDOR\IWPD_36(cbhermosill)</Data><Data>HttpException</Data><Data>No se pueden validar datos. (le français [lə fʁɑ̃sɛ] ( listen) or la langue française [la lɑ̃ɡ fʁɑ̃sɛz])" + "\x0001" + @"汉语 / 漢語 --:" + "\x0013" + @":--汉语 / 漢語</Data><Data>http://cbhermosilla.es/ScriptResource.axd?d=sdUSoDA_p4m7C8RvW7GhwLy4-JvXN1IcbzfRDWczGaZK4pT_avDiah8wSHZqBBjyvhhqa0cQYI_FWQYwCqlPsA8BsjFn19zRsw08qPt-rkQyZ6ODPVJ_Dp7CuLQKGPn6lQd-SOyyiu0VTTAgMiLVZqD6__M1&amp;t=635057131997880000</Data><Data>/ScriptResource.axd</Data><Data>66.249.76.207</Data><Data></Data><Data>False</Data><Data></Data><Data>SERVIDOR\IWPD_36(cbhermosill)</Data><Data>7</Data><Data>SERVIDOR\IWPD_36(cbhermosill)</Data><Data>False</Data><Data>   en System.Web.Configuration.MachineKeySection.EncryptOrDecryptData(Boolean fEncrypt, Byte[] buf, Byte[] modifier, Int32 start, Int32 length, IVType ivType, Boolean useValidationSymAlgo, Boolean signData) en System.Web.Configuration.MachineKeySection.EncryptOrDecryptData(Boolean fEncrypt, Byte[] buf, Byte[] modifier, Int32 start, Int32 length, IVType ivType, Boolean useValidationSymAlgo) en System.Web.UI.Page.DecryptStringWithIV(String s, IVType ivType) en System.Web.UI.Page.DecryptString(String s)</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>99.99.99.99</Data><Data Name='IpPort'>52813</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>127.0.0.1</Data><Data Name='IpPort'>52813</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2012-04-05T20:26:30.000000000Z'/><EventRecordID>408488</EventRecordID><Channel>Application</Channel><Computer>dallas</Computer><Security/></System><EventData><Data>sa1</Data><Data> Reason: Could not find a login matching the name provided.</Data><Data> [CLIENT: 99.99.99.100]</Data><Binary>184800000E00000007000000440041004C004C00410053000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2012-04-05T20:26:30.000000000Z'/><EventRecordID>408488</EventRecordID><Channel>Application</Channel><Computer>dallas</Computer><Security/></System><EventData><Data>sa1</Data><Data> Reason: Could not find a login matching the name provided.</Data><Data> [CLIENT: 0.0.0.0]</Data><Binary>184800000E00000007000000440041004C004C00410053000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>99.99.99.98</Data><Data Name='IpPort'>52813</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>5152</EventID><Version>0</Version><Level>0</Level><Task>12809</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2013-07-23T22:33:04.141430800Z' /><EventRecordID>4892828</EventRecordID><Correlation /><Execution ProcessID='4' ThreadID='72' /><Channel>Security</Channel><Computer>HostWeb30.hostworx.co.za</Computer><Security /></System><EventData><Data Name='ProcessId'>0</Data><Data Name='Application'>-</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>37.140.141.29</Data><Data Name='SourcePort'>32480</Data><Data Name='DestAddress'>196.22.190.33</Data><Data Name='DestPort'>80</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>689661</Data><Data Name='LayerName'>%%14597</Data><Data Name='LayerRTID'>13</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>5152</EventID><Version>0</Version><Level>0</Level><Task>12809</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2013-07-24T11:09:21.153847400Z'/><EventRecordID>4910290</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='76'/><Channel>Security</Channel><Computer>HostWeb30.hostworx.co.za</Computer><Security/></System><EventData><Data Name='ProcessId'>4</Data><Data Name='Application'>System</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>82.61.45.195</Data><Data Name='SourcePort'>3079</Data><Data Name='DestAddress'>196.22.190.31</Data><Data Name='DestPort'>445</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>755725</Data><Data Name='LayerName'>%%14610</Data><Data Name='LayerRTID'>44</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12809</Task><Opcode>0</Opcode><Keywords>0x8010000000000001</Keywords><TimeCreated SystemTime='2013-07-24T11:24:51.369052700Z'/><EventRecordID>4910770</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='88'/><Channel>Security</Channel><Computer>HostWeb30.hostworx.co.za</Computer><Security/></System><EventData><Data Name='ProcessId'>2788</Data><Data Name='Application'>\device\harddiskvolume2\program files (x86)\rhinosoft.com\serv-u\servudaemon.exe</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>37.235.53.240</Data><Data Name='SourcePort'>39058</Data><Data Name='DestAddress'>196.22.190.31</Data><Data Name='DestPort'>21</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>780480</Data><Data Name='LayerName'>%%14610</Data><Data Name='LayerRTID'>44</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2014-08-25T09:11:06.000000000Z'/><EventRecordID>116411121</EventRecordID><Channel>Application</Channel><Computer>s16240956</Computer><Security/></System><EventData><Data>sa</Data><Data> Raison : impossible de trouver une connexion correspondant au nom fourni.</Data><Data> [CLIENT : 218.10.17.192]</Data><Binary>184800000E0000000A0000005300310036003200340030003900350036000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSExchangeTransport' /><EventID Qualifiers='32772'>1035</EventID><Level>3</Level><Task>1</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2015-06-08T08:13:12.000000000Z' /><EventRecordID>667364</EventRecordID><Channel>Application</Channel><Computer>DC.sicoir.local</Computer><Security /></System><EventData><Data>LogonDenied</Data><Data>Default DC</Data><Data>Ntlm</Data><Data>212.48.88.133</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER' /><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2015-09-10T14:20:42.000000000Z' /><EventRecordID>4439286</EventRecordID><Channel>Application</Channel><Computer>DSVR018379</Computer><Security /></System><EventData><Data>sa</Data><Data>Reason: Password did not match that for the login provided.</Data><Data>[CLIENT: 222.186.61.16]</Data><Binary>184800000E0000000B00000044005300560052003000310038003300370039000000070000006D00610073007400650072000000</Binary></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2017-08-09T11:06:11.486303500Z' /><EventRecordID>17925</EventRecordID><Correlation ActivityID='{A7FB7D60-01E0-0000-877D-FBA7E001D301}' /><Execution ProcessID='648' ThreadID='972' /><Channel>Security</Channel><Computer>DESKTOP-N8QJFLU</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>steven.powell</Data><Data Name='TargetDomainName'>VENOM</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>SP-W7-PC</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>37.191.115.2</Data><Data Name='IpPort'>0</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS' Guid='{1139C61B-B549-4251-8ED3-27250A1EDEC8}' /><EventID>140</EventID><Version>0</Version><Level>3</Level><Task>4</Task><Opcode>14</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2016-11-13T11:52:25.314996400Z' /><EventRecordID>1683867</EventRecordID><Correlation ActivityID='{F4204608-FB58-4924-A3D9-B8A1B0870000}' /><Execution ProcessID='2920' ThreadID='4104' /><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>SERVER</Computer><Security UserID='S-1-5-20' /></System><EventData><Data Name='IPString'>1.2.3.4</Data></EventData></Event>",
                @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER' /><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2017-11-25T02:03:39.164598300Z' /><EventRecordID>19044</EventRecordID><Channel>Application</Channel><Computer>srv01</Computer><Security /></System><EventData><Data>sa</Data><Data>Raison : le mot de passe ne correspond pas à la connexion spécifiée.</Data><Data> [CLIENT : 196.65.47.84]</Data><Binary>184800000E0000000D00000053004500520056004500550052002D0043004F004E0047000000070000006D00610073007400650072000000</Binary></EventData></Event>"
            };

            string[] xmlTestStringsDelay = new string[]
            {
                xmlTestStrings[5]
            };

            foreach (string xml in xmlTestStrings)
            {
                ProcessEventViewerXml(xml);
            }
            service.ProcessPendingIPAddresses();

            for (int i = 0; i < 255 && service.IsRunning; i++)
            {
                TestRemoteDesktopAttemptWithIPAddress("99.99.1." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.2." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.3." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.4." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.5." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.6." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.7." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.8." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.9." + i.ToString(), 10);
                TestRemoteDesktopAttemptWithIPAddress("99.99.10." + i.ToString(), 10);
            }

            foreach (string xml in xmlTestStringsDelay)
            {
                // Fire this test event after a 15 second delay, to test ExpireTime duration.
                Task.Run(() =>
                {
                    Task.Delay(15000).Wait();
                    ProcessEventViewerXml(xml);
                });
            }
        }
    }
}
