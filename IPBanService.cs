#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Security.Permissions;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Xml;
using System.Text.RegularExpressions;
using System.Reflection;

#endregion Imports

namespace IPBan
{
    public class IPBanService : IIPBanService, IHttpRequestMaker
    {
        private enum UrlType
        {
            Start,
            Update,
            Stop,
            Config
        }

        private class PendingIPAddress
        {
            public string IPAddress { get; set; }
            public string UserName { get; set; }
            public DateTime DateTime { get; set; }
            public int Counter { get; set; }
        }

        private string configFilePath;
        private Task cycleTask;
        private bool run;
        private EventLogQuery query;
        private EventLogWatcher watcher;
        private bool needsBanScript;
        private bool gotStartUrl;

        // note that an ip that has a block count may not yet be in the ipAddressesAndBanDate dictionary
        // for locking, always use ipAddressesAndBlockCounts
        private Dictionary<string, IPBlockCount> ipAddressesAndBlockCounts = new Dictionary<string, IPBlockCount>();
        private Dictionary<string, DateTime> ipAddressesAndBanDate = new Dictionary<string, DateTime>();

        private DateTime lastConfigFileDateTime = DateTime.MinValue;
        private readonly ManualResetEvent cycleEvent = new ManualResetEvent(false);
        private readonly object configLock = new object();
        private static readonly Regex invalidXmlRegex = new Regex(@"(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\uFEFF\uFFFE\uFFFF]", RegexOptions.Compiled);

        // the windows event viewer calls back on a background thread, this allows pushing the ip addresses to a list that will be accessed
        //  in the main loop
        private readonly List<PendingIPAddress> pendingIPAddresses = new List<PendingIPAddress>();

        private void RunTask(Action action)
        {
            if (MultiThreaded)
            {
                System.Threading.Tasks.Task.Run(action);
            }
            else
            {
                action.Invoke();
            }
        }

        private void ExecuteBanScript()
        {
            string[] ipAddresses;
            KeyValuePair<string, DateTime>[] ipAndBanDateArray;

            // quickly copy out data in the lock
            lock (ipAddressesAndBlockCounts)
            {
                ipAddresses = ipAddressesAndBanDate.Keys.ToArray();
                ipAndBanDateArray = ipAddressesAndBanDate.ToArray();
            }

            // now that we are out of the lock, do more expensive operations

            // create rules for all banned ip addresses
            IPBanWindowsFirewall.CreateRules(ipAddresses);

            // write all banned ip addresses
            using (StreamWriter writer = File.CreateText(Config.BanFile))
            {
                foreach (KeyValuePair<string, DateTime> ipAndBanDate in ipAndBanDateArray)
                {
                    writer.WriteLine("{0}\t{1}", ipAndBanDate.Key, ipAndBanDate.Value.ToString("o"));
                }
            }
        }

        internal void ReadAppSettings()
        {
            try
            {
                DateTime lastDateTime = File.GetLastWriteTimeUtc(configFilePath);
                if (lastDateTime > lastConfigFileDateTime)
                {
                    lastConfigFileDateTime = lastDateTime;
                    lock (configLock)
                    {
                        IPBanConfig newConfig = new IPBanConfig(configFilePath) { ExternalConfig = IPBanDelegate };
                        Config = newConfig;
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Exception(ex);

                if (Config == null)
                {
                    throw new ApplicationException("Configuration failed to load, make sure to unblock all the files. Right click each file, select properties and then unblock.", ex);
                }
            }
        }

        private void SetNetworkInfo()
        {
            if (string.IsNullOrWhiteSpace(FQDN))
            {
                string serverName = System.Environment.MachineName;
                try
                {
                    FQDN = System.Net.Dns.GetHostEntry(serverName).HostName;
                }
                catch
                {
                    FQDN = serverName;
                }
            }

            if (string.IsNullOrWhiteSpace(LocalIPAddressString))
            {
                try
                {
                    // append ipv4 first, then the ipv6 then the remote ip
                    IPAddress[] ips = Dns.GetHostAddresses(Dns.GetHostName());
                    foreach (IPAddress ip in ips)
                    {
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            LocalIPAddressString = ip.ToString();
                            break;
                        }
                    }
                    if (string.IsNullOrWhiteSpace(LocalIPAddressString))
                    {
                        foreach (IPAddress ip in ips)
                        {
                            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                            {
                                LocalIPAddressString = ip.ToString();
                                break;
                            }
                        }
                    }
                }
                catch
                {

                }
            }

            if (string.IsNullOrWhiteSpace(RemoteIPAddressString))
            {
                try
                {
                    byte[] bytes = RequestMaker.DownloadDataAsync(Config.ExternalIPAddressUrl).ConfigureAwait(false).GetAwaiter().GetResult();
                    RemoteIPAddressString = Encoding.UTF8.GetString(bytes).Trim();
                }
                catch
                {

                }
            }

            // hit start url if first time, if not first time will be ignored
            GetUrl(UrlType.Start);

            // send update
            GetUrl(UrlType.Update);

            // request new config file
            GetUrl(UrlType.Config);
        }

        private void LogInitialConfig()
        {
            Log.Write(LogLevel.Info, "Whitelist: {0}, Whitelist Regex: {1}", Config.WhiteList, Config.WhiteListRegex);
            Log.Write(LogLevel.Info, "Blacklist: {0}, Blacklist Regex: {1}", Config.BlackList, Config.BlackListRegex);

            if (!string.IsNullOrWhiteSpace(Config.AllowedUserNames))
            {
                Log.Write(LogLevel.Info, "Allowed Users: {0}", Config.AllowedUserNames);
            }
        }

        private void ProcessBanFileOnStart()
        {
            lock (ipAddressesAndBlockCounts)
            {
                ipAddressesAndBlockCounts.Clear();
                ipAddressesAndBanDate.Clear();
                if (File.Exists(Config.BanFile))
                {
                    if (Config.BanFileClearOnRestart)
                    {
                        // don't re-ban any ip addresses, per config option
                        File.Delete(Config.BanFile);
                    }
                    else
                    {
                        string[] lines = File.ReadAllLines(Config.BanFile);
                        DateTime now = CurrentDateTime;
                        foreach (string ip in lines)
                        {
                            string[] pieces = ip.Split('\t');
                            if (pieces.Length > 0)
                            {
                                string ipTrimmed = pieces[0].Trim();
                                if (IPAddress.TryParse(ipTrimmed, out IPAddress tmp))
                                {
                                    // setup a ban entry for the ip address
                                    IPBlockCount blockCount = new IPBlockCount(now, Config.FailedLoginAttemptsBeforeBan);
                                    ipAddressesAndBlockCounts[ipTrimmed] = blockCount;
                                    if (pieces.Length > 1)
                                    {
                                        try
                                        {
                                            // use the date/time if we have it
                                            ipAddressesAndBanDate[ipTrimmed] = DateTime.Parse(pieces[1]).ToUniversalTime();
                                        }
                                        catch
                                        {
                                            // corrupt date/time in the file, fallback to current date/time
                                            ipAddressesAndBanDate[ipTrimmed] = CurrentDateTime;
                                        }
                                    }
                                    else
                                    {
                                        // otherwise fall back to current date/time
                                        ipAddressesAndBanDate[ipTrimmed] = CurrentDateTime;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ExecuteBanScript();
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
                foreach (ExpressionsToBlockGroup group in Config.GetGroupsMatchingKeywords(keywordsULONG))
                {
                    foreach (ExpressionToBlock expression in group.Expressions)
                    {
                        // find all the nodes, try and get an ip from any of them
                        XmlNodeList nodes = doc.SelectNodes(expression.XPath);

                        if (nodes.Count == 0)
                        {
                            Log.Write(LogLevel.Info, "No nodes found for xpath {0}", expression.XPath);
                            ipAddress = null;
                            break;
                        }

                        // if there is a regex, it must match
                        if (string.IsNullOrWhiteSpace(expression.Regex))
                        {
                            // count as a match, do not modify the ip address if it was already set
                            Log.Write(LogLevel.Info, "No regex, so counting as a match");
                        }
                        else
                        {
                            bool foundMatch = false;

                            // try and find an ip from any of the nodes
                            foreach (XmlNode node in nodes)
                            {
                                // if we get a match, stop checking nodes
                                if ((foundMatch = GetIPAddressAndUserNameFromRegex(expression.RegexObject, node.InnerText, ref ipAddress, ref userName)))
                                {
                                    break;
                                }
                            }

                            if (!foundMatch)
                            {
                                Log.Write(LogLevel.Info, "Regex {0} did not match any nodes with xpath {1}", expression.Regex, expression.XPath);
                                break;
                            }
                        }
                    }

                    if (ipAddress != null)
                    {
                        break;
                    }
                }
            }
        }

        private void ProcessPendingIPAddresses()
        {
            List<PendingIPAddress> ipAddresses;
            lock (pendingIPAddresses)
            {
                if (pendingIPAddresses.Count == 0)
                {
                    return;
                }
                ipAddresses = new List<PendingIPAddress>(pendingIPAddresses);
                pendingIPAddresses.Clear();
            }

            ProcessPendingIPAddresses(ipAddresses);
        }

        private void ProcessPendingIPAddresses(IEnumerable<PendingIPAddress> ipAddresses)
        {
            List<KeyValuePair<string, string>> bannedIpAddresses = new List<KeyValuePair<string, string>>();

            foreach (PendingIPAddress p in ipAddresses)
            {
                string ipAddress = p.IPAddress;
                string userName = p.UserName;
                DateTime dateTime = p.DateTime;
                int counter = p.Counter;

                if (Config.IsWhiteListed(ipAddress))
                {
                    Log.Write(LogLevel.Info, "Ignoring whitelisted ip address {0}, user name: {1}", ipAddress, userName);
                }
                else
                {
                    // check for the target user name for additional blacklisting checks                    
                    bool blackListed = Config.IsBlackListed(ipAddress) || (userName != null && Config.IsBlackListed(userName));

                    lock (ipAddressesAndBlockCounts)
                    {
                        // Get the IPBlockCount, if one exists.
                        if (!ipAddressesAndBlockCounts.TryGetValue(ipAddress, out IPBlockCount ipBlockCount))
                        {
                            // This is the first failed login attempt, so record a new IPBlockCount.
                            ipBlockCount = new IPBlockCount();
                            ipAddressesAndBlockCounts[ipAddress] = ipBlockCount;
                        }

                        // Increment the count.
                        ipBlockCount.IncrementCount(CurrentDateTime, counter);

                        Log.Write(LogLevel.Info, "Incrementing count for ip {0} to {1}, user name: {2}", ipAddress, ipBlockCount.Count, userName);

                        // if the ip is black listed or they have reached the maximum failed login attempts before ban, ban them
                        if (blackListed || ipBlockCount.Count >= Config.FailedLoginAttemptsBeforeBan)
                        {
                            // if they are not black listed OR this is the first increment of a black listed ip address, perform the ban
                            if (!blackListed || ipBlockCount.Count >= 1)
                            {
                                if (!ipAddressesAndBanDate.ContainsKey(ipAddress))
                                {
                                    bannedIpAddresses.Add(new KeyValuePair<string, string>(ipAddress, userName));
                                    Log.Write(LogLevel.Error, "Banning ip address: {0}, user name: {1}, black listed: {2}, count: {3}", ipAddress, userName, blackListed, ipBlockCount.Count);
                                    ipAddressesAndBanDate[ipAddress] = dateTime;
                                    needsBanScript = true;
                                }
                            }
                            else
                            {
                                Log.Write(LogLevel.Info, "Ignoring previously banned black listed ip {0}, user name: {1}, ip should already be banned", ipAddress, userName);
                            }
                        }
                        else if (ipBlockCount.Count > Config.FailedLoginAttemptsBeforeBan)
                        {
                            Log.Write(LogLevel.Warning, "Got event with ip address {0}, count {1}, ip should already be banned", ipAddress, ipBlockCount.Count);
                        }
                    }
                }
            }

            if (bannedIpAddresses.Count != 0)
            {
                ProcessBannedIPAddresses(bannedIpAddresses);
            }
        }

        private void ProcessBannedIPAddresses(IEnumerable<KeyValuePair<string, string>> bannedIPAddresses)
        {
            // kick off external process and delegate notification in another thread
            string programToRunConfigString = Config.ProcessToRunOnBan;
            RunTask(() =>
            {
                foreach (var bannedIp in bannedIPAddresses)
                {
                    // Run a process if one is in config
                    if (!string.IsNullOrWhiteSpace(programToRunConfigString))
                    {
                        try
                        {
                            string[] pieces = programToRunConfigString.Split('|');
                            if (pieces.Length == 2)
                            {
                                string program = pieces[0];
                                string arguments = pieces[1];
                                Process.Start(program, arguments.Replace("###IPADDRESS###", bannedIp.Key).Replace("###USERNAME###", bannedIp.Value));
                            }
                            else
                            {
                                throw new ArgumentException("Invalid config option for process to run on ban: " + programToRunConfigString);
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Exception("Failed to execute process on ban", ex);
                        }
                    }
                    if (IPBanDelegate != null)
                    {
                        try
                        {
                            IPBanDelegate.IPAddressBanned(bannedIp.Key, bannedIp.Value, true);
                        }
                        catch (Exception ex)
                        {
                            Log.Exception("Error in delegate IPAddressBanned", ex);
                        }
                    }
                }
            });
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
            AddPendingIPAddressAndUserName(ipAddress, userName);
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
            foreach (ExpressionsToBlockGroup group in Config.Expressions.Groups)
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
                query = new EventLogQuery(null, PathType.LogName, queryString);
                watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += EventRecordWritten;
                watcher.Enabled = true;
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

        private void RunTests()
        {
            string[] xmlTestStrings = new string[]
            {
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

            for (int i = 0; i < 255 && run; i++)
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
                ThreadPool.QueueUserWorkItem(new WaitCallback(DelayTest), xml);
            }
        }

        private void DelayTest(object stateInfo)
        {
            Thread.Sleep(15000);
            ProcessEventViewerXml((string)stateInfo);
        }

        private void Initialize()
        {
            run = true;
            ReadAppSettings();
            IPBanWindowsFirewall.RulePrefix = Config.RuleName;
            ProcessBanFileOnStart();
            SetupEventLogWatcher();
            LogInitialConfig();
            if (IPBanDelegate != null)
            {
                IPBanDelegate.Start(this);
            }
        }

        private void CheckForExpiredIP()
        {
            List<string> ipAddressesToForget = new List<string>();
            bool fileChanged = false;
            KeyValuePair<string, DateTime>[] blockList;
            KeyValuePair<string, IPBlockCount>[] ipBlockCountList;

            // brief lock, we make copies of everything and work on the copies so we don't hold a lock too long
            lock (ipAddressesAndBlockCounts)
            {
                blockList = ipAddressesAndBanDate.ToArray();
                ipBlockCountList = ipAddressesAndBlockCounts.ToArray();
            }

            DateTime now = CurrentDateTime;

            // Check the block list for expired IPs.
            foreach (KeyValuePair<string, DateTime> keyValue in blockList)
            {
                // never un-ban a blacklisted entry
                if (Config.IsBlackListed(keyValue.Key))
                {
                    continue;
                }
                // if ban duration has expired or ip is white listed, un-ban
                else if ((Config.BanTime.Ticks > 0 && (now - keyValue.Value) > Config.BanTime) || Config.IsWhiteListed(keyValue.Key))
                {
                    Log.Write(LogLevel.Error, "Un-banning ip address {0}", keyValue.Key);
                    lock (ipAddressesAndBlockCounts)
                    {
                        // take the ip out of the lists and mark the file as changed so that the ban script re-runs without this ip
                        ipAddressesAndBanDate.Remove(keyValue.Key);
                        ipAddressesAndBlockCounts.Remove(keyValue.Key);
                        fileChanged = true;
                    }
                }
            }

            // if we are allowing ip addresses failed login attempts to expire and get reset back to 0
            if (Config.ExpireTime.TotalSeconds > 0)
            {
                // Check the list of failed login attempts, that are not yet blocked, for expired IPs.
                foreach (KeyValuePair<string, IPBlockCount> keyValue in ipBlockCountList)
                {
                    if (Config.IsBlackListed(keyValue.Key))
                    {
                        continue;
                    }

                    // Find this IP address in the block list.
                    var block = from b in blockList
                                where b.Key == keyValue.Key
                                select b;

                    // If this IP is not yet blocked, and an invalid login attempt has not been made in the past timespan, see if we should forget it.
                    if (block.Count() == 0)
                    {
                        TimeSpan elapsed = (now - keyValue.Value.LastFailedLogin);

                        if (elapsed > Config.ExpireTime)
                        {
                            Log.Write(LogLevel.Info, "Forgetting ip address {0}", keyValue.Key);
                            ipAddressesToForget.Add(keyValue.Key);
                        }
                    }
                }

                // Remove the IPs that have expired.
                lock (ipAddressesAndBlockCounts)
                {
                    foreach (string ip in ipAddressesToForget)
                    {
                        // no need to mark the file as changed because this ip was not banned, it only had some number of failed login attempts
                        ipAddressesAndBlockCounts.Remove(ip);
                    }
                }

                // notify delegate outside of lock
                if (IPBanDelegate != null)
                {
                    // notify delegate of unban in background thread
                    RunTask(() =>
                    {
                        foreach (string ip in ipAddressesToForget)
                        {
                            try
                            {
                                IPBanDelegate.IPAddressBanned(ip, null, false);
                            }
                            catch (Exception ex)
                            {
                                Log.Exception("Error in delegate IPAddressBanned", ex);
                            }
                        }
                    });
                }
            }

            // if the file changed, re-run the ban script with the updated list of ip addresses
            needsBanScript = fileChanged;
        }

        private static bool IpAddressIsInRange(string ipAddress, string cidrMask)
        {
            try
            {
                string[] parts = cidrMask.Split('/');
                int IP_addr = BitConverter.ToInt32(IPAddress.Parse(parts[0]).GetAddressBytes(), 0);
                int CIDR_addr = BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0);
                int CIDR_mask = IPAddress.HostToNetworkOrder(-1 << (32 - int.Parse(parts[1])));
                return ((IP_addr & CIDR_mask) == (CIDR_addr & CIDR_mask));
            }
            catch
            {
                return false;
            }
        }

        private void UpdateDelegate()
        {
            if (IPBanDelegate == null)
            {
                return;
            }

            try
            {
                // we don't do the delegate update in a background thread because if it changes state, we need that done on the main loop thread
                if (IPBanDelegate.Update())
                {
                    bool changed = false;
                    DateTime now = CurrentDateTime;

                    // sync up the blacklist and whitelist from the delegate
                    lock (ipAddressesAndBlockCounts)
                    {
                        foreach (string ip in IPBanDelegate.EnumerateBlackList())
                        {
                            // ban all blacklisted ip addresses
                            if (!ipAddressesAndBanDate.ContainsKey(ip))
                            {
                                changed = true;
                                ipAddressesAndBanDate[ip] = now;
                                ipAddressesAndBlockCounts[ip] = new IPBlockCount { Count = Config.FailedLoginAttemptsBeforeBan, LastFailedLogin = now };
                            }
                        }
                        List<string> unban = new List<string>();
                        foreach (KeyValuePair<string, DateTime> kv in ipAddressesAndBanDate)
                        {
                            if (!IPBanDelegate.IsBlacklisted(kv.Key))
                            {
                                changed = true;
                                unban.Add(kv.Key);
                            }
                        }
                        foreach (string ip in unban)
                        {
                            ipAddressesAndBanDate.Remove(ip);
                            ipAddressesAndBlockCounts.Remove(ip);
                        }
                        foreach (string ip in IPBanDelegate.EnumerateWhiteList())
                        {
                            // un-ban all whitelisted ip addresses
                            if (ipAddressesAndBanDate.ContainsKey(ip))
                            {
                                ipAddressesAndBanDate.Remove(ip);
                                ipAddressesAndBlockCounts.Remove(ip);
                                changed = true;
                            }
                            // check for subnet matches, unban any ip from the local subnet
                            else if (ip.Contains('/'))
                            {
                                foreach (string key in ipAddressesAndBanDate.Keys.ToArray())
                                {
                                    if (IpAddressIsInRange(key, ip))
                                    {
                                        ipAddressesAndBanDate.Remove(ip);
                                        ipAddressesAndBlockCounts.Remove(ip);
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                    needsBanScript = changed;
                }
            }
            catch (Exception ex)
            {
                Log.Exception("Error in delegate Update", ex);
            }
        }

        private void GetUrl(UrlType urlType)
        {
            if ((urlType == UrlType.Start && gotStartUrl) || string.IsNullOrWhiteSpace(LocalIPAddressString) || string.IsNullOrWhiteSpace(FQDN))
            {
                return;
            }
            else if (urlType == UrlType.Stop)
            {
                gotStartUrl = false;
            }
            string url;
            switch (urlType)
            {
                case UrlType.Start: url = Config.GetUrlStart; break;
                case UrlType.Stop: url = Config.GetUrlStop; break;
                case UrlType.Update: url = Config.GetUrlUpdate; break;
                case UrlType.Config: url = Config.GetUrlConfig; break;
                default: return;
            }

            if (!string.IsNullOrWhiteSpace(url))
            {
                Assembly a = IPBanService.GetIPBanAssembly();
                url = url.Replace("###IPADDRESS###", WebUtility.UrlEncode(LocalIPAddressString))
                    .Replace("###MACHINENAME###", WebUtility.UrlEncode(FQDN))
                    .Replace("###VERSION###", WebUtility.UrlEncode(a.GetName().Version.ToString()))
                    .Replace("###GUID###", WebUtility.UrlEncode(MachineGuid));
                RunTask(() =>
                {
                    try
                    {
                        byte[] bytes = RequestMaker.DownloadDataAsync(url).ConfigureAwait(false).GetAwaiter().GetResult();
                        if (urlType == UrlType.Start)
                        {
                            gotStartUrl = true;
                        }
                        else if (urlType == UrlType.Update)
                        {
                            // if the update url sends bytes, we assume a software update, and run the result as an .exe
                            if (bytes.Length != 0)
                            {
                                string tempFile = Path.Combine(Path.GetTempPath(), "IPBanServiceUpdate.exe");
                                File.WriteAllBytes(tempFile, bytes);

                                // however you are doing the update, you must allow -c and -d parameters
                                // pass -c to tell the update executable to delete itself when done
                                // pass -d for a directory which tells the .exe where this service lives
                                string args = "-c \"-d=" + AppDomain.CurrentDomain.BaseDirectory + "\"";
                                Process.Start(tempFile, args);
                            }
                        }
                        else if (urlType == UrlType.Config && bytes.Length != 0)
                        {
                            UpdateConfig(Encoding.UTF8.GetString(bytes));
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Exception(ex, "Error getting url of type {0} at {1}", urlType, url);
                    }
                });
            }
        }

        private void CycleTask()
        {
            System.Diagnostics.Stopwatch timer = new Stopwatch();
            try
            {
                while (run)
                {
                    timer.Restart();
                    RunCycle();
                    TimeSpan nextWait = Config.CycleTime - timer.Elapsed;
                    if (nextWait.TotalMilliseconds < 1.0)
                    {
                        nextWait = TimeSpan.FromMilliseconds(1.0);
                    }
                    cycleEvent.WaitOne(nextWait);
                }
            }
            catch (Exception ex)
            {
                Log.Exception(ex);
            }
        }

        /// <summary>
        /// Manually run one cycle. This is called automatically, unless ManualCycle is true.
        /// </summary>
        public void RunCycle()
        {
            ReadAppSettings();
            SetNetworkInfo();
            UpdateDelegate();
            CheckForExpiredIP();
            ProcessPendingIPAddresses();
            if (needsBanScript)
            {
                needsBanScript = false;
                ExecuteBanScript();
            }
        }

        /// <summary>
        /// Process xml from event viewer
        /// </summary>
        /// <param name="xml"></param>
        public void ProcessEventViewerXml(string xml)
        {
            Log.Write(LogLevel.Info, "Processing xml: {0}", xml);

            XmlDocument doc = ParseXml(xml);
            ExtractIPAddressAndUserNameFromXml(doc, out string ipAddress, out string userName);
            ProcessIPAddressAndUserName(ipAddress, userName, doc);
        }

        /// <summary>
        /// Add an ip address to be checked for banning later
        /// </summary>
        /// <param name="ipAddress">IP Address, required</param>
        /// <param name="userName">User Name, optional</param>
        public void AddPendingIPAddressAndUserName(string ipAddress, string userName = null)
        {
            lock (pendingIPAddresses)
            {
                PendingIPAddress existing = pendingIPAddresses.FirstOrDefault(p => p.IPAddress == ipAddress && p.UserName == userName);
                if (existing == null)
                {
                    existing = new PendingIPAddress { IPAddress = ipAddress, UserName = userName, DateTime = CurrentDateTime };
                    pendingIPAddresses.Add(existing);
                }
                existing.Counter++;
            }
        }

        /// <summary>
        /// Get an ip address and user name out of text using regex
        /// </summary>
        /// <param name="regex">Regex</param>
        /// <param name="text">Text</param>
        /// <param name="ipAddress">Found ip address or null if none</param>
        /// <param name="userName">Found user name or null if none</param>
        /// <returns>True if a regex match was found, false otherwise</returns>
        public static bool GetIPAddressAndUserNameFromRegex(Regex regex, string text, ref string ipAddress, ref string userName)
        {
            bool foundMatch = false;

            foreach (Match m in regex.Matches(text))
            {
                if (!m.Success)
                {
                    continue;
                }

                // check for a user name
                Group userNameGroup = m.Groups["username"];
                if (userNameGroup != null && userNameGroup.Success)
                {
                    userName = (userName ?? userNameGroup.Value.Trim());
                }

                // check if the regex had an ipadddress group
                Group ipAddressGroup = m.Groups["ipaddress"];
                if (ipAddressGroup != null && ipAddressGroup.Success && !string.IsNullOrWhiteSpace(ipAddressGroup.Value))
                {
                    string tempIPAddress = ipAddressGroup.Value.Trim();
                    if (IPAddress.TryParse(tempIPAddress, out IPAddress tmp))
                    {
                        ipAddress = tempIPAddress;
                        foundMatch = true;
                        break;
                    }

                    // Check Host by name
                    Log.Write(LogLevel.Info, "Parsing as IP failed, checking dns '{0}'", tempIPAddress);
                    try
                    {
                        IPHostEntry entry = Dns.GetHostEntry(tempIPAddress);
                        if (entry != null && entry.AddressList != null && entry.AddressList.Length > 0)
                        {
                            ipAddress = entry.AddressList.FirstOrDefault().ToString();
                            Log.Write(LogLevel.Info, "Dns result '{0}' = '{1}'", tempIPAddress, ipAddress);
                            foundMatch = true;
                            break;
                        }
                    }
                    catch
                    {
                        Log.Write(LogLevel.Info, "Parsing as dns failed '{0}'", tempIPAddress);
                    }
                }
                else
                {
                    // found a match but no ip address, that is OK.
                    foundMatch = true;
                }
            }

            if (!foundMatch)
            {
                ipAddress = null;
            }

            return foundMatch;
        }

        /// <summary>
        /// Ban/unban an ip address
        /// </summary>
        /// <param name="ip">IP address to ban or unban</param>
        /// <param name="ban">True to ban, false to unban</param>
        public void BanIpAddress(string ip, bool ban)
        {
            ip = ip?.Trim();
            if (string.IsNullOrWhiteSpace(ip))
            {
                return;
            }
            else if (ban)
            {
                if (!Config.IsWhiteListed(ip))
                {
                    lock (ipAddressesAndBlockCounts)
                    {
                        ipAddressesAndBanDate[ip] = CurrentDateTime;
                        ipAddressesAndBlockCounts[ip] = new IPBlockCount(CurrentDateTime, Config.FailedLoginAttemptsBeforeBan);
                    }
                }
            }
            else
            {
                lock (ipAddressesAndBlockCounts)
                {
                    ipAddressesAndBanDate.Remove(ip);
                    ipAddressesAndBlockCounts.Remove(ip);
                }
            }
        }

        /// <summary>
        /// Write a new config file
        /// </summary>
        /// <param name="xml">Xml of the new config file</param>
        public void UpdateConfig(string xml)
        {
            try
            {
                // Ensure valid xml before writing the file
                XmlDocument doc = new XmlDocument();
                using (XmlReader xmlReader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { CheckCharacters = false }))
                {
                    doc.Load(xmlReader);
                }
                string configFile = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
                string text = File.ReadAllText(configFile);

                // if the file changed, update it
                if (text != xml)
                {
                    lock (configLock)
                    {
                        File.WriteAllText(configFile, xml);
                    }
                }
            }
            catch
            {
            }
        }

        /// <summary>
        /// Stop the service, dispose of all resources
        /// </summary>
        public void Dispose()
        {
            if (!run)
            {
                return;
            }

            run = false;
            cycleEvent.Set();
            cycleTask?.Wait();
            cycleEvent.Dispose();
            GetUrl(UrlType.Stop);
            query = null;
            if (IPBanDelegate != null)
            {
                try
                {
                    IPBanDelegate.Stop();
                    IPBanDelegate.Dispose();
                }
                catch
                {
                }
                IPBanDelegate = null;
            }
            if (watcher != null)
            {
                watcher.Dispose();
                watcher = null;
            }
            Log.Write(LogLevel.Info, "Stopped IPBan service");
        }

        /// <summary>
        /// Initialize and start the service
        /// </summary>
        public void Start()
        {
            Log.Write(LogLevel.Info, "Started IPBan service");
            Initialize();
            if (RunTestsOnStart)
            {
                RunTests();
            }
            if (!ManualCycle)
            {
                cycleTask = Task.Run((Action)CycleTask);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configFilePath">Config file path or null for default</param>
        public IPBanService(string configFilePath = null)
        {
            this.configFilePath = (string.IsNullOrWhiteSpace(configFilePath) ? AppDomain.CurrentDomain.SetupInformation.ConfigurationFile : configFilePath);
            RequestMaker = this;
        }

        /// <summary>
        /// Get the IPBan assembly
        /// </summary>
        /// <returns>IPBan assembly</returns>
        public static Assembly GetIPBanAssembly()
        {
            return typeof(IPBanService).Assembly;
        }

        /// <summary>
        /// Calls Dispose
        /// </summary>
        public void Stop()
        {
            Dispose();
        }

        /// <summary>
        /// Implementation of IHttpRequestMaker
        /// </summary>
        /// <param name="url">Url</param>
        /// <returns>Task of bytes</returns>
        async Task<byte[]> IHttpRequestMaker.DownloadDataAsync(string url)
        {
            using (WebClient client = new WebClient())
            {
                Assembly a = (Assembly.GetEntryAssembly() ?? IPBanService.GetIPBanAssembly());
                client.UseDefaultCredentials = true;
                client.Headers["User-Agent"] = a.GetName().Name;
                return await client.DownloadDataTaskAsync(url);
            }
        }

        /// <summary>
        /// Http request maker, defaults to this
        /// </summary>
        public IHttpRequestMaker RequestMaker { get; set; }

        /// <summary>
        /// Whether to run unit tests on start. Default is false.
        /// </summary>
        public bool RunTestsOnStart { get; set; }

        /// <summary>
        /// Configuration
        /// </summary>
        public IPBanConfig Config { get; private set; }

        /// <summary>
        /// Local ip address
        /// </summary>
        public string LocalIPAddressString { get; private set; }

        /// <summary>
        /// Remote ip address
        /// </summary>
        public string RemoteIPAddressString { get; private set; }

        /// <summary>
        /// Fully qualified domain name
        /// </summary>
        public string FQDN { get; private set; }

        /// <summary>
        /// Machine guid, null/empty for none
        /// </summary>
        public string MachineGuid { get; set; }

        /// <summary>
        /// External delegate to allow external config, whitelist, blacklist, etc.
        /// </summary>
        public IIPBanDelegate IPBanDelegate { get; set; }

        /// <summary>
        /// Whether delegate callbacks and other tasks are multithreaded. Default is true. Set to false if unit or integration testing.
        /// </summary>
        public bool MultiThreaded { get; set; } = true;

        /// <summary>
        /// True if the cycle is manual, in which case RunCycle must be called periodically, otherwise if false RunCycle is called automatically.
        /// </summary>
        public bool ManualCycle { get; set; }
        
        private DateTime currentDateTime;
        /// <summary>
        /// Allows changing the current date time to facilitate testing of behavior over elapsed times
        /// </summary>
        public DateTime CurrentDateTime
        {
            get { return currentDateTime == default(DateTime) ? DateTime.UtcNow : currentDateTime; }
            set { currentDateTime = value; }
        }
    }
}
