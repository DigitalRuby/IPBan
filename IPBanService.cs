#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Permissions;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Xml;
using System.Text.RegularExpressions;

#endregion Imports

namespace IPBan
{
    public class IPBanService : ServiceBase
    {
        private const string fileScript = @"
pushd advfirewall firewall
{0} rule name=""{1}""{2}remoteip=""{3}"" action=block protocol=any dir=in
popd
";

        private IPBanConfig config;
        private bool addRule = true;
        private Thread serviceThread;
        private bool run;
        private EventLogQuery query;
        private EventLogWatcher watcher;
        private EventLogReader reader;
        private Dictionary<string, int> ipBlocker = new Dictionary<string, int>();
        private Dictionary<string, DateTime> ipBlockerDate = new Dictionary<string, DateTime>();

        private void ExecuteBanScript()
        {
            lock (ipBlocker)
            {
                string ipAddresesListForFile = string.Join(Environment.NewLine, ipBlockerDate.Keys);

                if (ipBlockerDate.Count == 0)
                {
                    DeleteRule();
                }
                else
                {
                    CreateRule();
                }

                File.WriteAllText(config.BanFile, ipAddresesListForFile);
            }
        }

        private void ReadAppSettings()
        {
            config = new IPBanConfig();
        }

        private void DeleteRule()
        {
            ProcessStartInfo info = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall firewall delete rule \"name=" + config.RuleName + "\"",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = true
            };
            Process.Start(info).WaitForExit();
            addRule = true;
        }

        private void CreateRule()
        {
            string ipAddresses = string.Join(",", ipBlockerDate.Keys);
            string verb = (addRule ? "add" : "set");
            string isNew = (addRule ? " " : " new ");
            string script = string.Format(fileScript, verb, config.RuleName, isNew, ipAddresses);
            string scriptFileName = "banscript.txt";
            File.WriteAllText(scriptFileName, script);
            Process.Start("netsh", "exec " + scriptFileName).WaitForExit();
            addRule = false;
        }

        private void ClearBannedIP()
        {
            if (File.Exists(config.BanFile))
            {
                lock (ipBlocker)
                {
                    DeleteRule();
                    File.Delete(config.BanFile);
                }
            }
        }

        private void ProcessXml(string xml)
        {
            Log.Write(LogLevel.Info, "Processing xml: {0}", xml);

            string ipAddress = null;
            XmlTextReader reader = new XmlTextReader(new StringReader(xml));
            reader.Namespaces = false;
            XmlDocument doc = new XmlDocument();
            doc.Load(reader);
            XmlNode keywordsNode = doc.SelectSingleNode("//Keywords");

            if (keywordsNode != null)
            {
                // we must match on keywords
                foreach (ExpressionsToBlockGroup group in config.Expressions.Groups.Where(g => g.Keywords == keywordsNode.InnerText))
                {
                    foreach (ExpressionToBlock expression in group.Expressions)
                    {
                        // we must find a node for each xpath expression
                        XmlNodeList nodes = doc.SelectNodes(expression.XPath);

                        if (nodes.Count == 0)
                        {
                            Log.Write(LogLevel.Warning, "No nodes found for xpath {0}", expression.XPath);
                            ipAddress = null;
                            break;
                        }

                        // if there is a regex, it must match
                        if (expression.Regex.Length == 0)
                        {
                            Log.Write(LogLevel.Info, "No regex, so counting as a match");
                        }
                        else
                        {
                            bool foundMatch = false;

                            foreach (XmlNode node in nodes)
                            {
                                Match m = expression.RegexObject.Match(node.InnerText);
                                if (m.Success)
                                {
                                    foundMatch = true;

                                    // check if the regex had an ipadddress group
                                    Group ipAddressGroup = m.Groups["ipaddress"];
                                    if (ipAddressGroup != null && ipAddressGroup.Success && !string.IsNullOrWhiteSpace(ipAddressGroup.Value))
                                    {
                                        ipAddress = ipAddressGroup.Value.Trim();
                                    }

                                    break;
                                }
                            }

                            if (!foundMatch)
                            {
                                // no match, move on to the next group to check
                                Log.Write(LogLevel.Warning, "Regex {0} did not match any nodes with xpath {1}", expression.Regex, expression.XPath);
                                ipAddress = null;
                                break;
                            }
                        }
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(ipAddress))
            {
                if (config.IsWhiteListed(ipAddress))
                {
                    Log.Write(LogLevel.Info, "Ignoring whitelisted ip address {0}", ipAddress);
                }
                else
                {
                    int count;
                    lock (ipBlocker)
                    {
                        ipBlocker.TryGetValue(ipAddress, out count);
                        count++;
                        ipBlocker[ipAddress] = count;
                        
                        if (count == config.FailedLoginAttemptsBeforeBan)
                        {
                            Log.Write(LogLevel.Error, "Banning ip address {0}", ipAddress);
                            ipBlockerDate[ipAddress] = DateTime.UtcNow;
                            ExecuteBanScript();
                        }
                        else if (count > config.FailedLoginAttemptsBeforeBan)
                        {
                            Log.Write(LogLevel.Info, "Go event with ip address {0}, count {1}, ip is already banned");
                        }
                        else
                        {
                            Log.Write(LogLevel.Info, "Got event with ip address {0}, count: {1}", ipAddress, count);
                        }
                    }
                }
            }
        }

        private void EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            EventRecord rec = e.EventRecord;
            string xml = rec.ToXml();

            ProcessXml(xml);            
        }

        private void SetupWatcher()
        {
            int id = 0;
            string queryString = "<QueryList>";
            foreach (ExpressionsToBlockGroup group in config.Expressions.Groups)
            {
                ulong keywordsDecimal = ulong.Parse(group.Keywords.Substring(2), NumberStyles.AllowHexSpecifier);
                queryString += "<Query Id='" + (++id).ToString() + "' Path='" + group.Path + "'><Select Path='" + group.Path + "'>*[System[(band(Keywords," + keywordsDecimal.ToString() + "))]]</Select></Query>";

                foreach (ExpressionToBlock expression in group.Expressions)
                {
                    expression.Regex = (expression.Regex ?? string.Empty).Trim();
                    expression.RegexObject = new Regex(expression.Regex, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);
                }
            }
            queryString += "</QueryList>";
            query = new EventLogQuery("Security", PathType.LogName, queryString);
            reader = new EventLogReader(query);
            reader.BatchSize = 10;
            watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += new EventHandler<EventRecordWrittenEventArgs>(EventRecordWritten);
            watcher.Enabled = true;
        }

        private void RunTests()
        {
            string xml1 = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>99.99.99.99</Data><Data Name='IpPort'>52813</Data></EventData></Event>";
            string xml2 = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>127.0.0.1</Data><Data Name='IpPort'>52813</Data></EventData></Event>";
            string xml3 = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2012-04-05T20:26:30.000000000Z'/><EventRecordID>408488</EventRecordID><Channel>Application</Channel><Computer>dallas</Computer><Security/></System><EventData><Data>sa1</Data><Data> Reason: Could not find a login matching the name provided.</Data><Data> [CLIENT: 99.99.99.100]</Data><Binary>184800000E00000007000000440041004C004C00410053000000070000006D00610073007400650072000000</Binary></EventData></Event>";
            string xml4 = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID><Level>0</Level><Task>4</Task><Keywords>0x90000000000000</Keywords><TimeCreated SystemTime='2012-04-05T20:26:30.000000000Z'/><EventRecordID>408488</EventRecordID><Channel>Application</Channel><Computer>dallas</Computer><Security/></System><EventData><Data>sa1</Data><Data> Reason: Could not find a login matching the name provided.</Data><Data> [CLIENT: 0.0.0.0]</Data><Binary>184800000E00000007000000440041004C004C00410053000000070000006D00610073007400650072000000</Binary></EventData></Event>";
            
            ProcessXml(xml1);
            ProcessXml(xml2);
            ProcessXml(xml3);
            ProcessXml(xml4);
        }

        private void Initialize()
        {
            ReadAppSettings();
            ClearBannedIP();
            SetupWatcher();

#if DEBUG

            RunTests();            

#endif

        }

        private void CheckForExpiredIP()
        {
            bool fileChanged = false;
            KeyValuePair<string, DateTime>[] blockList;
            lock (ipBlocker)
            {
                blockList = ipBlockerDate.ToArray();
            }

            DateTime now = DateTime.UtcNow;

            foreach (KeyValuePair<string, DateTime> keyValue in blockList)
            {
                TimeSpan elapsed = now - keyValue.Value;

                if (elapsed.Days > 0)
                {
                    Log.Write(LogLevel.Error, "Un-banning ip address {0}", keyValue.Key);
                    lock (ipBlocker)
                    {
                        ipBlockerDate.Remove(keyValue.Key);
                        ipBlocker.Remove(keyValue.Key);
                        fileChanged = true;
                    }
                }
            }

            if (fileChanged)
            {
                ExecuteBanScript();
            }
        }

        private void ServiceThread()
        {
            Initialize();

            DateTime lastCycle = DateTime.UtcNow;
            TimeSpan sleepInterval = TimeSpan.FromSeconds(1.0d);

            while (run)
            {
                Thread.Sleep(sleepInterval);
                DateTime now = DateTime.UtcNow;
                if ((now - lastCycle) >= config.CycleTime)
                {
                    lastCycle = now;
                    CheckForExpiredIP();
                }
            }
        }

        protected override void OnStart(string[] args)
        {
            base.OnStart(args);

            Log.Write(LogLevel.Info, "Started IPBan service");
            run = true;
            serviceThread = new Thread(new ThreadStart(ServiceThread));
            serviceThread.Start();
        }

        protected override void OnStop()
        {
            base.OnStop();

            run = false;
            query = null;
            watcher = null;

            Log.Write(LogLevel.Info, "Stopped IPBan service");
        }

        public static void RunService(string[] args)
        {
            System.ServiceProcess.ServiceBase[] ServicesToRun;
            ServicesToRun = new System.ServiceProcess.ServiceBase[] { new IPBanService() };
            System.ServiceProcess.ServiceBase.Run(ServicesToRun);
        }

        public static void RunConsole(string[] args)
        {
            IPBanService svc = new IPBanService();
            svc.OnStart(args);
            Console.WriteLine("Press ENTER to quit");
            Console.ReadLine();
            svc.OnStop();
        }

        public static void Main(string[] args)
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            if (args.Length != 0 && args[0] == "debug")
            {
                RunConsole(args);
            }
            else
            {
                RunService(args);
            }
        }
    }
}


/*

<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-02-19T05:10:05.080038000Z'/><EventRecordID>1633642</EventRecordID><Correlation/><Execution ProcessID='544' ThreadID='4472'/><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>user</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x1959c</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>183.62.15.154</Data><Data Name='IpPort'>22272</Data></EventData></Event>

*/