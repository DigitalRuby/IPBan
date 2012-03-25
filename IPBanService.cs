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
        private ExpressionsToBlock expressions;
        private int failedLoginAttemptsBeforeBan = 5;
        private TimeSpan banTime = TimeSpan.FromDays(1.0d);
        private string banFile = "banlog.txt";
        private TimeSpan cycleTime = TimeSpan.FromMinutes(1.0d);
        private string rulePrefix = "BlockIPAddress";
        private readonly HashSet<string> whiteList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private Thread serviceThread;
        private bool run;
        private EventLogQuery query;
        private EventLogWatcher watcher;
        private EventLogReader reader;
        private Dictionary<string, int> ipBlocker = new Dictionary<string, int>();
        private Dictionary<string, DateTime> ipBlockerDate = new Dictionary<string, DateTime>();

        private void ReadAppSettings()
        {
            string value = ConfigurationManager.AppSettings["FailedLoginAttemptsBeforeBan"];
            failedLoginAttemptsBeforeBan = int.Parse(value);

            value = ConfigurationManager.AppSettings["BanTime"];
            banTime = TimeSpan.Parse(value);

            value = ConfigurationManager.AppSettings["BanFile"];
            banFile = value;
            if (!Path.IsPathRooted(banFile))
            {
                string exeFullPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                banFile = Path.Combine(Path.GetDirectoryName(exeFullPath), banFile);
            }

            value = ConfigurationManager.AppSettings["CycleTime"];
            cycleTime = TimeSpan.Parse(value);

            value = ConfigurationManager.AppSettings["RulePrefix"];
            rulePrefix = value;

            value = ConfigurationManager.AppSettings["Whitelist"];
            whiteList.Clear();
            if (!string.IsNullOrWhiteSpace(value))
            {
                foreach (string ip in value.Split(','))
                {
                    whiteList.Add(ip.Trim());
                }
            }

            expressions = (ExpressionsToBlock)System.Configuration.ConfigurationManager.GetSection("ExpressionsToBlock");
        }

        private void ClearBannedIP()
        {
            if (File.Exists(banFile))
            {
                lock (ipBlocker)
                {
                    string[] ips = File.ReadAllLines(banFile);

                    foreach (string ip in ips)
                    {
                        ProcessStartInfo info = new ProcessStartInfo
                        {
                            FileName = "netsh",
                            Arguments = "advfirewall firewall delete rule \"name=" + rulePrefix + ip + "\"",
                            CreateNoWindow = true,
                            WindowStyle = ProcessWindowStyle.Hidden,
                            UseShellExecute = true
                        };
                        Process.Start(info);
                    }

                    File.Delete(banFile);
                }
            }
        }

        private void ProcessXml(string xml)
        {
            string ipAddress = null;
            XmlTextReader reader = new XmlTextReader(new StringReader(xml));
            reader.Namespaces = false;
            XmlDocument doc = new XmlDocument();
            doc.Load(reader);
            XmlNode keywordsNode = doc.SelectSingleNode("//Keywords");

            if (keywordsNode != null)
            {
                // we must match on keywords
                foreach (ExpressionsToBlockGroup group in expressions.Groups.Where(g => g.Keywords == keywordsNode.InnerText))
                {
                    foreach (ExpressionToBlock expression in group.Expressions)
                    {
                        // we must find a node for each xpath expression
                        XmlNodeList nodes = doc.SelectNodes(expression.XPath);
                        bool failure = false;

                        if (nodes.Count == 0)
                        {
                            Console.WriteLine("No nodes found for xpath {0}", expression.XPath);
                            ipAddress = null;
                            break;
                        }

                        // if there is a regex, it must match
                        if (expression.Regex.Length != 0)
                        {
                            foreach (XmlNode node in nodes)
                            {
                                Match m = expression.RegexObject.Match(node.InnerText);
                                if (!m.Success)
                                {
                                    Console.WriteLine("Regex {0} did not match", expression.Regex);
                                    ipAddress = null;
                                    failure = true;
                                    break;
                                }

                                // check if the regex had an ipadddress group
                                Group ipAddressGroup = m.Groups["ipaddress"];
                                if (ipAddressGroup != null && ipAddressGroup.Success && !string.IsNullOrWhiteSpace(ipAddressGroup.Value))
                                {
                                    ipAddress = ipAddressGroup.Value.Trim();
                                }
                            }

                            if (failure)
                            {
                                break;
                            }
                        }

                        if (ipAddress != null)
                        {
                            // found an ip, we are done
                            break;
                        }
                    }

                    if (ipAddress != null)
                    {
                        // found an ip, we are done
                        break;
                    }
                }
            }

            IPAddress ip;
            if (!string.IsNullOrWhiteSpace(ipAddress) && !whiteList.Contains(ipAddress) && IPAddress.TryParse(ipAddress, out ip) && ipAddress != "127.0.0.1")
            {
                int count;
                lock (ipBlocker)
                {
                    ipBlocker.TryGetValue(ipAddress, out count);
                    count++;
                    ipBlocker[ipAddress] = count;
                    Console.WriteLine("Got event with ip address {0}, count: {1}", ipAddress, count);
                    if (count == failedLoginAttemptsBeforeBan)
                    {
                        Console.WriteLine("Banning ip address {0}", ipAddress);
                        Process.Start("netsh", "advfirewall firewall add rule \"name=" + rulePrefix + ipAddress + "\" dir=in protocol=any action=block remoteip=" + ipAddress);
                        File.AppendAllText(banFile, ipAddress + Environment.NewLine);
                        ipBlockerDate[ipAddress] = DateTime.UtcNow;
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
            foreach (ExpressionsToBlockGroup group in expressions.Groups)
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

        private void Initialize()
        {
            ReadAppSettings();
            ClearBannedIP();
            SetupWatcher();

            /*
            string xml = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' />
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' />
    <EventRecordID>1657124</EventRecordID>
    <Correlation />
    <Execution ProcessID='544' ThreadID='6616' />
    <Channel>Security</Channel>
    <Computer>69-64-65-123</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-18</Data>
    <Data Name='SubjectUserName'>69-64-65-123$</Data>
    <Data Name='SubjectDomainName'>WORKGROUP</Data>
    <Data Name='SubjectLogonId'>0x3e7</Data>
    <Data Name='TargetUserSid'>S-1-0-0</Data>
    <Data Name='TargetUserName'>forex</Data>
    <Data Name='TargetDomainName'>69-64-65-123</Data>
    <Data Name='Status'>0xc000006d</Data>
    <Data Name='FailureReason'>%%2313</Data>
    <Data Name='SubStatus'>0xc0000064</Data>
    <Data Name='LogonType'>10</Data>
    <Data Name='LogonProcessName'>User32 </Data>
    <Data Name='AuthenticationPackageName'>Negotiate</Data>
    <Data Name='WorkstationName'>69-64-65-123</Data>
    <Data Name='TransmittedServices'>-</Data>
    <Data Name='LmPackageName'>-</Data>
    <Data Name='KeyLength'>0</Data>
    <Data Name='ProcessId'>0x2e40</Data>
    <Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data>
    <Data Name='IpAddress'>85.17.84.74</Data>
    <Data Name='IpPort'>52813</Data>
  </EventData>
</Event>";

            ProcessXml(xml);
            */
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
                    Console.WriteLine("Un-banning ip address {0}", keyValue.Key);
                    Process.Start("netsh", "advfirewall firewall delete rule \"name=" + rulePrefix + keyValue.Key + "\"");
                    lock (ipBlocker)
                    {
                        ipBlockerDate.Remove(keyValue.Key);
                        fileChanged = true;
                    }
                }
            }

            if (fileChanged)
            {
                lock (ipBlocker)
                {
                    File.WriteAllLines(banFile, ipBlockerDate.Keys.ToArray());
                }
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
                if ((now - lastCycle) >= cycleTime)
                {
                    lastCycle = now;
                    CheckForExpiredIP();
                }
            }
        }

        protected override void OnStart(string[] args)
        {
            base.OnStart(args);

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

#if DEBUG

            RunConsole(args);

#else

            if (args[0] == "debug")
            {
                RunConsole(args);
            }
            else
            {
                RunService(args);
            }

#endif

        }
    }
}


/*

<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-02-19T05:10:05.080038000Z'/><EventRecordID>1633642</EventRecordID><Correlation/><Execution ProcessID='544' ThreadID='4472'/><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>user</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x1959c</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>183.62.15.154</Data><Data Name='IpPort'>22272</Data></EventData></Event>

*/