using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Security.Permissions;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Xml;

namespace IPBan
{
    public class IPBanService : ServiceBase
    {
        private int failedLoginAttemptsBeforeBan = 5;
        private TimeSpan banTime = TimeSpan.FromDays(1.0d);
        private string banFile = "banlog.txt";
        private TimeSpan cycleTime = TimeSpan.FromMinutes(1.0d);
        private string rulePrefix = "BlockIPAddress";

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

        private void EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            EventRecord rec = e.EventRecord;
            string xml = rec.ToXml().Replace(" xmlns='http://schemas.microsoft.com/win/2004/08/events/event'", string.Empty);
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);
            XmlNode element = doc.SelectSingleNode("//Data[@Name='IpAddress']");
            if (element != null && element.InnerText != null && element.InnerText.Length != 0)
            {
                string ipToBlock = element.InnerText;

                int count;
                lock (ipBlocker)
                {
                    ipBlocker.TryGetValue(ipToBlock, out count);
                    if (count < failedLoginAttemptsBeforeBan && ++count == failedLoginAttemptsBeforeBan)
                    {
                        Process.Start("netsh", "advfirewall firewall add rule \"name=" + rulePrefix + ipToBlock + "\" dir=in protocol=any action=block remoteip=" + ipToBlock);
                        File.AppendAllText(banFile, ipToBlock + Environment.NewLine);

                        lock (ipBlockerDate)
                        {
                            ipBlockerDate[ipToBlock] = DateTime.UtcNow;
                        }
                    }
                    ipBlocker[ipToBlock] = count;
                }
            }
        }

        private void Initialize()
        {
            ReadAppSettings();
            ClearBannedIP();

            if (File.Exists(banFile))
            {
                foreach (string bannedIP in File.ReadAllLines(banFile))
                {
                    ipBlockerDate[bannedIP] = DateTime.Now.Subtract(banTime);
                }

                File.Delete(banFile);
            }

            // audit success: 9007199254740992
            // audit failure: 4503599627370496
            // (Level=1 or Level=2 or Level=3 or Level=4 or Level=0 or Level=5) and 
            string queryString = @"<QueryList><Query Id=""0"" Path=""Security""><Select Path=""Security"">*[System[(band(Keywords,4503599627370496))]]</Select></Query></QueryList>";
            query = new EventLogQuery("Security", PathType.LogName, queryString);
            reader = new EventLogReader(query);
            watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += new EventHandler<EventRecordWrittenEventArgs>(EventRecordWritten);
            watcher.Enabled = true;
        }

        private void CheckForExpiredIP()
        {
            bool fileChanged = false;
            KeyValuePair<string, DateTime>[] blockList;
            lock (ipBlockerDate)
            {
                blockList = ipBlockerDate.ToArray();
            }

            DateTime now = DateTime.UtcNow;

            foreach (KeyValuePair<string, DateTime> keyValue in blockList)
            {
                TimeSpan elapsed = now - keyValue.Value;

                if (elapsed.Days > 0)
                {
                    Process.Start("netsh", "advfirewall firewall delete rule \"name=" + rulePrefix + keyValue.Key + "\"");
                    lock (ipBlockerDate)
                    {
                        ipBlockerDate.Remove(keyValue.Key);
                        fileChanged = true;
                    }
                }
            }

            if (fileChanged)
            {
                lock (ipBlocker)
                lock (ipBlockerDate)
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

        public static void Main(string[] args)
        {

#if DEBUG

            IPBanService svc = new IPBanService();
            svc.OnStart(args);
            Console.WriteLine("Press ENTER to quit");
            Console.ReadLine();
            svc.OnStop();

#else

            System.ServiceProcess.ServiceBase[] ServicesToRun;
            ServicesToRun = new System.ServiceProcess.ServiceBase[] { new IPBanService() };
            System.ServiceProcess.ServiceBase.Run(ServicesToRun);

#endif

        }
    }
}


/*

<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-02-19T05:10:05.080038000Z'/><EventRecordID>1633642</EventRecordID><Correlation/><Execution ProcessID='544' ThreadID='4472'/><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>user</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x1959c</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>183.62.15.154</Data><Data Name='IpPort'>22272</Data></EventData></Event>

*/