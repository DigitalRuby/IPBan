#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.ServiceProcess;

#endregion Imports

namespace IPBan
{
    public class IPBanWindowsApp : ServiceBase
    {
        private static IPBanService service;
        private static IPBanWindowsEventViewer eventViewer;

        private static void CreateService(bool testing)
        {
            if (service != null)
            {
                service.Dispose();
            }
            service = IPBanService.CreateService(testing);
            service.Start();
            eventViewer = new IPBanWindowsEventViewer(service);
        }

        private static void RequireAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    throw new InvalidOperationException("Application must be run as administrator");
                }
            }
        }

        private static void TestDB()
        {
            IPBanDB db = new IPBanDB();
            db.Truncate(true);
            const string ip = "10.10.10.10";
            DateTime dt1 = new DateTime(2018, 1, 1, 1, 1, 1, 1, DateTimeKind.Utc);
            DateTime dt2 = new DateTime(2019, 1, 1, 1, 1, 1, 1, DateTimeKind.Utc);
            int count = db.IncrementFailedLoginCount(ip, dt1, 1);
            if (count != 1)
            {
                throw new InvalidDataException("Failed login count is wrong");
            }
            count = db.IncrementFailedLoginCount(ip, dt2, 2);
            if (count != 3)
            {
                throw new InvalidDataException("Failed login count is wrong");
            }
            if (!db.SetBanDate(ip, dt2))
            {
                throw new InvalidDataException("Ban date should have been set");
            }
            if (db.SetBanDate(ip, dt2 + TimeSpan.FromDays(1.0))) // no effect
            {
                throw new InvalidDataException("Ban date should not have been set");
            }
            IPBanDB.IPAddressEntry e = db.GetIPAddress(ip);
            if (e.IPAddress != ip)
            {
                throw new InvalidDataException("Wrong ip address from db");
            }
            if (e.LastFailedLogin != dt2)
            {
                throw new InvalidDataException("Last failed login datetime is not correct");
            }
            if (e.FailedLoginCount != 3)
            {
                throw new InvalidDataException("Last failed login count is not correct");
            }
            if (e.BanDate != dt2)
            {
                throw new InvalidDataException("Ban date is not correct");
            }
            count = db.IncrementFailedLoginCount("5.5.5.5", dt1, 2);
            if (count != 2)
            {
                throw new InvalidDataException("Count of failed login is wrong");
            }
            count = db.GetIPAddressCount();
            if (count != 2)
            {
                throw new InvalidDataException("Count of all ip is wrong");
            }
            count = db.GetBannedIPAddressCount();
            if (count != 1)
            {
                throw new InvalidDataException("Count of banned ip is wrong");
            }
            DateTime? banDate = db.GetBanDate(ip);
            if (banDate != dt2)
            {
                throw new InvalidDataException("Ban date is wrong");
            }
            banDate = db.GetBanDate("5.5.5.5");
            if (banDate != null)
            {
                throw new InvalidDataException("Ban date is wrong");
            }
            db.SetBannedIPAddresses(new string[] { ip, "5.5.5.5", "5.5.5.6", "::5.5.5.5", "6.6.6.6", "11.11.11.11", "12.12.12.12", "11.11.11.11" }, dt2);
            count = db.GetBannedIPAddressCount();
            if (count != 7)
            {
                throw new InvalidDataException("Count of banned ip is wrong");
            }
            IPAddressRange range = IPAddressRange.Parse("5.5.5.0/24");
            count = 0;
            foreach (string ipAddress in db.DeleteIPAddresses(range))
            {
                if (ipAddress != "5.5.5.5" && ipAddress != "5.5.5.6")
                {
                    throw new InvalidDataException("Wrong ip address deleted from range");
                }
                count++;
            }
            db.SetBannedIPAddresses(new string[] { "5.5.5.5", "5.5.5.6" }, dt2);
            if (db.IncrementFailedLoginCount("9.9.9.9", dt2, 1) != 1)
            {
                throw new InvalidDataException("Failed login count is wrong");
            }
            count = 0;
            range = new IPAddressRange { Begin = System.Net.IPAddress.Parse("::5.5.5.0"), End = System.Net.IPAddress.Parse("::5.5.5.255") };
            foreach (string ipAddress in db.DeleteIPAddresses(range))
            {
                if (ipAddress != "::5.5.5.5")
                {
                    throw new InvalidDataException("Wrong ip address deleted from range");
                }
                count++;
            }
            if (count != 1)
            {
                throw new InvalidDataException("Wrong number of ip addresses deleted from range");
            }
            IPBanDB.IPAddressEntry[] ipAll = db.EnumerateIPAddresses().ToArray();
            if (ipAll.Length != 7)
            {
                throw new InvalidDataException("IP address count is wrong");
            }
            IPBanDB.IPAddressEntry[] bannedIpAll = db.EnumerateBannedIPAddresses().ToArray();
            if (bannedIpAll.Length != 6)
            {
                throw new InvalidDataException("Banned ip address count is wrong");
            }
            Console.WriteLine("IPBanDB test complete, no errors");
        }

        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            CreateService(false);
        }

        protected override void OnStop()
        {
            service.Stop();
            service = null;
            base.OnStop();
        }

        protected override void OnSessionChange(SessionChangeDescription changeDescription)
        {
            base.OnSessionChange(changeDescription);
        }

        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            return base.OnPowerEvent(powerStatus);
        }

        protected virtual void Preshutdown()
        {
        }

        protected override void OnCustomCommand(int command)
        {
            // command is SERVICE_CONTROL_PRESHUTDOWN
            if (command == 0x0000000F)
            {
                Preshutdown();
            }
            else
            {
                base.OnCustomCommand(command);
            }
        }

        public IPBanWindowsApp()
        {
            CanShutdown = false;
            CanStop = CanHandleSessionChangeEvent = CanHandlePowerEvent = true;
            var acceptedCommandsField = typeof(ServiceBase).GetField("acceptedCommands", BindingFlags.Instance | BindingFlags.NonPublic);
            if (acceptedCommandsField != null)
            {
                int acceptedCommands = (int)acceptedCommandsField.GetValue(this);
                acceptedCommands |= 0x00000100; // SERVICE_ACCEPT_PRESHUTDOWN;
                acceptedCommandsField.SetValue(this, acceptedCommands);
            }
        }

        public static int RunWindowsService(string[] args)
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
            System.ServiceProcess.ServiceBase[] ServicesToRun;
            ServicesToRun = new System.ServiceProcess.ServiceBase[] { new IPBanWindowsApp() };
            System.ServiceProcess.ServiceBase.Run(ServicesToRun);
            return 0;
        }

        public static int RunConsole(string[] args)
        {
            if (args.Contains("test-ipbandb", StringComparer.OrdinalIgnoreCase))
            {
                TestDB();
                return 0;
            }

            bool test = args.Contains("test", StringComparer.OrdinalIgnoreCase);
            bool test2 = args.Contains("test-eventViewer", StringComparer.OrdinalIgnoreCase);
            CreateService(test || test2);
            if (test)
            {
                eventViewer.RunTests();
            }
            else if (test2)
            {
                eventViewer.TestAllEntries();
            }
            else
            {
                Console.WriteLine("Press ENTER to quit");
                Console.ReadLine();
            }
            service.Stop();
            return 0;
        }

        public static int ServiceEntryPoint(string[] args)
        {
            RequireAdministrator();
            if (Console.IsInputRedirected)
            {
                return IPBanWindowsApp.RunWindowsService(args);
            }
            else
            {
                return IPBanWindowsApp.RunConsole(args);
            }
        }

        public static int WindowsMain(string[] args)
        {
            return ServiceEntryPoint(args);
        }
    }
}
