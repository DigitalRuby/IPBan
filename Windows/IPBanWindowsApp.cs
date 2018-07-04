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
using System.Reflection;
using System.Security.Permissions;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml;
using System.Text.RegularExpressions;

#endregion Imports

namespace IPBan
{
    public class IPBanWindowsApp : ServiceBase
    {
        private static IPBanService service;
        private static IPBanWindowsEventViewer eventViewer;
        private static Type instanceType;

        private static void CreateService()
        {
            if (service != null)
            {
                service.Dispose();
            }
            service = IPBanService.CreateService(instanceType);
            service.Start();
            eventViewer = new IPBanWindowsEventViewer(service);
        }

        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            CreateService();
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

        public static int RunService(string[] args)
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
            System.ServiceProcess.ServiceBase[] ServicesToRun;
            ServicesToRun = new System.ServiceProcess.ServiceBase[] { new IPBanWindowsApp() };
            System.ServiceProcess.ServiceBase.Run(ServicesToRun);
            return 0;
        }

        public static int RunConsole(string[] args)
        {
            CreateService();
            Console.WriteLine("Press ENTER to quit");
            if (args.Contains("test", StringComparer.OrdinalIgnoreCase))
            {
                eventViewer.RunTests();
            }
            Console.ReadLine();
            service.Stop();
            return 0;
        }

        public static int ServiceEntryPoint(string[] args)
        {
            if (Environment.UserInteractive)
            {
                return IPBanWindowsApp.RunConsole(args);
            }
            else
            {
                return IPBanWindowsApp.RunService(args);
            }
        }

        public static int WindowsMain(string[] args, Type instanceType)
        {
            IPBanWindowsApp.instanceType = instanceType;
            return ServiceEntryPoint(args);
        }
    }
}
