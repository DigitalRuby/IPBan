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
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Xml;
using System.Text.RegularExpressions;

#endregion Imports

namespace IPBan
{
    public class IPBanServiceRunner : ServiceBase
    {
        private static IPBanServiceRunner runner = new IPBanServiceRunner();
        private static IPBanService service = new IPBanService();

        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            service.Start();
        }

        protected override void OnStop()
        {
            base.OnStop();
            service.Stop();
        }

        public int RunService(string[] args)
        {
            System.ServiceProcess.ServiceBase[] ServicesToRun;
            ServicesToRun = new System.ServiceProcess.ServiceBase[] { this };
            System.ServiceProcess.ServiceBase.Run(ServicesToRun);
            return 0;
        }

        public int RunConsole(string[] args)
        {
            if (args.Contains("test", StringComparer.OrdinalIgnoreCase))
            {
                service.RunTestsOnStart = true;
            }
            service.Start();
            Console.WriteLine("Press ENTER to quit");
            Console.ReadLine();
            service.Stop();
            return 0;
        }

        public static int Main(string[] args)
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
            runner = new IPBanServiceRunner();
            if (args.Length != 0 && args[0] == "debug")
            {
                return runner.RunConsole(args);
            }
            else
            {
                return runner.RunService(args);
            }
        }
    }
}
