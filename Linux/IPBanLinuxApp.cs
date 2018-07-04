using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace IPBan
{
    public static class IPBanLinuxApp
    {
        public static void LinuxMain(string[] args, Type instanceType = null)
        {
            IPBanService service = IPBanService.CreateService(instanceType);
            service.Start();
            Log.Write(NLog.LogLevel.Warn, "IPBan Linux Service Running, Press Ctrl-C to quit.");
            ManualResetEvent wait = new ManualResetEvent(false);
            wait.WaitOne();
        }
    }
}


