using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace IPBan
{
    public class IPBanLinuxApp
    {
        public static void Main(string[] args)
        {
            IPBanService service = IPBanService.CreateService();
            service.Start();
            Log.Write(NLog.LogLevel.Warn, "IPBan Linux Service Running, Press Ctrl-C to quit.");
            ManualResetEvent wait = new ManualResetEvent(false);
            wait.WaitOne();
        }
    }
}


