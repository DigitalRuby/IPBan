using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace IPBan
{
    public static class IPBanMacApp
    {
        public static void MacMain(string[] args)
        {
            IPBanService service = IPBanService.CreateService();
            service.Start();
            IPBanLog.Warn("IPBan Mac Service Running, Press Ctrl-C to quit.");
            ManualResetEvent wait = new ManualResetEvent(false);
            wait.WaitOne();
        }
    }
}


