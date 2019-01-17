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
            bool testing = false; // TODO: Change to true if we are running Mac tests
            IPBanService service = IPBanService.CreateService(testing);
            service.Start();
            IPBanLog.Warn("IPBan Mac Service Running, Press Ctrl-C to quit.");
            ManualResetEvent wait = new ManualResetEvent(false);
            wait.WaitOne();
        }
    }
}


