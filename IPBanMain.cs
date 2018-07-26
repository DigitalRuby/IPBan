using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace IPBan
{
    public static class IPBanMain
    {
        public static int Main(string[] args)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                IPBanWindowsApp.WindowsMain(args);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                IPBanLinuxApp.LinuxMain(args);
            }
            else
            {
                throw new PlatformNotSupportedException();
            }
            return 0;
        }
    }
}
