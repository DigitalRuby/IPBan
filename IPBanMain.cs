using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace IPBan
{
    public static class IPBanMain
    {
        /// <summary>
        /// The instance type of the IPBanService to create, null for default
        /// This could be called by another application embedded this application
        /// with a custom service class.
        /// </summary>
        public static Type InstanceType { get; set; }

        public static int Main(string[] args)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                IPBanWindowsApp.WindowsMain(args, InstanceType);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                IPBanLinuxApp.LinuxMain(args, InstanceType);
            }
            else
            {
                throw new PlatformNotSupportedException();
            }
            return 0;
        }
    }
}
