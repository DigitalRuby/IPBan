using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace IPBan
{
    /// <summary>
    /// Supported ipban operating systems
    /// </summary>
    public enum IPBanOperatingSystem
    {
        /// <summary>
        /// Windows
        /// </summary>
        Windows,

        /// <summary>
        /// Linux
        /// </summary>
        Linux,

        /// <summary>
        /// Macintosh / OS 10
        /// </summary>
        OSX
    }

    /// <summary>
    /// Mark a class as requiring a specific operating system
    /// </summary>
    [AttributeUsage(AttributeTargets.Class)]
    public class RequiredOperatingSystemAttribute : Attribute
    {
        public RequiredOperatingSystemAttribute(IPBanOperatingSystem os)
        {
            OperatingSystem = os;
        }

        public bool IsValid
        {
            get
            {
                switch (OperatingSystem)
                {
                    case IPBanOperatingSystem.Linux:
                        return RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

                    case IPBanOperatingSystem.Windows:
                        return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

                    default:
                        return false;
                }
            }
        }

        public IPBanOperatingSystem OperatingSystem { get; private set; }
    }
}
