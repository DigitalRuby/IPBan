using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace IPBan
{
    public enum IPBanOperatingSystem
    {
        Windows,
        Linux
    }

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
