/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
            IPBanExtensionMethods.RequireAdministrator();

            if (args.Length != 0 && args[0].Equals("info", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("System info: {0}", IPBanOS.OSString());
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                IPBanWindowsApp.WindowsMain(args);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                IPBanLinuxApp.LinuxMain(args);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                throw new PlatformNotSupportedException("Mac OSX is not yet supported, but may be in the future.");
                //IPBanMacApp.MacMain(args);
            }
            else
            {
                throw new PlatformNotSupportedException();
            }
            return 0;
        }
    }
}
