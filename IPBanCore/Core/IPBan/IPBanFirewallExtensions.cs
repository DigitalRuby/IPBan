/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://www.digitalruby.com

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
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Firewall extension methods
    /// </summary>
    public static class IPBanFirewallExtensions
    {
        /// <summary>
        /// Check if ip address is allowed. Only use from tests.
        /// </summary>
        /// <param name="firewall">Firewall</param>
        /// <param name="ipAddress">IP addresses</param>
        /// <param name="ruleName">Rule name</param>
        /// <param name="port">Port</param>
        /// <returns>True if allowed, false otherwise</returns>
        public static bool IsIPAddressAllowed(this IIPBanFirewall firewall, string ipAddress, out string ruleName, int port = 0)
        {
            var result = firewall.Query([new IPEndPoint(IPAddressRange.Parse(ipAddress).Begin, port)]);
            if (result.Count == 0)
            {
                ruleName = null;
                return false;
            }
            ruleName = result[0].ruleName;
            return result[0].allowed;
        }

        /// <summary>
        /// Check if ip is blocked. Only use from tests.
        /// </summary>
        /// <param name="firewall">Firewall</param>
        /// <param name="ipAddress">IP</param>
        /// <param name="port">Port</param>
        /// <returns>True if blocked, false otherwise</returns>
        public static bool IsIPAddressBlocked(this IIPBanFirewall firewall, string ipAddress, int port = 0)
        {
            return IsIPAddressBlocked(firewall, ipAddress, out _, port);
        }

        /// <summary>
        /// Check if ip is blocked. Only use from tests.
        /// </summary>
        /// <param name="firewall">Firewall</param>
        /// <param name="ipAddress">IP</param>
        /// <param name="ruleName">Found rule name</param>
        /// <param name="port">Port</param>
        /// <returns>True if blocked, false otherwise</returns>
        public static bool IsIPAddressBlocked(this IIPBanFirewall firewall, string ipAddress, out string ruleName, int port = 0)
        {
            var result = firewall.Query([new IPEndPoint(IPAddressRange.Parse(ipAddress).Begin, port)]);
            if (result.Count == 0)
            {
                ruleName = null;
                return false;
            }
            ruleName = result[0].ruleName;
            return result[0].blocked;
        }
    }
}
