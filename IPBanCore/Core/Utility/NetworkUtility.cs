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

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Network utility methods
    /// </summary>
    public static class NetworkUtility
    {
        // https://en.wikipedia.org/wiki/Reserved_IP_addresses

        /// <summary>
        /// First ipv4
        /// </summary>
        public static readonly System.Net.IPAddress FirstIPV4 = System.Net.IPAddress.Parse("0.0.0.0");

        /// <summary>
        /// Last ipv4
        /// </summary>
        public static readonly System.Net.IPAddress LastIPV4 = System.Net.IPAddress.Parse("255.255.255.255");

        /// <summary>
        /// IPV4 internal ranges
        /// </summary>
        public static readonly IReadOnlyCollection<IPAddressRange> InternalRangesIPV4 = new IPAddressRange[]
        {
            IPAddressRange.Parse("0.0.0.0-0.255.255.255"),
            IPAddressRange.Parse("10.0.0.0-10.255.255.255"),
            IPAddressRange.Parse("100.64.0.0-100.127.255.255"),
            IPAddressRange.Parse("127.0.0.0–127.255.255.255"),
            IPAddressRange.Parse("169.254.0.0-169.254.255.255"),
            IPAddressRange.Parse("172.16.0.0-172.31.255.255"),
            IPAddressRange.Parse("192.0.0.0-192.0.0.255"),
            IPAddressRange.Parse("192.0.2.0-192.0.2.255"),
            IPAddressRange.Parse("192.88.99.0-192.88.99.255 "),
            IPAddressRange.Parse("192.168.0.0-192.168.255.255"),
            IPAddressRange.Parse("198.18.0.0-198.19.255.255"),
            IPAddressRange.Parse("198.51.100.0-198.51.100.255"),
            IPAddressRange.Parse("203.0.113.0-203.0.113.255"),
            IPAddressRange.Parse("224.0.0.0-239.255.255.255"),
            IPAddressRange.Parse("233.252.0.0-233.252.0.255"),
            IPAddressRange.Parse("240.0.0.0-255.255.255.255")
        };
        private static readonly List<IPV4Range> internalRangesIPV4Optimized = InternalRangesIPV4.Select(r => new IPV4Range(r)).ToList();

        /// <summary>
        /// First iPV6
        /// </summary>
        public static readonly System.Net.IPAddress FirstIPV6 = System.Net.IPAddress.Parse("0000:0000:0000:0000:0000:0000:0000:0000");

        /// <summary>
        /// Last IPV6
        /// </summary>
        public static readonly System.Net.IPAddress LastIPV6 = System.Net.IPAddress.Parse("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF");

        /// <summary>
        /// Internal IPV6 ranges
        /// </summary>
        public static readonly IReadOnlyCollection<IPAddressRange> InternalRangesIPV6 = new IPAddressRange[]
        {
            IPAddressRange.Parse("::-1FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
            //IPAddressRange.Parse("100::/64"),
            IPAddressRange.Parse("2001:0000::/32"),
            IPAddressRange.Parse("2001:db8::/32"),
            IPAddressRange.Parse("2002::/16"),
            IPAddressRange.Parse("4000:0000:0000:0000:0000:0000:0000:0000-FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF")
            //IPAddressRange.Parse("fc00::/7"),
            //IPAddressRange.Parse("fd00::/8"),
            //IPAddressRange.Parse("fe80::/10"),
            //IPAddressRange.Parse("ff00::/8")
        };
        private static readonly List<IPV6Range> internalRangesIPV6Optimized = InternalRangesIPV6.Select(r => new IPV6Range(r)).ToList();

        /// <summary>
        /// An extension method to determine if an IP address is internal, as specified in RFC1918
        /// </summary>
        /// <param name="ip">The IP address that will be tested</param>
        /// <returns>Returns true if the IP is internal, false if it is external</returns>
        public static bool IsInternal(this System.Net.IPAddress ip)
        {
            try
            {
                ip = ip.Clean();
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    uint value = ip.ToUInt32();
                    return internalRangesIPV4Optimized.BinarySearch(new IPV4Range(value, value)) >= 0;
                }
                else
                {
                    UInt128 value = ip.ToUInt128();
                    return internalRangesIPV6Optimized.BinarySearch(new IPV6Range(value, value)) >= 0;
                }
            }
            catch (System.Exception ex)
            {
                Logger.Warn("Invalid ip isinternal check: {0}, {1}", ip, ex);
                return true;
            }
        }

        /// <summary>
        /// Get the local configured dns servers for this machine from all network interfaces
        /// </summary>
        /// <returns>All dns servers for this local machine</returns>
        public static IReadOnlyCollection<IPAddress> GetLocalDnsServers()
        {
            List<IPAddress> dnsServers = new();
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
                    IPAddressCollection dnsAddresses = ipProperties.DnsAddresses;
                    dnsServers.AddRange(dnsAddresses);
                }
            }

            return dnsServers;
        }

        /// <summary>
        /// Get computer mac address in hex.
        /// </summary>
        /// <returns>Mac address or empty string if no network adapter found</returns>
        public static string GetMacAddress()
        {
            const int minMacLength = 12;
            string macAddress = string.Empty;
            string possibleMacAddress;
            long maxSpeed = -1;
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                var props = nic.GetIPProperties();
                if (nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    if (nic.Speed > maxSpeed && !string.IsNullOrEmpty(possibleMacAddress = nic.GetPhysicalAddress().ToString()) &&
                        possibleMacAddress.Length >= minMacLength)
                    {
                        maxSpeed = nic.Speed;
                        macAddress = possibleMacAddress;
                    }
                }
            }
            return macAddress;
        }

        /// <summary>
        /// Get all ips of local machine
        /// </summary>
        /// <returns>All ips of local machine</returns>
        public static IReadOnlyCollection<string> GetAllIPAddresses()
        {
            HashSet<string> ipSet = new();
            foreach (NetworkInterface netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (netInterface.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProps = netInterface.GetIPProperties();
                    foreach (UnicastIPAddressInformation addr in ipProps.UnicastAddresses)
                    {
                        if (!addr.Address.IsLocalHost())
                        {
                            string ipString = addr.Address.ToString();
                            ipString = System.Text.RegularExpressions.Regex.Replace(ipString, "%.*$", string.Empty);
                            ipSet.Add(ipString);
                        }
                    }
                }
            }
            return ipSet;
        }
    }
}
