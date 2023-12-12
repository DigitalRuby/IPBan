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

using Microsoft.Win32;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Network utility methods
    /// </summary>
    public static class NetworkUtility
    {
        // https://en.wikipedia.org/wiki/Reserved_IP_addresses
        private static readonly System.Net.IPAddress[] localHostIP = [System.Net.IPAddress.Parse("127.0.0.1"), System.Net.IPAddress.Parse("::1")];

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
            IPAddressRange.Parse("::-1FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // loopbacks
            //IPAddressRange.Parse("::FFFF:0:0-::FFFF:FFFF:FFFF"), // ipv4 mapped
            IPAddressRange.Parse("100::-100:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // discard prefix
            //IPAddressRange.Parse("2001::-2001:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // teredo
            IPAddressRange.Parse("2001:10::-2001:2F:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // ORCHID
            IPAddressRange.Parse("2001:DB8::-2001:DB8:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // documentation
            //IPAddressRange.Parse("2002::-2002:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // 6to4
            IPAddressRange.Parse("FC00::-FCFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // unique local
            IPAddressRange.Parse("FE80::-FE80:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // link local
            IPAddressRange.Parse("FEC0::-FEC0:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), // site local
            IPAddressRange.Parse("FF00::-FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF") // multicast
        };
        private static readonly List<IPV6Range> internalRangesIPV6Optimized = InternalRangesIPV6.Select(r => new IPV6Range(r)).ToList();

        /// <summary>
        /// An extension method to determine if an IP address is internal, as specified in RFC1918
        /// </summary>
        /// <param name="ip">The IP address that will be tested</param>
        /// <returns>Returns true if the IP is internal or null, false if it is external</returns>
        public static bool IsInternal(this System.Net.IPAddress ip)
        {
            try
            {
                if (ip == null)
                {
                    return false;
                }
                ip = ip.Clean();
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    uint value = ip.ToUInt32();
                    int idx = internalRangesIPV4Optimized.BinarySearch(new IPV4Range(value, value));
                    return idx >= 0;
                }
                else
                {
                    UInt128 value = ip.ToUInt128();
                    int idx = internalRangesIPV6Optimized.BinarySearch(new IPV6Range(value, value));
                    return idx >= 0;
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
            List<IPAddress> dnsServers = [];
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
        /// Get all ips of local machine, in priority order.
        /// On Windows, priority is first attempted to be read using the 'Interface Metric' from adapter properties.
        ///  If this is not able to read, then the routing table priority is used.
        /// On Linux, priority is currently ignored.
        /// </summary>
        /// <returns>All ips of local machine (key) and priority (value). Higher priority are sorted first.</returns>
        public static IReadOnlyCollection<KeyValuePair<System.Net.IPAddress, int>> GetIPAddressesByPriority()
        {
            Dictionary<System.Net.IPAddress, int> ips = [];
            foreach (NetworkInterface netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (netInterface.OperationalStatus == OperationalStatus.Up &&
                (
                    string.IsNullOrWhiteSpace(netInterface.Name) ||
                        (!netInterface.Name.Contains("loopback", System.StringComparison.OrdinalIgnoreCase) &&
                        !netInterface.Name.Contains("vEthernet (wsl)", StringComparison.OrdinalIgnoreCase)))
                )
                {
                    IPInterfaceProperties ipProps = netInterface.GetIPProperties();
                    var indexV4 = 0;
                    var indexV6 = 0;

                    // attempt to get priorities/metrics, ignoring exceptions
                    try
                    {
                        TryGetInterfaceMetric(netInterface.Id, true, out indexV4);
                        // this is not a real priority but leaving it for reference (it's routing table priority)
                        // indexV4 = ipProps.GetIPv4Properties().Index;
                    }
                    catch
                    {
                    }
                    try
                    {
                        TryGetInterfaceMetric(netInterface.Id, false, out indexV6);
                        // this is not a real priority but leaving it for reference (it's routing table priority)
                        // indexV6 = ipProps.GetIPv6Properties().Index;
                    }
                    catch
                    {
                    }

                    foreach (UnicastIPAddressInformation addr in ipProps.UnicastAddresses)
                    {
                        if (!addr.Address.IsLocalHost())
                        {
                            var cleanedIp = addr.Address.Clean();
                            if (!ips.ContainsKey(cleanedIp))
                            {
                                var priority = cleanedIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? indexV4 : indexV6;
                                ips.Add(cleanedIp, priority);
                            }
                        }
                    }
                }
            }
            return ips.OrderByDescending(i => i.Value)
                .ThenBy(i => i.Key.AddressFamily)
                .ToArray();
        }

        /// <summary>
        /// Attempt to retrieve the interface metric from an adapter id. Currently only works on Windows.
        /// </summary>
        /// <param name="adapterId">Adapter id</param>
        /// <param name="ipv4">Is this an ipv4 or ipv6 adapter?</param>
        /// <param name="metric">The result interface metric or 0 if not found</param>
        /// <returns>True if interface metric was retrieved, false otherwise</returns>
        public static bool TryGetInterfaceMetric(string adapterId, bool ipv4, out int metric)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // try getting the real value from the registry
                var typeKey = "Tcpip" + (ipv4 ? string.Empty : "6");
                using var interfacesKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{typeKey}\Parameters\Interfaces");
                foreach (string subKeyName in interfacesKey.GetSubKeyNames())
                {
                    using var subKey = interfacesKey.OpenSubKey(subKeyName);
                    if (subKey.Name.Contains(adapterId, System.StringComparison.OrdinalIgnoreCase))
                    {
                        string metricString;
                        int _tmpInt;

                        // try finding the same in sub keys, sometimes Windows makes a clone of the key as a child
                        foreach (string subkeyName2 in subKey.GetSubKeyNames())
                        {
                            using var subkey2 = subKey.OpenSubKey(subkeyName2);
                            metricString = subkey2.GetValue("InterfaceMetric")?.ToString();
                            if (int.TryParse(metricString, out _tmpInt))
                            {
                                metric = _tmpInt;
                                return true;
                            }
                        }

                        metricString = subKey.GetValue("InterfaceMetric")?.ToString();
                        if (int.TryParse(metricString, out _tmpInt))
                        {
                            metric = _tmpInt;
                            return true;
                        }

                        break;
                    }
                }
            }
            metric = 0;
            return false;
        }

        /// <summary>
        /// Get all ip addresses of the machine, in sorted order,
        /// putting external ipv4 first,
        /// then external ipv6,
        /// then priority,
        /// then internal ipv4,
        /// then internal ipv6,
        /// then finally by ip itself
        /// </summary>
        /// <param name="ipAddresses">The ip addresses to sort, or null to query the hardware on the machine</param>
        /// <param name="preferInternal">Whether to prefer internal ip addresses</param>
        /// <returns>IP addresses</returns>
        public static IEnumerable<System.Net.IPAddress> GetSortedIPAddresses(
            IEnumerable<KeyValuePair<string, int>> ipAddresses = null, bool preferInternal = false)
        {
            try
            {
                List<KeyValuePair<System.Net.IPAddress, int>> collection;
                if (ipAddresses is null)
                {
                    collection = [.. GetIPAddressesByPriority()];
                }
                else
                {
                    collection = ipAddresses.Select(o => new KeyValuePair<System.Net.IPAddress, int>(System.Net.IPAddress.Parse(o.Key), o.Value)).ToList();
                }
                collection.Sort((ip1, ip2) =>
                {
                    int internal1 = ip1.Key.IsInternal() ? 1 : 0;
                    int internal2 = ip2.Key.IsInternal() ? 1 : 0;
                    if (internal1 != internal2)
                    {
                        return preferInternal ? internal2.CompareTo(internal1) : internal1.CompareTo(internal2);
                    }
                    int priority1 = ip1.Value;
                    int priority2 = ip2.Value;
                    if (priority1 != priority2)
                    {
                        return priority2.CompareTo(priority1);
                    }
                    int family1 = ip1.Key.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 1 : 0;
                    int family2 = ip2.Key.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 1 : 0;
                    if (family1 != family2)
                    {
                        return family1.CompareTo(family2);
                    }
                    return ip1.Key.CompareTo(ip2.Key);
                });
                return collection.Select(c => c.Key);
            }
            catch
            {
                // non-fatal
            }
            return Array.Empty<System.Net.IPAddress>();
        }
    }
}
