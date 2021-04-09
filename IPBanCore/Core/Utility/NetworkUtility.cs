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
using System.Net;
using System.Net.NetworkInformation;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Network utility methods
    /// </summary>
    public static class NetworkUtility
    {
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
