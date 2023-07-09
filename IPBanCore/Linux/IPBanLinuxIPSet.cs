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
using System.IO;
using System.Linq;
using System.Threading;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Helper methods to work with ipset on Linux
    /// </summary>
    public static class IPBanLinuxIPSet
    {
        /// <summary>
        /// Set entry
        /// </summary>
        /// <param name="Add">True if add, false if delete</param>
        /// <param name="SetName">Set name</param>
        /// <param name="Range">Range, can be a single ip</param>
        public record SetEntry(bool Add, string SetName, IPAddressRange Range);

        /// <summary>
        /// INetFamily for ipv4
        /// </summary>
        public const string INetFamilyIPV4 = "inet";

        /// <summary>
        /// INetFamily for ipv6
        /// </summary>
        public const string INetFamilyIPV6 = "inet6";

        /// <summary>
        /// Max set count
        /// </summary>
        public const int MaxCount = 4194304;

        /// <summary>
        /// Hash size
        /// </summary>
        public const int HashSize = 1024;

        /// <summary>
        /// Single ip type
        /// </summary>
        public const string HashTypeSingleIP = "ip";

        /// <summary>
        /// Cidr mask or range type
        /// </summary>
        public const string HashTypeNetwork = "net";

        /// <summary>
        /// Reset ipset to the default empty state
        /// </summary>
        public static void Reset()
        {
            IPBanLinuxFirewallIPTables.RunProcess("ipset", true, "-F");
        }

        /// <summary>
        /// Reset a single set to the default empty state
        /// </summary>
        /// <param name="setName">Set name to reset</param>
        /// <returns>True if set was reset, false otherwise</returns>
        public static bool Reset(string setName)
        {
            int exitCode = IPBanLinuxFirewallIPTables.RunProcess("ipset", true, $"-F {setName}");
            return exitCode == 0;
        }

        /// <summary>
        /// Dump all the contents of ipset to a file
        /// </summary>
        /// <param name="fileName">File name to write ipset to</param>
        public static void SaveToFile(string fileName)
        {
            IPBanLinuxFirewallIPTables.RunProcess("ipset", true, $"save > \"{fileName}\"");
        }

        /// <summary>
        /// Restore the entire contents of ipset from a file
        /// </summary>
        /// <param name="fileName">File name to read ipset from</param>
        /// <returns>True if restored, false if not</returns>
        public static bool RestoreFromFile(string fileName)
        {
            if (File.Exists(fileName))
            {
                int exitCode = IPBanLinuxFirewallIPTables.RunProcess("ipset", true, $"restore < \"{fileName}\"");
                return exitCode == 0;
            }
            return false;
        }

        /// <summary>
        /// Get all set names
        /// </summary>
        /// <returns>Set names</returns>
        public static IReadOnlyCollection<string> GetSetNames()
        {
            IPBanLinuxFirewallIPTables.RunProcess("ipset", true, out IReadOnlyList<string> sets, "-L -n");
            return sets;
        }

        /// <summary>
        /// Enumerate all set values
        /// </summary>
        /// <returns>Set values</returns>
        public static IEnumerable<SetEntry> EnumerateSets()
        {
            string tempFile = OSUtility.GetTempFileName();
            try
            {
                IPBanLinuxIPSet.SaveToFile(tempFile);
                foreach (string line in File.ReadLines(tempFile))
                {
                    string[] pieces = line.Split(' ');
                    if (pieces.Length > 2)
                    {
                        bool add = pieces[0] == "add";
                        // note: pieces[0] can be 'del' but we don't care about those
                        if (add && IPAddressRange.TryParse(pieces[2], out var range))
                        {
                            yield return new SetEntry(add, pieces[1], range);
                        }
                    }
                }
            }
            finally
            {
                ExtensionMethods.FileDeleteWithRetry(tempFile);
            }
        }

        /// <summary>
        /// Create a set file
        /// </summary>
        /// <param name="fileName">File name or null to make a temp file to restore automatically</param>
        /// <param name="setName">Set name</param>
        /// <param name="hashType">Hash type (see constants on this class)</param>
        /// <param name="inetFamily">INet family (see constants on this class)</param>
        /// <param name="items">Items to add to the set, depends on the hash type</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if failure</returns>
        /// <exception cref="OperationCanceledException"></exception>
        public static bool UpsertSetFile(string fileName, string setName, string hashType,
            string inetFamily, IEnumerable<string> items, CancellationToken cancelToken)
        {
            const int maxIPExtractedFromRange = 256;
            bool deleteFile = string.IsNullOrWhiteSpace(fileName);
            bool result = true;

            if (deleteFile)
            {
                fileName = Path.GetTempFileName();
            }
            try
            {
                // add and remove the appropriate ip addresses from the set
                using StreamWriter writer = File.CreateText(fileName);
                var allowedAddressFamily = inetFamily == INetFamilyIPV4 ? System.Net.Sockets.AddressFamily.InterNetwork :
                    System.Net.Sockets.AddressFamily.InterNetworkV6;

                // if the set already exists, flush it entirely
                var sets = IPBanLinuxIPSet.GetSetNames();
                if (sets.Contains(setName))
                {
                    writer.WriteLine($"flush {setName}");// hash:{hashType} family {INetFamily} hashsize {hashSize} maxelem {maxCount} -exist");
                }

                // create the set
                writer.WriteLine($"create {setName} hash:{hashType} family {inetFamily} hashsize {HashSize} maxelem {MaxCount} -exist");
                foreach (string ipAddress in items)
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(cancelToken);
                    }

                    // if we have a valid ip range of the correct address family, process it
                    if (IPAddressRange.TryParse(ipAddress, out IPAddressRange range) &&
                        range.Begin.AddressFamily == allowedAddressFamily && range.End.AddressFamily == allowedAddressFamily)
                    {
                        // if this is a single ip set, or this ip is not a range, add it
                        if (hashType != HashTypeNetwork || range.Single)
                        {
                            writer.WriteLine($"add {setName} {range.Begin} -exist");
                        }
                        else if (range.GetPrefixLength(false) < 0)
                        {
                            // attempt to write the ips in this range if the count is low enough
                            if (range.GetCount() <= maxIPExtractedFromRange)
                            {
                                foreach (System.Net.IPAddress ip in range)
                                {
                                    writer.WriteLine($"add {setName} {ip} -exist");
                                }
                            }
                            else
                            {
                                Logger.Debug("Skipped writing non-cidr range {0} because of too many ips", range);
                            }
                        }
                        else
                        {
                            // add the range in cidr notation
                            writer.WriteLine($"add {setName} {range.ToCidrString()} -exist");
                        }
                    }
                }
            }
            finally
            {
                if (deleteFile)
                {
                    result = RestoreFromFile(fileName);
                    File.Delete(fileName);
                }
            }

            return result;
        }

        /// <summary>
        /// Update a set file with delta changes
        /// </summary>
        /// <param name="fileName">File name or null to make a temp file to restore automatically</param>
        /// <param name="setName">Set name</param>
        /// <param name="hashType">Hash type (see constants on this class)</param>
        /// <param name="inetFamily">INet family (see constants on this class)</param>
        /// <param name="items">Items to add to the set, depends on the hash type</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if failure</returns>
        /// <exception cref="OperationCanceledException"></exception>
        public static bool UpsertSetFileDelta(string fileName, string setName, string hashType,
            string inetFamily, IEnumerable<IPBanFirewallIPAddressDelta> items, CancellationToken cancelToken)
        {
            bool deleteFile = string.IsNullOrWhiteSpace(fileName);
            bool result = true;

            if (deleteFile)
            {
                fileName = Path.GetTempFileName();
            }
            try
            {
                // add and remove the appropriate ip addresses from the set
                var allowedAddressFamily = inetFamily == INetFamilyIPV4 ? System.Net.Sockets.AddressFamily.InterNetwork :
                System.Net.Sockets.AddressFamily.InterNetworkV6;
                using StreamWriter writer = File.CreateText(fileName);

                // create the set if not exist
                writer.WriteLine($"create {setName} hash:{hashType} family {inetFamily} hashsize {HashSize} maxelem {MaxCount} -exist");
                foreach (IPBanFirewallIPAddressDelta delta in items)
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(cancelToken);
                    }

                    // if we have a valid ip range of the correct address family, process it
                    if (IPAddressRange.TryParse(delta.IPAddress, out IPAddressRange range) &&
                        range.Begin.AddressFamily == allowedAddressFamily && range.End.AddressFamily == allowedAddressFamily)
                    {
                        var type = delta.Added ? "add" : "del";
                        if (range.Single)
                        {
                            writer.WriteLine($"{type} {setName} {range.Begin} -exist");
                        }
                        else if (range.GetPrefixLength(false) >= 0)
                        {
                            writer.WriteLine($"{type} {setName} {range.ToCidrString()} -exist");
                        }
                        else
                        {
                            Logger.Debug("Ignoring invalid set delta entry {0}: {1}", type, range);
                        }
                    }
                }
            }
            finally
            {
                if (deleteFile)
                {
                    result = RestoreFromFile(fileName);
                    File.Delete(fileName);
                }
            }

            return result;
        }

        /// <summary>
        /// Delete a set
        /// </summary>
        /// <param name="setName">The set to delete</param>
        public static void DeleteSet(string setName)
        {
            IPBanLinuxFirewallIPTables.RunProcess("ipset", true, out IReadOnlyList<string> lines, "-L -n");
            foreach (string line in lines)
            {
                if (line.Trim().Equals(setName, StringComparison.OrdinalIgnoreCase))
                {
                    IPBanLinuxFirewallIPTables.RunProcess("ipset", true, $"destroy {setName}");
                    break;
                }
            }
        }
    }
}
