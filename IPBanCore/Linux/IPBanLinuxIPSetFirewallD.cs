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
using System.IO;
using System.Linq;
using System.Threading;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Helper methods to work with sets on Linux firewalld.
    /// Use sets this way: https://firewalld.org/documentation/man-pages/firewalld.ipset.html
    /// This class also works on Windows but only modifies files, does not actually use the firewall.
    /// </summary>
    public static class IPBanLinuxIPSetFirewallD
    {
        private static readonly string setsFolder;

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

        static IPBanLinuxIPSetFirewallD()
        {
            if (OSUtility.IsLinux)
            {
                setsFolder = "/etc/firewalld/ipsets";
            }
            else
            {
                // windows virtual layer
                setsFolder = Path.Combine(System.AppContext.BaseDirectory, "firewalld", "override", "ipsets");
                Directory.CreateDirectory(setsFolder);
            }
        }

        /// <summary>
        /// Reset firewalld to the default state
        /// </summary>
        /// <param name="setPrefix">Prefix</param>
        /// <returns>True if success, false if error</returns>
        public static bool DeleteAllSets(string setPrefix)
        {
            var setFiles = Directory.GetFiles(setsFolder);
            foreach (var file in setFiles)
            {
                var setName = Path.GetFileNameWithoutExtension(file);
                DeleteSet(setName);
            }
            return true;
        }

        /// <summary>
        /// Reset a single set to the default empty state
        /// </summary>
        /// <param name="setName">Set name to reset</param>
        /// <returns>True if success, false if error or not exists</returns>
        public static bool DeleteSet(string setName)
        {
            // rewrite the set file without any entry elements
            var setFileName = Path.Combine(setsFolder, setName + ".xml");
            if (!File.Exists(setFileName))
            {
                return false;
            }

            var setFileName2 = setFileName + ".tmp";
            {
                var setFileTmpWriter = File.CreateText(setFileName2);
                foreach (var line in File.ReadLines(setFileName))
                {
                    if (!line.Contains("<entry>"))
                    {
                        setFileTmpWriter.WriteLine(line);
                    }
                }
            }
            File.Move(setFileName2, setFileName, true);

            return true;
        }

        /// <summary>
        /// Determine if a set exists
        /// </summary>
        /// <param name="setName">Set name</param>
        /// <returns>True if exists, false otherwise</returns>
        public static bool SetExists(string setName)
        {
            var setFileName = Path.Combine(setsFolder, setName + ".xml");
            return File.Exists(setFileName);
        }

        /// <summary>
        /// Upsert a aset
        /// </summary>
        /// <param name="setName">Set name</param>
        /// <param name="hashType">Hash type</param>
        /// <param name="inetType">Inet type</param>
        /// <param name="entries">Entries</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if error</returns>
        public static bool UpsertSet(string setName, string hashType, string inetType,
            IEnumerable<IPAddressRange> entries, CancellationToken cancelToken)
        {
            WriteSet(setName, hashType, inetType, entries.Select(e => e.ToString()), cancelToken);
            return true;
        }

        /// <summary>
        /// Upsert a set using deltas
        /// </summary>
        /// <param name="setName">Set name</param>
        /// <param name="hashType">Hash type</param>
        /// <param name="inetType">Inet type</param>
        /// <param name="entries">Entries</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if error</returns>
        public static bool UpsertSetDelta(string setName, string hashType, string inetType,
            IEnumerable<IPBanFirewallIPAddressDelta> entries, CancellationToken cancelToken)
        {
            var existingEntries = ReadSet(setName);
            foreach (var entry in entries)
            {
                if (entry.Added)
                {
                    existingEntries.Add(entry.IPAddress);
                }
                else
                {
                    existingEntries.Remove(entry.IPAddress);
                }
            }
            WriteSet(setName, hashType, inetType, existingEntries, cancelToken);
            return true;
        }

        /// <summary>
        /// Get all set names
        /// </summary>
        /// <param name="setPrefix">Set prefix</param>
        /// <returns>Set names</returns>
        public static IReadOnlyCollection<string> GetSetNames(string setPrefix)
        {
            HashSet<string> sets = new();
            var setFiles = Directory.GetFiles(setsFolder);
            foreach (var file in setFiles)
            {
                var setName = Path.GetFileNameWithoutExtension(file);
                if (setName.StartsWith(setPrefix))
                {
                    sets.Add(setName);
                }
            }
            return sets;
        }

        /// <summary>
        /// Get the entries in a set
        /// </summary>
        /// <param name="setName">Set name</param>
        /// <returns>Entries</returns>
        public static ICollection<string> ReadSet(string setName)
        {
            HashSet<string> entries = new();
            var setFileName = Path.Combine(setsFolder, setName + ".xml");
            if (File.Exists(setFileName))
            {
                using var xmlReader = System.Xml.XmlReader.Create(setFileName);
                while (xmlReader.Read())
                {
                    if (xmlReader.NodeType == System.Xml.XmlNodeType.Element &&
                        xmlReader.Name == "entry")
                    {
                        var entry = xmlReader.ReadContentAsString();
                        entries.Add(entry);
                    }
                }
            }
            return entries;
        }

        /// <summary>
        /// Read ipset options
        /// </summary>
        /// <param name="setName">Set name</param>
        /// <returns>Options or default if not found</returns>
        public static (string hashType, string inetFamily, int hashSize, int maxCount) ReadSetOptions(string setName)
        {
            var fileName = Path.Combine(setsFolder, setName + ".xml");
            if (!File.Exists(fileName))
            {
                return default;
            }
            using var xmlReader = System.Xml.XmlReader.Create(fileName);

            // advance to and read ipset element type attribute value
            string hashType = null;
            string family = null;
            int hashSize = 0;
            int maxElem = 0;

            // ipset is assumed to always be the first element
            if (xmlReader.ReadToFollowing("ipset") &&
                xmlReader.MoveToAttribute("type"))
            {
                hashType = xmlReader.ReadContentAsString();
            }

            // next are the option elements
            while (xmlReader.ReadToFollowing("option") && xmlReader.MoveToAttribute("name"))
            {
                var optionName = xmlReader.Name;
                if (xmlReader.MoveToAttribute("value"))
                {
                    switch (optionName)
                    {
                        case "family":
                            family = xmlReader.ReadContentAsString();
                            break;
                        case "hashsize":
                            hashSize = xmlReader.ReadContentAsInt();
                            break;
                        case "maxelem":
                            maxElem = xmlReader.ReadContentAsInt();
                            break;
                    }
                }
                if (family is not null && hashSize != 0 && maxElem != 0)
                {
                    // done!
                    break;
                }
            }

            return (hashType, family, hashSize, maxElem);
        }

        private static void WriteSet(string setName, string hashType, string inetFamily, IEnumerable<string> entries,
            CancellationToken cancelToken)
        {
            // first write the set
            var fileName = Path.Combine(setsFolder, setName + ".xml");
            using var writer = File.CreateText(fileName);
            writer.WriteLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            writer.WriteLine($"<ipset type=\"hash:{hashType}\">");
            writer.WriteLine($"<option name=\"family\" value=\"{inetFamily}\" />");
            writer.WriteLine($"<option name=\"hashsize\" value=\"{IPBanLinuxIPSetIPTables.HashSize}\" />");
            writer.WriteLine($"<option name=\"maxelem\" value=\"{IPBanLinuxIPSetIPTables.MaxCount}\" />");
            foreach (var entry in entries)
            {
                writer.WriteLine($"<entry>{entry}</entry>");
            }
            writer.WriteLine("</ipset>");
        }
    }
}
