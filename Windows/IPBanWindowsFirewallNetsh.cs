#if USE_WINDOWS_NETSH_FIREWALL

#region Imports

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

#endregion Imports

// TODO: If we ever can't use COM, we need to switch to this implementation of Windows firewall

namespace IPBan
{
    /// <summary>
    /// Helper class for Windows firewall and banning ip addresses.
    /// </summary>
    [RequiredOperatingSystem(IPBanOperatingSystem.Windows)]
    public class IPBanWindowsFirewallNetsh : IIPBanFirewall
    {
        private const string fileScriptHeader = "pushd advfirewall firewall";
        private const string fileScriptAddLine = @"add rule name=""{0}"" remoteip=""{1}"" action=block protocol=any dir=in";
        private const string fileScriptDeleteLine = "delete rule name=\"{0}\"";
        private const string fileScriptEnd = "popd";
        private const int blockSize = 1000;

        private void RunScript(string scriptFileName)
        {
            ProcessStartInfo info = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "exec \"" + scriptFileName + "\"",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = true
            };
            Process p = Process.Start(info);
            p.WaitForExit();
            File.Delete(scriptFileName);
        }

        private void WriteDeleteRules(StreamWriter writer, bool writeHeader)
        {
            string subRuleName;
            const int maxRulesToDelete = 1000000;
            if (writeHeader)
            {
                writer.WriteLine(fileScriptHeader);
            }
            for (int i = 0; i < maxRulesToDelete; i += blockSize)
            {
                subRuleName = RulePrefix + i.ToString(CultureInfo.InvariantCulture);
                writer.WriteLine(fileScriptDeleteLine, subRuleName);
            }
            if (writeHeader)
            {
                writer.WriteLine(fileScriptEnd);
            }
        }

        public string RulePrefix { get; private set; } = "IPBan_";

        public bool CreateRules(IReadOnlyList<string> ipAddresses)
        {
            string subRuleName;
            string scriptFileName = Path.GetTempFileName();
            Directory.CreateDirectory(Path.GetDirectoryName(scriptFileName));
            using (StreamWriter writer = File.CreateText(scriptFileName))
            {
                writer.WriteLine(fileScriptHeader);
                WriteDeleteRules(writer, false);
                for (int i = 0; i < ipAddresses.Count; i += blockSize)
                {
                    subRuleName = RulePrefix + i.ToString(CultureInfo.InvariantCulture);
                    string ipAddressesArray = string.Join(",", ipAddresses.Skip(i).Take(blockSize));
                    string line = string.Format(fileScriptAddLine, subRuleName, ipAddressesArray);
                    writer.WriteLine(line);
                }
                writer.WriteLine(fileScriptEnd);
            }
            RunScript(scriptFileName);
            return true;
        }

        public bool DeleteRules(int startIndex = 0)
        {
            string scriptFileName = Path.GetTempFileName();
            Directory.CreateDirectory(Path.GetDirectoryName(scriptFileName));
            using (StreamWriter writer = File.CreateText(scriptFileName))
            {
                WriteDeleteRules(writer, true);
            }
            RunScript(scriptFileName);
            return true;
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return new string[0];
        }

        public void Initialize(string rulePrefix)
        {
        }

        public bool IsIPAddressBlocked(string ipAddress)
        {
            return false;
        }
    }
}

#endif
