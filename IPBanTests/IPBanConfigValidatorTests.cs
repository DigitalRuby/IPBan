/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using System;
using System.IO;
using System.Linq;
using System.Net;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// Validates customer/sample configs under TestData/Configs, especially whitelist behavior
    /// for ipban1.config (customer report that Whitelist was not working).
    /// </summary>
    [TestFixture]
    public sealed class IPBanConfigValidatorTests
    {
        private const string Ipban1ConfigRelativePath = "TestData/Configs/ipban1.config";

        private static readonly string[] ExpectedWhitelistCidrs =
        [
            "11.22.33.0/24",
            "22.33.44.0/24"
        ];

        private static readonly string[] ExpectedWhitelistSingleIps =
        [
            "22.33.44.246",
            "33.44.55.100",
            "44.55.66.147",
            "55.66.77.63",
            "1.2.3.131"
        ];

        private static readonly TimeSpan[] ExpectedBanTimes =
        [
            TimeSpan.FromMinutes(5),
            TimeSpan.FromMinutes(10),
            TimeSpan.FromMinutes(30),
            TimeSpan.FromHours(1),
            TimeSpan.FromDays(1),
            TimeSpan.FromDays(7)
        ];

        private IPBanConfig cfg;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            string path = Path.Combine(AppContext.BaseDirectory, Ipban1ConfigRelativePath);
            ClassicAssert.IsTrue(File.Exists(path), $"Expected config at {path}");
            cfg = IPBanConfig.LoadFromXml(File.ReadAllText(path));
        }

        [Test]
        public void Ipban1_LoadsSuccessfully()
        {
            ClassicAssert.IsNotNull(cfg);
            ClassicAssert.IsFalse(string.IsNullOrWhiteSpace(cfg.Xml));
            ClassicAssert.IsNotEmpty(cfg.AppSettings);
        }

        [Test]
        public void Ipban1_CoreAppSettings_ParsedCorrectly()
        {
            ClassicAssert.AreEqual(5, cfg.FailedLoginAttemptsBeforeBan);
            ClassicAssert.IsFalse(cfg.ResetFailedLoginCountForUnbannedIPAddresses);
            ClassicAssert.IsFalse(cfg.ClearBannedIPAddressesOnRestart);
            ClassicAssert.IsTrue(cfg.ClearFailedLoginsOnSuccessfulLogin);
            ClassicAssert.IsFalse(cfg.ProcessInternalIPAddresses);
            ClassicAssert.AreEqual(TimeSpan.FromDays(1), cfg.ExpireTime);
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(15), cfg.CycleTime);
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(1), cfg.MinimumTimeBetweenFailedLoginAttempts);
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(5), cfg.MinimumTimeBetweenSuccessfulLoginAttempts);
            ClassicAssert.AreEqual("IPBan_", cfg.FirewallRulePrefix);
            ClassicAssert.AreEqual("@", cfg.TruncateUserNameChars);
            ClassicAssert.IsTrue(cfg.UseDefaultBannedIPAddressHandler);
            ClassicAssert.IsEmpty(cfg.FirewallUriRules);
            ClassicAssert.IsEmpty(cfg.ExtraRules);
        }

        [Test]
        public void Ipban1_BanTimes_ParsedDespiteSpacesAfterCommas()
        {
            // BanTime value uses spaces after commas; entries must still parse in ascending order
            ClassicAssert.AreEqual(ExpectedBanTimes.Length, cfg.BanTimes.Length);
            for (int i = 0; i < ExpectedBanTimes.Length; i++)
            {
                ClassicAssert.AreEqual(ExpectedBanTimes[i], cfg.BanTimes[i], $"BanTimes[{i}]");
            }
        }

        [Test]
        public void Ipban1_BanTimeMultiplier_IsPresentInAppSettingsButIgnored()
        {
            // Customer config includes BanTimeMultiplier; that key is not a real setting.
            // ResetFailedLoginCountForUnbannedIPAddresses is the real related option.
            ClassicAssert.IsTrue(cfg.AppSettings.ContainsKey("BanTimeMultiplier"));
            ClassicAssert.AreEqual("true", cfg.AppSettings["BanTimeMultiplier"]);
            ClassicAssert.IsFalse(cfg.ResetFailedLoginCountForUnbannedIPAddresses);
        }

        [Test]
        public void Ipban1_Whitelist_ValueAndRangesParsed()
        {
            ClassicAssert.AreEqual(
                "11.22.33.0/24,22.33.44.0/24,22.33.44.246,33.44.55.100,44.55.66.147,55.66.77.63,1.2.3.131",
                cfg.WhitelistFilter.Value);

            var ranges = cfg.WhitelistFilter.IPAddressRanges
                .Select(r => r.ToCidrString())
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToArray();

            string[] expected = ExpectedWhitelistCidrs
                .Concat(ExpectedWhitelistSingleIps)
                .Select(s => IPAddressRange.Parse(s).ToCidrString())
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToArray();

            ClassicAssert.AreEqual(expected.Length, ranges.Length);
            CollectionAssert.AreEqual(expected, ranges);
        }

        [Test]
        public void Ipban1_WhitelistRegex_Parsed()
        {
            ClassicAssert.IsNotNull(cfg.WhitelistFilter.Regex);
            ClassicAssert.AreEqual(
                @"^(11\.22\.33\.[0-9]+|22\.33\.44\.[0-9]+|33\.44\.55\.100|44\.55\.66\.147|55\.66\.77\.63|1\.2\.3\.131)$",
                cfg.WhitelistFilter.Regex.ToString());
        }

        [Test]
        public void Ipban1_Blacklist_Empty()
        {
            ClassicAssert.IsTrue(string.IsNullOrEmpty(cfg.BlacklistFilter.Value));
            ClassicAssert.IsNull(cfg.BlacklistFilter.Regex);
            ClassicAssert.IsEmpty(cfg.BlacklistFilter.IPAddressRanges);
            ClassicAssert.IsFalse(cfg.BlacklistFilter.IsFiltered("11.22.33.1", out _));
            ClassicAssert.IsFalse(cfg.BlacklistFilter.IsFiltered("99.99.99.99", out _));
        }

        [Test]
        public void Ipban1_UserNameWhitelist_Empty()
        {
            ClassicAssert.IsEmpty(cfg.UserNameWhitelist);
            ClassicAssert.IsTrue(string.IsNullOrEmpty(cfg.UserNameWhitelistRegex));
            ClassicAssert.AreEqual(20, cfg.FailedLoginAttemptsBeforeBanUserNameWhitelist);
            ClassicAssert.IsFalse(cfg.IsUserNameWithinMaximumEditDistanceOfUserNameWhitelist("admin", out bool hasList));
            ClassicAssert.IsFalse(hasList);
        }

        [TestCase("11.22.33.0")]
        [TestCase("11.22.33.1")]
        [TestCase("11.22.33.128")]
        [TestCase("11.22.33.255")]
        [TestCase("22.33.44.0")]
        [TestCase("22.33.44.1")]
        [TestCase("22.33.44.246")]
        [TestCase("22.33.44.255")]
        [TestCase("33.44.55.100")]
        [TestCase("44.55.66.147")]
        [TestCase("55.66.77.63")]
        [TestCase("1.2.3.131")]
        public void Ipban1_Whitelist_MatchesListedIps(string ip)
        {
            ClassicAssert.IsTrue(cfg.IsWhitelisted(ip, out string reason), $"Expected {ip} whitelisted");
            ClassicAssert.AreEqual("IP list", reason);
        }

        [TestCase("11.22.32.255")]
        [TestCase("11.22.34.0")]
        [TestCase("22.33.43.255")]
        [TestCase("22.33.45.0")]
        [TestCase("33.44.55.101")]
        [TestCase("1.2.3.132")]
        [TestCase("1.2.3.130")]
        [TestCase("99.99.99.99")]
        [TestCase("10.0.0.1")]
        public void Ipban1_Whitelist_DoesNotMatchOtherIps(string ip)
        {
            ClassicAssert.IsFalse(cfg.IsWhitelisted(ip, out _), $"Did not expect {ip} whitelisted");
        }

        [Test]
        public void Ipban1_Whitelist_MatchesIpv4MappedToIpv6()
        {
            ClassicAssert.IsTrue(cfg.IsWhitelisted("::ffff:11.22.33.50", out string reason));
            ClassicAssert.AreEqual("IP list", reason);
        }

        [Test]
        public void Ipban1_Whitelist_MatchesWithSurroundingWhitespace()
        {
            ClassicAssert.IsTrue(cfg.IsWhitelisted(" 11.22.33.50 ", out string reason));
            ClassicAssert.AreEqual("IP list", reason);
        }

        [Test]
        public void Ipban1_Whitelist_RangeApi_MatchesCidrMembers()
        {
            ClassicAssert.IsTrue(cfg.IsWhitelisted(IPAddressRange.Parse("11.22.33.50"), out string reason));
            ClassicAssert.AreEqual("IP list", reason);

            ClassicAssert.IsTrue(cfg.IsWhitelisted(IPAddressRange.Parse("11.22.33.0/24"), out reason));
            ClassicAssert.AreEqual("IP list", reason);

            ClassicAssert.IsFalse(cfg.IsWhitelisted(IPAddressRange.Parse("11.22.34.0/24"), out _));
        }

        [Test]
        public void Ipban1_WhitelistRegex_MatchesWhenIpListCleared()
        {
            // Regex alone must still whitelist the same ranges (customer added it as a workaround)
            var regexOnly = new IPBanFilter(string.Empty, cfg.WhitelistFilter.Regex.ToString(), null, null, null, null);

            ClassicAssert.IsTrue(regexOnly.IsFiltered("11.22.33.50", out string reason));
            ClassicAssert.AreEqual("Regex", reason);
            ClassicAssert.IsTrue(regexOnly.IsFiltered("22.33.44.99", out reason));
            ClassicAssert.AreEqual("Regex", reason);
            ClassicAssert.IsTrue(regexOnly.IsFiltered("33.44.55.100", out reason));
            ClassicAssert.AreEqual("Regex", reason);
            ClassicAssert.IsFalse(regexOnly.IsFiltered("1.2.3.132", out _));
            ClassicAssert.IsFalse(regexOnly.IsFiltered("11.22.34.1", out _));
        }

        [Test]
        public void Ipban1_Whitelist_BeatsBlacklist()
        {
            var blacklist = new IPBanFilter(
                "11.22.33.50,99.99.99.99",
                null,
                null,
                null,
                null,
                cfg.WhitelistFilter);

            ClassicAssert.IsFalse(blacklist.IsFiltered("11.22.33.50", out string reason),
                "Whitelisted IP must not be blacklisted");
            ClassicAssert.AreEqual("Counter filter", reason);

            ClassicAssert.IsTrue(blacklist.IsFiltered("99.99.99.99", out reason));
            ClassicAssert.AreEqual("IP list", reason);
        }

        [Test]
        public void Ipban1_Whitelist_FirewallRangesContainListedIps()
        {
            // Firewall GlobalWhitelist uses IPAddressRanges only (CIDR/IP list), not regex
            ClassicAssert.GreaterOrEqual(cfg.WhitelistFilter.IPAddressRanges.Count, 7);
            ClassicAssert.IsTrue(cfg.WhitelistFilter.IPAddressRanges.Any(r =>
                r.Contains(IPAddress.Parse("11.22.33.1"))));
            ClassicAssert.IsTrue(cfg.WhitelistFilter.IPAddressRanges.Any(r =>
                r.Contains(IPAddress.Parse("1.2.3.131"))));
        }

        [Test]
        public void Ipban1_LogFilesToParse_ContainsApache()
        {
            var apache = cfg.LogFilesToParse.FirstOrDefault(f => f.Source == "Apache");
            ClassicAssert.IsNotNull(apache);
            StringAssert.Contains("Tomcat", apache.PathAndMask);
            ClassicAssert.IsFalse(string.IsNullOrWhiteSpace(apache.FailedLoginRegex?.ToString()));
        }

        [Test]
        public void Ipban1_EventViewer_BlockAndNotifyGroupsPresent()
        {
            ClassicAssert.IsNotNull(cfg.WindowsEventViewerExpressionsToBlock);
            ClassicAssert.IsNotEmpty(cfg.WindowsEventViewerExpressionsToBlock.Groups);

            string[] expectedBlockSources = ["RDP", "IPBanCustom", "MSSQL", "MySQL", "phpMyAdmin", "SSH", "VNC", "RRAS"];
            foreach (string source in expectedBlockSources)
            {
                ClassicAssert.IsTrue(
                    cfg.WindowsEventViewerExpressionsToBlock.Groups.Any(g => g.Source == source),
                    $"Missing ExpressionsToBlock source {source}");
            }

            ClassicAssert.IsNotNull(cfg.WindowsEventViewerExpressionsToNotify);
            ClassicAssert.IsNotEmpty(cfg.WindowsEventViewerExpressionsToNotify.Groups);
            ClassicAssert.IsTrue(cfg.WindowsEventViewerExpressionsToNotify.Groups.Any(g => g.Source == "RDP"));
            ClassicAssert.IsTrue(cfg.WindowsEventViewerExpressionsToNotify.Groups.Any(g => g.Source == "MSSQL"));
        }

        [Test]
        public void Ipban1_MssqlExpressions_IncludeKoreanClientLabel()
        {
            var mssqlGroups = cfg.WindowsEventViewerExpressionsToBlock.Groups
                .Where(g => g.Source == "MSSQL")
                .ToArray();
            ClassicAssert.IsNotEmpty(mssqlGroups);

            bool foundKoreanClient = mssqlGroups
                .SelectMany(g => g.Expressions)
                .Select(e => e.Regex?.ToString() ?? string.Empty)
                .Any(r => r.Contains("클라이언트", StringComparison.Ordinal));
            ClassicAssert.IsTrue(foundKoreanClient, "Expected Korean CLIENT label in MSSQL IP regex");
        }
    }
}
