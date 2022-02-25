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

using DigitalRuby.IPBanCore;

using NUnit.Framework;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanFirewallTests
    {
        internal static readonly Type[] firewallTypes = new[] { typeof(IPBanWindowsFirewall), typeof(IPBanLinuxFirewall) };
        private IIPBanFirewall firewall;

        [SetUp]
        public void TestStart()
        {
            firewall = IPBanFirewallUtility.CreateFirewall(firewallTypes);
            Assert.AreNotEqual(typeof(IPBanMemoryFirewall), firewall.GetType());

            // clear all blocks
            firewall.Truncate();
        }

        [TearDown]
        public void TestStop()
        {
            // clear all blocks
            firewall.Truncate();
            firewall.Dispose();
        }

        [Test]
        public void TestBlock()
        {
            firewall.BlockIPAddresses(null, new string[] { "99.99.99.99" }).Sync();
            Assert.IsTrue(firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public void TestBlockClearsOutExtraRules()
        {
            List<string> ips = new(2020);
            for (int i = 0; i < 2020; i++)
            {
                string ip = "99.99." + ((i & 0x0000FF00) >> 8).ToString() + "." + (i & 0x000000FF).ToString();
                ips.Add(ip);
            }

            firewall.BlockIPAddresses("TMP_", ips).Sync();
            IPAddressRange[] ranges = firewall.EnumerateIPAddresses("TMP_").ToArray();
            Assert.AreEqual(ips.Count, ranges.Length);

            ips.RemoveRange(1000, ips.Count - 1000);

            firewall.BlockIPAddresses("TMP_", ips).Sync();
            ranges = firewall.EnumerateIPAddresses("TMP_").ToArray();
            Assert.AreEqual(ips.Count, ranges.Length);
        }

        [Test]
        public void TestFirewallMultipleRules()
        {
            string[] toBlock = new string[512 * 10];
            for (int i = 0; i < toBlock.Length; i++)
            {
                toBlock[i] = "10.10." + ((i & 0xFF00) >> 8) + "." + (i & 0x00FF);
            }
            firewall.BlockIPAddresses(null, toBlock).Sync();
            string[] bannedIP = firewall.EnumerateBannedIPAddresses().ToArray();
            foreach (string origIP in toBlock)
            {
                Assert.IsTrue(bannedIP.Contains(origIP));
            }
        }

        [Test]
        public void TestIPV6()
        {
            string[] toBlock = new string[] { "fe80::c872:be03:5c94:4af2%8", "192.168.0.20" };
            firewall.BlockIPAddresses(null, toBlock).Sync();
            string[] bannedIP = firewall.EnumerateBannedIPAddresses().ToArray();
            string[] bannedIP2 = firewall.EnumerateIPAddresses().Select(i => i.Begin.ToString()).ToArray();
            Assert.AreEqual(bannedIP.Length, bannedIP2.Length);
            for (int i = 0; i < bannedIP.Length; i++)
            {
                Assert.AreEqual(bannedIP[i], bannedIP2[i]);
            }
            foreach (string origIP in toBlock)
            {
                if (ExtensionMethods.TryNormalizeIPAddress(origIP, out string normalizedIP))
                {
                    Assert.IsTrue(bannedIP.Contains(normalizedIP));
                }
                else
                {
                    Assert.Fail("Bad ip: " + origIP);
                }
            }
        }

        [Test]
        public void TestIPConversion()
        {
            uint value = "192.168.1.123".ToIPAddress().ToUInt32();
            Assert.AreEqual(0xc0a8017b, value);
            string ip = value.ToIPAddress().ToString();
            Assert.AreEqual("192.168.1.123", ip);
            UInt128 value2 = "fe80::c872:be03:5c94:4af2".ToIPAddress().ToUInt128();
            Assert.AreEqual((UInt128)System.Numerics.BigInteger.Parse("338288524927261089668462712717925698290"), value2);
            string ip2 = value2.ToIPAddress().ToString();
            Assert.AreEqual("fe80::c872:be03:5c94:4af2", ip2);
            Assert.IsNull("a".ToIPAddress());
            Assert.IsNull("".ToIPAddress());
            Assert.IsNull(((string)null).ToIPAddress());
            Assert.Throws(typeof(InvalidOperationException), () =>
            {
                "192.168.1.123".ToIPAddress().ToUInt128();
            });
            Assert.Throws(typeof(InvalidOperationException), () =>
            {
                "fe80::c872:be03:5c94:4af2".ToIPAddress().ToUInt32();
            });
        }

        [Test]
        public void TestIPInternal()
        {
            IPAddress ip = IPAddress.Parse("127.0.0.1");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("::1");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("10.0.0.0");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("10.255.255.255");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("127.0.0.0");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("127.255.255.255");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("172.16.0.0");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("172.31.255.255");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("192.168.0.0");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("192.168.255.255");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("99.99.99.99");
            Assert.IsFalse(ip.IsInternal());
        }

        [Test]
        public void TestBlockDelta()
        {
            Random r = new();
            byte[] ipBytes = new byte[4];
            string[] ips = new string[5005];
            for (int i = 0; i < ips.Length; i++)
            {
                r.NextBytes(ipBytes);
                ipBytes[0] = 99;
                string ip = new IPAddress(ipBytes).ToString();
                if (ips.Contains(ip))
                {
                    i--;
                    continue;
                }
                ips[i] = ip;
            }
            string[] newIps = new string[10];
            Array.Sort(ips);

            // make new ip to add, ensure they are not in the list
            for (int i = 0; i < newIps.Length; i++)
            {
                r.NextBytes(ipBytes);
                ipBytes[0] = 98;
                string ip = new IPAddress(ipBytes).ToString();
                newIps[i] = ip;
            }

            string[] ipsToRemove = new string[] { ips[999], ips[444], ips[0], ips[1000], ips[1444], ips[1999] };
            string[] ipsToAddExist = new string[] { ips[995], ips[441], ips[54], ips[1200], ips[1344], ips[1599] };
            Array.Sort(ipsToRemove);

            firewall.BlockIPAddresses(null, ips).Sync();
            string[] ipsBlocked = firewall.EnumerateIPAddresses(null).Select(i => i.Begin.ToString()).ToArray();
            Assert.AreEqual(ips.Length, ipsBlocked.Length, "Mismatching count from firewall block and retrieval");
            Assert.AreEqual(ipsBlocked.Length, new HashSet<string>(ipsBlocked).Count, "Duplicate ip from firewall block and retrieval");
            Array.Sort(ipsBlocked);
            Assert.AreEqual(ips, ipsBlocked);
            firewall.BlockIPAddressesDelta(null, new IPBanFirewallIPAddressDelta[]
            {
                // remove 6 that exist
                new IPBanFirewallIPAddressDelta { IPAddress = ipsToRemove[0] },
                new IPBanFirewallIPAddressDelta { IPAddress = ipsToRemove[1] },
                new IPBanFirewallIPAddressDelta { IPAddress = ipsToRemove[2] },
                new IPBanFirewallIPAddressDelta { IPAddress = ipsToRemove[3] },
                new IPBanFirewallIPAddressDelta { IPAddress = ipsToRemove[4] },
                new IPBanFirewallIPAddressDelta { IPAddress = ipsToRemove[5] },

                // remove 1 that does not exist
                new IPBanFirewallIPAddressDelta { IPAddress = "88.88.88.88" },

                // add 10 new
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[0] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[1] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[2] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[3] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[4] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[5] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[6] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[7] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[8] },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = newIps[9] }
            }).Sync();

            foreach (string ip in ipsToRemove)
            {
                Assert.IsFalse(firewall.IsIPAddressBlocked(ip, out _), "Failed to remove ip " + ip);
            }
            string[] firewallIP = firewall.EnumerateIPAddresses().Select(r2 => r2.Begin.ToString()).ToArray();
            string[] sentIP = ips.Where(i => !ipsToRemove.Contains(i)).Union(newIps).ToArray();
            Array.Sort(firewallIP);
            Array.Sort(sentIP);
            Assert.AreEqual(sentIP, firewallIP);

            // clear out everything
            firewall.Truncate();

            // block 1000, on Windows this will cause a rule overflow
            firewall.BlockIPAddresses(null, ips.Take(1000));

            firewall.BlockIPAddressesDelta(null, new IPBanFirewallIPAddressDelta[]
            {
                // add a one-off, on Windows this should cause a rule overflow
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = "91.91.91.91" }
            }).Sync();

            firewallIP = firewall.EnumerateIPAddresses().Select(r2 => r2.Begin.ToString()).ToArray();
            sentIP = ips.Take(1000).Concat(new string[] { "91.91.91.91" }).ToArray();
            Array.Sort(firewallIP);
            Array.Sort(sentIP);
            Assert.AreEqual(sentIP, firewallIP);
            Assert.IsTrue(firewall.IsIPAddressBlocked("91.91.91.91", out _), "Failed to block overflow ip 91.91.91.91");
        }

        [Test]
        public void TestParseIP()
        {
            Assert.IsTrue(ExtensionMethods.TryNormalizeIPAddress("1.1.1.1", out _));
            Assert.IsTrue(ExtensionMethods.TryNormalizeIPAddress("1.1.1.1:8080", out _));
            Assert.IsTrue(ExtensionMethods.TryNormalizeIPAddress("1.1.1.1/24", out _)); // fe80::c872:be03:5c94:4af2%8
            Assert.IsTrue(ExtensionMethods.TryNormalizeIPAddress("fe80::c872:be03:5c94:4af2%8", out _));
            Assert.IsFalse(ExtensionMethods.TryNormalizeIPAddress("a.1.1.1", out _));
        }
    }
}
