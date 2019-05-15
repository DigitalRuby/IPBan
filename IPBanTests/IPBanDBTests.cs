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
using System.IO;
using System.Linq;
using DigitalRuby.IPBan;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanDBTests
    {
        [Test]
        public void TestDB()
        {
            DateTime now = DateTime.UtcNow;
            using (IPBanDB db = new IPBanDB())
            {
                db.Truncate(true);
                const string ip = "10.10.10.10";
                DateTime dt1 = new DateTime(2018, 1, 1, 1, 1, 1, 1, DateTimeKind.Utc);
                DateTime dt2 = new DateTime(2019, 1, 1, 1, 1, 1, 1, DateTimeKind.Utc);
                int count = db.IncrementFailedLoginCount(ip, dt1, 1);
                Assert.AreEqual(1, count);
                Assert.AreEqual(1, db.EnumerateIPAddresses(dt1.AddMinutes(1.0)).Count());
                count = db.IncrementFailedLoginCount(ip, dt2, 2);
                Assert.AreEqual(3, count);
                Assert.AreEqual(0, db.EnumerateIPAddresses(dt1.AddMinutes(1.0)).Count());
                Assert.IsTrue(db.SetBanDate(ip, dt2));
                Assert.IsFalse(db.SetBanDate(ip, dt2 + TimeSpan.FromDays(1.0))); // no effect
                IPBanDB.IPAddressEntry e = db.GetIPAddress(ip);
                Assert.AreEqual(ip, e.IPAddress);
                Assert.AreEqual(dt2, e.LastFailedLogin);
                Assert.AreEqual(3, e.FailedLoginCount);
                Assert.AreEqual(dt2, e.BanDate);
                count = db.IncrementFailedLoginCount("5.5.5.5", dt1, 2);
                Assert.AreEqual(2, count);
                count = db.GetIPAddressCount();
                Assert.AreEqual(2, count);
                count = db.GetBannedIPAddressCount();
                Assert.AreEqual(1, count);
                DateTime? banDate = db.GetBanDate(ip);
                Assert.IsNotNull(banDate);
                Assert.AreEqual(dt2, banDate);
                banDate = db.GetBanDate("5.5.5.5");
                Assert.IsNull(banDate);
                count = db.SetBannedIPAddresses(new KeyValuePair<string, DateTime>[]
                {
                    new KeyValuePair<string, DateTime>(ip, dt2),
                    new KeyValuePair<string, DateTime>("5.5.5.5", dt2),
                    new KeyValuePair<string, DateTime>("5.5.5.6", dt2),
                    new KeyValuePair<string, DateTime>("::5.5.5.5", dt2),
                    new KeyValuePair<string, DateTime>("6.6.6.6", dt2),
                    new KeyValuePair<string, DateTime>("11.11.11.11", dt2),
                    new KeyValuePair<string, DateTime>("12.12.12.12", dt2),
                    new KeyValuePair<string, DateTime>("11.11.11.11", dt2)
                });
                Assert.AreEqual(6, count);
                count = db.GetBannedIPAddressCount();
                Assert.AreEqual(7, count);
                IPAddressRange range = IPAddressRange.Parse("5.5.5.0/24");
                count = 0;
                foreach (string ipAddress in db.DeleteIPAddresses(range))
                {
                    Assert.IsTrue(ipAddress == "5.5.5.5" || ipAddress == "5.5.5.6");
                    count++;
                }
                db.SetBannedIPAddresses(new KeyValuePair<string, DateTime>[]
                {
                    new KeyValuePair<string, DateTime>("5.5.5.5", dt2),
                    new KeyValuePair<string, DateTime>("5.5.5.6", dt2)
                });
                count = db.IncrementFailedLoginCount("9.9.9.9", dt2, 1);
                Assert.AreEqual(1, count);
                count = 0;
                range = new IPAddressRange { Begin = System.Net.IPAddress.Parse("::5.5.5.0"), End = System.Net.IPAddress.Parse("::5.5.5.255") };
                foreach (string ipAddress in db.DeleteIPAddresses(range))
                {
                    Assert.AreEqual(ipAddress, "::5.5.5.5");
                    count++;
                }
                Assert.AreEqual(1, count);
                IPBanDB.IPAddressEntry[] ipAll = db.EnumerateIPAddresses().ToArray();
                Assert.AreEqual(7, ipAll.Length);
                string[] bannedIpAll = db.EnumerateBannedIPAddresses().ToArray();
                Assert.AreEqual(6, bannedIpAll.Length);

                // ensure deltas work properly
                Assert.AreEqual(1, db.SetIPAddressesState(new string[] { "5.5.5.5" }, IPBanDB.IPAddressState.RemovePending));
                IPBanFirewallIPAddressDelta[] deltas = db.EnumerateIPAddressesDelta(false).ToArray();
                Assert.AreEqual(6, deltas.Length);
                Assert.AreEqual("10.10.10.10", deltas[0].IPAddress);
                Assert.AreEqual("11.11.11.11", deltas[1].IPAddress);
                Assert.AreEqual("12.12.12.12", deltas[2].IPAddress);
                Assert.AreEqual("5.5.5.5", deltas[3].IPAddress);
                Assert.AreEqual("5.5.5.6", deltas[4].IPAddress);
                Assert.AreEqual("6.6.6.6", deltas[5].IPAddress);
                Assert.IsTrue(deltas[0].Added);
                Assert.IsTrue(deltas[1].Added);
                Assert.IsTrue(deltas[2].Added);
                Assert.IsFalse(deltas[3].Added);
                Assert.IsTrue(deltas[4].Added);
                Assert.IsTrue(deltas[5].Added);
                deltas = db.EnumerateIPAddressesDelta(true).ToArray();
                Assert.AreEqual(6, deltas.Length);
                Assert.AreEqual("10.10.10.10", deltas[0].IPAddress);
                Assert.AreEqual("11.11.11.11", deltas[1].IPAddress);
                Assert.AreEqual("12.12.12.12", deltas[2].IPAddress);
                Assert.AreEqual("5.5.5.5", deltas[3].IPAddress);
                Assert.AreEqual("5.5.5.6", deltas[4].IPAddress);
                Assert.AreEqual("6.6.6.6", deltas[5].IPAddress);
                Assert.IsTrue(deltas[0].Added);
                Assert.IsTrue(deltas[1].Added);
                Assert.IsTrue(deltas[2].Added);
                Assert.IsFalse(deltas[3].Added);
                Assert.IsTrue(deltas[4].Added);
                Assert.IsTrue(deltas[5].Added);
                deltas = db.EnumerateIPAddressesDelta(true).ToArray();
                Assert.AreEqual(0, deltas.Length);

                db.Truncate(true);
                KeyValuePair<string, DateTime>[] ips = new KeyValuePair<string, DateTime>[65536];
                int index = 0;
                for (int i = 0; i < 256; i++)
                {
                    for (int j = 0; j < 256; j++)
                    {
                        ips[index++] = new KeyValuePair<string, DateTime>("255." + i + ".255." + j, (now = now.AddMilliseconds(1)));
                    }
                }
                count = db.SetBannedIPAddresses(ips);
                Assert.AreEqual(65536, count);
                Assert.AreEqual(65536 - 1634, db.EnumerateIPAddresses(null, now.Subtract(TimeSpan.FromMilliseconds(1634.0))).Count());
                TimeSpan span = (DateTime.UtcNow - now);

                // make sure performance is good
                Assert.Less(span, TimeSpan.FromSeconds(10.0));
            }
        }
    }
}