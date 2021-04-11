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

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanDBTests
    {
        [TearDown]
        public void Teardown()
        {
            IPBanService.UtcNow = default;
        }

        [Test]
        public void TestDB()
        {
            IPBanService.UtcNow = new DateTime(2020, 1, 1);
            DateTime now = IPBanService.UtcNow;
            using IPBanDB db = new();
            db.Truncate(true);
            const string ip = "10.10.10.10";
            int year = now.Year;
            DateTime dt1 = new(year - 1, 1, 1, 1, 1, 1, 1, DateTimeKind.Utc);
            DateTime dt2 = new(year, 1, 1, 1, 1, 1, 1, DateTimeKind.Utc);
            DateTime dt3 = new(year + 1, 1, 1, 1, 1, 1, 1, DateTimeKind.Utc);
            DateTime dt4 = new(year + 2, 1, 1, 1, 1, 1, 1, DateTimeKind.Utc);
            int count = db.IncrementFailedLoginCount(ip, "testuser", "testsource", dt1, 1);
            Assert.IsTrue(db.TryGetIPAddress(ip, out IPBanDB.IPAddressEntry entry));
            Assert.AreEqual(entry.UserName, "testuser");
            Assert.AreEqual(entry.Source, "testsource");
            Assert.AreEqual(1, count);
            Assert.AreEqual(1, db.EnumerateIPAddresses(dt1.AddMinutes(1.0)).Count());
            count = db.IncrementFailedLoginCount(ip, null, null, dt2, 2);
            Assert.AreEqual(3, count);
            Assert.AreEqual(0, db.EnumerateIPAddresses(dt1.AddMinutes(1.0)).Count());
            Assert.IsTrue(db.SetBanDates(ip, dt2, dt3, now));

            // increment fail login for a ban or ban pending should do nothing
            Assert.AreEqual(3, db.IncrementFailedLoginCount(ip, null, null, dt2.AddSeconds(15.0f), 10));

            Assert.IsFalse(db.SetBanDates(ip, dt2 + TimeSpan.FromDays(1.0), dt4, now)); // no effect
            Assert.IsTrue(db.TryGetIPAddress(ip, out IPBanDB.IPAddressEntry e));
            Assert.AreEqual(ip, e.IPAddress);
            Assert.AreEqual(dt2, e.LastFailedLogin);
            Assert.AreEqual(3, e.FailedLoginCount);
            Assert.AreEqual(dt2, e.BanStartDate);
            count = db.IncrementFailedLoginCount("5.5.5.5", null, null, dt1, 2);
            Assert.AreEqual(2, count);
            count = db.GetIPAddressCount();
            Assert.AreEqual(2, count);
            count = db.GetBannedIPAddressCount();
            Assert.AreEqual(1, count);
            Assert.IsTrue(db.TryGetBanDates(ip, out KeyValuePair<DateTime?, DateTime?> banDate));
            Assert.AreEqual(dt2, banDate.Key);
            Assert.AreEqual(dt3, banDate.Value);
            Assert.IsTrue(db.TryGetBanDates("5.5.5.5", out banDate));
            count = db.SetBannedIPAddresses(new Tuple<string, DateTime, DateTime>[]
            {
                    new Tuple<string, DateTime, DateTime>(ip, dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("5.5.5.5", dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("5.5.5.6", dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("::5.5.5.5", dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("6.6.6.6", dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("11.11.11.11", dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("12.12.12.12", dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("11.11.11.11", dt2, dt3)
            }, now);
            Assert.AreEqual(6, count);
            IPAddressRange range = IPAddressRange.Parse("5.5.5.0/24");
            count = 0;
            foreach (string ipAddress in db.DeleteIPAddresses(range))
            {
                Assert.IsTrue(ipAddress == "5.5.5.5" || ipAddress == "5.5.5.6");
                count++;
            }
            db.SetBannedIPAddresses(new Tuple<string, DateTime, DateTime>[]
            {
                    new Tuple<string, DateTime, DateTime>("5.5.5.5", dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("5.5.5.6", dt2, dt3)
            }, now);
            count = db.IncrementFailedLoginCount("9.9.9.9", null, null, dt2, 1);
            Assert.AreEqual(1, count);
            count = 0;
            range = new IPAddressRange(System.Net.IPAddress.Parse("::5.5.5.0"), System.Net.IPAddress.Parse("::5.5.5.255"));
            foreach (string ipAddress in db.DeleteIPAddresses(range))
            {
                Assert.AreEqual(ipAddress, "::5.5.5.5");
                count++;
            }
            Assert.AreEqual(1, count);
            IPBanDB.IPAddressEntry[] ipAll = db.EnumerateIPAddresses().ToArray();
            Assert.AreEqual(7, ipAll.Length);

            // ensure deltas work properly
            Assert.AreEqual(1, db.SetIPAddressesState(new string[] { "5.5.5.5" }, IPBanDB.IPAddressState.RemovePending));
            IPBanFirewallIPAddressDelta[] deltas = db.EnumerateIPAddressesDeltaAndUpdateState(false, now).ToArray();
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
            deltas = db.EnumerateIPAddressesDeltaAndUpdateState(true, now).ToArray();
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
            string[] bannedIpAll = db.EnumerateBannedIPAddresses().ToArray();
            Assert.AreEqual(5, bannedIpAll.Length);
            deltas = db.EnumerateIPAddressesDeltaAndUpdateState(true, now).ToArray();
            Assert.AreEqual(0, deltas.Length);

            db.Truncate(true);
            DateTime banStart = now;
            Tuple<string, DateTime, DateTime>[] ips = new Tuple<string, DateTime, DateTime>[65536];
            int index = 0;
            for (int i = 0; i < 256; i++)
            {
                for (int j = 0; j < 256; j++)
                {
                    ips[index++] = new Tuple<string, DateTime, DateTime>("255." + i + ".255." + j, banStart, (now = now.AddMilliseconds(1)));
                }
            }
            count = db.SetBannedIPAddresses(ips, now);
            Assert.AreEqual(65536, count);
            DateTime cutOff = now - TimeSpan.FromMilliseconds(1634.0);
            IPBanDB.IPAddressEntry[] entries = db.EnumerateIPAddresses(null, cutOff).ToArray();
            Assert.AreEqual(65536 - 1634, entries.Length);
            TimeSpan span = (IPBanService.UtcNow - now);

            // make sure performance is good
            Assert.Less(span, TimeSpan.FromSeconds(10.0));
        }
    }
}