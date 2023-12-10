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
using NUnit.Framework.Legacy;

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
            ClassicAssert.IsTrue(db.TryGetIPAddress(ip, out IPBanDB.IPAddressEntry entry));
            ClassicAssert.AreEqual(entry.UserName, "testuser");
            ClassicAssert.AreEqual(entry.Source, "testsource");
            ClassicAssert.AreEqual(1, count);
            ClassicAssert.AreEqual(1, db.EnumerateIPAddresses(dt1.AddMinutes(1.0)).Count());
            count = db.IncrementFailedLoginCount(ip, null, null, dt2, 2);
            ClassicAssert.AreEqual(3, count);
            ClassicAssert.AreEqual(0, db.EnumerateIPAddresses(dt1.AddMinutes(1.0)).Count());
            ClassicAssert.IsTrue(db.SetBanDates(ip, dt2, dt3, now));

            // increment fail login for a ban or ban pending should do nothing
            ClassicAssert.AreEqual(3, db.IncrementFailedLoginCount(ip, null, null, dt2.AddSeconds(15.0f), 10));

            ClassicAssert.IsFalse(db.SetBanDates(ip, dt2 + TimeSpan.FromDays(1.0), dt4, now)); // no effect
            ClassicAssert.IsTrue(db.TryGetIPAddress(ip, out IPBanDB.IPAddressEntry e));
            ClassicAssert.AreEqual(ip, e.IPAddress);
            ClassicAssert.AreEqual(dt2, e.LastFailedLogin);
            ClassicAssert.AreEqual(3, e.FailedLoginCount);
            ClassicAssert.AreEqual(dt2, e.BanStartDate);
            count = db.IncrementFailedLoginCount("5.5.5.5", null, null, dt1, 2);
            ClassicAssert.AreEqual(2, count);
            count = db.GetIPAddressCount();
            ClassicAssert.AreEqual(2, count);
            count = db.GetBannedIPAddressCount();
            ClassicAssert.AreEqual(1, count);
            ClassicAssert.IsTrue(db.TryGetBanDates(ip, out KeyValuePair<DateTime?, DateTime?> banDate));
            ClassicAssert.AreEqual(dt2, banDate.Key);
            ClassicAssert.AreEqual(dt3, banDate.Value);
            ClassicAssert.IsTrue(db.TryGetBanDates("5.5.5.5", out banDate));
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
            ClassicAssert.AreEqual(6, count);
            IPAddressRange range = IPAddressRange.Parse("5.5.5.0/24");
            count = 0;
            foreach (string ipAddress in db.DeleteIPAddresses(range))
            {
                ClassicAssert.IsTrue(ipAddress == "5.5.5.5" || ipAddress == "5.5.5.6");
                count++;
            }
            db.SetBannedIPAddresses(new Tuple<string, DateTime, DateTime>[]
            {
                    new Tuple<string, DateTime, DateTime>("5.5.5.5", dt2, dt3),
                    new Tuple<string, DateTime, DateTime>("5.5.5.6", dt2, dt3)
            }, now);
            count = db.IncrementFailedLoginCount("9.9.9.9", null, null, dt2, 1);
            ClassicAssert.AreEqual(1, count);
            count = 0;
            range = new IPAddressRange(System.Net.IPAddress.Parse("::5.5.5.0"), System.Net.IPAddress.Parse("::5.5.5.255"));
            foreach (string ipAddress in db.DeleteIPAddresses(range))
            {
                ClassicAssert.AreEqual(ipAddress, "::5.5.5.5");
                count++;
            }
            ClassicAssert.AreEqual(1, count);
            IPBanDB.IPAddressEntry[] ipAll = db.EnumerateIPAddresses().ToArray();
            ClassicAssert.AreEqual(7, ipAll.Length);

            // ensure deltas work properly
            ClassicAssert.AreEqual(1, db.SetIPAddressesState(new string[] { "5.5.5.5" }, IPBanDB.IPAddressState.RemovePending));
            IPBanFirewallIPAddressDelta[] deltas = db.EnumerateIPAddressesDeltaAndUpdateState(false, now).ToArray();
            ClassicAssert.AreEqual(6, deltas.Length);
            ClassicAssert.AreEqual("10.10.10.10", deltas[0].IPAddress);
            ClassicAssert.AreEqual("11.11.11.11", deltas[1].IPAddress);
            ClassicAssert.AreEqual("12.12.12.12", deltas[2].IPAddress);
            ClassicAssert.AreEqual("5.5.5.5", deltas[3].IPAddress);
            ClassicAssert.AreEqual("5.5.5.6", deltas[4].IPAddress);
            ClassicAssert.AreEqual("6.6.6.6", deltas[5].IPAddress);
            ClassicAssert.IsTrue(deltas[0].Added);
            ClassicAssert.IsTrue(deltas[1].Added);
            ClassicAssert.IsTrue(deltas[2].Added);
            ClassicAssert.IsFalse(deltas[3].Added);
            ClassicAssert.IsTrue(deltas[4].Added);
            ClassicAssert.IsTrue(deltas[5].Added);
            deltas = db.EnumerateIPAddressesDeltaAndUpdateState(true, now).ToArray();
            ClassicAssert.AreEqual(6, deltas.Length);
            ClassicAssert.AreEqual("10.10.10.10", deltas[0].IPAddress);
            ClassicAssert.AreEqual("11.11.11.11", deltas[1].IPAddress);
            ClassicAssert.AreEqual("12.12.12.12", deltas[2].IPAddress);
            ClassicAssert.AreEqual("5.5.5.5", deltas[3].IPAddress);
            ClassicAssert.AreEqual("5.5.5.6", deltas[4].IPAddress);
            ClassicAssert.AreEqual("6.6.6.6", deltas[5].IPAddress);
            ClassicAssert.IsTrue(deltas[0].Added);
            ClassicAssert.IsTrue(deltas[1].Added);
            ClassicAssert.IsTrue(deltas[2].Added);
            ClassicAssert.IsFalse(deltas[3].Added);
            ClassicAssert.IsTrue(deltas[4].Added);
            ClassicAssert.IsTrue(deltas[5].Added);
            string[] bannedIpAll = db.EnumerateBannedIPAddresses().ToArray();
            ClassicAssert.AreEqual(5, bannedIpAll.Length);
            deltas = db.EnumerateIPAddressesDeltaAndUpdateState(true, now).ToArray();
            ClassicAssert.AreEqual(0, deltas.Length);

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
            ClassicAssert.AreEqual(65536, count);
            DateTime cutOff = now - TimeSpan.FromMilliseconds(1634.0);
            IPBanDB.IPAddressEntry[] entries = db.EnumerateIPAddresses(null, cutOff).ToArray();
            ClassicAssert.AreEqual(65536 - 1634, entries.Length);
            TimeSpan span = (IPBanService.UtcNow - now);

            // make sure performance is good
            ClassicAssert.Less(span, TimeSpan.FromSeconds(10.0));
        }
    }
}