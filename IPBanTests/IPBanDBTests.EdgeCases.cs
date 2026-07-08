/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPBanDB - DeleteIPAddress / DeleteIPAddresses, ban-state
queries, EnumerateBannedIPAddresses, Truncate variants. Complements the existing
IPBanDBTests file with edge cases and the lesser-used overloads.
*/

using System;
using System.Linq;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    public partial class IPBanDBTests
    {
        [Test]
        public void IncrementFailedLoginCount_NonIp_ReturnsZero()
        {
            using IPBanDB db = new();
            db.Truncate(true);
            int count = db.IncrementFailedLoginCount("not-an-ip", "user", "src", DateTime.UtcNow, 1);
            ClassicAssert.AreEqual(0, count);
        }

        [Test]
        public void TryGetIPAddress_NonIp_ReturnsFalse()
        {
            using IPBanDB db = new();
            db.Truncate(true);
            ClassicAssert.IsFalse(db.TryGetIPAddress("not-an-ip", out _));
        }

        [Test]
        public void TryGetBanDates_NonExistentIp_ReturnsFalse()
        {
            using IPBanDB db = new();
            db.Truncate(true);
            ClassicAssert.IsFalse(db.TryGetBanDates("9.9.9.9", out _));
        }

        [Test]
        public void SetBanDates_NewIp_AndQuery()
        {
            // The DB stores ban dates as UTC unix timestamps; the round-trip returns local time
            // when read back (the conversion uses .ToDateTimeUnixMilliseconds()), so just verify
            // the round-trip value equals the round-tripped form rather than the literal we put in.
            IPBanService.UtcNow = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            using IPBanDB db = new();
            db.Truncate(true);
            DateTime now = IPBanService.UtcNow;
            ClassicAssert.IsTrue(db.SetBanDates("1.2.3.4", now, now.AddDays(1), now));
            ClassicAssert.IsTrue(db.TryGetBanDates("1.2.3.4", out var dates));
            ClassicAssert.AreEqual(now.ToUnixMillisecondsLong(), dates.Key.Value.ToUnixMillisecondsLong());
            ClassicAssert.AreEqual(now.AddDays(1).ToUnixMillisecondsLong(), dates.Value.Value.ToUnixMillisecondsLong());
            ClassicAssert.GreaterOrEqual(db.GetIPAddressCount(), 1);
            ClassicAssert.GreaterOrEqual(db.GetBannedIPAddressCount(), 1);
            ClassicAssert.IsTrue(db.TryGetIPAddressState("1.2.3.4", out _));
        }

        [Test]
        public void SetBannedIPAddresses_ZeroOrMore()
        {
            IPBanService.UtcNow = new DateTime(2024, 1, 1);
            using IPBanDB db = new();
            db.Truncate(true);

            DateTime now = IPBanService.UtcNow;
            int count = db.SetBannedIPAddresses(new[]
            {
                new Tuple<string, DateTime, DateTime>("10.0.0.1", now, now.AddDays(1)),
                new Tuple<string, DateTime, DateTime>("10.0.0.2", now, now.AddDays(1)),
            }, now);
            ClassicAssert.AreEqual(2, count);
        }

        [Test]
        public void DeleteIPAddress_RoundTrip()
        {
            IPBanService.UtcNow = new DateTime(2024, 1, 1);
            using IPBanDB db = new();
            db.Truncate(true);
            DateTime now = IPBanService.UtcNow;
            db.SetBanDates("8.8.8.8", now, now.AddDays(1), now);
            ClassicAssert.IsTrue(db.DeleteIPAddress("8.8.8.8"));
            ClassicAssert.IsFalse(db.TryGetIPAddress("8.8.8.8", out _));
        }

        [Test]
        public void DeleteIPAddresses_ByCollection()
        {
            IPBanService.UtcNow = new DateTime(2024, 1, 1);
            using IPBanDB db = new();
            db.Truncate(true);
            DateTime now = IPBanService.UtcNow;
            db.SetBanDates("8.8.8.8", now, now.AddDays(1), now);
            db.SetBanDates("9.9.9.9", now, now.AddDays(1), now);
            int deleted = db.DeleteIPAddresses(new[] { "8.8.8.8", "9.9.9.9", "missing.ip" });
            ClassicAssert.GreaterOrEqual(deleted, 2);
        }

        [Test]
        public void DeleteIPAddresses_ByRange()
        {
            IPBanService.UtcNow = new DateTime(2024, 1, 1);
            using IPBanDB db = new();
            db.Truncate(true);
            DateTime now = IPBanService.UtcNow;
            db.SetBanDates("10.0.0.5", now, now.AddDays(1), now);
            db.SetBanDates("10.0.0.6", now, now.AddDays(1), now);
            db.SetBanDates("11.0.0.5", now, now.AddDays(1), now);
            var deleted = db.DeleteIPAddresses(IPAddressRange.Parse("10.0.0.0/24")).ToArray();
            ClassicAssert.GreaterOrEqual(deleted.Length, 2);
            ClassicAssert.IsTrue(db.TryGetIPAddress("11.0.0.5", out _));
        }

        [Test]
        public void EnumerateBannedIPAddresses_AfterStateActive_Lists()
        {
            // EnumerateBannedIPAddresses filters by State = 0 (active in firewall). SetBanDates
            // alone records state 1 (pending). Promote to active via SetIPAddressesState first.
            IPBanService.UtcNow = new DateTime(2024, 1, 1);
            using IPBanDB db = new();
            db.Truncate(true);
            DateTime now = IPBanService.UtcNow;
            db.SetBanDates("4.4.4.4", now, now.AddDays(1), now);
            db.SetIPAddressesState(new[] { "4.4.4.4" }, IPBanDB.IPAddressState.Active);
            var ips = db.EnumerateBannedIPAddresses().ToArray();
            ClassicAssert.IsTrue(ips.Contains("4.4.4.4"));
        }

        [Test]
        public void Truncate_OnlyBans_KeepsFailedOnly()
        {
            IPBanService.UtcNow = new DateTime(2024, 1, 1);
            using IPBanDB db = new();
            db.Truncate(true);
            DateTime now = IPBanService.UtcNow;
            db.IncrementFailedLoginCount("3.3.3.3", "user", "src", now, 1);
            db.SetBanDates("4.4.4.4", now, now.AddDays(1), now);
            db.Truncate(confirm: true, onlyBans: true);
            ClassicAssert.IsTrue(db.TryGetIPAddress("3.3.3.3", out _));
            ClassicAssert.IsFalse(db.TryGetIPAddress("4.4.4.4", out _));
        }

        [Test]
        public void Truncate_NotConfirmed_DoesNothing()
        {
            IPBanService.UtcNow = new DateTime(2024, 1, 1);
            using IPBanDB db = new();
            db.Truncate(true);
            db.IncrementFailedLoginCount("5.5.5.5", "user", "src", IPBanService.UtcNow, 1);
            db.Truncate(confirm: false);
            ClassicAssert.IsTrue(db.TryGetIPAddress("5.5.5.5", out _));
        }
    }
}
