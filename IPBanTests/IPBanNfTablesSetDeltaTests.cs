/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanLinuxFirewallNFTables.ComputeSetElementDelta. nft -f runs as one transaction, so a
single delete of an element that is not in the set ("Error: element does not exist") rolls back
every add in the same batch. The delta computation must only emit operations nft will accept.
*/

using System.Collections.Generic;
using System.Linq;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanNfTablesSetDeltaTests
    {
        private static List<IPAddressRange> Ranges(params string[] values) =>
            [.. values.Select(v => IPAddressRange.Parse(v))];

        private static string[] Strings(IEnumerable<IPAddressRange> ranges) =>
            [.. ranges.OrderBy(r => r).Select(r => r.ToString())];

        private static string[] Expect(params string[] values) => Strings(Ranges(values));

        private static void Compute(List<IPAddressRange> existing, List<IPAddressRange> adds, List<IPAddressRange> removes,
            out List<IPAddressRange> toDelete, out List<IPAddressRange> toAdd)
        {
            toDelete = [];
            toAdd = [];
            IPBanLinuxFirewallNFTables.ComputeSetElementDelta(existing, adds, removes, toDelete, toAdd);
        }

        [Test]
        public void RemoveMissingElement_IsSkipped()
        {
            Compute(Ranges("1.1.1.1"), [], Ranges("129.121.140.225"), out var toDelete, out var toAdd);
            CollectionAssert.IsEmpty(toDelete);
            CollectionAssert.IsEmpty(toAdd);
        }

        [Test]
        public void RemoveMissingElement_DoesNotDropAdds()
        {
            Compute(Ranges("1.1.1.1"), Ranges("20.219.14.152"), Ranges("91.207.54.182", "112.199.113.210"),
                out var toDelete, out var toAdd);
            CollectionAssert.IsEmpty(toDelete);
            CollectionAssert.AreEqual(Expect("20.219.14.152"), Strings(toAdd));
        }

        [Test]
        public void RemoveExactElement_IsDeleted()
        {
            Compute(Ranges("1.1.1.1", "2.2.2.2"), [], Ranges("2.2.2.2"), out var toDelete, out var toAdd);
            CollectionAssert.AreEqual(Expect("2.2.2.2"), Strings(toDelete));
            CollectionAssert.IsEmpty(toAdd);
        }

        [Test]
        public void RemoveFromCombinedRange_SplitsRange()
        {
            // a full set update combines adjacent ips into ranges, a later single ip unban must split the range
            Compute(Ranges("10.0.0.1-10.0.0.5"), [], Ranges("10.0.0.3"), out var toDelete, out var toAdd);
            CollectionAssert.AreEqual(Expect("10.0.0.1-10.0.0.5"), Strings(toDelete));
            CollectionAssert.AreEqual(Expect("10.0.0.1-10.0.0.2", "10.0.0.4-10.0.0.5"), Strings(toAdd));
        }

        [Test]
        public void RemoveRangeEdgesAndMultiple_SplitsOnce()
        {
            Compute(Ranges("10.0.0.1-10.0.0.5"), [], Ranges("10.0.0.1", "10.0.0.5", "10.0.0.3"),
                out var toDelete, out var toAdd);
            CollectionAssert.AreEqual(Expect("10.0.0.1-10.0.0.5"), Strings(toDelete));
            CollectionAssert.AreEqual(Expect("10.0.0.2", "10.0.0.4"), Strings(toAdd));
        }

        [Test]
        public void AddAlreadyCovered_IsSkipped()
        {
            Compute(Ranges("10.0.0.0/24", "5.5.5.5"), Ranges("10.0.0.7", "5.5.5.5"), [], out var toDelete, out var toAdd);
            CollectionAssert.IsEmpty(toDelete);
            CollectionAssert.IsEmpty(toAdd);
        }

        [Test]
        public void AddAndRemoveSameIP_RemoveWins()
        {
            Compute(Ranges("3.3.3.3"), Ranges("3.3.3.3", "4.4.4.4"), Ranges("3.3.3.3"), out var toDelete, out var toAdd);
            CollectionAssert.AreEqual(Expect("3.3.3.3"), Strings(toDelete));
            CollectionAssert.AreEqual(Expect("4.4.4.4"), Strings(toAdd));
        }

        [Test]
        public void DuplicateAdds_AddedOnce()
        {
            Compute([], Ranges("6.6.6.6", "6.6.6.6"), [], out var toDelete, out var toAdd);
            CollectionAssert.IsEmpty(toDelete);
            CollectionAssert.AreEqual(Expect("6.6.6.6"), Strings(toAdd));
        }

        [Test]
        public void AddIntoSplitRange_NotDuplicated()
        {
            // 10.0.0.4 is re-added as part of the split pieces, so a separate add must not duplicate it
            Compute(Ranges("10.0.0.1-10.0.0.5"), Ranges("10.0.0.4"), Ranges("10.0.0.3"), out var toDelete, out var toAdd);
            CollectionAssert.AreEqual(Expect("10.0.0.1-10.0.0.5"), Strings(toDelete));
            CollectionAssert.AreEqual(Expect("10.0.0.1-10.0.0.2", "10.0.0.4-10.0.0.5"), Strings(toAdd));
        }

        [Test]
        public void IPv6_RemoveFromRange_Splits()
        {
            Compute(Ranges("2001:db8::1-2001:db8::3"), [], Ranges("2001:db8::2"), out var toDelete, out var toAdd);
            CollectionAssert.AreEqual(Expect("2001:db8::1-2001:db8::3"), Strings(toDelete));
            CollectionAssert.AreEqual(Expect("2001:db8::1", "2001:db8::3"), Strings(toAdd));
        }
    }
}
