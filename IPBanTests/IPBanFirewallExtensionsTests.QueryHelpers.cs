/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for the IIPBanFirewall extension wrappers (IsIPAddressBlocked /
IsIPAddressAllowed) — the helpers that go through Query() rather than the
firewall's own block/allow lookup methods.
*/

using System.Linq;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    public sealed partial class IPBanFirewallExtensionsTests
    {
        [Test]
        public void IsIPAddressBlocked_OnEmptyFirewall_ReturnsFalse()
        {
            using var fw = new IPBanMemoryFirewall();
            ClassicAssert.IsFalse(((IIPBanFirewall)fw).IsIPAddressBlocked("8.8.8.8"));
            ClassicAssert.IsFalse(((IIPBanFirewall)fw).IsIPAddressBlocked("8.8.8.8", out var ruleName, 0));
            ClassicAssert.IsNull(ruleName);
        }

        [Test]
        public async Task IsIPAddressBlocked_AfterBlock_ReturnsTrue()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses(null, new[] { "8.8.8.8" });
            ClassicAssert.IsTrue(((IIPBanFirewall)fw).IsIPAddressBlocked("8.8.8.8"));
            ClassicAssert.IsTrue(((IIPBanFirewall)fw).IsIPAddressBlocked("8.8.8.8", out var ruleName, 0));
            ClassicAssert.IsNotNull(ruleName);
        }

        [Test]
        public async Task IsIPAddressAllowed_AfterAllow_ReturnsTrue()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.AllowIPAddresses(new[] { "1.2.3.4" });
            ClassicAssert.IsTrue(((IIPBanFirewall)fw).IsIPAddressAllowed("1.2.3.4", out _));
            ClassicAssert.IsFalse(((IIPBanFirewall)fw).IsIPAddressAllowed("9.9.9.9", out _));
        }
    }
}
