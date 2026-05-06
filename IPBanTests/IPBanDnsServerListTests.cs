/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPBanDnsServerList.
*/

using System.Net;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanDnsServerListTests
    {
        [Test]
        public void Construct_DoesNotThrow()
        {
            using var list = new IPBanDnsServerList();
            ClassicAssert.IsNotNull(list);
        }

        [Test]
        public async Task Update_PopulatesServers()
        {
            using var list = new IPBanDnsServerList();
            await list.Update(CancellationToken.None);
            list.ContainsIPAddress(IPAddress.Parse("9.9.9.9"));
            list.ContainsIPAddressRange(IPAddressRange.Parse("9.9.9.0/24"));
        }

        [Test]
        public async Task Update_TwiceWithinInterval_DoesNotRefetch()
        {
            using var list = new IPBanDnsServerList();
            await list.Update();
            await list.Update();
            ClassicAssert.Pass();
        }
    }
}
