/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for the smaller public surface of IPBanService:
ResetMachineGuid, ReadOverrideConfigAsync, FailedLoginAttempts, AddUpdater /
TryGetUpdater / RemoveUpdater, RunFirewallTask, IsWhitelisted.
*/

using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanServiceMiscTests
    {
        private IPBanService service;

        [OneTimeSetUp]
        public void OneTimeSetup()
        {
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
        }

        [SetUp]
        public void Setup()
        {
            service.DB.Truncate(true);
            service.Firewall.Truncate();
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            IPBanService.DisposeIPBanTestService(service);
            service = null;
        }

        [Test]
        public void ResetMachineGuid_DoesNotThrow()
        {
            Assert.DoesNotThrow(() => service.ResetMachineGuid("abc"));
        }

        [Test]
        public async Task ReadOverrideConfigAsync_ReturnsString()
        {
            string overrideXml = await service.ReadOverrideConfigAsync();
            // Override config can be empty or whitespace; we just ensure no throw and a string value.
            ClassicAssert.IsNotNull(overrideXml);
        }

        [Test]
        public void FailedLoginAttempts_EnumerableNotNull()
        {
            var attempts = service.FailedLoginAttempts;
            ClassicAssert.IsNotNull(attempts);
            // Force enumeration to verify the underlying call works
            _ = attempts.ToArray();
        }

        private sealed class StubUpdater : IUpdater
        {
            public Task Update(CancellationToken cancelToken = default) => Task.CompletedTask;
            public void Dispose() { }
        }

        [Test]
        public void AddUpdater_ReturnsTrueForNew_FalseForDuplicateOrNull()
        {
            var updater = new StubUpdater();
            try
            {
                ClassicAssert.IsTrue(service.AddUpdater(updater));
                ClassicAssert.IsFalse(service.AddUpdater(updater), "duplicate should not be added");
                ClassicAssert.IsFalse(service.AddUpdater(null));
            }
            finally
            {
                service.RemoveUpdater(updater);
            }
        }

        [Test]
        public void TryGetUpdater_FindsByType()
        {
            var updater = new StubUpdater();
            try
            {
                service.AddUpdater(updater);
                ClassicAssert.IsTrue(service.TryGetUpdater(out StubUpdater found));
                ClassicAssert.AreSame(updater, found);
            }
            finally
            {
                service.RemoveUpdater(updater);
            }
        }

        [Test]
        public void TryGetUpdater_TypeNotFound_ReturnsFalse()
        {
            ClassicAssert.IsFalse(service.TryGetUpdater(out StubUpdater _));
        }

        [Test]
        public async Task RunFirewallTask_SingleThreaded_InvokesAction()
        {
            int hits = 0;
            await service.RunFirewallTask((state, fw, cancel) =>
            {
                System.Threading.Interlocked.Increment(ref hits);
                return Task.CompletedTask;
            }, 1, "TestTask");
            ClassicAssert.AreEqual(1, hits);
        }

        [Test]
        public void IsWhitelisted_NotWhitelistedByDefault()
        {
            ClassicAssert.IsFalse(service.IsWhitelisted("9.9.9.9", out _));
            ClassicAssert.IsFalse(service.IsWhitelisted(IPAddressRange.Parse("9.9.9.0/24"), out _));
        }
    }
}
