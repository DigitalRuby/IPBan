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
using System.Net;
using System.Text;
using System.Threading.Tasks;
using DigitalRuby.IPBan;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanDelegateTests : IIPBanDelegate
    {
        private const string ip1 = "99.99.99.99";
        private const string ip2 = "99.99.99.98";
        private const string ip3 = "99.99.99.97";
        private static readonly IPAddressLogEvent info1 = new IPAddressLogEvent { Count = 98, IPAddress = ip1, Source = "RDP", UserName = "test_user", Type = IPAddressEventType.FailedLogin };
        private static readonly IPAddressLogEvent info2 = new IPAddressLogEvent { Count = 99, IPAddress = ip2, Source = "SSH", UserName = "test_user2", Type = IPAddressEventType.FailedLogin };
        private static readonly IPAddressLogEvent info3 = new IPAddressLogEvent { Count = 97, IPAddress = ip3, Source = "SSH", UserName = "test_user3", Type = IPAddressEventType.SuccessfulLogin };

        private readonly Dictionary<string, int> events = new Dictionary<string, int>();
        private IPBanService service;

        private void AddEvent(string evt, params object[] format)
        {
            foreach (object obj in format)
            {
                evt += "_" + obj?.ToString();
            }
            events.TryGetValue(evt, out int count);
            events[evt] = ++count;
        }

        private void AssertEvent(string evt, int count)
        {
            Assert.IsTrue(events.ContainsKey(evt), "Missing event " + evt);
            Assert.AreEqual(count, events[evt], "Mismatching event count for event " + evt);
        }

        [SetUp]
        public void Setup()
        {
            // ensure a clean start
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            service.IPBanDelegate = this;
        }

        [TearDown]
        public void Teardown()
        {
            IPBanService.DisposeIPBanTestService(service);
            events.Clear();
        }

        private void AddLoginEvents()
        {
            service.AddIPAddressLogEvents(new IPAddressLogEvent[] { info1, info2, info3 });
            service.RunCycle().Sync();

            Assert.AreEqual(7, events.Count);
            AssertEvent("LoginAttemptSucceeded_99.99.99.97_SSH_test_user3", 1);
            AssertEvent("Update", 1);
            AssertEvent("IsIPAddressWhitelisted", 4);
            AssertEvent("LoginAttemptFailed_99.99.99.99_RDP_test_user", 1);
            AssertEvent("LoginAttemptFailed_99.99.99.98_SSH_test_user2", 1);
            AssertEvent("IPAddressBanned_99.99.99.99_RDP_test_user_True", 1);
            AssertEvent("IPAddressBanned_99.99.99.98_SSH_test_user2_True", 1);

            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.98", out _));
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public void TestDelegateCallbacks()
        {
            AddLoginEvents();
        }

        void IIPBanDelegate.Start(IIPBanService service)
        {
            AddEvent(nameof(IIPBanDelegate.Start));
        }

        Task IIPBanDelegate.Update()
        {
            AddEvent(nameof(IIPBanDelegate.Update));
            return Task.CompletedTask;
        }

        Task IIPBanDelegate.IPAddressBanned(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp, bool banned)
        {
            AddEvent(nameof(IIPBanDelegate.IPAddressBanned), ip, source, userName, banned);
            return Task.CompletedTask;
        }

        Task IIPBanDelegate.LoginAttemptFailed(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp)
        {
            AddEvent(nameof(IIPBanDelegate.LoginAttemptFailed), ip, source, userName);
            return Task.CompletedTask;
        }

        Task IIPBanDelegate.LoginAttemptSucceeded(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp)
        {
            AddEvent(nameof(IIPBanDelegate.LoginAttemptSucceeded), ip, source, userName);
            return Task.CompletedTask;
        }

        bool IIPBanDelegate.IsIPAddressWhitelisted(string ipAddress)
        {
            AddEvent(nameof(IIPBanDelegate.IsIPAddressWhitelisted));
            return false;
        }

        void IDisposable.Dispose()
        {
            AddEvent(nameof(IIPBanDelegate.Dispose));
        }

        event Action IIPBanDelegate.WhitelistChanged
        {
            add { }
            remove { }
        }
    }
}
