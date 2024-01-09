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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanEventViewerTests : IIPBanDelegate
    {
        private readonly Dictionary<string, int> successEvents = [];

        private IPBanService service;

        [SetUp]
        public void Setup()
        {
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            service.IPBanDelegate = this;
            service.Firewall.Truncate();
        }

        [TearDown]
        public void TearDown()
        {
            IPBanService.DisposeIPBanTestService(service);
            successEvents.Clear();
        }

        /*
        private void TestRemoteDesktopAttemptWithIPAddress(string ipAddress, int count)
        {
            string xml = string.Format(@"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}' /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2012-03-25T17:12:36.848116500Z' /><EventRecordID>1657124</EventRecordID><Correlation /><Execution ProcessID='544' ThreadID='6616' /><Channel>Security</Channel><Computer>69-64-65-123</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>69-64-65-123$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>forex</Data><Data Name='TargetDomainName'>69-64-65-123</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>69-64-65-123</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x2e40</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>{0}</Data><Data Name='IpPort'>52813</Data></EventData></Event>", ipAddress);

            while (count-- > 0)
            {
                service.EventViewer.ProcessEventViewerXml(xml);
            }
        }
        */

        private class EventViewerTest
        {
            public EventViewerTest(string[] lines)
            {
                if (lines.Length != 5)
                {
                    throw new System.IO.InvalidDataException("Expected 5 lines of event viewer test data");
                }
                Xml = lines[0].Trim();
                IPAddress = lines[1].Trim();
                UserName = lines[2].Trim();
                if (UserName == "[nouser]")
                {
                    UserName = string.Empty;
                }
                Source = lines[3].Trim();
                Enum.TryParse<IPAddressEventType>(lines[4].Trim(), true, out var eventType);
                EventType = eventType;
            }

            public override string ToString()
            {
                return $"Xml: {Xml}, IP: {IPAddress}, User: {UserName}, Source: {Source}, Type: {EventType}";
            }

            public string Xml { get; init; }
            public string IPAddress { get; init; }
            public string UserName { get; init; }
            public string Source { get; init; }
            public IPAddressEventType EventType { get; init; }
        }

        private static IReadOnlyCollection<EventViewerTest> ReadEventViewerTests()
        {
            string[] lines = File.ReadAllLines("TestData/EventViewer/EventViewerTests.txt")
                .Select(l => l.Trim())
                .Where(l => !l.StartsWith('#'))
                .ToArray();
            List<EventViewerTest> tests = new(lines.Length / 6);

            for (int i = 0; i < lines.Length; i += 6)
            {
                tests.Add(new(lines.Skip(i).Take(5).ToArray()));
            }

            return tests;
        }

        [Test]
        public void TestEventViewer()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return;
            }

            IReadOnlyCollection<EventViewerTest> tests = ReadEventViewerTests();

            for (int i = 0; i < 5; i++)
            {
                foreach (var test in tests)
                {
                    IPAddressLogEvent result = service.EventViewer.ProcessEventViewerXml(test.Xml);
                    string foundIp = (result is null ? "x" : result.IPAddress ?? string.Empty);
                    string foundUser = (result is null ? "x" : result.UserName ?? string.Empty);
                    string foundSource = (result is null ? "x" : result.Source ?? string.Empty);
                    IPAddressEventType foundType = (result is null ? IPAddressEventType.None : result.Type);
                    ClassicAssert.AreEqual(test.IPAddress, foundIp);
                    ClassicAssert.AreEqual(test.UserName, foundUser);
                    ClassicAssert.AreEqual(test.Source, foundSource);
                    ClassicAssert.AreEqual(test.EventType, foundType);
                }
                service.RunCycleAsync().Sync();

                // pretend enough time has passed to not batch the login attempts
                IPBanService.UtcNow += TimeSpan.FromSeconds(10.0);
            }

            string[] actualBlockedIPAddresses = service.Firewall.EnumerateBannedIPAddresses().ToArray();
            string[] expectedBlockedIPAddresses = tests
                .Where(t => t.EventType == IPAddressEventType.FailedLogin)
                .Select(t => t.IPAddress)
                .ToArray();

            Array.Sort(actualBlockedIPAddresses);
            Array.Sort(expectedBlockedIPAddresses);
            if (expectedBlockedIPAddresses.Length != actualBlockedIPAddresses.Length)
            {
                ClassicAssert.Fail("Failed to block ips: " + string.Join(", ", expectedBlockedIPAddresses.Except(actualBlockedIPAddresses)));
            }
            ClassicAssert.AreEqual(expectedBlockedIPAddresses, actualBlockedIPAddresses);

            int expectedSuccessCount = tests.Where(t => t.EventType == IPAddressEventType.SuccessfulLogin).Count();
            ClassicAssert.AreEqual(expectedSuccessCount, successEvents.Count);

            foreach (var test in tests.Where(t => t.EventType == IPAddressEventType.SuccessfulLogin))
            {
                var shortString = $"{test.IPAddress}_{test.Source}_{test.UserName}";
                ClassicAssert.AreEqual(5, successEvents[shortString]);
            }
        }

        void IDisposable.Dispose() => GC.SuppressFinalize(this);

        Task IIPBanDelegate.IPAddressBanned(string ip, string source, string userName, string machineGuid,
            string osName, string osVersion, DateTime timestamp, bool banned, IPAddressNotificationFlags notificationFlags)
        {
            return Task.CompletedTask;
        }

        Task IIPBanDelegate.LoginAttemptFailed(string ip, string source, string userName, string machineGuid,
            string osName, string osVersion, int count, DateTime timestamp, IPAddressNotificationFlags notificationFlags)
        {
            return Task.CompletedTask;
        }

        Task IIPBanDelegate.LoginAttemptSucceeded(string ip, string source, string userName, string machineGuid,
            string osName, string osVersion, int count, DateTime timestamp, IPAddressNotificationFlags notificationFlags)
        {
            string key = ip + "_" + (source?.ToString()) + "_" + (userName?.ToString());
            successEvents.TryGetValue(key, out int count2);
            successEvents[key] = ++count2;
            return Task.CompletedTask;
        }

        void IIPBanDelegate.Start(IIPBanService service)
        {

        }

        Task IIPBanDelegate.RunCycleAsync(CancellationToken cancelToken)
        {
            return Task.CompletedTask;
        }

        /*
        /// <summary>
        /// Test all entries in the event viewer that match config
        /// </summary>
        public void TestAllEntries()
        {
            int count = 0;
            try
            {
                TimeSpan timeout = TimeSpan.FromMilliseconds(20.0);
                string queryString = GetEventLogQueryString(null);
                EventLogQuery query = new EventLogQuery(null, PathType.LogName, queryString)
                {
                    Session = new EventLogSession("localhost")
                };
                EventLogReader reader = new EventLogReader(query);
                EventRecord record;
                while ((record = reader.ReadEvent(timeout)) != null)
                {
                    if (++count % 100 == 0)
                    {
                        Console.Write("Count: {0}    \r", count);
                    }
                    ProcessEventViewerXml(record.ToXml());
                }
                service.RunCycle();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex.Message);
            }
            Console.WriteLine("Tested {0} entries        ", count);
        }
        */
    }
}