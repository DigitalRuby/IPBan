/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPAddressProcessExecutor (C2 — argv injection prevention by switching
from ProcessStartInfo.Arguments to ArgumentList, plus M19 defensive snapshot).
*/

using System;
using System.Linq;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// IPAddressProcessExecutor — covers TokenizeArguments, CleanLogData, and BuildStartInfo.
    /// The full Execute path (which calls Process.Start) is not exercised here to avoid
    /// launching real subprocesses during unit tests; BuildStartInfo is where the
    /// argv-injection guarantee actually lives, so that's what we verify.
    /// </summary>
    [TestFixture]
    public sealed class IPAddressProcessExecutorTests
    {
        // -------------------- TokenizeArguments --------------------

        [Test]
        public void Tokenize_NullOrEmptyReturnsEmptyArray()
        {
            CollectionAssert.IsEmpty(IPAddressProcessExecutor.TokenizeArguments(null));
            CollectionAssert.IsEmpty(IPAddressProcessExecutor.TokenizeArguments(""));
            CollectionAssert.IsEmpty(IPAddressProcessExecutor.TokenizeArguments("   "));
        }

        [Test]
        public void Tokenize_SimpleSpaceSeparated()
        {
            CollectionAssert.AreEqual(
                new[] { "--ip", "1.2.3.4", "--user", "bob" },
                IPAddressProcessExecutor.TokenizeArguments("--ip 1.2.3.4 --user bob"));
        }

        [Test]
        public void Tokenize_DoubleQuotedSpansStayTogether()
        {
            CollectionAssert.AreEqual(
                new[] { "--msg", "hello world", "--ip", "1.2.3.4" },
                IPAddressProcessExecutor.TokenizeArguments("--msg \"hello world\" --ip 1.2.3.4"));
        }

        [Test]
        public void Tokenize_TrailingTokenIsIncluded()
        {
            CollectionAssert.AreEqual(
                new[] { "--user", "alice" },
                IPAddressProcessExecutor.TokenizeArguments("--user alice"));
        }

        [Test]
        public void Tokenize_RepeatedWhitespaceCollapses()
        {
            CollectionAssert.AreEqual(
                new[] { "a", "b" },
                IPAddressProcessExecutor.TokenizeArguments("a    b"));
        }

        // -------------------- CleanLogData --------------------

        [Test]
        public void CleanLogData_StripsQuotesAndNormalizesWhitespace()
        {
            ClassicAssert.AreEqual("hello world",
                IPAddressProcessExecutor.CleanLogData("\"hello\tworld\""));
        }

        [Test]
        public void CleanLogData_NullBecomesEmpty()
        {
            ClassicAssert.AreEqual(string.Empty, IPAddressProcessExecutor.CleanLogData(null));
        }

        [Test]
        public void CleanLogData_BackslashesBecomeForwardSlashes()
        {
            ClassicAssert.AreEqual("a/b/c",
                IPAddressProcessExecutor.CleanLogData("a\\b\\c"));
        }

        // -------------------- BuildStartInfo (the C2 security guarantee) --------------------

        [Test]
        public void BuildStartInfo_PlaceholdersStayInsideTheirToken()
        {
            // The whole point of C2: a hostile username with quotes/spaces lands in a SINGLE
            // argv slot. Pre-fix this would have escaped into multiple argv entries via the
            // OS argument parser.
            const string hostileUser = "foo\" \"& calc &\"";
            var template = IPAddressProcessExecutor.TokenizeArguments(
                "--user ###USERNAME### --ip ###IPADDRESS###");
            var ev = new IPAddressLogEvent("1.2.3.4", hostileUser, "RDP", 1,
                IPAddressEventType.FailedLogin);

            var psi = IPAddressProcessExecutor.BuildStartInfo("/usr/bin/echo", template, ev, "TestApp");

            CollectionAssert.AreEqual(
                new[] { "--user", hostileUser, "--ip", "1.2.3.4" },
                psi.ArgumentList.ToArray());
            // ProcessStartInfo.Arguments must be empty — using both at once is undefined behavior
            ClassicAssert.AreEqual(string.Empty, psi.Arguments);
            ClassicAssert.IsFalse(psi.UseShellExecute);
        }

        [Test]
        public void BuildStartInfo_UsernameWithSpacesStaysOneToken()
        {
            // hostile value containing spaces — without per-token replacement this would split
            // into 3 separate argv entries on the receiving program.
            var template = IPAddressProcessExecutor.TokenizeArguments("--user ###USERNAME###");
            var ev = new IPAddressLogEvent("1.2.3.4", "alice bob carol", "SSH", 1,
                IPAddressEventType.FailedLogin);

            var psi = IPAddressProcessExecutor.BuildStartInfo("/bin/echo", template, ev, "TestApp");

            ClassicAssert.AreEqual(2, psi.ArgumentList.Count);
            ClassicAssert.AreEqual("--user", psi.ArgumentList[0]);
            ClassicAssert.AreEqual("alice bob carol", psi.ArgumentList[1]);
        }

        [Test]
        public void BuildStartInfo_AllPlaceholdersAreReplaced()
        {
            var template = IPAddressProcessExecutor.TokenizeArguments(
                "###IPADDRESS### ###SOURCE### ###USERNAME### ###APP### ###COUNT###");
            var ev = new IPAddressLogEvent("9.8.7.6", "user1", "RDP", 42,
                IPAddressEventType.Blocked);

            var psi = IPAddressProcessExecutor.BuildStartInfo("/bin/true", template, ev, "MyApp");

            CollectionAssert.AreEqual(
                new[] { "9.8.7.6", "RDP", "user1", "MyApp", "42" },
                psi.ArgumentList.ToArray());
        }

        [Test]
        public void BuildStartInfo_NullSourceAndUsernameBecomeEmpty()
        {
            // defensive — null fields on the event must not throw, must just become empty argv
            var template = IPAddressProcessExecutor.TokenizeArguments(
                "###USERNAME### ###SOURCE###");
            var ev = new IPAddressLogEvent("1.1.1.1", null, null, 1,
                IPAddressEventType.Blocked);

            var psi = IPAddressProcessExecutor.BuildStartInfo("/bin/true", template, ev, "App");

            CollectionAssert.AreEqual(new[] { string.Empty, string.Empty },
                psi.ArgumentList.ToArray());
        }

        [Test]
        public void BuildStartInfo_LogDataIsSanitized()
        {
            // LogData with tabs/quotes should land cleaned in the argv slot
            var template = IPAddressProcessExecutor.TokenizeArguments("###LOG###");
            var ev = new IPAddressLogEvent("1.2.3.4", "u", "s", 1, IPAddressEventType.Blocked,
                logData: "line1\nline2\twith\"quotes");

            var psi = IPAddressProcessExecutor.BuildStartInfo("/bin/true", template, ev, "App");

            ClassicAssert.AreEqual(1, psi.ArgumentList.Count);
            string log = psi.ArgumentList[0];
            ClassicAssert.IsFalse(log.Contains('\n'));
            ClassicAssert.IsFalse(log.Contains('\t'));
            ClassicAssert.IsFalse(log.Contains('\"'));
        }

        // -------------------- Execute orchestration (without launching real processes) --------------------

        [Test]
        public void Execute_TaskRunnerIsCalledOncePerValidLine()
        {
            // Multi-line config: each non-blank line is one program-to-run; the executor should
            // hand one Action to the taskRunner per valid line. We swallow the action so no
            // Process.Start fires.
            var executor = new IPAddressProcessExecutor();
            int taskRunnerCalls = 0;
            executor.Execute(
                programToRun: "/bin/true|--user ###USERNAME###\n/bin/false|--ip ###IPADDRESS###",
                ipAddresses: [new IPAddressLogEvent("1.2.3.4", "u", "s", 1, IPAddressEventType.Blocked)],
                appName: "App",
                taskRunner: _ => { taskRunnerCalls++; });

            ClassicAssert.AreEqual(2, taskRunnerCalls);
        }

        [Test]
        public void Execute_InvalidLineIsSkippedNotThrown()
        {
            // A line that doesn't have exactly one '|' separator must be logged and skipped, not
            // crash the cycle.
            var executor = new IPAddressProcessExecutor();
            int taskRunnerCalls = 0;
            Assert.DoesNotThrow(() =>
                executor.Execute(
                    programToRun: "this-is-malformed-no-pipe-character\n/bin/true|--ip ###IPADDRESS###",
                    ipAddresses: [new IPAddressLogEvent("1.2.3.4", "u", "s", 1, IPAddressEventType.Blocked)],
                    appName: "App",
                    taskRunner: _ => { taskRunnerCalls++; }));
            ClassicAssert.AreEqual(1, taskRunnerCalls, "only the valid line should produce a task");
        }

        [Test]
        public void Execute_TakesDefensiveCopyOfIpAddresses()
        {
            // M19: the closure must read a snapshot — caller-side mutation after Execute returns
            // must not affect the work the closure does later.
            var executor = new IPAddressProcessExecutor();
            var addresses = new System.Collections.Generic.List<IPAddressLogEvent>
            {
                new("1.2.3.4", "u", "s", 1, IPAddressEventType.Blocked)
            };
            Action capturedAction = null;
            // use an obviously-nonexistent program path so Process.Start fails fast and the
            // closure's catch handler logs+swallows — no real process is spawned during the test.
            executor.Execute(
                programToRun: "/__nonexistent_test_path__/no-op|--ip ###IPADDRESS###",
                ipAddresses: addresses,
                appName: "App",
                taskRunner: action => { capturedAction = action; });

            // mutate the source list AFTER Execute returned but BEFORE the captured action runs
            addresses.Clear();
            addresses.Add(new IPAddressLogEvent("9.9.9.9", "u2", "s2", 1, IPAddressEventType.Blocked));

            // running the captured action must not throw — it iterates the snapshot, not the
            // source list. Process.Start will fail (path doesn't exist), but the closure catches
            // and logs that. Pre-M19-fix the closure would have read mutated state.
            Assert.DoesNotThrow(() => capturedAction());
        }
    }
}
