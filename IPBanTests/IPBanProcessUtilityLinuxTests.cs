/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Linux-only integration test for ProcessUtility.CreateDetachedProcess. Verifies
that the call ends up with a job in the `at` queue containing the expected
shell-escaped command body. We don't wait for atd to actually run the job —
that's a 60s timing dependency we can't control. Instead we read back the
queued job via `at -c <id>` and check its contents, then `atrm` for cleanup.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    [Category("LinuxIntegration")]
    public sealed class IPBanProcessUtilityLinuxTests
    {
        [Test]
        public void CreateDetachedProcess_QueuesAtJobWithEscapedCommand()
        {
            // Gate the test on platform and tooling availability. If anything's missing this
            // becomes a clean Ignore rather than a noisy failure on systems that can't run it.
            if (!OSUtility.IsLinux)
            {
                Assert.Ignore("Linux-only test");
            }
            if (!CommandExists("at") || !CommandExists("atq") || !CommandExists("atrm"))
            {
                Assert.Ignore("'at' tooling is not installed on this host");
            }
            if (!CanSudoNonInteractive())
            {
                Assert.Ignore("sudo is not configured for passwordless execution by the test user");
            }

            // A unique marker so we can identify our specific job in atq and verify it didn't get
            // confused with an unrelated one already in the queue.
            string uniqueMarker = "ipban-proctest-" + Guid.NewGuid().ToString("N");
            HashSet<string> jobsBefore = ListAtJobs();

            try
            {
                // /bin/true is on every Linux, takes any args, and is harmless if atd does fire
                // the job before our cleanup runs.
                ProcessUtility.CreateDetachedProcess("/bin/true", "--marker=" + uniqueMarker);

                // Give `at` a moment to write its spool entry. atq reads from disk and the write
                // is essentially instantaneous, but we leave a small buffer for slow filesystems.
                Thread.Sleep(500);

                HashSet<string> jobsAfter = ListAtJobs();
                string[] newJobs = jobsAfter.Except(jobsBefore).ToArray();

                ClassicAssert.AreEqual(1, newJobs.Length,
                    $"expected exactly one new at job (got {newJobs.Length}: {string.Join(',', newJobs)})");

                string body = ReadAtJob(newJobs[0]);
                ClassicAssert.IsNotNull(body, "at -c returned no output for the queued job");

                // The command pumped through stdin should be present verbatim, including the
                // single-quote escaping around fileName that BashEscape applied.
                StringAssert.Contains("sudo '/bin/true'", body,
                    "fileName should be wrapped in single quotes inside the queued job body");
                StringAssert.Contains(uniqueMarker, body,
                    "the marker we passed in arguments should appear in the queued job body");
            }
            finally
            {
                // Always clean up jobs we created — including any leftover from the assertion
                // path so this test doesn't pollute the queue if it asserts mid-way.
                foreach (string jobId in ListAtJobs().Except(jobsBefore))
                {
                    try { RunCapturing("atrm", jobId); } catch { /* best effort */ }
                }
            }
        }

        [Test]
        public void CreateDetachedProcess_HandlesPathWithShellMetacharacters()
        {
            // The point of BashEscape is that paths containing spaces, semicolons, backticks,
            // or `$()` are inert. We can't actually create a file at "/tmp/foo;rm -rf /;" without
            // it being interpreted, but we CAN check that a path with spaces survives the round
            // trip through `at` and is single-quoted as expected.
            if (!OSUtility.IsLinux)
            {
                Assert.Ignore("Linux-only test");
            }
            if (!CommandExists("at") || !CommandExists("atq") || !CommandExists("atrm"))
            {
                Assert.Ignore("'at' tooling is not installed on this host");
            }
            if (!CanSudoNonInteractive())
            {
                Assert.Ignore("sudo is not configured for passwordless execution by the test user");
            }

            // Create a real script at a path containing a space so chmod actually has something
            // to act on. Path is operator-controlled in production, so spaces are realistic.
            string scriptPath = Path.Combine(Path.GetTempPath(), "ipban proctest " + Guid.NewGuid().ToString("N") + ".sh");
            File.WriteAllText(scriptPath, "#!/bin/sh\nexit 0\n");

            HashSet<string> jobsBefore = ListAtJobs();

            try
            {
                ProcessUtility.CreateDetachedProcess(scriptPath, string.Empty);
                Thread.Sleep(500);

                HashSet<string> jobsAfter = ListAtJobs();
                string[] newJobs = jobsAfter.Except(jobsBefore).ToArray();
                ClassicAssert.AreEqual(1, newJobs.Length);

                string body = ReadAtJob(newJobs[0]);

                // The path contains a space — it must appear in the queued body wrapped in
                // single quotes. The naked path WITHOUT quotes would be interpreted as two
                // separate tokens by /bin/sh when atd later runs the job.
                string expectedQuoted = "'" + scriptPath + "'";
                StringAssert.Contains(expectedQuoted, body,
                    "queued job body should contain the path inside single quotes");
            }
            finally
            {
                foreach (string jobId in ListAtJobs().Except(jobsBefore))
                {
                    try { RunCapturing("atrm", jobId); } catch { /* best effort */ }
                }
                try { File.Delete(scriptPath); } catch { /* best effort */ }
            }
        }

        /// <summary>
        /// End-to-end check that atd actually fires the queued job and the resulting command
        /// runs. We schedule `/bin/touch /tmp/&lt;marker&gt;` and poll until the marker appears.
        /// atd polls its spool at minute boundaries, so this test takes ~30s average and up to
        /// ~75s worst case. Tagged separately so it can be excluded from fast CI runs.
        /// </summary>
        [Test]
        [Category("LinuxIntegrationSlow")]
        [CancelAfter(120_000)]
        public void CreateDetachedProcess_AtdActuallyRunsTheJob()
        {
            if (!OSUtility.IsLinux)
            {
                Assert.Ignore("Linux-only test");
                return;
            }
            if (!CommandExists("at") || !CommandExists("atq") || !CommandExists("atrm"))
            {
                Assert.Ignore("'at' tooling is not installed on this host");
            }
            if (!CanSudoNonInteractive())
            {
                Assert.Ignore("sudo is not configured for passwordless execution by the test user");
            }
            if (!IsAtdRunning())
            {
                Assert.Ignore("atd is not running — scheduled jobs would never fire");
            }

            // Marker file in /tmp. Job will run as root via sudo so the file is created with
            // root ownership; cleanup uses sudo rm to handle the sticky-bit case where the
            // test user can't otherwise unlink it.
            string markerPath = "/tmp/ipban_proctest_marker_" + Guid.NewGuid().ToString("N");
            try { File.Delete(markerPath); } catch { /* not there yet, fine */ }

            HashSet<string> jobsBefore = ListAtJobs();
            var sw = Stopwatch.StartNew();
            try
            {
                // /bin/touch creates the file as a side effect — observable from the test
                ProcessUtility.CreateDetachedProcess("/bin/touch", markerPath);

                // Poll for the marker. atd batches jobs to the next minute boundary so the job
                // fires anywhere from a few seconds to ~75s after our submission.
                bool fired = false;
                while (sw.Elapsed < TimeSpan.FromSeconds(90))
                {
                    if (File.Exists(markerPath))
                    {
                        fired = true;
                        break;
                    }
                    Thread.Sleep(1_000);
                }
                sw.Stop();

                ClassicAssert.IsTrue(fired,
                    $"atd did not run the queued job within {sw.Elapsed.TotalSeconds:F0}s — " +
                    "marker file was never created");
                TestContext.Out.WriteLine(
                    $"atd executed the scheduled job after {sw.Elapsed.TotalSeconds:F1}s");
            }
            finally
            {
                // Marker is root-owned in /tmp (sticky bit). sudo rm handles that cleanly.
                try { RunCapturing("sudo", "-n", "rm", "-f", markerPath); } catch { /* best effort */ }
                foreach (string jobId in ListAtJobs().Except(jobsBefore))
                {
                    try { RunCapturing("atrm", jobId); } catch { /* best effort */ }
                }
            }
        }

        // -------- helpers --------

        private static bool CommandExists(string command)
        {
            // `command -v <name>` is portable across sh and bash; returns 0 if found.
            var (exit, _) = RunCapturing("/bin/sh", "-c", "command -v " + command);
            return exit == 0;
        }

        private static bool CanSudoNonInteractive()
        {
            // sudo -n returns non-zero if a password would be required. Probe with `true` which
            // is harmless and exits 0 if sudo lets us through.
            var (exit, _) = RunCapturing("sudo", "-n", "true");
            return exit == 0;
        }

        /// <summary>True if an `atd` process is running — without it, scheduled jobs never fire.</summary>
        private static bool IsAtdRunning()
        {
            // pgrep is on every modern Linux. Exit 0 means at least one match.
            var (exit, _) = RunCapturing("pgrep", "-x", "atd");
            return exit == 0;
        }

        /// <summary>Parse atq output into a set of job ids. atq lines look like "5\tFri Jan ...".</summary>
        private static HashSet<string> ListAtJobs()
        {
            var (exit, output) = RunCapturing("atq");
            var ids = new HashSet<string>();
            if (exit != 0 || string.IsNullOrEmpty(output))
            {
                return ids;
            }
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                int tab = line.IndexOfAny(new[] { '\t', ' ' });
                if (tab > 0)
                {
                    ids.Add(line[..tab].Trim());
                }
            }
            return ids;
        }

        /// <summary>Read the body of an at job. `at -c <id>` prints the job's commands plus envrionment.</summary>
        private static string ReadAtJob(string jobId)
        {
            var (_, output) = RunCapturing("at", "-c", jobId);
            return output ?? string.Empty;
        }

        /// <summary>Run a command, capture stdout, return exit code and combined output.</summary>
        private static (int exitCode, string output) RunCapturing(string program, params string[] args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = program,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var arg in args)
            {
                psi.ArgumentList.Add(arg);
            }
            try
            {
                using var p = Process.Start(psi);
                if (p is null)
                {
                    return (-1, string.Empty);
                }
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit(5_000);
                return (p.ExitCode, stdout + stderr);
            }
            catch
            {
                return (-1, string.Empty);
            }
        }
    }
}
