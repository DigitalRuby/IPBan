/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Linux-only integration test for ProcessUtility.CreateDetachedProcess. The
content of the queued at-job is verified by the cross-platform unit tests
on ProcessUtility.BuildAtJobBody (in IPBanProcessUtilityTests). This file
exists to verify that the *integration* — chmod, pipe to at, atd dispatch
— actually runs the requested binary on a real Linux host. We schedule a
side-effect (touch a marker file) and observe it.
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
    [Category("LinuxIntegrationSlow")]
    public sealed class IPBanProcessUtilityLinuxTests
    {
        /// <summary>
        /// End-to-end check that atd actually fires the queued job and the resulting command
        /// runs. We schedule `/bin/touch /tmp/&lt;marker&gt;` and poll until the marker appears.
        /// atd polls its spool at minute boundaries, so this test takes ~30s average and up to
        /// ~75s worst case. Tagged separately so it can be excluded from fast CI runs.
        /// </summary>
        [Test]
        [CancelAfter(120_000)]
        public void CreateDetachedProcess_AtdActuallyRunsTheJob()
        {
            if (!OSUtility.IsLinux)
            {
                Assert.Ignore("Linux-only test");
                return;
            }
            if (!CommandExists("at") || !CommandExists("atrm"))
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
            if (!TryProbeAtIsUsable(out string atProbeError))
            {
                Assert.Ignore("at command did not accept a probe job — " + atProbeError);
            }

            // Marker file in /tmp. The at job runs as root via sudo so the file is created
            // with root ownership; cleanup uses sudo rm to handle the sticky-bit case where
            // the test user can't otherwise unlink a root-owned file in /tmp.
            string markerPath = "/tmp/ipban_proctest_marker_" + Guid.NewGuid().ToString("N");
            try { File.Delete(markerPath); } catch { /* not there yet, fine */ }

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

        /// <summary>
        /// Verify that the test user can submit jobs to at. Schedules a no-op job for one
        /// minute in the future (so atd hasn't dequeued it yet by the time we check),
        /// confirms the job exists in atq, then atrm's it. Returns false with a diagnostic
        /// if the at toolchain is installed but rejecting the job (Ubuntu's at.deny, missing
        /// spool dir, etc.).
        /// </summary>
        private static bool TryProbeAtIsUsable(out string error)
        {
            // Schedule for "now + 1 minute" — using "now" was racy because atd polls every
            // minute boundary and immediately dispatches past-due jobs, so a job submitted at
            // 14:47:50 with "now" runs at 14:48:00 and disappears from the queue before we
            // can inspect it. "now + 1 minute" guarantees the job sits in the queue.
            var psi = new ProcessStartInfo
            {
                FileName = "at",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("now");
            psi.ArgumentList.Add("+");
            psi.ArgumentList.Add("1");
            psi.ArgumentList.Add("minute");

            string stderr;
            int exitCode;
            string probeJobId = null;
            try
            {
                using var p = Process.Start(psi);
                p.StandardInput.Write("/bin/true\n");
                p.StandardInput.Close();
                stderr = p.StandardError.ReadToEnd();
                p.WaitForExit(5_000);
                exitCode = p.ExitCode;

                // at writes "job N at <time>" to stderr. Parse N for atrm cleanup.
                var match = System.Text.RegularExpressions.Regex.Match(stderr, @"job\s+(\d+)\s+at");
                if (match.Success)
                {
                    probeJobId = match.Groups[1].Value;
                }
            }
            catch (Exception ex)
            {
                error = "Process.Start(at) threw: " + ex.Message;
                return false;
            }
            finally
            {
                // Always remove our probe job so we don't pollute the queue
                if (probeJobId is not null)
                {
                    try { RunCapturing("atrm", probeJobId); } catch { /* best effort */ }
                }
            }

            if (exitCode != 0)
            {
                error = $"at probe exit={exitCode}, stderr=" +
                    (string.IsNullOrWhiteSpace(stderr) ? "(empty)" : stderr.Trim());
                return false;
            }
            if (probeJobId is null)
            {
                error = "at probe exit=0 but stderr did not contain a 'job N at...' line; got: " +
                    (string.IsNullOrWhiteSpace(stderr) ? "(empty)" : stderr.Trim());
                return false;
            }

            error = string.Empty;
            return true;
        }

        /// <summary>Run a command, capture stdout+stderr, return exit code and combined output.</summary>
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
