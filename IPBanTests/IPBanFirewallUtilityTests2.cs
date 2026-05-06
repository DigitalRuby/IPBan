/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPBanFirewallUtility.RunProcess - exercising input/output
file/stream redirection on a cross-platform "echo"-equivalent command.
*/

using System.IO;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanFirewallUtilityRunProcessTests
    {
        // Pick a tiny program that exists on both platforms.
        private static string Program => OSUtility.IsWindows ? "cmd.exe" : "echo";
        private static string[] EchoArgs => OSUtility.IsWindows
            ? new[] { "/c", "echo", "hello" }
            : new[] { "hello" };

        [Test]
        public void RunProcess_NoInputNoOutput_ReturnsZero()
        {
            int code = IPBanFirewallUtility.RunProcess(Program, null, null, EchoArgs);
            ClassicAssert.AreEqual(0, code);
        }

        [Test]
        public void RunProcess_OutputToStream_CapturesOutput()
        {
            using var ms = new MemoryStream();
            int code = IPBanFirewallUtility.RunProcess(Program, null, ms, EchoArgs);
            ClassicAssert.AreEqual(0, code);
            ms.Position = 0;
            string text = new StreamReader(ms).ReadToEnd();
            StringAssert.Contains("hello", text);
        }

        [Test]
        public void RunProcess_OutputToFile_CapturesOutput()
        {
            string outPath = Path.Combine(Path.GetTempPath(), "ipban_runproc_" + System.Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                int code = IPBanFirewallUtility.RunProcess(Program, null, outPath, EchoArgs);
                ClassicAssert.AreEqual(0, code);
                StringAssert.Contains("hello", File.ReadAllText(outPath));
            }
            finally
            {
                try { File.Delete(outPath); } catch { /* best effort */ }
            }
        }

        [Test]
        public void RunProcess_InputFromStream_NoCrash()
        {
            // For programs that don't read stdin, providing one is harmless.
            using var inMs = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("ignored"));
            int code = IPBanFirewallUtility.RunProcess(Program, inMs, null, EchoArgs);
            ClassicAssert.AreEqual(0, code);
        }

        [Test]
        public void RunProcess_InputFromFile_NoCrash()
        {
            string inPath = Path.Combine(Path.GetTempPath(), "ipban_runproc_in_" + System.Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(inPath, "ignored stdin");
                int code = IPBanFirewallUtility.RunProcess(Program, inPath, null, EchoArgs);
                ClassicAssert.AreEqual(0, code);
            }
            finally
            {
                try { File.Delete(inPath); } catch { /* best effort */ }
            }
        }

        [Test]
        public void RunProcess_NonZeroExit_ReportedNotThrown()
        {
            // Force a non-zero exit
            string program = OSUtility.IsWindows ? "cmd.exe" : "sh";
            string[] args = OSUtility.IsWindows
                ? new[] { "/c", "exit", "5" }
                : new[] { "-c", "exit 5" };
            int code = IPBanFirewallUtility.RunProcess(program, null, null, args);
            ClassicAssert.AreEqual(5, code);
        }
    }
}
