/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for OSUtility - properties, OS metric helpers, user-active check,
process helpers, and the RequiredOperatingSystemAttribute matcher.
*/

using System;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanOSUtilityTests
    {
        [Test]
        public void Name_AndDescription_AreSet()
        {
            ClassicAssert.IsNotNull(OSUtility.Name);
            ClassicAssert.IsNotEmpty(OSUtility.Name);
            ClassicAssert.IsNotNull(OSUtility.Description);
            ClassicAssert.IsNotNull(OSUtility.Version);
            ClassicAssert.IsNotNull(OSUtility.FriendlyName);
            ClassicAssert.IsNotNull(OSUtility.CpuArchitecture);
        }

        [Test]
        public void OSInfo_ContainsAllPieces()
        {
            string info = OSUtility.OSInfo;
            ClassicAssert.IsNotNull(info);
            StringAssert.Contains(OSUtility.Name, info);
            StringAssert.Contains(OSUtility.Version, info);
            StringAssert.Contains(OSUtility.FriendlyName, info);
            StringAssert.Contains(OSUtility.Description, info);
        }

        [Test]
        public void SoftwareVersion_IsThreeDottedNumbers()
        {
            string v = OSUtility.SoftwareVersion;
            ClassicAssert.IsNotNull(v);
            string[] parts = v.Split('.');
            ClassicAssert.AreEqual(3, parts.Length, "expected major.minor.build, got " + v);
        }

        [Test]
        public void IsWindowsLinuxMac_AreMutuallyExclusive()
        {
            int trueCount = (OSUtility.IsWindows ? 1 : 0) + (OSUtility.IsLinux ? 1 : 0) + (OSUtility.IsMac ? 1 : 0);
            ClassicAssert.LessOrEqual(trueCount, 1, "at most one OS flag should be true");
        }

        [Test]
        public void WindowsVersionFlags_DoNotThrow()
        {
            _ = OSUtility.IsWindows7OrServer2008;
            _ = OSUtility.IsWindows8OrServer2012;
            _ = OSUtility.IsWindows8OrServer2012OrNewer;
            _ = OSUtility.IsWindows10OrServer2016OrNewer;
            _ = OSUtility.IsWindows11OrServer2022OrNewer;
            ClassicAssert.Pass();
        }

        [Test]
        public void FQDN_IsNotEmpty()
        {
            ClassicAssert.IsNotNull(OSUtility.FQDN);
            ClassicAssert.IsNotEmpty(OSUtility.FQDN);
        }

        [Test]
        public void GetMemoryUsage_ReturnsSomethingOnSupportedOS()
        {
            // On Windows or Linux, this should generally return true.
            bool ok = OSUtility.GetMemoryUsage(out long total, out long avail);
            if (ok)
            {
                ClassicAssert.Greater(total, 0);
                ClassicAssert.GreaterOrEqual(avail, 0);
            }
        }

        [Test]
        public void GetDiskUsage_ReturnsSomething()
        {
            bool ok = OSUtility.GetDiskUsage(out long total, out long avail);
            if (ok)
            {
                ClassicAssert.Greater(total, 0);
                ClassicAssert.GreaterOrEqual(avail, 0);
            }
        }

        [Test]
        public void GetCpuUsage_DoesNotThrow()
        {
            // The first call kicks off a background task on Windows; the value can be 0.
            OSUtility.GetCpuUsage(out float p);
            ClassicAssert.GreaterOrEqual(p, 0f);
            ClassicAssert.LessOrEqual(p, 1f);
        }

        [Test]
        public void GetNetworkUsage_DoesNotThrow()
        {
            bool ok = OSUtility.GetNetworkUsage(out float p);
            ClassicAssert.IsTrue(ok);
            ClassicAssert.GreaterOrEqual(p, 0f);
            ClassicAssert.LessOrEqual(p, 1f);
        }

        [Test]
        public void GetDiskIopsUsage_DoesNotThrow()
        {
            OSUtility.GetDiskIopsUsage(out float p);
            ClassicAssert.GreaterOrEqual(p, 0f);
            ClassicAssert.LessOrEqual(p, 1f);
        }

        [Test]
        public void StartProcessAndWait_BasicVariant_RunsCmdEcho()
        {
            // Run a tiny command that exits 0 on both platforms.
            string program = OSUtility.IsWindows ? "cmd.exe" : "echo";
            string args = OSUtility.IsWindows ? "/c echo hi" : "hi";
            string output = OSUtility.StartProcessAndWait(program, args);
            ClassicAssert.IsNotNull(output);
        }

        [Test]
        public void StartProcessAndWait_WithExitCode_Captured()
        {
            string program = OSUtility.IsWindows ? "cmd.exe" : "echo";
            string args = OSUtility.IsWindows ? "/c echo hi" : "hi";
            string output = OSUtility.StartProcessAndWait(program, args, out int code);
            ClassicAssert.IsNotNull(output);
            ClassicAssert.AreEqual(0, code);
        }

        [Test]
        public void StartProcessAndWait_BadExitCode_ThrowsWhenAllowedListProvided()
        {
            string program = OSUtility.IsWindows ? "cmd.exe" : "sh";
            string args = OSUtility.IsWindows ? "/c exit 7" : "-c \"exit 7\"";
            // 7 is not in allowed list, expect an exception
            Assert.Throws<ApplicationException>(() => OSUtility.StartProcessAndWait(60000, program, args, 0));
        }

        [Test]
        public void UserIsActive_ForUnknownUser_ReturnsFalse()
        {
            ClassicAssert.IsFalse(OSUtility.UserIsActive("__definitely_not_a_real_user__" + Guid.NewGuid().ToString("N")));
        }

        [Test]
        public void UserIsActive_NullOrEmpty_ReturnsFalse()
        {
            ClassicAssert.IsFalse(OSUtility.UserIsActive(null));
            ClassicAssert.IsFalse(OSUtility.UserIsActive(string.Empty));
            ClassicAssert.IsFalse(OSUtility.UserIsActive("   "));
        }

        [Test]
        public async Task FileExistsWithFallbackAndRetryAsync_ExistingFile_ReturnsTrue()
        {
            string path = System.IO.Path.GetTempFileName();
            try
            {
                bool exists = await OSUtility.FileExistsWithFallbackAndRetryAsync(path);
                ClassicAssert.IsTrue(exists);
            }
            finally
            {
                try { System.IO.File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileExistsWithFallbackAndRetryAsync_MissingFile_ReturnsFalse()
        {
            string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            bool exists = await OSUtility.FileExistsWithFallbackAndRetryAsync(path);
            ClassicAssert.IsFalse(exists);
        }

        [Test]
        public void AddAppDomainExceptionHandlers_DoesNotThrow()
        {
            // Use the current AppDomain - handlers are additive
            Assert.DoesNotThrow(() => OSUtility.AddAppDomainExceptionHandlers(AppDomain.CurrentDomain));
        }
    }

    // -------------------- RequiredOperatingSystemAttribute --------------------

    [TestFixture]
    public sealed class IPBanRequiredOperatingSystemAttributeTests
    {
        [Test]
        public void IsMatch_NullOS_DoesNotMatch()
        {
            var attr = new RequiredOperatingSystemAttribute(null);
            ClassicAssert.IsFalse(attr.IsMatch);
        }

        [Test]
        public void IsMatch_EmptyOS_DoesNotMatch()
        {
            var attr = new RequiredOperatingSystemAttribute("   ");
            ClassicAssert.IsFalse(attr.IsMatch);
        }

        [Test]
        public void IsMatch_NegativePriority_DoesNotMatch()
        {
            var attr = new RequiredOperatingSystemAttribute(OSUtility.Name) { Priority = -1 };
            ClassicAssert.IsFalse(attr.IsMatch);
        }

        [Test]
        public void IsMatch_CurrentOS_Matches()
        {
            var attr = new RequiredOperatingSystemAttribute(OSUtility.Name) { Priority = 1 };
            ClassicAssert.IsTrue(attr.IsMatch);
        }

        [Test]
        public void IsMatch_OtherOS_DoesNotMatch()
        {
            // Use a string that absolutely won't match
            var attr = new RequiredOperatingSystemAttribute("DefinitelyNotARealOS") { Priority = 1 };
            ClassicAssert.IsFalse(attr.IsMatch);
        }

        [Test]
        public void Priority_ReadsEnvironmentOverride()
        {
            // Use a transient env var to verify the priority override path
            string envName = "IPBAN_TEST_PRIORITY_" + Guid.NewGuid().ToString("N");
            try
            {
                Environment.SetEnvironmentVariable(envName, "42");
                var attr = new RequiredOperatingSystemAttribute(OSUtility.Name)
                {
                    Priority = 5,
                    PriorityEnvironmentVariable = envName,
                };
                ClassicAssert.AreEqual(42, attr.Priority);
            }
            finally
            {
                Environment.SetEnvironmentVariable(envName, null);
            }
        }

        [Test]
        public void Priority_FallsBackWhenEnvVarMissing()
        {
            var attr = new RequiredOperatingSystemAttribute(OSUtility.Name)
            {
                Priority = 7,
                PriorityEnvironmentVariable = "NEVER_SET_THIS_VAR_" + Guid.NewGuid().ToString("N"),
            };
            ClassicAssert.AreEqual(7, attr.Priority);
        }

        [Test]
        public void Priority_FallsBackWhenEnvVarNotInteger()
        {
            string envName = "IPBAN_TEST_PRIORITY_BAD_" + Guid.NewGuid().ToString("N");
            try
            {
                Environment.SetEnvironmentVariable(envName, "not-a-number");
                var attr = new RequiredOperatingSystemAttribute(OSUtility.Name)
                {
                    Priority = 11,
                    PriorityEnvironmentVariable = envName,
                };
                ClassicAssert.AreEqual(11, attr.Priority);
            }
            finally
            {
                Environment.SetEnvironmentVariable(envName, null);
            }
        }

        [Test]
        public void IsMatch_WithEnvVarRequirement()
        {
            string envName = "IPBAN_TEST_REQ_" + Guid.NewGuid().ToString("N");
            try
            {
                Environment.SetEnvironmentVariable(envName, "ONE");
                var attr1 = new RequiredOperatingSystemAttribute(OSUtility.Name)
                {
                    Priority = 5,
                    RequireEnvironmentVariable = $"{envName}=ONE"
                };
                ClassicAssert.IsTrue(attr1.IsMatch);

                var attr2 = new RequiredOperatingSystemAttribute(OSUtility.Name)
                {
                    Priority = 5,
                    RequireEnvironmentVariable = $"{envName}=OTHER"
                };
                ClassicAssert.IsFalse(attr2.IsMatch);
            }
            finally
            {
                Environment.SetEnvironmentVariable(envName, null);
            }
        }

        [Test]
        public void IsMatch_VersionMinimums_Honoured()
        {
            // Major version is unlikely to be 1000.
            var attr = new RequiredOperatingSystemAttribute(OSUtility.Name)
            {
                Priority = 1,
                MajorVersionMinimum = 1000,
            };
            ClassicAssert.IsFalse(attr.IsMatch);

            // Major 1, minor 0 should always match.
            var attr2 = new RequiredOperatingSystemAttribute(OSUtility.Name) { Priority = 1, MajorVersionMinimum = 1, MinorVersionMinimum = 0 };
            ClassicAssert.IsTrue(attr2.IsMatch);
        }

        [Test]
        public void RequiredOS_IsTrimmed()
        {
            var attr = new RequiredOperatingSystemAttribute("  Windows  ");
            ClassicAssert.AreEqual("Windows", attr.RequiredOS);
        }
    }
}
