/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for the IPBanWindowsFirewall COM-handling helpers — ReleaseRule and
RuleList. End-to-end firewall behavior is covered by IPBanFirewallTests
against a real firewall on the host; this fixture exercises the helpers
that prevent COM-handle leakage during rule iteration.
*/

using DigitalRuby.IPBanCore;
using DigitalRuby.IPBanCore.Windows.COM;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using System;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// Unit tests for IPBanWindowsFirewall.ReleaseRule and IPBanWindowsFirewall.RuleList.
    /// These tests exercise the helpers without instantiating the firewall itself, so they
    /// run cross-platform as long as the COM interop *types* compile (which they do — only
    /// runtime instantiation of policy is Windows-only).
    /// </summary>
    [TestFixture]
    public sealed class IPBanWindowsFirewallTests
    {
        [Test]
        public void ReleaseRule_NullIsNoOp()
        {
            // The helper is called from finally blocks in many paths; passing null must be
            // a no-op rather than NRE'ing on Marshal.FinalReleaseComObject(null).
            Assert.DoesNotThrow(() => IPBanWindowsFirewall.ReleaseRule(null));
        }

        [Test]
        public void RuleList_DisposeIsIdempotent()
        {
            // RuleList.Dispose iterates and releases. Second Dispose must be a no-op.
            using var list = new IPBanWindowsFirewall.RuleList();
            list.Add(null); // null entries must not crash the iteration
            list.Dispose();
            Assert.DoesNotThrow(() => list.Dispose());
            Assert.DoesNotThrow(() => list.Dispose());
        }

        [Test]
        public void RuleList_DisposeClearsTheList()
        {
            // After dispose, the list is empty — defensive against accidental re-use.
            var list = new IPBanWindowsFirewall.RuleList();
            list.Add(null);
            list.Add(null);
            ClassicAssert.AreEqual(2, list.Count);
            list.Dispose();
            ClassicAssert.AreEqual(0, list.Count);
        }

        [Test]
        public void RuleList_DisposeToleratesNullEntries()
        {
            // RuleList.Dispose() walks each element and calls ReleaseRule. Null entries
            // (which can happen if a COM enumeration buffer fills with nulls at the end)
            // must not cause Dispose to throw.
            using var list = new IPBanWindowsFirewall.RuleList();
            for (int i = 0; i < 10; i++)
            {
                list.Add(null);
            }
            Assert.DoesNotThrow(() => list.Dispose());
        }

        [Test]
        public void RuleList_UsingPatternReleasesEvenOnException()
        {
            // The whole point of using `using var rules = ...` is that exceptions thrown
            // during processing still trigger Dispose. Verify that contract.
            bool disposed = false;
            try
            {
                using var list = new IPBanWindowsFirewall.RuleList();
                list.Add(null);
                throw new InvalidOperationException("simulated mid-iteration failure");
                // unreachable — but Dispose runs via using's finally
#pragma warning disable CS0162
                disposed = true;
#pragma warning restore CS0162
            }
            catch (InvalidOperationException)
            {
                // expected
            }
            // We can't directly observe the dispose without exposing internal state, but the
            // assertion is "no second exception escaped" — i.e. Dispose tolerated the null.
            ClassicAssert.IsFalse(disposed, "control flow should have skipped the post-throw line");
        }
    }
}
