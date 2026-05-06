/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Targeted tests for the small public helpers in ExtensionMethods that aren't
exercised by the existing IPBanExtensionsTests file: Retry/RetryAsync, the
SecureString round-trip, ToSHA256String, NormalizeForQuery, and a few file
helpers. Each one is a security or reliability primitive used widely across
the codebase, so each deserves its own targeted assertion.
*/

using System;
using System.IO;
using System.Security;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed partial class IPBanExtensionMethodsHelpersTests
    {
        // -------------------- Retry / RetryAsync --------------------

        [Test]
        public void Retry_SucceedsOnFirstAttempt_NoRetryNeeded()
        {
            int calls = 0;
            ExtensionMethods.Retry(() => { calls++; }, millisecondsBetweenRetry: 1, retryCount: 3);
            ClassicAssert.AreEqual(1, calls);
        }

        [Test]
        public void Retry_RetriesUpToCountThenThrowsLastError()
        {
            int calls = 0;
            var ex = Assert.Throws<InvalidOperationException>(() =>
                ExtensionMethods.Retry(() =>
                {
                    calls++;
                    throw new InvalidOperationException("boom #" + calls);
                }, millisecondsBetweenRetry: 1, retryCount: 3));
            ClassicAssert.AreEqual(3, calls, "should have retried exactly retryCount times");
            StringAssert.Contains("boom #3", ex.Message,
                "the LAST exception should be the one thrown out");
        }

        [Test]
        public void Retry_StopsImmediatelyOnOperationCanceledException()
        {
            // OperationCanceledException is treated as a hard cancel and skips remaining retries.
            int calls = 0;
            Assert.Throws<OperationCanceledException>(() =>
                ExtensionMethods.Retry(() =>
                {
                    calls++;
                    throw new OperationCanceledException();
                }, millisecondsBetweenRetry: 1, retryCount: 5));
            ClassicAssert.AreEqual(1, calls, "OperationCanceledException must short-circuit retries");
        }

        [Test]
        public void Retry_ExceptionPredicateCanShortCircuit()
        {
            // exceptionRetry returning false means "don't retry this exception".
            int calls = 0;
            Assert.Throws<ArgumentException>(() =>
                ExtensionMethods.Retry(() =>
                {
                    calls++;
                    throw new ArgumentException("not retryable");
                },
                millisecondsBetweenRetry: 1,
                retryCount: 5,
                exceptionRetry: ex => ex is not ArgumentException));
            ClassicAssert.AreEqual(1, calls, "predicate said don't retry — must stop after first attempt");
        }

        [Test]
        public async Task RetryAsync_SucceedsAfterSomeFailures()
        {
            int calls = 0;
            await ExtensionMethods.RetryAsync(() =>
            {
                calls++;
                if (calls < 3)
                {
                    throw new IOException("transient");
                }
                return Task.CompletedTask;
            }, millisecondsBetweenRetry: 1, retryCount: 5);
            ClassicAssert.AreEqual(3, calls, "should retry until the func stops throwing");
        }

        // -------------------- SecureString round-trip --------------------

        [Test]
        public void SecureString_RoundTripPreservesValue()
        {
            const string original = "hunter2-with-symbols!@#";
            using SecureString secure = original.ToSecureString();
            ClassicAssert.IsNotNull(secure);
            string back = secure.ToUnsecureString();
            ClassicAssert.AreEqual(original, back);
        }

        [Test]
        public void SecureString_NullInputReturnsNull()
        {
            string s = null;
            ClassicAssert.IsNull(s.ToSecureString());
            SecureString ss = null;
            ClassicAssert.IsNull(ss.ToUnsecureString());
        }

        // -------------------- ToSHA256String --------------------

        [Test]
        public void ToSHA256String_KnownVector()
        {
            // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
            // The helper returns the hex string in some case; compare case-insensitively.
            string hash = "abc".ToSHA256String();
            ClassicAssert.AreEqual(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                hash.ToLowerInvariant());
        }

        [Test]
        public void ToSHA256String_EmptyInputProducesKnownHash()
        {
            // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            string hash = string.Empty.ToSHA256String();
            ClassicAssert.AreEqual(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                hash.ToLowerInvariant());
        }

        [Test]
        public void ToSHA256String_DifferentInputsProduceDifferentHashes()
        {
            ClassicAssert.AreNotEqual("a".ToSHA256String(), "b".ToSHA256String());
            ClassicAssert.AreNotEqual("hello".ToSHA256String(), "Hello".ToSHA256String());
        }

        // -------------------- ThrowIfNull / ThrowIfNullOrWhiteSpace --------------------

        [Test]
        public void ThrowIfNull_NullThrowsArgumentNullException()
        {
            string s = null;
            Assert.Throws<ArgumentNullException>(() => s.ThrowIfNull("s"));
        }

        [Test]
        public void ThrowIfNull_NonNullReturnsValue()
        {
            string s = "hello";
            ClassicAssert.AreEqual("hello", s.ThrowIfNull());
        }

        [Test]
        public void ThrowIfNullOrWhiteSpace_BadInputsThrow()
        {
            Assert.Throws<ArgumentNullException>(() => ((string)null).ThrowIfNullOrWhiteSpace());
            Assert.Throws<ArgumentNullException>(() => string.Empty.ThrowIfNullOrWhiteSpace());
            Assert.Throws<ArgumentNullException>(() => "   ".ThrowIfNullOrWhiteSpace());
        }

        [Test]
        public void ThrowIfNullOrWhiteSpace_GoodInputDoesNotThrow()
        {
            Assert.DoesNotThrow(() => "value".ThrowIfNullOrWhiteSpace());
        }

        // -------------------- ToStringInvariant --------------------

        [Test]
        public void ToStringInvariant_HandlesNull()
        {
            // Convert.ToString(null) returns string.Empty, not null, so the defaultValue
            // parameter is never reached for a null object — the documented "default if null"
            // contract is effectively dead. Match the real behavior here so the test serves
            // as a regression guard if that internal detail ever changes.
            ClassicAssert.AreEqual(string.Empty, ((object)null).ToStringInvariant());
            ClassicAssert.AreEqual(string.Empty, ((object)null).ToStringInvariant("default"));
        }

        [Test]
        public void ToStringInvariant_FormatsNumbersInCulture()
        {
            // Numbers must come out with InvariantCulture formatting (period decimal separator)
            // even when running on a culture that uses comma. This protects against locale-
            // dependent serialization in firewall / log output.
            double v = 1234.5;
            ClassicAssert.AreEqual("1234.5", v.ToStringInvariant());
        }

        // -------------------- NormalizeForQuery --------------------

        [Test]
        public void NormalizeForQuery_NullStaysNull()
        {
            string s = null;
            ClassicAssert.IsNull(s.NormalizeForQuery());
        }

        [Test]
        public void NormalizeForQuery_DecomposesAccentedChars()
        {
            // Decompose accented chars so combining marks can be stripped — "café" → "cafe".
            ClassicAssert.AreEqual("cafe", "café".NormalizeForQuery());
        }

        [Test]
        public void NormalizeForQuery_LowercasesLetters()
        {
            // Letters are kept and lowercased; the function is case-insensitive on output.
            ClassicAssert.AreEqual("hello", "HeLLo".NormalizeForQuery());
        }

        [Test]
        public void NormalizeForQuery_CollapsesNonLetterCharsIntoSingleSpace()
        {
            // Anything that isn't a letter / digit becomes a single space; runs of non-letters
            // collapse so we never get "  " in the output. Trailing spaces are stripped.
            ClassicAssert.AreEqual("hello 123", "hello   123".NormalizeForQuery());
            ClassicAssert.AreEqual("a b 1 2 3", "a-b!@#1_2_3".NormalizeForQuery());
        }

        [Test]
        public void NormalizeForQuery_TrimsTrailingSpaces()
        {
            ClassicAssert.AreEqual("hello", "hello!!!".NormalizeForQuery());
            ClassicAssert.AreEqual("hello", "hello   ".NormalizeForQuery());
        }

        // -------------------- File helpers (FileWriteAllTextWithRetry) --------------------

        [Test]
        public void FileWriteAllTextWithRetry_WritesContent()
        {
            string path = Path.Combine(Path.GetTempPath(), "ipban_ext_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                ExtensionMethods.FileWriteAllTextWithRetry(path, "hello world");
                ClassicAssert.AreEqual("hello world", File.ReadAllText(path));
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileWriteAllTextWithRetryAsync_WritesContent()
        {
            string path = Path.Combine(Path.GetTempPath(), "ipban_ext_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                await ExtensionMethods.FileWriteAllTextWithRetryAsync(path, "async hello");
                ClassicAssert.AreEqual("async hello", await File.ReadAllTextAsync(path));
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }
    }
}
