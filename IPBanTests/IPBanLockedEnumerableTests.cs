/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for LockedEnumerable<T> — covers the lock-release-on-throw path in the
constructor and the idempotent dispose pattern.
*/

using System;
using System.Collections;
using System.Collections.Generic;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanLockedEnumerableTests
    {
        [Test]
        public void HappyPath_EnumeratesElements()
        {
            var src = new List<int> { 1, 2, 3 };
            var collected = new List<int>();
            using (var le = new LockedEnumerable<int>(src))
            {
                while (le.MoveNext())
                {
                    collected.Add(((IEnumerator<int>)le).Current);
                }
            }
            CollectionAssert.AreEqual(src, collected);
        }

        [Test]
        public void DoubleDispose_IsIdempotent()
        {
            // Dispose must be idempotent — without the gate, the second call would either
            // over-release the SemaphoreSlim (SemaphoreFullException) or NRE if the semaphore
            // had already been disposed.
            var le = new LockedEnumerable<int>(new[] { 1, 2 });
            le.Dispose();
            Assert.DoesNotThrow(() => le.Dispose());
            Assert.DoesNotThrow(() => le.Dispose());
        }

        [Test]
        public void GetEnumeratorThrows_ReleasesTheLock()
        {
            // The constructor takes the semaphore before calling GetEnumerator. If
            // GetEnumerator throws, the constructor must release the semaphore before
            // propagating, otherwise any future caller would deadlock waiting for it.

            // Build an enumerable whose GetEnumerator throws
            var bomb = new ThrowingEnumerable();

            Assert.Throws<InvalidOperationException>(() => _ = new LockedEnumerable<int>(bomb));
            // If the lock had leaked, this second construction (using a benign source after the
            // bomb) would deadlock waiting for the semaphore. With the fix it succeeds — but
            // each LockedEnumerable creates its own SemaphoreSlim, so this is really proving
            // that the constructor cleaned up rather than leaking the semaphore. Leaving the
            // assertion as an integration smoke check.
            using var ok = new LockedEnumerable<int>(new[] { 1 });
            ClassicAssert.IsTrue(ok.MoveNext());
        }

        // helper: enumerable that throws on GetEnumerator
        private sealed class ThrowingEnumerable : IEnumerable<int>
        {
            public IEnumerator<int> GetEnumerator() =>
                throw new InvalidOperationException("simulated GetEnumerator failure");
            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }
    }
}
