/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanAsyncQueueTests
    {
        [Test]
        public async Task TestEnqueueDequeue()
        {
            TimeSpan timeout = TimeSpan.FromMilliseconds(1.0);
            AsyncQueue<int> queue = new();
            await queue.EnqueueAsync(1);
            await queue.EnqueueRangeAsync([2, 3]);
            ClassicAssert.AreEqual(1, queue.TryDequeueAsync(timeout).Sync().Value);
            ClassicAssert.AreEqual(2, queue.TryDequeueAsync(timeout).Sync().Value);
            ClassicAssert.AreEqual(3, queue.TryDequeueAsync(timeout).Sync().Value);
        }

        [Test]
        public async Task TestMultipleThreads()
        {
            AsyncQueue<int> queue = new();
            int count = 0;
            List<Task> tasks = [];
            CancellationTokenSource cancelToken = new();

            for (int i = 0; i < 10; i++)
            {
                Task task = Task.Run(async () =>
                {
                    int value;
                    try
                    {
                        while ((value = (await queue.TryDequeueAsync(cancelToken.Token)).Value) > 0)
                        {
                            Interlocked.Add(ref count, value);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                    }
                });
                tasks.Add(task);
            }

            for (int i = 1; i <= 1000; i++)
            {
                await queue.EnqueueAsync(i);
            }

            const int expectedSum = 500500;
            SpinWait.SpinUntil(() => Volatile.Read(ref count) == expectedSum, TimeSpan.FromSeconds(1));

            cancelToken.Cancel();
            ClassicAssert.IsTrue(Task.WhenAll([.. tasks]).Wait(1000));
            ClassicAssert.AreEqual(expectedSum, count); // sum of 1 to 1000
        }

        // -------------------- idempotent dispose --------------------

        [Test]
        public void DoubleDisposeDoesNotThrow()
        {
            // Without the idempotency gate, the second Dispose would NRE on the already-disposed
            // inner SemaphoreSlim.
            AsyncQueue<int> queue = new();
            queue.Dispose();
            Assert.DoesNotThrow(() => queue.Dispose());
            ClassicAssert.IsTrue(queue.IsDisposed);
        }

        [Test]
        public async Task EnqueueAfterDisposeIsNoOpNotThrow()
        {
            // After Dispose, Enqueue paths must short-circuit cleanly instead of crashing
            // with ObjectDisposedException from the underlying semaphore.
            AsyncQueue<int> queue = new();
            queue.Dispose();
            Assert.DoesNotThrowAsync(async () => await queue.EnqueueAsync(42));
            Assert.DoesNotThrowAsync(async () => await queue.EnqueueRangeAsync([1, 2, 3]));
            // dequeue from a disposed queue returns the negative result, no throw
            var result = await queue.TryDequeueAsync(TimeSpan.FromMilliseconds(10));
            ClassicAssert.IsFalse(result.Key);
        }

        // -------------------- range enqueue exception safety --------------------

        [Test]
        public async Task EnqueueRangeAsync_PartiallyFailedEnumerator_ReleasesOnlyEnqueuedCount()
        {
            // If the source enumerator throws partway through, items already enqueued must be
            // matched by Release calls — otherwise the semaphore count drifts out of sync with
            // the actual queue contents and consumers either block forever or wake spuriously.
            AsyncQueue<int> queue = new();
            IEnumerable<int> Throwing()
            {
                yield return 1;
                yield return 2;
                throw new InvalidOperationException("simulated source failure");
            }

            // The enumerator throws; the exception propagates, but two items are already enqueued.
            Assert.ThrowsAsync<InvalidOperationException>(async () => await queue.EnqueueRangeAsync(Throwing()));

            // Both items must still be dequeueable — proving the Release(2) fired in the finally.
            var first = await queue.TryDequeueAsync(TimeSpan.FromMilliseconds(50));
            var second = await queue.TryDequeueAsync(TimeSpan.FromMilliseconds(50));
            ClassicAssert.IsTrue(first.Key, "first item should be dequeueable");
            ClassicAssert.AreEqual(1, first.Value);
            ClassicAssert.IsTrue(second.Key, "second item should be dequeueable");
            ClassicAssert.AreEqual(2, second.Value);
        }

        [Test]
        public async Task EnqueueRangeAsync_NullSourceIsNoOp()
        {
            AsyncQueue<int> queue = new();
            Assert.DoesNotThrowAsync(async () => await queue.EnqueueRangeAsync(null));
            var result = await queue.TryDequeueAsync(TimeSpan.FromMilliseconds(10));
            ClassicAssert.IsFalse(result.Key);
        }
    }
}
