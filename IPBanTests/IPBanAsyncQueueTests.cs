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
            await queue.EnqueueRangeAsync(new[] { 2, 3 });
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

            for (int i = 0; i < 10 && count != 1000; i++)
            {
                Thread.Sleep(100);
            }

            cancelToken.Cancel();
            ClassicAssert.IsTrue(Task.WhenAll([.. tasks]).Wait(1000));
            ClassicAssert.AreEqual(500500, count); // sum of 1 to 1000
        }
    }
}