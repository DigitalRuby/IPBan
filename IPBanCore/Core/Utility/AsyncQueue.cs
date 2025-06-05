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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// An async, non-blocking queue. This class is thread safe.
    /// </summary>
    /// <typeparam name="T">Type of object in the queue</typeparam>
    public class AsyncQueue<T> : IDisposable
    {
        private readonly SemaphoreSlim locker = new(0);
        private readonly ConcurrentQueue<T> queue = new();

        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            locker.Dispose();
        }

        /// <summary>
        /// Add an item to the queue, causing TryDequeueAsync to return an item
        /// </summary>
        /// <param name="item"></param>
        /// <returns>Task</returns>
        public ValueTask EnqueueAsync(T item)
        {
            queue.Enqueue(item);
            locker.Release(1);
            return new();
        }

        /// <summary>
        /// Add many items to the queue, causing TryDequeueAsync to return for each item
        /// </summary>
        /// <param name="source">Source</param>
        public ValueTask EnqueueRangeAsync(IEnumerable<T> source)
        {
            int count = 0;
            foreach (var item in source)
            {
                queue.Enqueue(item);
                count++;
            }
            locker.Release(count);
            return new();
        }

        /// <summary>
        /// Attempt to dequeue an item asynchronously
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns>Key value pair, key is true if item was dequeued, false otherwise. Value is the item or default(T) if not success</returns>
        public Task<KeyValuePair<bool, T>> TryDequeueAsync(CancellationToken cancellationToken = default)
        {
            return TryDequeueAsync(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        /// <summary>
        /// Attempt to dequeue an item asynchronously
        /// </summary>
        /// <param name="timeout">Timeout, Timeout.InfiniteTimeSpan for none</param>
        /// <param name="cancellationToken"></param>
        /// <returns>Key value pair, key is true if item was dequeued, false otherwise. Value is the item or default(T) if not success</returns>
        public async Task<KeyValuePair<bool, T>> TryDequeueAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            try
            {
                bool acquiredLock = await locker.WaitAsync(timeout, cancellationToken);
                if (acquiredLock && queue.TryDequeue(out var result))
                {
                    return new KeyValuePair<bool, T>(true, result);
                }
            }
            catch
            {

            }
            return new KeyValuePair<bool, T>(false, default);
        }
    }
}
