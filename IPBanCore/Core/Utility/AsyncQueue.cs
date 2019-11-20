/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// An async, non-blocking queue. This class is thread safe.
    /// </summary>
    /// <typeparam name="T">Type of object in the queue</typeparam>
    public class AsyncQueue<T>
    {
        private readonly BufferBlock<T> queue = new BufferBlock<T>();

        /// <summary>
        /// Add an item to the queue, causing TryDequeueAsync to return an item
        /// </summary>
        /// <param name="item"></param>
        public void Enqueue(T item)
        {
            queue.Post(item);
        }

        /// <summary>
        /// Add many items to the queue, causing TryDequeueAsync to return for each item
        /// </summary>
        /// <param name="source">Source</param>
        public void EnqueueRange(IEnumerable<T> source)
        {
            foreach (var item in source)
            {
                queue.Post(item);
            }
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
                T result = await queue.ReceiveAsync(timeout, cancellationToken);
                return new KeyValuePair<bool, T>(true, result);
            }
            catch
            {
                return new KeyValuePair<bool, T>(false, default);
            }
        }

        /// <summary>
        /// Number of items in the queue
        /// </summary>
        public int Count
        {
            get { return queue.Count; }
        }
    }
}
