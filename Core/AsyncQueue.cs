using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace DigitalRuby.IPBan
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
