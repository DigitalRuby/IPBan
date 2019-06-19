using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    /// <summary>
    /// An async, non-blocking queue. This class is thread safe.
    /// </summary>
    /// <typeparam name="T">Type of object in the queue</typeparam>
    public class AsyncQueue<T>
    {
        private readonly SemaphoreSlim semaphore = new SemaphoreSlim(0);
        private readonly ConcurrentQueue<T> queue = new ConcurrentQueue<T>();

        /// <summary>
        /// Add an item to the queue, causing TryDequeueAsync to return an item
        /// </summary>
        /// <param name="item"></param>
        public void Enqueue(T item)
        {
            queue.Enqueue(item);
            semaphore.Release();
        }

        /// <summary>
        /// Add many items to the queue, causing TryDequeueAsync to return for each item
        /// </summary>
        /// <param name="source">Source</param>
        public void EnqueueRange(IEnumerable<T> source)
        {
            var count = 0;
            foreach (var item in source)
            {
                queue.Enqueue(item);
                count++;
            }
            semaphore.Release(count);
        }

        /// <summary>
        /// Attempt to dequeue an item asynchronously
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns>Key value pair, key is true if item was dequeued, false otherwise. Value is the item or default(T) if not success</returns>
        public Task<KeyValuePair<bool, T>> TryDequeueAsync(CancellationToken cancellationToken = default)
        {
            return TryDequeueAsync(Timeout.Infinite, cancellationToken);
        }

        /// <summary>
        /// Attempt to dequeue an item asynchronously
        /// </summary>
        /// <param name="timeoutMilliseconds">Timeout in milliseconds</param>
        /// <param name="cancellationToken"></param>
        /// <returns>Key value pair, key is true if item was dequeued, false otherwise. Value is the item or default(T) if not success</returns>
        public async Task<KeyValuePair<bool, T>> TryDequeueAsync(int timeoutMilliseconds, CancellationToken cancellationToken = default)
        {
            bool waitResult = await semaphore.WaitAsync(timeoutMilliseconds, cancellationToken);
            if (waitResult && queue.TryDequeue(out T item))
            {
                return new KeyValuePair<bool, T>(true, item);
            }
            return new KeyValuePair<bool, T>(false, default);
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
