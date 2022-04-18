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
// https://github.com/copenhagenatomics/CA_DataUploader/pull/90/files#diff-24a9664c904fe9276878f37dc1438aae578a76b7ef34eabbebf6ac66eaad83e6

using System;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Async compatible reader / writer lock based on https://stackoverflow.com/a/64757462/66372<br/>
    /// it doesn't have a lot of protection, so keep its usage simple i.e. blocks where try/finally can be used and no recursion can happen<br/>
    /// How it works:<br/>
    ///  - in general, a reader/writer lock allows any amount of readers to enter the lock while only a single writer can do so. While the writer holds the lock, no reader can hold the lock<br/>
    ///  - 2 semaphores + a count of readers in the lock are used to provide the above guarantees<br/>
    ///  - to guarantee no new readers or writers can enter the lock while a writer is active, a write semaphore is used<br/>
    ///    - both readers and writers acquire this semaphore first when trying to take the lock<br/>
    ///    - readers release the semaphore just after acquiring the read lock, so more readers can enter the lock (so technically acquiring of readers locks do not happens in parallel)<br/>
    ///  - to guarantee the writer does not enter the lock while there are still readers in the lock, a read semaphore is used<br/>
    ///    - both the writer and the first reader acquire this semaphore when trying to take the lock. They do it *after* they hold the write semaphore<br/>
    ///    - the last active reader holding the lock, releases the read semaphore. Note it does not need to be the reader that acquired it first.<br/>
    ///    - to track a reader acquiring/releasing a lock is the first/last one, a reader count is tracked when acquiring/releasing the read lock.<br/>
    ///  - cancellation tokens are supported so that readers/writers can abort while waiting for an active writer to finish its job.<br/>
    /// </summary>
    public sealed class AsyncReaderWriterLock : IDisposable
    {
        private sealed class LockDisposer : IDisposable
        {
            private Action disposer;

            public LockDisposer(Action disposer)
            {
                this.disposer = disposer ?? throw new ArgumentNullException(nameof(disposer));
            }

            public void Dispose()
            {
                disposer?.Invoke();
                disposer = null;
            }
        }

        private static readonly TimeSpan defaultTimeout = TimeSpan.FromMilliseconds(-1.0);

        private readonly SemaphoreSlim _readSemaphore = new(1, 1);
        private readonly SemaphoreSlim _writeSemaphore = new(1, 1);

        private int _readerCount;

        /// <summary>
        /// Acquire writer lock
        /// </summary>
        /// <param name="timeout">Timeout</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Task of disposable to dispose of the lock</returns>
        public async Task<IDisposable> AcquireWriterLockAsync(TimeSpan? timeout = null, CancellationToken cancelToken = default)
        {
            timeout ??= defaultTimeout;

            // attempt to grab the writer lock
            if (!(await _writeSemaphore.WaitAsync(timeout.Value, cancelToken).ConfigureAwait(false)))
            {
                throw new TimeoutException("Failed to acquire outter write lock after timeout");
            }

            try
            {
                // we also need the reader lock so no more readers can execute
                if (!(await _readSemaphore.WaitAsync(timeout.Value, cancelToken).ConfigureAwait(false)))
                {
                    throw new TimeoutException("Failed to acquire inner read lock with write lock after timeout");
                }
                return new LockDisposer(ReleaseWriterLock);
            }
            catch
            {
                _writeSemaphore.Release();
                throw;
            }
        }

        /// <summary>
        /// Release writer lock
        /// </summary>
        private void ReleaseWriterLock()
        {
            _readSemaphore.Release();
            _writeSemaphore.Release();
        }

        /// <summary>
        /// Acquire reader lock
        /// </summary>
        /// <param name="timeout">Timeout (null for infinite)</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Task of disposable to dispose of the lock</returns>
        public async Task<IDisposable> AcquireReaderLockAsync(TimeSpan? timeout = null, CancellationToken cancelToken = default)
        {
            timeout ??= defaultTimeout;

            // grab writer lock first, it should be super fast
            if (!(await _writeSemaphore.WaitAsync(timeout.Value, cancelToken).ConfigureAwait(false)))
            {
                throw new TimeoutException("Failed to acquire outter write lock after timeout");
            }

            // if first reader, acquire the reader lock, future readers will just increment over the inner loop here
            if (Interlocked.Increment(ref _readerCount) == 1)
            {
                try
                {
                    if (!(await _readSemaphore.WaitAsync(timeout.Value, cancelToken).ConfigureAwait(false)))
                    {
                        throw new TimeoutException("Failed to acquire inner read lock with read lock after timeout");
                    }
                }
                catch
                {
                    Interlocked.Decrement(ref _readerCount);
                    _writeSemaphore.Release();
                    throw;
                }
            }

            // we don't need the writer lock anymore
            _writeSemaphore.Release();

            return new LockDisposer(ReleaseReaderLock);
        }

        /// <summary>
        /// Release reader lock
        /// </summary>
        private void ReleaseReaderLock()
        {
            if (Interlocked.Decrement(ref _readerCount) == 0)
            {
                _readSemaphore.Release();
            }
        }

        /// <summary>
        /// Dispose of all resources
        /// </summary>
        public void Dispose()
        {
            _writeSemaphore.Dispose();
            _readSemaphore.Dispose();
        }
    }
}
