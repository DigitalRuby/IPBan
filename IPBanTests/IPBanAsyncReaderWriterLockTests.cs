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
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// Tests for AsyncReaderWriterLock
    /// </summary>
    [TestFixture]
    public class IPBanAsyncReaderWriterLockTests
    {
        private static readonly TimeSpan timeout = TimeSpan.FromMilliseconds(1);

        /// <summary>
        /// Test read lock
        /// </summary>
        /// <returns>Task</returns>
        [Test]
        public async Task TestReaderLock()
        {
            // can acquire multiple readers
            using var locker = new AsyncReaderWriterLock();
            using var lock1 = await locker.AcquireReaderLockAsync(timeout);
            using var lock2 = await locker.AcquireReaderLockAsync(timeout);

            // cannot acquire writer while reader is held
            Assert.ThrowsAsync<TimeoutException>(() => locker.AcquireWriterLockAsync(timeout));
            lock1.Dispose();
            lock2.Dispose();

            // multiple dispose are no-op
            lock1.Dispose();
            lock2.Dispose();

            // now can acquire writer
            using var lock3 = locker.AcquireWriterLockAsync(timeout);
        }

        /// <summary>
        /// Test write lock
        /// </summary>
        /// <returns>Task</returns>
        [Test]
        public async Task TestWriterLock()
        {
            // cannot acquire writer or reader if write already acquired
            using var locker = new AsyncReaderWriterLock();
            using var lock1 = await locker.AcquireWriterLockAsync(timeout);

            // not allowed
            Assert.ThrowsAsync<TimeoutException>(() => locker.AcquireWriterLockAsync(timeout));

            // not allowed
            Assert.ThrowsAsync<TimeoutException>(() => locker.AcquireReaderLockAsync(timeout));

            // dispose writer
            lock1.Dispose();

            // now can acquire another writer
            using var lock2 = locker.AcquireWriterLockAsync(timeout);
        }
    }
}