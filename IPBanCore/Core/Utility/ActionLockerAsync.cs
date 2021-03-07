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
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Simple way to lock an Action or Func in an async lock
    /// </summary>
    public class ActionLockerAsync
    {
        private readonly SemaphoreSlim locker = new(1, 1);

        /// <summary>
        /// Lock an action around async acquisition of the lock
        /// </summary>
        /// <param name="action">Action to execute in a lock</param>
        /// <param name="cancelToken">Cancel token for acquiring the lock</param>
        /// <returns>Task</returns>
        public async Task LockActionAsync(Func<Task> action, CancellationToken cancelToken = default)
        {
            await locker.WaitAsync(cancelToken);
            try
            {
                await action.Invoke();
            }
            finally
            {
                locker.Release();
            }
        }

        /// <summary>
        /// Lock a func around async acquisition of the lock
        /// </summary>
        /// <param name="func">Func to execute in a lock</param>
        /// <param name="cancelToken">Cancel token for acquiring the lock</param>
        /// <returns>Task</returns>
        public async Task<T> LockFunctionAsync<T>(Func<Task<T>> func, CancellationToken cancelToken = default)
        {
            await locker.WaitAsync(cancelToken);
            try
            {
                return await func.Invoke();
            }
            finally
            {
                locker.Release();
            }
        }
    }
}
