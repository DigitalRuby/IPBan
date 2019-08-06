using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    /// <summary>
    /// Simple way to lock an Action or Func in an async lock
    /// </summary>
    public class ActionLockerAsync
    {
        private readonly SemaphoreSlim locker = new SemaphoreSlim(1, 1);

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
