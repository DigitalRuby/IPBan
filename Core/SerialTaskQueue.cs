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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    /// <summary>
    /// A group of serial task queues
    /// </summary>
    public class SerialTaskQueue : IDisposable
    {
        /// <summary>
        /// Serial task queue instance
        /// </summary>
        private class SerialTaskQueueGroup : IDisposable
        {
            private readonly BlockingCollection<Func<CancellationToken, Task>> taskQueue = new BlockingCollection<Func<CancellationToken, Task>>();
            private readonly Task taskQueueRunner;
            private readonly CancellationTokenSource taskQueueRunnerCancel = new CancellationTokenSource();
            private readonly AutoResetEvent taskEmptyEvent = new AutoResetEvent(false);

            /// <summary>
            /// Cancel token - can pass this to tasks that are added to the task queue to allow them to cancel gracefully
            /// </summary>
            public CancellationToken CancelToken { get; private set; }

            /// <summary>
            /// Constructor
            /// </summary>
            public SerialTaskQueueGroup()
            {
                CancelToken = taskQueueRunnerCancel.Token;
                taskQueueRunner = StartQueue();
            }

            /// <summary>
            /// Dispose of the task queue
            /// </summary>
            public void Dispose()
            {
                try
                {
                    taskQueueRunnerCancel.Cancel();
                    Clear();
                }
                catch
                {
                }
            }

            /// <summary>
            /// Add an action
            /// </summary>
            /// <param name="action"></param>
            /// <returns>True if added, false if the queue is or has been disposed</returns>
            public bool Add(Func<CancellationToken, Task> action)
            {
                if (!taskQueueRunnerCancel.IsCancellationRequested)
                {
                    taskQueue.Add(action);
                    return true;
                }
                return false;
            }

            /// <summary>
            /// Wait for the queue to empty
            /// </summary>
            /// <param name="timeout">Timeout</param>
            /// <returns>True if success, false if timeout</returns>
            public bool Wait(TimeSpan timeout = default)
            {
                return taskEmptyEvent.WaitOne(timeout == default ? Timeout.InfiniteTimeSpan : timeout);
            }

            /// <summary>
            /// Clear the task queue
            /// </summary>
            public void Clear()
            {
                while (taskQueue.TryTake(out _)) { }
                taskEmptyEvent.Set();
            }

            private Task StartQueue()
            {
                return Task.Run(async () =>
                {
                    try
                    {
                        while (true)
                        {
                            try
                            {
                                while (taskQueue.TryTake(out Func<CancellationToken, Task> runner))
                                {
                                    await runner(taskQueueRunnerCancel.Token);
                                    if (taskQueueRunnerCancel.IsCancellationRequested || taskQueue.Count == 0)
                                    {
                                        taskEmptyEvent.Set();
                                        break;
                                    }
                                }
                                await Task.Delay(100);
                            }
                            catch (OperationCanceledException)
                            {
                                break;
                            }
                            catch (Exception ex)
                            {
                                IPBanLog.Info(ex.ToString());
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception ex)
                    {
                        IPBanLog.Info(ex.ToString());
                    }
                    Dispose();
                });
            }
        }

        private readonly Dictionary<string, SerialTaskQueueGroup> taskQueues = new Dictionary<string, SerialTaskQueueGroup>(StringComparer.OrdinalIgnoreCase);

        private bool disposed;

        /// <summary>
        /// Dispose of the task queue
        /// </summary>
        public void Dispose()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose of the task queue
        /// </summary>
        /// <param name="wait">Whether to wait for task queue to finish pending tasks</param>
        public void Dispose(bool wait)
        {
            if (disposed)
            {
                return;
            }

            try
            {
                disposed = true;
                if (wait)
                {
                    Wait();
                }
                SerialTaskQueueGroup[] groups;
                lock (this)
                {
                    groups = taskQueues.Values.ToArray();
                    taskQueues.Clear();
                }
                foreach (SerialTaskQueueGroup group in groups)
                {
                    group.Dispose();
                }
            }
            catch
            {
            }
        }

        /// <summary>
        /// Add an action
        /// </summary>
        /// <param name="action"></param>
        /// <param name="name">Queue name or empty string for default</param>
        /// <returns>True if added, false if the queue is or has been disposed</returns>
        public bool Add(Func<CancellationToken, Task> action, string name = "")
        {
            if (disposed || name == null || action == null)
            {
                return false;
            }
            SerialTaskQueueGroup group;
            lock (this)
            {
                if (!taskQueues.TryGetValue(name, out group))
                {
                    taskQueues[name] = group = new SerialTaskQueueGroup();
                }
            }
            if (group.CancelToken.IsCancellationRequested)
            {
                return false;
            }
            group.Add(async (token) =>
            {
                try
                {
                    await action(token);
                }
                catch (Exception ex)
                {
                    IPBanLog.Error(ex);
                }
            });
            return true;
        }

        /// <summary>
        /// Wait for the queue to empty
        /// </summary>
        /// <param name="timeout">Timeout</param>
        /// <param name="name">Queue name, empty string for default or null to wait for all queues</param>
        /// <returns>True if success, false if timeout</returns>
        public bool Wait(TimeSpan timeout = default, string name = "")
        {
            SerialTaskQueueGroup[] groups;
            lock (this)
            {
                groups = taskQueues.Where(t => t.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(t => t.Value).ToArray();
            }
            if (groups.Length == 0)
            {
                return false;
            }
            foreach (SerialTaskQueueGroup group in groups)
            {
                if (!group.Wait(timeout))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Clear all pending operations on task queues
        /// </summary>
        /// <param name="name">The queue to clear, empty string for default or null to clear all queues</param>
        public void Clear(string name = null)
        {
            SerialTaskQueueGroup[] groups;

            lock (this)
            {
                if (name == null)
                {
                    groups = taskQueues.Values.ToArray();
                }
                else if (taskQueues.TryGetValue(name, out SerialTaskQueueGroup _group))
                {
                    groups = new SerialTaskQueueGroup[] { _group };
                }
                else
                {
                    return;
                }
            }
            foreach (SerialTaskQueueGroup group in groups)
            {
                group.Clear();
            }
        }

        /// <summary>
        /// Get a cancellation token for a queue
        /// </summary>
        /// <param name="name">Queue name, empty string for default</param>
        /// <returns>Cancellation token or default if queue not found</returns>
        public CancellationToken GetToken(string name = "")
        {
            name.ThrowIfNull(nameof(name));

            lock (this)
            {
                if (taskQueues.TryGetValue(name, out SerialTaskQueueGroup group))
                {
                    return group.CancelToken;
                }
            }
            return default;
        }
    }
}
