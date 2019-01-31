using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IPBan
{
    public class SerialTaskQueue : IDisposable
    {
        private readonly BlockingCollection<Func<Task>> taskQueue = new BlockingCollection<Func<Task>>();
        private readonly Task taskQueueRunner;
        private readonly CancellationTokenSource taskQueueRunnerCancel = new CancellationTokenSource();
        private readonly AutoResetEvent taskEmptyEvent = new AutoResetEvent(false);

        private Task StartQueue()
        {
            return Task.Run(() =>
            {
                try
                {
                    while (!taskQueueRunnerCancel.IsCancellationRequested)
                    {
                        if (taskQueue.TryTake(out Func<Task> runner, -1, taskQueueRunnerCancel.Token))
                        {
                            try
                            {
                                Task task = runner();
                                task.Wait(-1, taskQueueRunnerCancel.Token);
                                if (taskQueue.Count == 0)
                                {
                                    taskEmptyEvent.Set();
                                }
                            }
                            catch (OperationCanceledException)
                            {
                                break;
                            }
                            catch
                            {
                            }
                        }
                    }
                }
                catch
                {
                }
                Dispose();
            });
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public SerialTaskQueue()
        {
            try
            {
                CancelToken = taskQueueRunnerCancel.Token;
                taskQueueRunner = StartQueue();
            }
            catch
            {
            }
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
        public bool Add(Func<Task> action)
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

        /// <summary>
        /// Cancel token - can pass this to tasks that are added to the task queue to allow them to cancel gracefully
        /// </summary>
        public CancellationToken CancelToken { get; private set; }
    }
}
