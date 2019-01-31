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
        private readonly BlockingCollection<Task> taskQueue = new BlockingCollection<Task>();
        private readonly Task taskQueueRunner;
        private readonly CancellationTokenSource taskQueueRunnerCancel = new CancellationTokenSource();

        private Task StartQueue()
        {
            return Task.Run(() =>
            {
                try
                {
                    while (!taskQueueRunnerCancel.IsCancellationRequested)
                    {
                        if (taskQueue.TryTake(out Task runner, -1, taskQueueRunnerCancel.Token))
                        {
                            try
                            {
                                runner.Wait(-1, taskQueueRunnerCancel.Token);
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
            }
            catch
            {
            }
        }

        /// <summary>
        /// Add a task
        /// </summary>
        /// <param name="task"></param>
        public void Add(Task task)
        {
            taskQueue.Add(task);
        }

        /// <summary>
        /// Clear the task queue
        /// </summary>
        public void Clear()
        {
            while (taskQueue.TryTake(out _)) { }
        }

        /// <summary>
        /// Cancel token - can pass this to tasks that are added to the task queue to allow them to cancel gracefully
        /// </summary>
        public CancellationToken CancelToken { get; private set; }
    }
}
