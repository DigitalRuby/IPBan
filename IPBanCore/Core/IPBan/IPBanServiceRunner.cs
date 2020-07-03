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
using System.IO;
using System.Threading.Tasks;
using System.Threading;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// IPBan service runner, assists with starting the service and make sure it runs
    /// properly if under a Windows service, systemd, etc.
    /// </summary>
    public sealed class IPBanServiceRunner : BackgroundService
    {
        private readonly CancellationTokenSource cancelToken = new CancellationTokenSource();
        private readonly Func<CancellationToken, Task> onStart;
        private readonly Func<CancellationToken, Task> onStop;

        private IHost host;
        private int disposeLock;
        private int stopLock;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="onStart">Action to execute on start</param>
        /// <param name="onStop">Action to execute on stop</param>
        private IPBanServiceRunner(Func<CancellationToken, Task> onStart, Func<CancellationToken, Task> onStop)
        {
            Logger.Warn("Initializing service");
            Directory.SetCurrentDirectory(AppContext.BaseDirectory);
            OSUtility.AddAppDomainExceptionHandlers(AppDomain.CurrentDomain);
            var hostBuilder = new HostBuilder()
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddHostedService<IPBanServiceRunner>(provider => this);
                });

            this.onStart = onStart;
            this.onStop = onStop;
            if (Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService())
            {
                Logger.Warn("Running as a Windows service");
                hostBuilder.UseWindowsService();
            }
            else if (Microsoft.Extensions.Hosting.Systemd.SystemdHelpers.IsSystemdService())
            {
                Logger.Warn("Running as a systemd service");
                hostBuilder.UseSystemd();
            }
            else
            {
                // adding console lifetime wrecks things if actually running under a service
                Logger.Warn("Running as a console app");
                hostBuilder.UseConsoleLifetime();
            }
            hostBuilder.UseContentRoot(AppContext.BaseDirectory);
            host = hostBuilder.Build();
        }

        /// <summary>
        /// Cleanup
        /// </summary>
        public override void Dispose()
        {
            if (host != null && Interlocked.Increment(ref disposeLock) == 1)
            {
                Logger.Warn("Disposing service");
                cancelToken.Cancel();
                base.Dispose();
                host.Dispose();
                host = null;
            }
        }

        /// <summary>
        /// Run the service
        /// </summary>
        /// <returns>Task</returns>
        public Task RunAsync()
        {
            Logger.Warn("Preparing to run service");
            return host.RunAsync(cancelToken.Token);
        }

        /// <summary>
        /// Run service helper method
        /// </summary>
        /// <param name="args">Args</param>
        /// <param name="onStart">Start</param>
        /// <param name="onStop">Stop</param>
        /// <returns>Task</returns>
#pragma warning disable IDE0060 // Remove unused parameter
        public static async Task MainService(string[] args, Func<CancellationToken, Task> onStart, Func<CancellationToken, Task> onStop = null)
#pragma warning restore IDE0060 // Remove unused parameter
        {
            try
            {
                using IPBanServiceRunner runner = new IPBanServiceRunner(onStart, onStop);
                await runner.RunAsync();
            }
            catch (OperationCanceledException)
            {
                // don't care
            }
            catch (Exception ex)
            {
                ExtensionMethods.FileWriteAllTextWithRetry(System.IO.Path.Combine(AppContext.BaseDirectory, "service_error.txt"), ex.ToString());
                Logger.Fatal("Fatal error running service", ex);
            }
        }

        /// <inheritdoc />
        public override async Task StartAsync(CancellationToken cancellationToken)
        {
            Logger.Warn("Starting service");
            await base.StartAsync(cancellationToken);
        }

        /// <inheritdoc />
        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref stopLock) == 1)
            {
                Logger.Warn("Stopping service");
                if (onStop != null)
                {
                    await onStop(cancellationToken);
                }
                await base.StopAsync(cancellationToken);
            }
        }

        /// <inheritdoc />
        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Logger.Warn("Running service");

            // fire off start event if there is one
            if (onStart != null)
            {
                onStart(stoppingToken).GetAwaiter();
            }

            return Task.CompletedTask;
        }
    }
}
