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
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading.Tasks;
using System.Threading;

namespace DigitalRuby.IPBanCore
{
    public class IPBanServiceRunner : IDisposable
    {
        private IPBanWindowsServiceRunner windowsService;

        private class IPBanWindowsServiceRunner : ServiceBase
        {
            private readonly IPBanServiceRunner runner;

            protected override void OnStart(string[] args)
            {
                base.OnStart(args);
                Task.Run(async () =>
                {
                    try
                    {
                        await runner.start.Invoke(args);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex);
                    }
                });
            }

            protected override void OnStop()
            {
                runner.Dispose();
                base.OnStop();
            }

            protected override void OnSessionChange(SessionChangeDescription changeDescription)
            {
                base.OnSessionChange(changeDescription);
            }

            protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
            {
                return base.OnPowerEvent(powerStatus);
            }

            protected virtual void Preshutdown()
            {
            }

            protected override void OnCustomCommand(int command)
            {
                // command is SERVICE_CONTROL_PRESHUTDOWN
                if (command == 0x0000000F)
                {
                    Preshutdown();
                }
                else
                {
                    base.OnCustomCommand(command);
                }
            }

            public IPBanWindowsServiceRunner(IPBanServiceRunner runner, string[] args)
            {
                runner.ThrowIfNull();
                try
                {
                    Logger.Warn("Running as a Windows service");
                    this.runner = runner;
                    CanShutdown = false;
                    CanStop = CanHandleSessionChangeEvent = CanHandlePowerEvent = true;
                    var acceptedCommandsField = typeof(ServiceBase).GetField("acceptedCommands", BindingFlags.Instance | BindingFlags.NonPublic);
                    if (acceptedCommandsField != null)
                    {
                        int acceptedCommands = (int)acceptedCommandsField.GetValue(this);
                        acceptedCommands |= 0x00000100; // SERVICE_ACCEPT_PRESHUTDOWN;
                        acceptedCommandsField.SetValue(this, acceptedCommands);
                    }
                    Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
                }
                catch (Exception ex)
                {
                    Logger.Error(ex);
                }
            }

            public Task Run()
            {
                System.ServiceProcess.ServiceBase[] ServicesToRun = new System.ServiceProcess.ServiceBase[] { this };
                System.ServiceProcess.ServiceBase.Run(ServicesToRun);
                return Task.CompletedTask;
            }
        }

        private readonly string[] args;
        private readonly Func<string[], Task> start;

        private Action stop;

        /// <summary>
        /// Start typed ipban service
        /// </summary>
        /// <typeparam name="T">Type of ipban service</typeparam>
        /// <param name="args">Args</param>
        /// <param name="started">Started callback</param>
        /// <returns>Task</returns>
        public static async Task MainService<T>(string[] args, Action started = null) where T : IPBanService
        {
            T service = IPBanService.CreateService<T>();
            await MainService(args, async (_args) =>
            {
                // kick off start in background thread, make sure service starts up in a timely manner
                await service.StartAsync();
                started?.Invoke();

                // wait for service to end
                await service.WaitAsync(Timeout.Infinite);
            }, () =>
            {
                // stop the service, will cause any WaitAsync to exit
                service.Stop();
            });
        }

        /// <summary>
        /// Start generic ipban service with callbacks. The service implementation should have already been created before this method is called.
        /// </summary>
        /// <param name="args">Args</param>
        /// <param name="start">Start callback, start your implementation running here</param>
        /// <param name="stop">Stop callback, stop your implementation running here</param>
        /// <param name="requireAdministrator">Whether administrator access is required</param>
        /// <returns>Task</returns>
        public static async Task MainService(string[] args, Func<string[], Task> start, Action stop, bool requireAdministrator = true)
        {
            try
            {
                using IPBanServiceRunner runner = new IPBanServiceRunner(args, start, stop);
                await runner.RunAsync(requireAdministrator);
            }
            catch (Exception ex)
            {
                ExtensionMethods.FileWriteAllTextWithRetry(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_fail.txt"), ex.ToString());
                Logger.Fatal("Fatal error starting service", ex);
            }
        }

        private async Task RunWindowsService(string[] args)
        {
            // if we have no console input and we are not in IIS and not running an installer, run as windows service
            if (Console.IsInputRedirected && !OSUtility.Instance.IsRunningInProcessIIS() &&
                !args.Any(a => a.StartsWith("-install", StringComparison.OrdinalIgnoreCase)))
            {
                // create and start using Windows service APIs
                windowsService = new IPBanWindowsServiceRunner(this, args);
                await windowsService.Run();
            }
            else
            {
                await RunConsoleService(args);
            }
        }

        private async Task RunConsoleService(string[] args)
        {
            try
            {
                await start.Invoke(args);
            }
            catch (Exception ex)
            {
                Logger.Error(ex);
            }
        }

        private async Task RunLinuxService(string[] args)
        {
            await RunConsoleService(args);
        }

        private void AppDomainExit(object sender, EventArgs e)
        {
            Dispose();
        }

        private void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Dispose();
        }

        /// <summary>
        /// Construct and start the service
        /// </summary>
        /// <param name="args">Command line args</param>
        /// <param name="start">Start action, params are command line args. This should start the internal service.</param>
        /// <param name="stop">Stop action, this should stop the internal service.</param>
        public IPBanServiceRunner(string[] args, Func<string[], Task> start, Action stop)
        {
            this.args = args ?? new string[0];
            start.ThrowIfNull();
            stop.ThrowIfNull();
            this.start = start;
            this.stop = stop;
            Console.CancelKeyPress += Console_CancelKeyPress;
            AppDomain.CurrentDomain.ProcessExit += AppDomainExit;
        }

        /// <summary>
        /// Run the service
        /// </summary>
        /// <param name="requireAdministrator">True to require administrator, false otherwise</param>
        /// <returns>Exit code</returns>
        public async Task RunAsync(bool requireAdministrator = true)
        {
            if (requireAdministrator)
            {
                ExtensionMethods.RequireAdministrator();
            }

            if (args.Length != 0 && (args[0].Equals("info", StringComparison.OrdinalIgnoreCase) || args[0].Equals("-info", StringComparison.OrdinalIgnoreCase)))
            {
                Logger.Warn("System info: {0}", OSUtility.Instance.OSString());
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                await RunWindowsService(args);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                await RunLinuxService(args);
            }
            else
            {
                throw new PlatformNotSupportedException();
            }
        }

        /// <summary>
        /// Dispose and stop
        /// </summary>
        public void Dispose()
        {
            IPBanWindowsServiceRunner runner = windowsService;
            windowsService = null;
            if (runner != null)
            {
                runner.Stop();
            }
            Action stopper = stop;
            stop = null;
            if (stopper != null)
            {
                stopper.Invoke();
            }
        }
    }
}
