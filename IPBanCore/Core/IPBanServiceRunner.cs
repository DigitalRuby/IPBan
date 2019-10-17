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
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading.Tasks;

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
                        IPBanLog.Error(ex);
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
                    IPBanLog.Warn("Running as a Windows service");
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
                    IPBanLog.Error(ex);
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

        private async Task RunWindowsService(string[] args)
        {
            if (Console.IsInputRedirected)
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
                IPBanLog.Error(ex);
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
                IPBanExtensionMethods.RequireAdministrator();
            }

            if (args.Length != 0 && (args[0].Equals("info", StringComparison.OrdinalIgnoreCase) || args[0].Equals("-info", StringComparison.OrdinalIgnoreCase)))
            {
                IPBanLog.Warn("System info: {0}", IPBanOS.OSString());
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
