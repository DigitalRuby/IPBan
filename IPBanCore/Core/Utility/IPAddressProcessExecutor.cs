using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Execute process for ip addresses
/// </summary>
public interface IIPAddressProcessExecutor
{
    /// <summary>
    /// Execute a process in background against ip addresses
    /// </summary>
    /// <param name="programToRun">Program to run</param>
    /// <param name="ipAddresses">IP addresses, should be a non-shared collection</param>
    /// <param name="appName">App name</param>
    /// <param name="taskRunner">Task runner</param>
    void Execute(string programToRun, IReadOnlyCollection<IPAddressLogEvent> ipAddresses,
        string appName, Action<Action> taskRunner);
}

/// <inheritdoc />
public sealed class IPAddressProcessExecutor : IIPAddressProcessExecutor
{
    /// <inheritdoc />
    public void Execute(string programToRun, IReadOnlyCollection<IPAddressLogEvent> ipAddresses,
        string appName, Action<Action> taskRunner)
    {
        foreach (string process in programToRun.Split('\n'))
        {
            string[] pieces = process.Trim().Split('|', StringSplitOptions.TrimEntries);
            if (pieces.Length != 2)
            {
                Logger.Error("Invalid config option for process to run: " + programToRun +
                    " -- should be two strings, | delimited with program and arguments.");
                continue;
            }

            taskRunner(() =>
            {
                string programFullPath = System.IO.Path.GetFullPath(pieces[0]);
                string programArgs = pieces[1];

                foreach (var ipAddress in ipAddresses)
                {
                    // log data cleanup
                    var logData = (ipAddress.LogData ?? string.Empty)
                        .Replace("\"", string.Empty)
                        .Replace("'", string.Empty)
                        .Replace("\\", "/")
                        .Replace("\n", " ")
                        .Replace("\r", " ")
                        .Replace("\t", " ")
                        .Trim();

                    string replacedArgs = programArgs.Replace("###IPADDRESS###", ipAddress.IPAddress)
                        .Replace("###SOURCE###", ipAddress.Source ?? string.Empty)
                        .Replace("###USERNAME###", ipAddress.UserName ?? string.Empty)
                        .Replace("###APP###", appName)
                        .Replace("###COUNT###", ipAddress.Count.ToStringInvariant())
                        .Replace("###LOG###", logData);

                    try
                    {
                        System.Diagnostics.ProcessStartInfo psi = new()
                        {
                            FileName = programFullPath,
                            WorkingDirectory = System.IO.Path.GetDirectoryName(programFullPath),
                            Arguments = replacedArgs
                        };
                        using var p = System.Diagnostics.Process.Start(psi);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Failed to execute process {0} {1}", programFullPath, replacedArgs);
                    }
                }
            });
        }
    }

    /// <summary>
    /// For testing only
    /// </summary>
    public sealed class TestIPAddressProcessExecutor : IIPAddressProcessExecutor
    {
        /// <summary>
        /// Whether the process was run
        /// </summary>
        public bool Ran { get; set; }

        /// <inheritdoc />
        public void Execute(string programToRun, IReadOnlyCollection<IPAddressLogEvent> ipAddresses, string appName, Action<Action> taskRunner)
        {
            Ran = true;
        }
    }
}
