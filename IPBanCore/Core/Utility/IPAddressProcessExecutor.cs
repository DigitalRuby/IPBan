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
    /// <summary>
    /// Tokenize an argument template into individual argv tokens, respecting double-quoted spans.
    /// We tokenize the *template* (config-supplied) once, then replace placeholders inside each
    /// token. This means an attacker-controlled username embedded as ###USERNAME### becomes a
    /// single argv entry no matter what characters it contains — it can never inject extra args.
    /// Public for testability; this is a pure function.
    /// </summary>
    public static string[] TokenizeArguments(string args)
    {
        if (string.IsNullOrEmpty(args))
        {
            return Array.Empty<string>();
        }
        var result = new List<string>();
        var current = new StringBuilder();
        bool inQuotes = false;
        foreach (var c in args)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (current.Length > 0)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                current.Append(c);
            }
        }
        if (current.Length > 0)
        {
            result.Add(current.ToString());
        }
        return [.. result];
    }

    /// <summary>
    /// Sanitize log data so embedded quotes / newlines can't disrupt downstream consumers.
    /// Public for testability — pure function.
    /// </summary>
    public static string CleanLogData(string raw) =>
        (raw ?? string.Empty)
            .Replace("\"", string.Empty)
            .Replace("'", string.Empty)
            .Replace("\\", "/")
            .Replace("\n", " ")
            .Replace("\r", " ")
            .Replace("\t", " ")
            .Trim();

    /// <summary>
    /// Build a <see cref="System.Diagnostics.ProcessStartInfo"/> for the given IP/template combo.
    /// Each pre-tokenized argument template element becomes one entry in <c>ArgumentList</c> after
    /// placeholder substitution, so attacker-controlled values cannot inject extra argv slots.
    /// Public for testability; this is a pure function.
    /// </summary>
    public static System.Diagnostics.ProcessStartInfo BuildStartInfo(
        string programFullPath, string[] argTokens, IPAddressLogEvent ipAddress, string appName)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = programFullPath,
            WorkingDirectory = System.IO.Path.GetDirectoryName(programFullPath),
            UseShellExecute = false,
        };
        string logData = CleanLogData(ipAddress.LogData);
        foreach (var token in argTokens)
        {
            // replacements happen *inside* the token so substituted values stay
            // inside their own argv slot — argv injection is impossible.
            psi.ArgumentList.Add(token
                .Replace("###IPADDRESS###", ipAddress.IPAddress)
                .Replace("###SOURCE###", ipAddress.Source ?? string.Empty)
                .Replace("###USERNAME###", ipAddress.UserName ?? string.Empty)
                .Replace("###APP###", appName)
                .Replace("###COUNT###", ipAddress.Count.ToStringInvariant())
                .Replace("###LOG###", logData)
                .Replace("###OSNAME###", OSUtility.Name)
                .Replace("###OSVERSION###", OSUtility.Version));
        }
        return psi;
    }

    /// <inheritdoc />
    public void Execute(string programToRun, IReadOnlyCollection<IPAddressLogEvent> ipAddresses,
        string appName, Action<Action> taskRunner)
    {
        // Defensive snapshot. The taskRunner may execute the closure asynchronously, and the
        // caller is allowed to mutate the original collection after Execute returns. Without
        // a snapshot the task thread could enumerate a list while it's being modified.
        var ipAddressSnapshot = ipAddresses.ToArray();

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

                // pre-tokenize the template once
                string[] argTokens = TokenizeArguments(programArgs);

                foreach (var ipAddress in ipAddressSnapshot)
                {
                    try
                    {
                        var psi = BuildStartInfo(programFullPath, argTokens, ipAddress, appName);
                        using var p = System.Diagnostics.Process.Start(psi);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Failed to execute process {0} {1}", programFullPath, programArgs);
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
