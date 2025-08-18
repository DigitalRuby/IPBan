using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore.Core.Utility
{
    /// <summary>
    /// Processor for command line
    /// </summary>
    public static class CommandLineProcessor
    {
        /// <summary>
        /// Processes the command line.
        /// </summary>
        public static async Task ProcessAsync(string[] args)
        {
            var rootCommand = new RootCommand("IPBan utility");

            // Common options
            var directoryOption = new Option<string>(
                name: "--directory",
                description: "IPBan installation folder (where various files lives).",
                getDefaultValue: () => @"C:\Program Files\IPBan"
            );
            directoryOption.AddAlias("-d");

            // info =====================
            var infoCommand = new Command("info", "Get information about hosting OS");
            infoCommand.SetHandler(() =>
            {
                Logger.Warn("System info: {0}", OSUtility.OSString());
            });

            // logfiletest =====================
            var logFileTestCommand = new Command(
                "logfiletest",
                "Test a log file with regexes for failures and successes. The file should contain 5 lines with log-filename regex-failure regex-failure-timestamp-format regex-success regex-success-timestamp-format");
            var fileArgument = new Argument<string>(
                "file", 
                description: "File containing information about test. THe file should contain the following lines: log-filename regex-failure regex-failure-timestamp-format regex-success regex-success-timestamp-format"
            );
            logFileTestCommand.AddArgument(fileArgument);

            logFileTestCommand.SetHandler(async file =>
            {
                var lines = await System.IO.File.ReadAllLinesAsync(file);
                if (lines.Length != 5)
                {
                    Console.WriteLine("File must contain exactly 5 lines.");
                    return;
                }
                IPBanLogFileTester.RunLogFileTest(lines[0], lines[1], lines[2], lines[3], lines[4]);
            }, fileArgument);

            // list
            var listCommand = new Command("list", "List currently banned IPs (State=Active/in firewall).");
            listCommand.AddOption(directoryOption);

            listCommand.SetHandler(async directory =>
            {
                try
                {
                    var dbPath = Path.Combine(directory, IPBanDB.FileName);
                    if (!CheckDb(dbPath))
                        return;

                    List<IPBanDB.IPAddressEntry> bans = await GetIPBanBannedIPsAsync(dbPath);

                    if (bans.Count == 0)
                    {
                        Console.WriteLine("No currently banned IPs (State=0).");
                        return;
                    }

                    Console.WriteLine($"Banned IPs found: {bans.Count}");
                    Console.WriteLine("IP\tFailedCount\tLastFailed\tBanDate");
                    foreach (var ban in bans)
                    {
                        string banStartDate = ban.BanStartDate?.ToString("yyyy-MM-dd HH:mm:ss");
                        string banEndDate = ban.BanEndDate?.ToString("yyyy-MM-dd HH:mm:ss");
                        Console.WriteLine($"{ban.IPAddress}\t{ban.FailedLoginCount}\t{banStartDate}\t{banEndDate}");
                    }
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync("[ERROR] " + ex.Message);
                    Environment.ExitCode = 1;
                }
            }, directoryOption);

            // unban <ip>  =====================
            var unbanCommand = new Command("unban", "Request UNBAN for an IP or for all currently banned IPs (writes to unban.txt).");
            var ipArgument = new Argument<string>("ip", () => null, "IP address (IPv4/IPv6) to unban. Omit and use --all to unban all.");
            var allOption = new Option<bool>(name: "--all", description: "Unban all currently banned IPs.") { Arity = ArgumentArity.ZeroOrOne };
            allOption.AddAlias("-a");
            var yesOption = new Option<bool>(name: "--yes", description: "Auto-confirm destructive actions without prompting.") { Arity = ArgumentArity.ZeroOrOne };
            yesOption.AddAlias("-y");

            unbanCommand.AddArgument(ipArgument);
            unbanCommand.AddOption(allOption);
            unbanCommand.AddOption(yesOption);
            unbanCommand.AddOption(directoryOption);

            unbanCommand.SetHandler(async (ip, all, yes, directory) =>
            {
                try
                {
                    if (!CheckDirectory(directory))
                        return;

                    if (all)
                    {
                        var dbPath = Path.Combine(directory, IPBanDB.FileName);
                        if (!CheckDb(dbPath))
                            return;

                        List<IPBanDB.IPAddressEntry> bans = await GetIPBanBannedIPsAsync(dbPath);

                        if (bans.Count == 0)
                        {
                            Console.WriteLine("No currently banned IPs to unban.");
                            return;
                        }

                        if (!yes)
                        {
                            Console.Write($"You are about to add {bans.Count} IP(s) to unban.txt. Proceed? [y/N]: ");
                            var resp = Console.ReadLine()?.Trim();
                            if (!string.Equals(resp, "y", StringComparison.OrdinalIgnoreCase) &&
                                !string.Equals(resp, "yes", StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Aborted.");
                                return;
                            }
                        }

                        var unbanFile = Path.Combine(directory, "unban.txt");
                        int appended = await AppendIpsUnique(unbanFile, bans);
                        Console.WriteLine($"UNBAN requests appended: {appended} (file: {unbanFile})");
                        Console.WriteLine("IPBan will process the file on the next cycle.");
                        return;
                    }

                    // Single-IP unban path
                    if (string.IsNullOrWhiteSpace(ip))
                    {
                        await Console.Error.WriteLineAsync("[ERROR] You must provide an IP or use --all.");
                        Environment.ExitCode = 2;
                        return;
                    }

                    if (!IPAddress.TryParse(ip, out _))
                    {
                        await Console.Error.WriteLineAsync($"[ERROR] Invalid IP address: {ip}");
                        Environment.ExitCode = 2;
                        return;
                    }

                    var singleUnbanFile = Path.Combine(directory, "unban.txt");
                    await AppendLinesUnique(singleUnbanFile, new[] { ip });
                    Console.WriteLine($"UNBAN request added for {ip} (file: {singleUnbanFile})");
                    Console.WriteLine("IPBan will process the file on the next cycle.");
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync("[ERROR] " + ex.Message);
                    Environment.ExitCode = 1;
                }
            }, ipArgument, allOption, yesOption, directoryOption);

            // ban <ip> =====================
            var banCommand = new Command("ban", "Request BAN for an IP (writes to ban.txt).");
            var ipRequiredArgument = new Argument<string>("ip", "IP address (IPv4/IPv6) to ban.");
            banCommand.AddArgument(ipRequiredArgument);
            banCommand.AddOption(directoryOption);

            banCommand.SetHandler(async (ip, directory) =>
            {
                try
                {
                    if (!CheckDirectory(directory))
                        return;

                    if (!IPAddress.TryParse(ip, out _))
                    {
                        Console.Error.WriteLine($"[ERROR] Invalid IP address: {ip}");
                        Environment.ExitCode = 2;
                        return;
                    }

                    var banFile = Path.Combine(directory, "ban.txt");
                    await AppendLinesUnique(banFile, new[] { ip });
                    Console.WriteLine($"BAN request added for {ip} (file: {banFile})");
                    Console.WriteLine("IPBan will process the file on the next cycle.");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[ERROR] " + ex.Message);
                    Environment.ExitCode = 1;
                }
            }, ipRequiredArgument, directoryOption);

            rootCommand.Add(infoCommand);
            rootCommand.Add(logFileTestCommand);
            rootCommand.Add(listCommand);
            rootCommand.Add(unbanCommand);
            rootCommand.Add(banCommand);

            await rootCommand.InvokeAsync(args);
        }


        private static bool CheckDirectory(string directory)
        {
            if (!Directory.Exists(directory))
            {
                Console.Error.WriteLine($"[ERROR] Service folder not found: {directory}");
                Environment.ExitCode = 2;
                return false;
            }

            return true;
        }

        private static bool CheckDb(string dbPath)
        {
            if (!File.Exists(dbPath))
            {
                Console.Error.WriteLine($"[ERROR] Database not found: {dbPath}");
                Environment.ExitCode = 2;
                return false;
            }

            return true;
        }

        private static async Task<List<IPBanDB.IPAddressEntry>> GetIPBanBannedIPsAsync(string dbPath)
        {
            await using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadOnly");
            await conn.OpenAsync();

            const string sql = @"
                    SELECT IPAddressText,
                           FailedLoginCount,
                           LastFailedLogin,
                           BanDate,
                           State
                    FROM IPAddresses
                    WHERE State = $state
                    ORDER BY BanDate DESC NULLS LAST, FailedLoginCount DESC, IPAddressText;
                ";

            await using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("$state", IPBanDB.IPAddressState.Active);

            await using var reader = await cmd.ExecuteReaderAsync(CommandBehavior.SequentialAccess);


            var ipAddressEntries = new List<IPBanDB.IPAddressEntry>();
            while (await reader.ReadAsync())
            {
                ipAddressEntries.Add(IPBanDB.ParseIPAddressEntry(reader));
            }

            return ipAddressEntries;
        }

        /// <summary>
        /// Appends the IPs to a file, avoiding duplicates (case-insensitive exact matches).
        /// Creates the file if it does not exist. Returns the number of IPs appended.
        /// </summary>
        private static async Task<int> AppendIpsUnique(string filePath, IEnumerable<IPBanDB.IPAddressEntry> ipAddressEntries)
        {
            var lines = ipAddressEntries.Select(_ => _.IPAddress.Trim());

            return await AppendLinesUnique(filePath, lines);
        }

        /// <summary>
        /// Appends lines to a file, avoiding duplicates (case-insensitive exact matches).
        /// Creates the file if it does not exist. Returns the number of lines appended.
        /// </summary>
        private static async Task<int> AppendLinesUnique(string filePath, IEnumerable<string> lines)
        {
            var existingLines = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (File.Exists(filePath))
            {
                foreach (var line in await File.ReadAllLinesAsync(filePath))
                {
                    var trimmedLine = line.Trim();
                    if (!string.IsNullOrEmpty(trimmedLine)) existingLines.Add(trimmedLine);
                }
            }

            var linesToAppend = lines.Where(ip => !string.IsNullOrEmpty(ip) && existingLines.Add(ip)).ToList();

            await using var fs = new FileStream(filePath, File.Exists(filePath) ? FileMode.Append : FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            await using var sw = new StreamWriter(fs);
            foreach (var lineToAppend in linesToAppend)
            {
                await sw.WriteLineAsync(lineToAppend);
            }
            return linesToAppend.Count;
        }


    }
}
