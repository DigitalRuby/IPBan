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
        /// <param name="args">Args</param>
        /// <returns>Exit code task</returns>
        public static Task<int> ProcessAsync(string[] args)
        {
            // Root
            var rootCommand = new RootCommand("IPBan utility");

            // Common options
            var directoryOption = new Option<string>("--directory")
            {
                Description = "IPBan installation folder (where various files lives).",
                DefaultValueFactory = _ => @"C:\\Program Files\\IPBan"
            };
            directoryOption.Aliases.Add("-d");

            // version =====================
            var versionCommand = new Command("version", "Get ipban software version");
            versionCommand.SetAction((context) =>
            {
                Console.WriteLine(OSUtility.SoftwareVersion);
                return 0;
            });

            // info =====================
            var infoCommand = new Command("info", "Get information about hosting OS");
            infoCommand.SetAction((context) =>
            {
                Console.WriteLine(OSUtility.OSInfo);
                return 0;
            });

            // migrate =====================
            var migrateCommand = new Command("migrate", "Migrate other provide to ipban.override.config).");
            migrateCommand.SetAction(context =>
            {
                return MigrationHelper.Migrate(args);
            });

            // logfiletest =====================
            var logFileTestCommand = new Command(
                "logfiletest",
                "Test a log file with regexes for failures and successes. It should contain 5 lines with log-filename regex-failure regex-failure-timestamp-format regex-success regex-success-timestamp-format");
            var fileArgument = new Argument<string>("file")
            {
                Description = "File containing information about test. It should contain the following lines: log-filename regex-failure regex-failure-timestamp-format regex-success regex-success-timestamp-format",
                Arity = ArgumentArity.ExactlyOne
            };
            logFileTestCommand.Arguments.Add(fileArgument);

            logFileTestCommand.SetAction(async context =>
            {
                var file = context.GetValue(fileArgument);
                var lines = await System.IO.File.ReadAllLinesAsync(file);
                if (lines.Length != 5)
                {
                    Console.WriteLine("File must contain exactly 5 lines.");
                    return 2;
                }
                IPBanLogFileTester.RunLogFileTest(lines[0], lines[1], lines[2], lines[3], lines[4]);
                return 0;
            });

            // list
            var listCommand = new Command("list", "List currently banned IPs (State=Active/in firewall).");
            listCommand.Options.Add(directoryOption);

            listCommand.SetAction(async context =>
            {
                try
                {
                    var directory = context.GetValue(directoryOption);
                    var dbPath = Path.Combine(directory, IPBanDB.FileName);
                    var exit = CheckDb(dbPath);
                    if (exit != 0)
                    {
                        return exit;
                    }

                    List<IPBanDB.IPAddressEntry> bans = await GetIPBanBannedIPsAsync(dbPath);

                    if (bans.Count == 0)
                    {
                        Console.WriteLine("No currently banned IPs (State=0).");
                        return 0;
                    }

                    Console.WriteLine($"Banned IPs found: {bans.Count}");
                    Console.WriteLine("IP\tFailedCount\tLastFailed\tBanDate");
                    foreach (var ban in bans)
                    {
                        string banStartDate = ban.BanStartDate?.ToString("yyyy-MM-dd HH:mm:ss");
                        string banEndDate = ban.BanEndDate?.ToString("yyyy-MM-dd HH:mm:ss");
                        Console.WriteLine($"{ban.IPAddress}\t{ban.FailedLoginCount}\t{banStartDate}\t{banEndDate}");
                    }
                    return 0;
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync("[ERROR] " + ex.Message);
                    return 1;
                }
            });

            // unban <ip>  =====================
            var unbanCommand = new Command("unban", "Request UNBAN for an IP or for all currently banned IPs (writes to unban.txt).");
            var ipArgument = new Argument<string>("ip")
            {
                Description = "IP address (IPv4/IPv6) to unban. Omit and use --all to unban all.",
                Arity = ArgumentArity.ZeroOrOne
            };
            var allOption = new Option<bool>("--all") { Description = "Unban all currently banned IPs." };
            allOption.Aliases.Add("-a");
            var yesOption = new Option<bool>("--yes") { Description = "Auto-confirm destructive actions without prompting." };
            yesOption.Aliases.Add("-y");

            unbanCommand.Arguments.Add(ipArgument);
            unbanCommand.Options.Add(allOption);
            unbanCommand.Options.Add(yesOption);
            unbanCommand.Options.Add(directoryOption);

            unbanCommand.SetAction(async context =>
            {
                try
                {
                    var ip = context.GetValue(ipArgument);
                    var all = context.GetValue(allOption);
                    var yes = context.GetValue(yesOption);
                    var directory = context.GetValue(directoryOption);
                    var exit = CheckDirectory(directory);
                    if (exit != 0)
                    {
                        return exit;
                    }

                    if (all)
                    {
                        var dbPath = Path.Combine(directory, IPBanDB.FileName);
                        exit = CheckDb(dbPath);
                        if (exit != 0)
                        {
                            return exit;
                        }

                        List<IPBanDB.IPAddressEntry> bans = await GetIPBanBannedIPsAsync(dbPath);

                        if (bans.Count == 0)
                        {
                            Console.WriteLine("No currently banned IPs to unban.");
                            return 0;
                        }

                        if (!yes)
                        {
                            Console.Write($"You are about to add {bans.Count} IP(s) to unban.txt. Proceed? [y/N]: ");
                            var resp = Console.ReadLine()?.Trim();
                            if (!string.Equals(resp, "y", StringComparison.OrdinalIgnoreCase) &&
                                !string.Equals(resp, "yes", StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Aborted.");
                                return 0;
                            }
                        }

                        var unbanFile = Path.Combine(directory, "unban.txt");
                        int appended = await AppendIpsUnique(unbanFile, bans);
                        Console.WriteLine($"UNBAN requests appended: {appended} (file: {unbanFile})");
                        Console.WriteLine("IPBan will process the file on the next cycle.");
                        return 0;
                    }

                    // Single-IP unban path
                    if (string.IsNullOrWhiteSpace(ip))
                    {
                        await Console.Error.WriteLineAsync("[ERROR] You must provide an IP or use --all.");
                        return 2;
                    }

                    if (!IPAddress.TryParse(ip, out _))
                    {
                        await Console.Error.WriteLineAsync($"[ERROR] Invalid IP address: {ip}");
                        return 2;
                    }

                    var singleUnbanFile = Path.Combine(directory, "unban.txt");
                    await AppendLinesUnique(singleUnbanFile, new[] { ip });
                    Console.WriteLine($"UNBAN request added for {ip} (file: {singleUnbanFile})");
                    Console.WriteLine("IPBan will process the file on the next cycle.");
                    return 0;
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync("[ERROR] " + ex.Message);
                    return 1;
                }
            });

            // ban <ip> =====================
            var banCommand = new Command("ban", "Request BAN for an IP (writes to ban.txt).");
            var ipRequiredArgument = new Argument<string>("ip") { Description = "IP address (IPv4/IPv6) to ban.", Arity = ArgumentArity.ExactlyOne };
            banCommand.Arguments.Add(ipRequiredArgument);
            banCommand.Options.Add(directoryOption);

            banCommand.SetAction(async context =>
            {
                try
                {
                    var ip = context.GetValue(ipRequiredArgument);
                    var directory = context.GetValue(directoryOption);
                    var exit = CheckDirectory(directory);
                    if (exit != 0)
                    {
                        return exit;
                    }
                    else if (!IPAddress.TryParse(ip, out _))
                    {
                        Console.Error.WriteLine($"[ERROR] Invalid IP address: {ip}");
                        return 2;
                    }

                    var banFile = Path.Combine(directory, "ban.txt");
                    await AppendLinesUnique(banFile, [ip]);
                    Console.WriteLine($"BAN request added for {ip} (file: {banFile})");
                    Console.WriteLine("IPBan will process the file on the next cycle.");
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[ERROR] " + ex.Message);
                    return 1;
                }
            });

            // wire-up
            rootCommand.Subcommands.Add(versionCommand);
            rootCommand.Subcommands.Add(infoCommand);
            rootCommand.Subcommands.Add(migrateCommand);
            rootCommand.Subcommands.Add(logFileTestCommand);
            rootCommand.Subcommands.Add(listCommand);
            rootCommand.Subcommands.Add(unbanCommand);
            rootCommand.Subcommands.Add(banCommand);

            return rootCommand.Parse(args).InvokeAsync();
        }


        private static int CheckDirectory(string directory)
        {
            if (!Directory.Exists(directory))
            {
                Console.Error.WriteLine($"[ERROR] Service folder not found: {directory}");
                return 2;
            }

            return 0;
        }

        private static int CheckDb(string dbPath)
        {
            if (!File.Exists(dbPath))
            {
                Console.Error.WriteLine($"[ERROR] Database not found: {dbPath}");
                return 2;
            }

            return 0;
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
