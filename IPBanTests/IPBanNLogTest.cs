using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using NLog;
using NLog.Config;
using NLog.Time;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests;

public sealed class IPBanNLogTest
{
    [Test]
    public void TestLogFileRotation()
    {
        foreach (var deleteLogFiles in new bool[] { true, false })
        {
            var baseDir = AppContext.BaseDirectory;
            var configPath = DigitalRuby.IPBanCore.Logger.ConfigPath;
            if (File.Exists(configPath))
            {
                File.Delete(configPath);
            }

            // always delete root log file since it will stack with unexpected entry count
            if (File.Exists(Path.Combine(baseDir, "logfile.txt")))
            {
                File.Delete(Path.Combine(baseDir, "logfile.txt"));
            }

            // only if requested, clean out old archive files, if they persist, fine, it shouldn't be a problem
            if (deleteLogFiles)
            {
                foreach (var file in Directory.GetFiles(baseDir, "logfile*.txt"))
                {
                    File.Delete(file);
                }
            }
            DigitalRuby.IPBanCore.Logger.ResetConfigFile(); // force initialize and save nlog config
            var logFactory = new LogFactory();
            var config = new XmlLoggingConfiguration(configPath, logFactory);
            var logger = logFactory.GetLogger("DailyArchiveContentTest");

            // Fake time source for instant day jumps
            var fakeTime = new FakeTimeSource();
            TimeSource.Current = fakeTime;
            fakeTime.TimeMutable = new DateTime(2025, 1, 1, 12, 0, 0);

            int totalDays = 31;

            // Act — simulate 31 days of logging
            for (int day = 1; day <= totalDays; day++)
            {
                string message = $"DayIndex={day:D2}";
                logger.Info(message);

                // Move to next day and trigger rollover
                fakeTime.TimeMutable = fakeTime.Time.AddDays(1).AddSeconds(1);
                LogManager.Flush();
                logFactory.ReconfigExistingLoggers();
            }

            logFactory.Shutdown();

            // Assert
            var logFiles = Directory.GetFiles(baseDir, "logfile*.txt")
                                    .OrderBy(f => f)
                                    .ToList();

            ClassicAssert.True(File.Exists(Path.Combine(baseDir, "logfile.txt")), "Active logfile.txt should exist.");
            ClassicAssert.True(logFiles.Count <= totalDays, $"Expected ≤{totalDays} log files but found {logFiles.Count}");

            var dayFound = new bool[totalDays + 1]; // 1-based index

            // Examine each file’s content
            foreach (var file in logFiles)
            {
                string text = File.ReadAllText(file);
                if (text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length != 1)
                {
                    throw new Exception($"File {Path.GetFileName(file)} contains unexpected number of log entries.");
                }

                var match = Regex.Match(text, @"DayIndex=(\d+)");
                if (!match.Success)
                {
                    throw new Exception($"File {Path.GetFileName(file)} does not contain expected day index.");
                }

                int dayIndex = int.Parse(match.Groups[1].Value);
                ClassicAssert.IsTrue(dayIndex >= 1 && dayIndex <= totalDays);
                ClassicAssert.False(dayFound[dayIndex], $"Duplicate DayIndex {dayIndex} in {Path.GetFileName(file)}");
                dayFound[dayIndex] = true;
            }

            // Ensure all days 1..31 appear exactly once
            for (int i = 1; i <= totalDays; i++)
            {
                ClassicAssert.True(dayFound[i], $"Missing DayIndex {i}");
            }
        }
    }

    private class FakeTimeSource : TimeSource
    {
        public DateTime TimeMutable;

        public override DateTime Time => TimeMutable;

        public override DateTime FromSystemTime(DateTime systemTime)
        {
            return systemTime.ToUniversalTime();
        }
    }
}
