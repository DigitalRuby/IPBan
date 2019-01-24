using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace IPBan
{
    public class IPBanLogFileScanner : IDisposable
    {
        private class WatchedFile
        {
            public WatchedFile(string fileName, long lastPosition = 0)
            {
                this.FileName = fileName;
                LastPosition = lastPosition;
            }

            public override bool Equals(object obj)
            {
                if (!(obj is WatchedFile other))
                {
                    return false;
                }
                return other.FileName == FileName;
            }

            public override int GetHashCode()
            {
                return FileName.GetHashCode();
            }

            public string FileName { get; private set; }
            public long LastPosition { get; set; }
            public long LastLength { get; set; }
        }

        private readonly IFailedLogin failedLogin;
        private readonly IDnsLookup dns;
        private readonly HashSet<WatchedFile> watchedFiles = new HashSet<WatchedFile>();
        private readonly AutoResetEvent ipEvent = new AutoResetEvent(false);
        private readonly System.Timers.Timer pingTimer;
        private readonly string directoryToWatch;
        private readonly string fileMask;
        private readonly long maxFileSize;

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="failedLogin">Interface for handling failed logins</param>
        /// <param name="dns">Interface for dns lookup</param>
        /// <param name="source">The source, i.e. SSH or SMTP, etc.</param>
        /// <param name="pathAndMask">File path and mask (i.e. /var/log/auth*.log)</param>
        /// <param name="recursive">Whether to parse all sub directories of path and mask recursively</param>
        /// <param name="regex">Regex to parse file lines to pull out ipaddress and username</param>
        /// <param name="maxFileSize">Max size of file before it is deleted or 0 for unlimited</param>
        /// <param name="pingIntervalMilliseconds"></param>
        public IPBanLogFileScanner(IFailedLogin failedLogin, IDnsLookup dns,
            string source, string pathAndMask, bool recursive, string regex, long maxFileSize = 0, int pingIntervalMilliseconds = 10000)
        {
            failedLogin.ThrowIfNull(nameof(failedLogin));
            dns.ThrowIfNull(nameof(dns));
            Source = source;
            this.failedLogin = failedLogin;
            this.dns = dns;
            this.maxFileSize = maxFileSize;
            PathAndMask = pathAndMask;
            Regex = IPBanConfig.ParseRegex(regex);
            directoryToWatch = Path.GetDirectoryName(pathAndMask);
            fileMask = Path.GetFileName(pathAndMask);
            pingTimer = new System.Timers.Timer(pingIntervalMilliseconds);
            pingTimer.Elapsed += PingTimerElapsed;
            pingTimer.Start();

            // add initial files
            SearchOption option = (recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
            string dir = Path.GetDirectoryName(pathAndMask);
            if (Directory.Exists(dir))
            {
                foreach (string existingFileName in Directory.GetFiles(dir, Path.GetFileName(pathAndMask), option))
                {
                    // start at end of existing files
                    AddPingFile(existingFileName, new FileInfo(existingFileName).Length);
                }
            }
        }

        public void Dispose()
        {
            // wait for any outstanding file pings
            while (!pingTimer.Enabled)
            {
                Thread.Sleep(20);
            }
            pingTimer.Dispose();
            lock (watchedFiles)
            {
                watchedFiles.Clear();
            }
        }

        /// <summary>
        /// Wait for ip addresses to be found, usually only needed for testing
        /// </summary>
        /// <param name="timeoutMilliseconds">Timeout in milliseconds</param>
        public void WaitForIPAddresses(int timeoutMilliseconds = 1000)
        {
            ipEvent.WaitOne(timeoutMilliseconds);
        }

        /// <summary>
        /// The source of the failed login
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// The path and mask to scan
        /// </summary>
        public string PathAndMask { get; private set; }

        /// <summary>
        /// The regex to find the ip address and user name from the file
        /// </summary>
        public Regex Regex { get; private set; }

        private void PingTimerElapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            PingFiles();
        }

        private void AddPingFile(string fileName, long pos)
        {
            lock (watchedFiles)
            {
                watchedFiles.Add(new WatchedFile(fileName, pos));
            }
        }

        private void RemovePingFile(string fileName)
        {
            lock (watchedFiles)
            {
                watchedFiles.Remove(new WatchedFile(fileName));
            }
        }

        private HashSet<WatchedFile> UpdateWatchedFiles()
        {
            HashSet<WatchedFile> watchedFilesCopy = new HashSet<WatchedFile>();

            try
            {
                // read in existing files that match the mask in the directory being watched
                if (Directory.Exists(directoryToWatch))
                {
                    foreach (string file in Directory.EnumerateFiles(directoryToWatch, fileMask, SearchOption.TopDirectoryOnly))
                    {
                        watchedFilesCopy.Add(new WatchedFile(file, new FileInfo(file).Length));
                    }
                }
            }
            catch
            {
                // nothing to do here, something failed enumerating the directory files
            }

            lock (watchedFiles)
            {
                // remove files that no longer exist
                foreach (WatchedFile existing in watchedFiles.ToArray())
                {
                    if (!watchedFilesCopy.Contains(existing))
                    {
                        IPBanLog.Debug("Removing parsed log file {0}", existing.FileName);
                        watchedFiles.Remove(existing);
                    }
                }

                // add new files
                foreach (WatchedFile newFile in watchedFilesCopy)
                {
                    // add the file, will fail if it already exists
                    if (watchedFiles.Add(newFile))
                    {
                        IPBanLog.Debug("Adding parsed log file {0}", newFile.FileName);
                    }
                }

                // make a copy so we can enumerate outside a lock
                watchedFilesCopy.Clear();
                foreach (WatchedFile file in watchedFiles)
                {
                    watchedFilesCopy.Add(file);
                }
            }

            return watchedFilesCopy;
        }

        private void PingFiles()
        {
            try
            {
                pingTimer.Enabled = false;
            }
            catch
            {
            }

            try
            {
                // re-open files and read one byte to flush disk cache
                foreach (WatchedFile file in UpdateWatchedFiles())
                {
                    // if file length has changed, ping the file
                    bool delete = false;

                    // ugly hack to force file to flush
                    using (FileStream fs = new FileStream(file.FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        try
                        {
                            fs.Position = fs.Length - 1;
                            fs.ReadByte();
                        }
                        catch
                        {
                        }
                    }

                    long len = new FileInfo(file.FileName).Length;

                    // if file has shrunk (deleted and recreated for example) reset positions to 0
                    if (len < file.LastLength || len < file.LastPosition)
                    {
                        file.LastPosition = 0;
                    }

                    // use file info for length compare to avoid doing a full file open
                    if (len != file.LastLength)
                    {
                        using (FileStream fs = new FileStream(file.FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            file.LastLength = len;
                            delete = PingFile(file, fs);
                        }
                    }
                    else
                    {
                        IPBanLog.Debug("Watched file {0} length has not changed", file.FileName);
                    }
                    if (delete)
                    {
                        try
                        {
                            File.Delete(file.FileName);
                        }
                        catch
                        {
                            // OK someone else might have it open, in which case we have no chance to delete
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
            }

            try
            {
                pingTimer.Enabled = true;
            }
            catch
            {
            }
        }

        private bool PingFile(WatchedFile file, FileStream fs)
        {
            const int maxCountBeforeNewline = 1024;
            int b;
            long lastNewlinePos = -1;
            byte[] bytes;
            long end = Math.Min(file.LastLength, fs.Length);
            int countBeforeNewline = 0;
            fs.Position = file.LastPosition;

            IPBanLog.Info("Processing watched file {0}, len = {1}, pos = {2}", file.FileName, file.LastLength, file.LastPosition);

            while (fs.Position < end && countBeforeNewline++ != maxCountBeforeNewline)
            {
                // read until last \n is found
                b = fs.ReadByte();
                if (b == '\n')
                {
                    lastNewlinePos = fs.Position - 1;
                    countBeforeNewline = 0;
                }
            }

            if (countBeforeNewline == maxCountBeforeNewline)
            {
                throw new InvalidOperationException("Log file " + this.fileMask + " may not be a plain text new line delimited file");
            }

            if (lastNewlinePos > -1)
            {
                // set file position ready for the next read right after the newline
                fs.Position = file.LastPosition;
                bytes = new BinaryReader(fs).ReadBytes((int)(lastNewlinePos - fs.Position));

                // set position for next ping
                file.LastPosition = lastNewlinePos + 1;

                // read text and run regex to find ip addresses to ban
                string subString = Encoding.UTF8.GetString(bytes);
                string[] lines = subString.Split('\n');
                bool foundOne = false;

                // find ip and user name from all lines
                foreach (string line in lines)
                {
                    string trimmedLine = line.Trim();
                    IPBanLog.Debug("Parsing log file line {0}...", trimmedLine);
                    IPAddressLogInfo info = IPBanService.GetIPAddressInfoFromRegex(dns, Regex, trimmedLine);
                    if (info.FoundMatch)
                    {
                        info.Source = info.Source ?? Source;
                        IPBanLog.Debug("Log file found match, ip: {0}, user: {1}, source: {2}, count: {3}", info.IPAddress, info.UserName, info.Source, info.Count);
                        failedLogin.AddFailedLogin(info);
                        foundOne = true;
                    }
                    else
                    {
                        IPBanLog.Debug("No match for line {0}", line);
                    }
                }

                if (foundOne)
                {
                    // signal that we have found ip addresses
                    ipEvent.Set();
                }
            }

            return (maxFileSize > 0 && fs.Length > maxFileSize);
        }
    }
}
