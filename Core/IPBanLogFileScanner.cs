using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace IPBan
{
    public class IPBanLogFileScanner : IUpdater
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

        private readonly IIPBanService service;
        private readonly HashSet<WatchedFile> watchedFiles = new HashSet<WatchedFile>();
        private readonly AutoResetEvent ipEvent = new AutoResetEvent(false);
        private readonly System.Timers.Timer pingTimer;
        private readonly string directoryToWatch;
        private readonly string fileMask;
        private readonly long maxFileSize;

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="service">IPBan service</param>
        /// <param name="pathAndMask">File path and mask (i.e. /var/log/auth*.log)</param>
        /// <param name="regex">Regex to parse file lines to pull out ipaddress and username</param>
        /// <param name="maxFileSize">Max size of file before it is deleted or 0 for unlimited</param>
        /// <param name="pingIntervalMilliseconds"></param>
        public IPBanLogFileScanner(IIPBanService service, string pathAndMask, string regex, long maxFileSize = 0, int pingIntervalMilliseconds = 10000)
        {
            this.service = service;
            this.maxFileSize = maxFileSize;
            service.AddUpdater(this);
            PathAndMask = pathAndMask;
            Regex = new Regex(regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.IgnorePatternWhitespace);
            directoryToWatch = Path.GetDirectoryName(pathAndMask);
            fileMask = Path.GetFileName(pathAndMask);
            pingTimer = new System.Timers.Timer(pingIntervalMilliseconds);
            pingTimer.Elapsed += PingTimerElapsed;
            pingTimer.Start();
            
            // add initial files
            foreach (string existingFileName in Directory.GetFiles(Path.GetDirectoryName(pathAndMask), Path.GetFileName(pathAndMask), SearchOption.TopDirectoryOnly))
            {
                // start at end of existing files
                AddPingFile(existingFileName, new FileInfo(existingFileName).Length);
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

        public void Update()
        {
        }

        /// <summary>
        /// Wait for ip addresses to be found, usually only needed for testing
        /// </summary>
        /// <param name="timeoutMilliseconds">Timeout in milliseconds</param>
        public void WaitForIPAddresses(int timeoutMilliseconds = 100000)
        {
            ipEvent.WaitOne(timeoutMilliseconds);
        }

        public string PathAndMask { get; private set; }
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
                        Log.Write(NLog.LogLevel.Debug, "Removing parsed log file {0}", existing.FileName);
                        watchedFiles.Remove(existing);
                    }
                }

                // add new files
                foreach (WatchedFile newFile in watchedFilesCopy)
                {
                    // add the file, will fail if it already exists
                    if (watchedFiles.Add(newFile))
                    {
                        Log.Write(NLog.LogLevel.Debug, "Adding parsed log file {0}", newFile.FileName);
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
            pingTimer.Enabled = false;

            // re-open files and read one byte to flush disk cache
            foreach (WatchedFile file in UpdateWatchedFiles())
            {
                try
                {
                    // if file length has changed, ping the file
                    bool delete = false;

                    // use file info for length compare to avoid doing a full file open
                    if (new FileInfo(file.FileName).Length != file.LastLength)
                    {
                        using (FileStream fs = new FileStream(file.FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            file.LastLength = fs.Length;
                            delete = PingFile(file, fs);
                        }
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
                catch (Exception ex)
                {
                    Log.Exception(ex);
                }
            }

            pingTimer.Enabled = true;
        }

        private bool PingFile(WatchedFile file, FileStream fs)
        {
            int b;
            long lastNewlinePos = -1;
            byte[] bytes;
            long end = fs.Length;
            fs.Position = file.LastPosition;

            while (fs.Position < end)
            {
                // read until last \n is found
                b = fs.ReadByte();
                if (b == '\n')
                {
                    lastNewlinePos = fs.Position - 1;
                }
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
                string ipAddress = null;
                string userName = null;
                bool foundOne = false;

                // find ip and user name from all lines
                foreach (string line in lines)
                {
                    Log.Write(NLog.LogLevel.Debug, "Parsing log file line {0}...", line);
                    bool foundMatch = IPBanService.GetIPAddressAndUserNameFromRegex(Regex, line.Trim(), ref ipAddress, ref userName);
                    if (foundMatch)
                    {
                        Log.Write(NLog.LogLevel.Debug, "Found match, ip: {0}, user: {1}", ipAddress, userName);
                        service.AddPendingIPAddressAndUserName(ipAddress, userName);
                        foundOne = true;
                    }
                    else
                    {
                        Log.Write(NLog.LogLevel.Debug, "No match!");
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
