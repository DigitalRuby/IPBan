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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    public class IPBanLogFileScanner : IDisposable
    {
        protected class WatchedFile
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

        private readonly HashSet<WatchedFile> watchedFiles = new HashSet<WatchedFile>();
        private readonly System.Timers.Timer pingTimer;
        private readonly string directoryToWatch;
        private readonly string fileMask;
        private readonly long maxFileSize;

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="pathAndMask">File path and mask (i.e. /var/log/auth*.log)</param>
        /// <param name="recursive">Whether to parse all sub directories of path and mask recursively</param>
        /// <param name="maxFileSizeBytes">Max size of file (in bytes) before it is deleted or 0 for unlimited</param>
        /// <param name="pingIntervalMilliseconds">Ping interval in milliseconds, less than 1 for manual ping required</param>
        public IPBanLogFileScanner(string pathAndMask, bool recursive, long maxFileSizeBytes = 0, int pingIntervalMilliseconds = 0)
        {
            this.maxFileSize = maxFileSizeBytes;
            PathAndMask = pathAndMask;
            directoryToWatch = Path.GetDirectoryName(pathAndMask);
            fileMask = Path.GetFileName(pathAndMask);
            if (pingIntervalMilliseconds > 0)
            {
                pingTimer = new System.Timers.Timer(pingIntervalMilliseconds);
                pingTimer.Elapsed += PingTimerElapsed;
                pingTimer.Start();
            }

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
            if (pingTimer != null)
            {
                while (!pingTimer.Enabled)
                {
                    Thread.Sleep(20);
                }
                pingTimer?.Dispose();
            }
            lock (watchedFiles)
            {
                watchedFiles.Clear();
            }
        }

        /// <summary>
        /// Ping the files, this is normally done on a timer, but if you have passed a 0 second
        /// ping interval to the constructor, you must call this manually
        /// </summary>
        public void PingFiles()
        {
            try
            {
                if (pingTimer != null)
                {
                    pingTimer.Enabled = false;
                }
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
                            if (fs.Length != 0)
                            {
                                fs.Position = fs.Length - 1;
                                fs.ReadByte();
                            }
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
                if (pingTimer != null)
                {
                    pingTimer.Enabled = true;
                }
            }
            catch
            {
            }
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

        /// <summary>
        /// Handler to read processed lines. Takes string param of line, returns bool true to continue processing,
        /// or false to stop processing.
        /// </summary>
        public System.Func<string, bool> ProcessLine { get; set; }

        /// <summary>
        /// Process a line
        /// </summary>
        /// <param name="line">Line to process</param>
        /// <returns>True to continue processing, false to stop</returns>
        protected virtual bool OnProcessLine(string line)
        {
            return true;
        }

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

        private bool PingFile(WatchedFile file, FileStream fs)
        {
            const int maxCountBeforeNewline = 1024;
            int b;
            long lastNewlinePos = -1;
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
                throw new InvalidOperationException($"Log file '{fileMask}' may not be a plain text new line delimited file");
            }

            if (lastNewlinePos > -1)
            {
                try
                {
                    // we could read line by line by going one byte at a time, but the hope here is that by taking
                    // advantage of stream reader and binary reader read bytes we can get some improved cpu usage
                    // at the expense of having to store all the bytes in memory for a small time
                    fs.Position = file.LastPosition;
                    byte[] bytes = new BinaryReader(fs).ReadBytes((int)(lastNewlinePos - fs.Position));

                    using (StreamReader reader = new StreamReader(new MemoryStream(bytes), Encoding.UTF8))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (!OnProcessLine(line) || (ProcessLine != null && !ProcessLine(line)))
                            {
                                break;
                            }
                        }
                    }
                }
                finally
                {
                    // set file position for next ping
                    fs.Position = file.LastPosition = ++lastNewlinePos;
                }
            }

            return (maxFileSize > 0 && fs.Length > maxFileSize);
        }
    }
}
