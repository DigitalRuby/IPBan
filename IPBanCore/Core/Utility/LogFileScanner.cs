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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Scans a file periodically looking for patterns.
    /// </summary>
    public class LogFileScanner : IDisposable
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

        private readonly HashSet<WatchedFile> watchedFiles = new HashSet<WatchedFile>();
        private readonly System.Timers.Timer fileProcessingTimer;
        private readonly string directoryToWatch;
        private readonly string fileMask;
        private readonly long maxFileSize;
        private readonly Encoding encoding;

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="pathAndMask">File path and mask (i.e. /var/log/auth*.log)</param>
        /// <param name="recursive">Whether to parse all sub directories of path and mask recursively</param>
        /// <param name="maxFileSizeBytes">Max size of file (in bytes) before it is deleted or 0 for unlimited</param>
        /// <param name="fileProcessingIntervalMilliseconds">How often to process files, in milliseconds, less than 1 for manual processing, in which case <see cref="ProcessFiles"/> must be called as needed.</param>
        /// <param name="encoding">Encoding or null for utf-8. The encoding must either be single or variable byte, like ASCII, Ansi, utf-8, etc. UTF-16 and the like are not supported.</param>
        public LogFileScanner(string pathAndMask, bool recursive, long maxFileSizeBytes = 0, int fileProcessingIntervalMilliseconds = 0, Encoding encoding = null)
        {
            // setup properties
            PathAndMask = pathAndMask?.Trim();
            PathAndMask.ThrowIfNullOrEmpty(nameof(pathAndMask), "Must pass a non-empty path and mask to log file scanner");
            this.maxFileSize = maxFileSizeBytes;
            directoryToWatch = Path.GetDirectoryName(pathAndMask);
            fileMask = Path.GetFileName(pathAndMask);
            this.encoding = encoding ?? Encoding.UTF8;

            // add initial files
            SearchOption option = (recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
            string dir = Path.GetDirectoryName(pathAndMask);
            if (Directory.Exists(dir))
            {
                lock (watchedFiles)
                {
                    foreach (string existingFileName in Directory.GetFiles(dir, Path.GetFileName(pathAndMask), option))
                    {
                        // start at end of existing files
                        FileInfo info = new FileInfo(existingFileName);
                        try
                        {
                            long pos = info.Length;
                            watchedFiles.Add(new WatchedFile(existingFileName, pos));
                        }
                        catch (Exception ex)
                        {
                            if (!(ex is FileNotFoundException || ex is IOException))
                            {
                                throw ex;
                            }
                            // ignore, maybe the file got deleted...
                        }
                    }
                }
            }

            // setup timer to ping files
            if (fileProcessingIntervalMilliseconds > 0)
            {
                fileProcessingTimer = new System.Timers.Timer(fileProcessingIntervalMilliseconds);
                fileProcessingTimer.Elapsed += (sender, args) => ProcessFiles();
                fileProcessingTimer.Start();
            }
        }

        /// <summary>
        /// Cleanup all resources
        /// </summary>
        public void Dispose()
        {
            // wait for any outstanding file pings
            if (fileProcessingTimer != null)
            {
                while (!fileProcessingTimer.Enabled)
                {
                    Thread.Sleep(20);
                }
                fileProcessingTimer?.Dispose();
            }
            lock (watchedFiles)
            {
                watchedFiles.Clear();
            }
        }

        /// <summary>
        /// Process the files, this is normally done on a timer, but if you have passed a 0 second
        /// ping interval to the constructor, you must call this manually
        /// </summary>
        public void ProcessFiles()
        {
            // disable timer while we parse so it doesn't stack
            SetProcessingTimerEnabled(false);

            try
            {
                foreach (WatchedFile file in GetCurrentWatchedFiles())
                {
                    // catch each file, that way one file exception doesn't bring down processing for all files
                    try
                    {
                        // ensure file has most recent data
                        long len = FlushFile(file.FileName);

                        // if file has shrunk (deleted and recreated for example) reset last position to 0 to ensure correct parsing from start of file
                        if (len < file.LastLength || len < file.LastPosition)
                        {
                            file.LastPosition = 0;
                        }

                        // if the length changed, we need to parse data from the file
                        if (len != file.LastLength)
                        {
                            using FileStream fs = new FileStream(file.FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 256);
                            file.LastLength = len;
                            ProcessFile(file, fs);
                        }
                        else
                        {
                            Logger.Debug("Watched file {0} length has not changed", file.FileName);
                        }

                        // if a max file size is specified and the file is over the max size, delete the file
                        if (maxFileSize > 0 && len > maxFileSize)
                        {
                            try
                            {
                                Logger.Warn("Deleting log file over max size: {0}", file.FileName);
                                File.Delete(file.FileName);
                            }
                            catch
                            {
                                // someone else might have it open, in which case we have no chance to delete
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex);
                    }
                }
            }
            finally
            {
                SetProcessingTimerEnabled(true);
            }
        }

        /// <summary>
        /// The path and mask to scan
        /// </summary>
        public string PathAndMask { get; private set; }

        /// <summary>
        /// The regex to find the ip address and user name from the file
        /// </summary>
        public Regex Regex { get; private set; }

        /// <summary>
        /// Handler to process text. As lines of log file are read, they are concatenated into a blob of text that always end in a newline.
        /// </summary>
        public System.Action<string> ProcessText { get; set; }

        /// <summary>
        /// Process text. Text will always end in a newline.
        /// </summary>
        /// <param name="text">Text to process</param>
        protected virtual void OnProcessText(string text) { }

        private void SetProcessingTimerEnabled(bool enabled)
        {
            try
            {
                if (fileProcessingTimer != null)
                {
                    fileProcessingTimer.Enabled = enabled;
                }
            }
            catch
            {
            }
        }

        private static long FlushFile(string fileName)
        {
            // by opening and seeking to the end, the os will flush the file and any pending data to disk
            using FileStream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 16);
            if (fs.Length != 0)
            {
                // force read a byte, this gets the file data flushed properly
                fs.Position = fs.Length - 1;
                fs.ReadByte();
            }
            return fs.Length;
        }

        private string ReplacePathVars(string path)
        {
            DateTime nowUtc = IPBanService.UtcNow;
            DateTime nowLocal = nowUtc.ToLocalTime();
            return path.Replace("{year}", nowUtc.Year.ToString("0000")).Replace("{month}", nowUtc.Month.ToString("00")).Replace("{day}", nowUtc.Day.ToString("00"))
                .Replace("{year-local}", nowLocal.Year.ToString("0000")).Replace("{month-local}", nowLocal.Month.ToString("00")).Replace("{day-local}", nowLocal.Day.ToString("00")); ;
        }

        private HashSet<WatchedFile> GetCurrentWatchedFiles()
        {
            HashSet<WatchedFile> watchedFilesCopy = new HashSet<WatchedFile>();

            try
            {
                // read in existing files that match the mask in the directory being watched
                if (Directory.Exists(directoryToWatch))
                {
                    string replacedDirectory = ReplacePathVars(directoryToWatch);
                    string replacedFileMask = ReplacePathVars(fileMask);
                    foreach (string file in Directory.EnumerateFiles(replacedDirectory, replacedFileMask, SearchOption.TopDirectoryOnly))
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
                        Logger.Debug("Removing parsed log file {0}", existing.FileName);
                        watchedFiles.Remove(existing);
                    }
                }

                // add new files
                foreach (WatchedFile newFile in watchedFilesCopy)
                {
                    // add the file, will fail if it already exists
                    if (watchedFiles.Add(newFile))
                    {
                        Logger.Debug("Adding parsed log file {0}", newFile.FileName);
                    }
                }

                // make a copy of everything so we can enumerate outside a lock
                watchedFilesCopy.Clear();
                foreach (WatchedFile file in watchedFiles)
                {
                    watchedFilesCopy.Add(file);
                }
            }

            return watchedFilesCopy;
        }

        private void ProcessFile(WatchedFile file, FileStream fs)
        {
            const int maxCountBeforeNewline = 1024;
            int b;
            long lastNewlinePos = -1;
            long end = Math.Min(file.LastLength, fs.Length);
            int countBeforeNewline = 0;
            fs.Position = file.LastPosition;

            Logger.Info("Processing log file {0}, len = {1}, pos = {2}", file.FileName, file.LastLength, file.LastPosition);

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
                throw new InvalidOperationException($"Log file '{file.FileName}' may not be a plain text new line delimited file");
            }

            if (lastNewlinePos > -1)
            {
                try
                {
                    // read all the text for the current set of lines into a string for processing
                    fs.Position = file.LastPosition;

                    // create giant text blob with all lines trimmed
                    byte[] bytes = new BinaryReader(fs).ReadBytes((int)(lastNewlinePos - fs.Position));
                    string text = "\n" + string.Join('\n', encoding.GetString(bytes).Split('\n').Select(l => l.Trim())) + "\n";

                    OnProcessText(text);
                    ProcessText?.Invoke(text);
                }
                finally
                {
                    // set file position for next ping
                    fs.Position = file.LastPosition = ++lastNewlinePos;
                }
            }
        }
    }
}
