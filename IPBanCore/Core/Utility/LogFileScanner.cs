/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://www.digitalruby.com

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

using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileSystemGlobbing.Abstractions;

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
        /// <summary>
        /// Represents a watched file from a log file scanner
        /// </summary>
        public class WatchedFile
        {
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="fileName">File name</param>
            /// <param name="lastPosition">Last position scanned</param>
            public WatchedFile(string fileName, long lastPosition = 0)
            {
                this.FileName = fileName;
                LastPosition = lastPosition;
            }

            /// <inheritdoc />
            public override bool Equals(object obj)
            {
                if (obj is not WatchedFile other)
                {
                    return false;
                }
                return other.FileName == FileName;
            }

            /// <inheritdoc />
            public override int GetHashCode() => FileName.GetHashCode();

            /// <summary>
            /// File name
            /// </summary>
            public string FileName { get; private set; }

            /// <summary>
            /// Last scanned position
            /// </summary>
            public long LastPosition { get; set; }

            /// <summary>
            /// Last file length
            /// </summary>
            public long LastLength { get; set; }

            /// <summary>
            /// True if this is a binary file
            /// </summary>
            public bool IsBinaryFile { get; internal set; }
        }

        private readonly HashSet<WatchedFile> watchedFiles = new();
        private readonly System.Timers.Timer fileProcessingTimer;
        private readonly long maxFileSize;
        private readonly Encoding encoding;
        private readonly ushort maxLineLength;

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="pathAndMask">File path and mask with glob syntax (i.e. /var/log/auth*.log)</param>
        /// <param name="maxFileSizeBytes">Max size of file (in bytes) before it is deleted or 0 for unlimited</param>
        /// <param name="fileProcessingIntervalMilliseconds">How often to process files, in milliseconds, less than 1 for manual processing, in which case <see cref="ProcessFiles"/> must be called as needed.</param>
        /// <param name="encoding">Encoding or null for utf-8. The encoding must either be single or variable byte, like ASCII, Ansi, utf-8, etc. UTF-16 and the like are not supported.</param>
        /// <param name="maxLineLength">Maximum line length before considering the file a binary file and failing</param>
        public LogFileScanner(string pathAndMask, long maxFileSizeBytes = 0, int fileProcessingIntervalMilliseconds = 0, Encoding encoding = null, ushort maxLineLength = 8192)
        {
            PathAndMask = pathAndMask;
            PathAndMask.ThrowIfNullOrEmpty(nameof(pathAndMask), "Must pass a non-empty path and mask to log file scanner");

            // set properties
            this.maxFileSize = maxFileSizeBytes;
            this.encoding = encoding ?? Encoding.UTF8;
            this.maxLineLength = maxLineLength;

            try
            {
                // add initial files
                foreach (WatchedFile file in LogFileScanner.GetFiles(PathAndMask))
                {
                    watchedFiles.Add(file);
                }
            }
            catch
            {
                // generally catching all exceptions and not reporting is bad, but in this case we don't care,
                // we will try to get files on every ProcessFiles call and can throw the exception then
            }

            // setup timer to process files
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
            GC.SuppressFinalize(this);
            // wait for any outstanding file processing
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

        /// <inheritdoc />
        public override string ToString()
        {
            return $"Path/Mask: {PathAndMask}, Files: {watchedFiles.Count}, Encoding: {encoding.EncodingName}";
        }

        /// <summary>
        /// Get all files from a path and mask
        /// </summary>
        /// <param name="pathAndMask">Path and mask, this uses glob syntax. This should use forward slash only for dir separators</param>
        /// <returns>Found files</returns>
        public static IReadOnlyCollection<WatchedFile> GetFiles(string pathAndMask)
        {
            List<WatchedFile> files = new();

            // pull out the directory portion of the path/mask, accounting for * syntax in the folder name
            string replacedPathAndMask = ReplacePathVars(pathAndMask);
            NormalizeGlob(replacedPathAndMask, out string dirPortion, out string globPortion);

            // create a matcher to match glob or regular file syntax
            Matcher fileMatcher = new Matcher(StringComparison.OrdinalIgnoreCase).AddInclude(globPortion);

            // get the base directory that does not have glob syntax
            DirectoryInfoWrapper baseDir = new(new DirectoryInfo(dirPortion));

            // read in existing files that match the mask in the directory being watched
            foreach (var file in fileMatcher.Execute(baseDir).Files)
            {
                try
                {
                    string fullPath = dirPortion + file.Path;
                    long fileLength = new FileInfo(fullPath).Length;
                    files.Add(new WatchedFile(fullPath, fileLength));
                }
                catch (Exception ex)
                {
                    if (!(ex is FileNotFoundException || ex is IOException))
                    {
                        throw;
                    }
                    // ignore, maybe the file got deleted...
                }
            }
            return files;
        }

        /// <summary>
        /// Process the files, this is normally done on a timer, but if you have passed a 0 second
        /// processing interval to the constructor, you must call this manually
        /// </summary>
        public void ProcessFiles()
        {
            // disable timer while we parse so it doesn't stack
            SetProcessingTimerEnabled(false);

            try
            {
                foreach (WatchedFile file in GetCurrentWatchedFiles().Where(f => !f.IsBinaryFile))
                {
                    // catch each file, that way one file exception doesn't bring down processing for all files
                    try
                    {
                        // ensure file has most recent data
                        long len = FlushFile(file.FileName);
                        if (len < 0)
                        {
                            continue;
                        }

                        // if file has shrunk (deleted and recreated for example) reset last position to 0 to ensure correct parsing from start of file
                        if (len < file.LastLength || len < file.LastPosition)
                        {
                            file.LastPosition = 0;
                        }

                        // if the length changed, we need to parse data from the file
                        if (len != file.LastLength)
                        {
                            using FileStream fs = new(file.FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            file.LastLength = len;
                            ProcessFile(file, fs);
                        }
                        else
                        {
                            Logger.Trace("Watched file {0} length has not changed", file.FileName);
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

        /// <summary>
        /// Normalize a glob. This gets everything with the * character and after escaped properly.
        /// </summary>
        /// <param name="glob">Glob</param>
        /// <param name="dirPortion">Directory portion</param>
        /// <param name="globPortion">Glob portion</param>
        /// <returns>Normalized glob</returns>
        public static string NormalizeGlob(string glob, out string dirPortion, out string globPortion)
        {
            dirPortion = globPortion = null;
            if (string.IsNullOrWhiteSpace(glob))
            {
                return glob;
            }

            // backslash to forward slash
            glob = glob.Replace('\\', '/').Trim();

            // find first segment that has a glob wildcard
            int pos = glob.IndexOf('*');
            if (pos >= 0)
            {
                for (int i = pos; i >= 0; i--)
                {
                    if (glob[i] == '/')
                    {
                        // directory is every segment before the glob wildcard
                        dirPortion = glob[..++i];

                        // glob is everything after
                        globPortion = glob[i..];
                        break;
                    }
                }
            }
            if (dirPortion is null)
            {
                pos = glob.LastIndexOfAny(new[] { '/', '\\' });
                if (pos < 0)
                {
                    throw new ArgumentException("Cannot normalize a glob that does not have a directory and a file piece");
                }

                // directory is every segment before the last dir sep
                dirPortion = glob[..++pos];

                // glob is everything after
                globPortion = glob[pos..];

                if (globPortion.Length == 0)
                {
                    throw new ArgumentException("Cannot normalize a glob that does not have a directory and a file piece");
                }
            }

            // escape needed chars
            globPortion = globPortion.Replace("(", "\\(").Replace(")", "\\)").Replace("[", "\\[").Replace("]", "\\]");

            return dirPortion + globPortion;
        }

        /// <summary>
        /// Replay a file being written to simulate regular logging
        /// </summary>
        /// <param name="sourceFile">Source file</param>
        /// <param name="destFile">Dest file</param>
        /// <param name="delay">Delay in ms before starting replay</param>
        /// <param name="cancelToken">Cancel token</param>
        public static void Replay(string sourceFile, string destFile, int delay, CancellationToken cancelToken = default)
        {
            FileInfo info = new(sourceFile);
            Random r = new();
            long pos = 0;
            ExtensionMethods.FileDeleteWithRetry(destFile);
            File.WriteAllText(destFile, string.Empty);
            Thread.Sleep(delay);
            while (pos >= 0 && !cancelToken.IsCancellationRequested)
            {
                try
                {
                    using var stream = new FileStream(info.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var stream2 = new FileStream(destFile, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
                    stream2.Position = stream2.Length;
                    stream.Position = pos;
                    int rand = r.Next(3, 1111);
                    for (int i = 0; i < rand; i++)
                    {
                        int b = stream.ReadByte();
                        pos++;
                        if (b >= 0)
                        {
                            stream2.WriteByte((byte)b);

                        }
                        else
                        {
                            pos = -1;
                            break;
                        }
                    }
                }
                catch
                {
                }
                Thread.Sleep(r.Next(1000, 10000));
            }
        }

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
            if (File.Exists(fileName))
            {
                // by opening and seeking to the end, the os will flush the file and any pending data to disk
                using FileStream fs = new(fileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 16);
                if (fs.Length != 0)
                {
                    // force read a byte, this gets the file data flushed properly
                    fs.Position = fs.Length - 1;
                    fs.ReadByte();
                }
                return fs.Length;
            }
            return -1;
        }

        private static string ReplacePathVars(string path)
        {
            DateTime nowUtc = IPBanService.UtcNow;
            DateTime nowLocal = nowUtc.ToLocalTime();
            return path.Replace("{year}", nowUtc.Year.ToString("0000"))
                .Replace("{month}", nowUtc.Month.ToString("00"))
                .Replace("{day}", nowUtc.Day.ToString("00"))
                .Replace("{year-local}", nowLocal.Year.ToString("0000"))
                .Replace("{month-local}", nowLocal.Month.ToString("00"))
                .Replace("{day-local}", nowLocal.Day.ToString("00"));
        }

        private HashSet<WatchedFile> GetCurrentWatchedFiles()
        {
            // read in existing files that match the mask in the directory being watched
            HashSet<WatchedFile> watchedFilesCopy = new();
            foreach (WatchedFile file in LogFileScanner.GetFiles(PathAndMask))
            {
                watchedFilesCopy.Add(file);
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
            Logger.Trace("Processing log file {0}, len = {1}, pos = {2}", file.FileName, file.LastLength, file.LastPosition);

            // seek to next position
            fs.Position = file.LastPosition;

            // fill up to 64K bytes
            byte[] bytes = new byte[ushort.MaxValue];
            int read = fs.Read(bytes, 0, bytes.Length);

            // setup state
            int bytesEnd;
            bool foundNewLine = false;

            // find the last newline char
            for (bytesEnd = read - 1; bytesEnd >= 0; bytesEnd--)
            {
                if (bytes[bytesEnd] == '\n')
                {
                    // take bytes up to and including the last newline char
                    bytesEnd++;
                    foundNewLine = true;
                    break;
                }
            }

            // check for binary file
            if (!foundNewLine)
            {
                if (read > maxLineLength)
                {
                    // max line length bytes without a new line
                    file.IsBinaryFile = true;
                    Logger.Warn($"Aborting parsing log file {file.FileName}, file may be a binary file");
                }
                // reset position try again on next cycle
                fs.Position = file.LastPosition;
                return;
            }

            // if we found a newline, process all the text up until that newline
            if (foundNewLine)
            {
                try
                {
                    // strip out all carriage returns and ensure string starts/ends with newlines
                    string foundText = encoding.GetString(bytes, 0, bytesEnd).Trim().Replace("\r", string.Empty);
                    string processText = "\n" + foundText + "\n";
                    OnProcessText(processText);
                    ProcessText?.Invoke(processText);
                }
                finally
                {
                    // set file position for next processing
                    fs.Position = file.LastPosition + bytesEnd;
                    file.LastPosition = fs.Position;
                }
            }
        }
    }
}
