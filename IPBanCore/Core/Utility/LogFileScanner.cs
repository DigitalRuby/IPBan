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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileSystemGlobbing.Abstractions;

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
                if (!(obj is WatchedFile other))
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

        private readonly HashSet<WatchedFile> watchedFiles = new HashSet<WatchedFile>();
        private readonly System.Timers.Timer fileProcessingTimer;
        private readonly long maxFileSize;
        private readonly Encoding encoding;
        private readonly int maxLineLength;

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="pathAndMask">File path and mask with glob syntax (i.e. /var/log/auth*.log)</param>
        /// <param name="maxFileSizeBytes">Max size of file (in bytes) before it is deleted or 0 for unlimited</param>
        /// <param name="fileProcessingIntervalMilliseconds">How often to process files, in milliseconds, less than 1 for manual processing, in which case <see cref="ProcessFiles"/> must be called as needed.</param>
        /// <param name="encoding">Encoding or null for utf-8. The encoding must either be single or variable byte, like ASCII, Ansi, utf-8, etc. UTF-16 and the like are not supported.</param>
        /// <param name="maxLineLength">Maximum line length before considering the file a binary file and failing</param>
        public LogFileScanner(string pathAndMask, long maxFileSizeBytes = 0, int fileProcessingIntervalMilliseconds = 0, Encoding encoding = null, int maxLineLength = 8192)
        {
            // glob syntax, replace all backslash to forward slash
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
            List<WatchedFile> files = new List<WatchedFile>();

            // pull out the directory portion of the path/mask, accounting for /* syntax in the folder name
            string replacedPathMask = ReplacePathVars(pathAndMask);
            int lastSlashPos = replacedPathMask.LastIndexOf('/');
            string baseDirectoryWithoutGlobSyntax = replacedPathMask.Substring(0, lastSlashPos);
            int pos = baseDirectoryWithoutGlobSyntax.IndexOf("/*");
            Matcher fileMatcher;
            if (pos < 0)
            {
                // no /* in the directory, assume file mask is the last piece
                string fileMask = replacedPathMask.Substring(++lastSlashPos);
                fileMatcher = new Matcher(StringComparison.OrdinalIgnoreCase).AddInclude(fileMask);
            }
            else
            {
                // found a /*, take the root directory and make that the base path and everything else the glob path
                string fileMask = replacedPathMask.Substring(pos);
                baseDirectoryWithoutGlobSyntax = replacedPathMask.Substring(0, pos);
                fileMatcher = new Matcher(StringComparison.OrdinalIgnoreCase).AddInclude(fileMask);
            }

            // get the base directory that does not have glob syntax
            DirectoryInfoWrapper baseDir = new DirectoryInfoWrapper(new DirectoryInfo(baseDirectoryWithoutGlobSyntax));

            // read in existing files that match the mask in the directory being watched
            foreach (var file in fileMatcher.Execute(baseDir).Files)
            {
                try
                {
                    FileInfo info = new FileInfo(Path.Combine(baseDirectoryWithoutGlobSyntax, file.Path));
                    files.Add(new WatchedFile(info.FullName, info.Length));
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
                            using FileStream fs = new FileStream(file.FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 256);
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
        /// Normalize a glob
        /// </summary>
        /// <param name="glob">Glob</param>
        /// <returns>Normalized glob</returns>
        public static string NormalizeGlob(string glob)
        {
            return glob?.Trim().Replace('\\', '/').Replace("(", "\\(").Replace(")", "\\)").Replace("[", "\\[").Replace("]", "\\]");
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
                using FileStream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 16);
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
            HashSet<WatchedFile> watchedFilesCopy = new HashSet<WatchedFile>();
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
            int b;
            long lastNewlinePos = -1;
            long end = Math.Min(file.LastLength, fs.Length);
            int countBeforeNewline = 0;
            fs.Position = file.LastPosition;

            Logger.Trace("Processing log file {0}, len = {1}, pos = {2}", file.FileName, file.LastLength, file.LastPosition);

            while (fs.Position < end && countBeforeNewline++ != maxLineLength)
            {
                // read until last \n is found
                b = fs.ReadByte();
                if (b == '\n')
                {
                    lastNewlinePos = fs.Position - 1;
                    countBeforeNewline = 0;
                }
            }

            if (countBeforeNewline > maxLineLength)
            {
                file.IsBinaryFile = true;
                Logger.Warn($"Aborting parsing log file {file.FileName}, file may be a binary file");
                return;
            }

            // if we found a newline, process all the text up until that newline
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
                    // set file position for next processing
                    fs.Position = file.LastPosition = ++lastNewlinePos;
                }
            }
        }
    }
}
