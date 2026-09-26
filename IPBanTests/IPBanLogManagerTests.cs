/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// Integration tests for <see cref="IPBanLogManager"/> id / path-and-mask matching:
    /// scanners with ids are keyed by id+path; scanners without ids collide on path alone.
    /// </summary>
    [TestFixture]
    public sealed class IPBanLogManagerTests
    {
        private IPBanService service;
        private string tempDir;

        [SetUp]
        public void SetUp()
        {
            tempDir = Path.Combine(Path.GetTempPath(), "ipban_logmgr_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
        }

        [TearDown]
        public void TearDown()
        {
            IPBanService.DisposeIPBanTestService(service);
            service = null;
            try { Directory.Delete(tempDir, true); } catch { /* best effort */ }
        }

        private IPBanLogManager GetLogManager()
        {
            ClassicAssert.IsTrue(service.TryGetUpdater(out IPBanLogManager manager));
            return manager;
        }

        private string PathInTemp(string fileName) => Path.Combine(tempDir, fileName).Replace('\\', '/');

        private async Task ApplyLogFilesAsync(params (string id, string source, string pathAndMask)[] entries)
        {
            XmlDocument doc = new();
            doc.LoadXml(service.Config.Xml);
            var logFilesNode = doc.SelectSingleNode("//LogFiles");
            ClassicAssert.IsNotNull(logFilesNode);
            logFilesNode.RemoveAll();

            foreach (var (id, source, pathAndMask) in entries)
            {
                var logFile = doc.CreateElement("LogFile");
                void Add(string name, string val)
                {
                    var e = doc.CreateElement(name);
                    e.InnerText = val;
                    logFile.AppendChild(e);
                }
                if (!string.IsNullOrWhiteSpace(id))
                {
                    Add("Id", id);
                }
                Add("Source", source);
                Add("PathAndMask", pathAndMask);
                Add("FailedLoginRegex", @"(?<ipaddress>\d+\.\d+\.\d+\.\d+)");
                Add("PlatformRegex", ".");
                Add("PingInterval", "0");
                Add("MaxFileSize", "0");
                Add("FailedLoginThreshold", "0");
                logFilesNode.AppendChild(logFile);
            }

            await service.ConfigReaderWriter.WriteConfigAsync(doc.OuterXml);
            await service.RunCycleAsync();
        }

        [Test]
        public async Task WithoutId_SamePathDifferentSource_ReplacesExistingScanner()
        {
            string path = PathInTemp("shared.log");
            File.WriteAllText(path, string.Empty);

            await ApplyLogFilesAsync((null, "SourceA", path));
            var manager = GetLogManager();
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.PathAndMask == path));
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s =>
                s.PathAndMask == path && string.IsNullOrWhiteSpace(s.Id) &&
                s is IPBanLogFileScanner lf && lf.Source == "SourceA"));

            // second no-id entry on the same path replaces the first (options differ by Source)
            await ApplyLogFilesAsync((null, "SourceB", path));
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.PathAndMask == path));
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s =>
                s.PathAndMask == path && string.IsNullOrWhiteSpace(s.Id) &&
                s is IPBanLogFileScanner lf && lf.Source == "SourceB"),
                "No-id path collision must replace the previous scanner with the new options");
        }

        [Test]
        public async Task WithoutId_OptionsUnchanged_KeepsSameScannerInstance()
        {
            string path = PathInTemp("stable.log");
            File.WriteAllText(path, string.Empty);

            await ApplyLogFilesAsync((null, "SourceA", path));
            var manager = GetLogManager();
            var first = manager.LogFilesToParse.Single(s => s.PathAndMask == path);

            await ApplyLogFilesAsync((null, "SourceA", path));
            var second = manager.LogFilesToParse.Single(s => s.PathAndMask == path);
            ClassicAssert.AreSame(first, second, "Identical no-id options must not recreate the scanner");
        }

        [Test]
        public async Task WithIds_SamePathDifferentIds_BothScannersCoexist()
        {
            string path = PathInTemp("shared.log");
            File.WriteAllText(path, string.Empty);

            await ApplyLogFilesAsync(
                ("RecipeA", "SourceA", path),
                ("RecipeB", "SourceB", path));

            var manager = GetLogManager();
            var onPath = manager.LogFilesToParse.Where(s => s.PathAndMask == path).ToArray();
            ClassicAssert.AreEqual(2, onPath.Length, "Distinct ids must allow multiple scanners on one path");
            ClassicAssert.IsTrue(onPath.Any(s => s.Id == "RecipeA"));
            ClassicAssert.IsTrue(onPath.Any(s => s.Id == "RecipeB"));
        }

        [Test]
        public async Task WithId_OptionsChange_ReplacesScannerKeepingId()
        {
            string path = PathInTemp("idchange.log");
            File.WriteAllText(path, string.Empty);

            await ApplyLogFilesAsync(("RecipeA", "SourceA", path));
            var manager = GetLogManager();
            var first = manager.LogFilesToParse.Single(s => s.Id == "RecipeA");

            await ApplyLogFilesAsync(("RecipeA", "SourceB", path));
            var second = manager.LogFilesToParse.Single(s => s.Id == "RecipeA" && s.PathAndMask == path);
            ClassicAssert.AreNotSame(first, second, "Option changes for the same id must recreate the scanner");
            ClassicAssert.IsTrue(second is IPBanLogFileScanner lf && lf.Source == "SourceB");
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.PathAndMask == path));
        }

        [Test]
        public async Task WithId_OptionsUnchanged_KeepsSameScannerInstance()
        {
            string path = PathInTemp("idstable.log");
            File.WriteAllText(path, string.Empty);

            await ApplyLogFilesAsync(("RecipeA", "SourceA", path));
            var manager = GetLogManager();
            var first = manager.LogFilesToParse.Single(s => s.Id == "RecipeA");

            await ApplyLogFilesAsync(("RecipeA", "SourceA", path));
            var second = manager.LogFilesToParse.Single(s => s.Id == "RecipeA");
            ClassicAssert.AreSame(first, second);
        }

        [Test]
        public async Task WithId_MultiPathEntry_CreatesScannerPerPath()
        {
            string path1 = PathInTemp("multi1.log");
            string path2 = PathInTemp("multi2.log");
            File.WriteAllText(path1, string.Empty);
            File.WriteAllText(path2, string.Empty);
            string pathAndMask = path1 + "\n" + path2;

            await ApplyLogFilesAsync(("MultiPath", "SourceA", pathAndMask));

            var manager = GetLogManager();
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.Id == "MultiPath" && s.PathAndMask == path1));
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.Id == "MultiPath" && s.PathAndMask == path2));
        }

        [Test]
        public async Task WithId_RemovedFromConfig_DisposesScanner()
        {
            string path = PathInTemp("gone.log");
            File.WriteAllText(path, string.Empty);

            await ApplyLogFilesAsync(
                ("KeepMe", "SourceA", path),
                ("DropMe", "SourceB", path));
            var manager = GetLogManager();
            ClassicAssert.AreEqual(2, manager.LogFilesToParse.Count(s => s.PathAndMask == path));

            await ApplyLogFilesAsync(("KeepMe", "SourceA", path));
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.PathAndMask == path));
            ClassicAssert.AreEqual("KeepMe", manager.LogFilesToParse.Single(s => s.PathAndMask == path).Id);
        }

        [Test]
        public async Task WithId_PathChange_MovesScannerToNewPath()
        {
            string pathOld = PathInTemp("old.log");
            string pathNew = PathInTemp("new.log");
            File.WriteAllText(pathOld, string.Empty);
            File.WriteAllText(pathNew, string.Empty);

            await ApplyLogFilesAsync(("Mover", "SourceA", pathOld));
            var manager = GetLogManager();
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.Id == "Mover" && s.PathAndMask == pathOld));

            await ApplyLogFilesAsync(("Mover", "SourceA", pathNew));
            ClassicAssert.AreEqual(0, manager.LogFilesToParse.Count(s => s.PathAndMask == pathOld));
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.Id == "Mover" && s.PathAndMask == pathNew));
        }

        [Test]
        public async Task Mixed_IdAndNoIdOnSamePath_BothCoexist()
        {
            string path = PathInTemp("mixed.log");
            File.WriteAllText(path, string.Empty);

            await ApplyLogFilesAsync(
                ("RecipeA", "SourceA", path),
                (null, "SourceB", path));

            var manager = GetLogManager();
            var onPath = manager.LogFilesToParse.Where(s => s.PathAndMask == path).ToArray();
            ClassicAssert.AreEqual(2, onPath.Length);
            ClassicAssert.IsTrue(onPath.Any(s => s.Id == "RecipeA"));
            ClassicAssert.IsTrue(onPath.Any(s => string.IsNullOrWhiteSpace(s.Id)));
        }

        [Test]
        public async Task WithId_CaseInsensitiveIdMatch_ReplacesOnOptionChange()
        {
            string path = PathInTemp("case.log");
            File.WriteAllText(path, string.Empty);

            await ApplyLogFilesAsync(("RecipeA", "SourceA", path));
            var manager = GetLogManager();
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s =>
                s.Id != null && s.Id.Equals("RecipeA", StringComparison.OrdinalIgnoreCase)));

            // same id different casing + different source should replace, not add a second scanner
            await ApplyLogFilesAsync(("recipea", "SourceB", path));
            ClassicAssert.AreEqual(1, manager.LogFilesToParse.Count(s => s.PathAndMask == path));
            var scanner = manager.LogFilesToParse.Single(s => s.PathAndMask == path);
            ClassicAssert.AreEqual("recipea", scanner.Id);
            ClassicAssert.IsTrue(scanner is IPBanLogFileScanner lf && lf.Source == "SourceB");
        }
    }
}
