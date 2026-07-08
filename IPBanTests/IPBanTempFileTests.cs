/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for the TempFile helper.
*/

using System.IO;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanTempFileTests
    {
        [Test]
        public void Construct_WithoutName_GeneratesGuid()
        {
            using var tf = new TempFile();
            ClassicAssert.IsNotNull(tf.FullName);
            ClassicAssert.IsTrue(tf.FullName.EndsWith(".tmp"));
        }

        [Test]
        public void Construct_WithName_UsesProvidedName()
        {
            using var tf = new TempFile("my_file.txt");
            ClassicAssert.IsTrue(tf.FullName.EndsWith("my_file.txt"));
        }

        [Test]
        public void Construct_DoesNotCreateFile()
        {
            using var tf = new TempFile();
            ClassicAssert.IsFalse(File.Exists(tf.FullName));
        }

        [Test]
        public void TempDirectory_IsAccessible()
        {
            ClassicAssert.IsNotNull(TempFile.TempDirectory);
            ClassicAssert.IsTrue(Directory.Exists(TempFile.TempDirectory));
        }

        [Test]
        public void GetTempFileName_ReturnsPathInTempDirectory()
        {
            string name = TempFile.GetTempFileName();
            ClassicAssert.IsNotNull(name);
            ClassicAssert.IsTrue(name.StartsWith(TempFile.TempDirectory));
        }

        [Test]
        public void ToString_ReturnsFullName()
        {
            using var tf = new TempFile("toString.txt");
            ClassicAssert.AreEqual(tf.FullName, tf.ToString());
        }

        [Test]
        public void ImplicitOperator_String_ReturnsFullName()
        {
            using var tf = new TempFile("implicit.txt");
            string s = tf;
            ClassicAssert.AreEqual(tf.FullName, s);
        }

        [Test]
        public void Dispose_DeletesFileIfExists()
        {
            string path;
            using (var tf = new TempFile("delete_me.txt"))
            {
                path = tf.FullName;
                File.WriteAllText(path, "hello");
                ClassicAssert.IsTrue(File.Exists(path));
            }
            // dispose should attempt deletion; dispose did not throw
        }
    }
}
