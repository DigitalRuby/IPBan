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

using DigitalRuby.IPBanCore;

using NUnit.Framework;

using System;
using System.Collections.Generic;
using System.Linq;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanStringSetTests
    {
        private readonly Random random = new();
        private string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        [Test]
        public void TestStringSet()
        {
            using StringSet set = new("test", true);
            set.Clear();
            List<string> strings = new();
            Random r = new();
            for (int i = 0; i < 1000; i++)
            {
                strings.Add(RandomString(64));
            }
            strings.Sort();
            Assert.AreEqual(strings.Count, set.AddMany(strings));
            Assert.AreEqual(0, set.AddMany(strings));
            string[] existing = set.Enumerate().ToArray();
            Assert.AreEqual(strings, existing);
            Assert.IsFalse(set.Contains("test"));
            Assert.IsFalse(set.Contains("test2"));
            Assert.IsTrue(set.Add("test"));
            Assert.IsTrue(set.Add("test2"));
            Assert.AreEqual(strings.Count + 2, set.GetCount());
            Assert.IsFalse(set.Add("test"));
            Assert.IsFalse(set.Add("test2"));
            Assert.IsTrue(set.Contains("test"));
            Assert.IsTrue(set.Contains("test2"));
            Assert.IsFalse(set.Contains("nothing"));
            Assert.AreEqual(2, set.DeleteMany(new string[] { "test", "test2" }));
            Assert.AreEqual(strings.Count, set.GetCount());
            Assert.IsFalse(set.Contains("test"));
            Assert.IsFalse(set.Contains("test2"));
            Assert.IsFalse(set.Contains("test3"));
            Assert.IsTrue(set.Add("test3"));
            Assert.AreEqual(strings.Count + 1, set.GetCount());
            Assert.IsTrue(set.Delete("test3"));
            Assert.IsFalse(set.Delete("test3"));
            Assert.AreEqual(strings.Count, set.GetCount());
            Assert.AreEqual(strings.Count, set.Clear());
            Assert.AreEqual(0, set.GetCount());
            Assert.AreEqual(Array.Empty<string>(), set.Enumerate());
        }
    }
}