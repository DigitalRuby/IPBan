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
using NUnit.Framework.Legacy;

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
            List<string> strings = [];
            Random r = new();
            for (int i = 0; i < 1000; i++)
            {
                strings.Add(RandomString(64));
            }
            strings.Sort();
            ClassicAssert.AreEqual(strings.Count, set.AddMany(strings));
            ClassicAssert.AreEqual(0, set.AddMany(strings));
            string[] existing = set.Enumerate().ToArray();
            ClassicAssert.AreEqual(strings, existing);
            ClassicAssert.IsFalse(set.Contains("test"));
            ClassicAssert.IsFalse(set.Contains("test2"));
            ClassicAssert.IsTrue(set.Add("test"));
            ClassicAssert.IsTrue(set.Add("test2"));
            ClassicAssert.AreEqual(strings.Count + 2, set.GetCount());
            ClassicAssert.IsFalse(set.Add("test"));
            ClassicAssert.IsFalse(set.Add("test2"));
            ClassicAssert.IsTrue(set.Contains("test"));
            ClassicAssert.IsTrue(set.Contains("test2"));
            ClassicAssert.IsFalse(set.Contains("nothing"));
            ClassicAssert.AreEqual(2, set.DeleteMany(new string[] { "test", "test2" }));
            ClassicAssert.AreEqual(strings.Count, set.GetCount());
            ClassicAssert.IsFalse(set.Contains("test"));
            ClassicAssert.IsFalse(set.Contains("test2"));
            ClassicAssert.IsFalse(set.Contains("test3"));
            ClassicAssert.IsTrue(set.Add("test3"));
            ClassicAssert.AreEqual(strings.Count + 1, set.GetCount());
            ClassicAssert.IsTrue(set.Delete("test3"));
            ClassicAssert.IsFalse(set.Delete("test3"));
            ClassicAssert.AreEqual(strings.Count, set.GetCount());
            ClassicAssert.AreEqual(strings.Count, set.Clear());
            ClassicAssert.AreEqual(0, set.GetCount());
            ClassicAssert.AreEqual(Array.Empty<string>(), set.Enumerate());
        }
    }
}