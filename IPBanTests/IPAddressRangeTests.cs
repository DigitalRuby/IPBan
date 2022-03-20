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
using System.Linq;
using System.Net;
using System.Net.Sockets;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// Test extensions
    /// </summary>
    public static class TestExtensions
    {
        /// <summary>
        /// Check if two objects are equal
        /// </summary>
        /// <param name="a">Obj a</param>
        /// <param name="b">Obj b</param>
        /// <exception cref="AssertionException">Objects are not equal</exception>
        public static void Is(this object a, object b, string message = null)
        {
            Assert.AreEqual(b, a, message);
        }

        /// <summary>
        /// Check if two objects are not equal
        /// </summary>
        /// <param name="a">Obj a</param>
        /// <param name="b">Obj b</param>
        /// <exception cref="AssertionException">Objects are equal</exception>
        public static void IsNot(this object a, object b, string message = null)
        {
            Assert.AreNotEqual(b, a, message);
        }
    }

    [TestFixture]
    public class IPAddressRangeTest
    {
        public TestContext TestContext { get; set; }

        [Test]
        public void CtorTest_Empty()
        {
            var range = new IPAddressRange();
            range.Begin.AddressFamily.Is(AddressFamily.InterNetwork);
            range.Begin.ToString().Is("0.0.0.0");
            range.End.AddressFamily.Is(AddressFamily.InterNetwork);
            range.End.ToString().Is("0.0.0.0");
        }

        [Test]
        public void CtorTest_Single()
        {
            var range = new IPAddressRange(IPAddress.Parse("192.168.0.88"));
            range.Begin.AddressFamily.Is(AddressFamily.InterNetwork);
            range.Begin.ToString().Is("192.168.0.88");
            range.End.AddressFamily.Is(AddressFamily.InterNetwork);
            range.End.ToString().Is("192.168.0.88");
            range.Contains(range.Begin).Is(true);
        }

        [Test]
        public void CtorTest_MaskLength()
        {
            var range = new IPAddressRange(IPAddress.Parse("192.168.0.80"), 24);
            range.Begin.AddressFamily.Is(AddressFamily.InterNetwork);
            range.Begin.ToString().Is("192.168.0.0");
            range.End.AddressFamily.Is(AddressFamily.InterNetwork);
            range.End.ToString().Is("192.168.0.255");
            range.Contains(range.Begin).Is(true);
        }

        [Test]
        public void CtorTest_IPv6_BeginEndAddresses()
        {
            var range = new IPAddressRange(
                begin: IPAddress.Parse("ff80::1"),
                end: IPAddress.Parse("ff80::34"));
            range.Begin.AddressFamily.Is(AddressFamily.InterNetworkV6);
            range.Begin.ToString().Is("ff80::1");
            range.End.AddressFamily.Is(AddressFamily.InterNetworkV6);
            range.End.ToString().Is("ff80::34");
            range.Contains(range.Begin).Is(true);
        }

        [Test]
        public void CtorTest_IPv6_BeginEndAddresses_with_ScopeId()
        {
            var range = new IPAddressRange(
                begin: IPAddress.Parse("ff80::56%23"),
                end: IPAddress.Parse("ff80::789%23"));
            range.Begin.AddressFamily.Is(AddressFamily.InterNetworkV6);
            range.Begin.ToString().Is("ff80::56");
            range.End.AddressFamily.Is(AddressFamily.InterNetworkV6);
            range.End.ToString().Is("ff80::789");
            range.Contains(range.Begin).Is(true);
        }

        [Test]
        public void ParseTest_IPv4_Uniaddress()
        {
            var range = IPAddressRange.Parse("192.168.60.13");
            range.Begin.AddressFamily.Is(AddressFamily.InterNetwork);
            range.Begin.ToString().Is("192.168.60.13");
            range.End.AddressFamily.Is(AddressFamily.InterNetwork);
            range.End.ToString().Is("192.168.60.13");
        }

        [Test]
        public void ParseTest_IPv4_CIDR()
        {
            var range = IPAddressRange.Parse("219.165.64.0/19");
            range.Begin.AddressFamily.Is(AddressFamily.InterNetwork);
            range.Begin.ToString().Is("219.165.64.0");
            range.End.AddressFamily.Is(AddressFamily.InterNetwork);
            range.End.ToString().Is("219.165.95.255");
        }

        [Test]
        public void ParseTest_IPv4_CIDR_Max()
        {
            var range = IPAddressRange.Parse("219.165.64.73/32");
            range.Begin.AddressFamily.Is(AddressFamily.InterNetwork);
            range.Begin.ToString().Is("219.165.64.73");
            range.End.AddressFamily.Is(AddressFamily.InterNetwork);
            range.End.ToString().Is("219.165.64.73");
        }

        [Test]
        public void ParseTest_IPv4_Bitmask()
        {
            var range = IPAddressRange.Parse("192.168.1.0/255.255.255.0");
            range.Begin.AddressFamily.Is(AddressFamily.InterNetwork);
            range.Begin.ToString().Is("192.168.1.0");
            range.End.AddressFamily.Is(AddressFamily.InterNetwork);
            range.End.ToString().Is("192.168.1.255");
        }

        [Test]
        public void ParseTest_IPv4_Begin_to_End()
        {
            var range = IPAddressRange.Parse("192.168.60.26-192.168.60.37");
            range.Begin.AddressFamily.Is(AddressFamily.InterNetwork);
            range.Begin.ToString().Is("192.168.60.26");
            range.End.AddressFamily.Is(AddressFamily.InterNetwork);
            range.End.ToString().Is("192.168.60.37");
        }

        [Test]
        public void ContainsTest_IPv4()
        {
            var range = IPAddressRange.Parse("192.168.60.26-192.168.60.37");

            range.Contains(IPAddress.Parse("192.168.60.25")).Is(false);
            range.Contains(IPAddress.Parse("192.168.60.26")).Is(true);
            range.Contains(IPAddress.Parse("192.168.60.27")).Is(true);

            range.Contains(IPAddress.Parse("192.168.60.36")).Is(true);
            range.Contains(IPAddress.Parse("192.168.60.37")).Is(true);
            range.Contains(IPAddress.Parse("192.168.60.38")).Is(false);
        }

        [Test]
        public void ContainsTest_TestIPv6_to_IPv4Range()
        {
            var range = IPAddressRange.Parse("192.168.60.26-192.168.60.37");

            range.Contains(IPAddress.Parse("c0a8:3c1a::")).Is(false);
        }

        [Test]
        public void ContainsTest_with_IPV4andv6_is_False_ever()
        {
            var fullRangeIPv6 = IPAddressRange.Parse("::-fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
            fullRangeIPv6.Contains(IPAddressRange.Parse("192.168.0.0/24")).Is(false);

            var fullRangeIPv4 = IPAddressRange.Parse("0.0.0.0-255.255.255.255");
            fullRangeIPv4.Contains(IPAddressRange.Parse("::1-::2")).Is(false);
        }

        [Test]
        public void ContainsTest_Range_is_True_IPv4()
        {
            var range = IPAddressRange.Parse("192.168.60.26-192.168.60.37");
            var range1_same = IPAddressRange.Parse("192.168.60.26-192.168.60.37");
            var range2_samestart = IPAddressRange.Parse("192.168.60.26-192.168.60.30");
            var range3_sameend = IPAddressRange.Parse("192.168.60.36-192.168.60.37");
            var range4_subset = IPAddressRange.Parse("192.168.60.29-192.168.60.32");

            range.Contains(range1_same).Is(true);
            range.Contains(range2_samestart).Is(true);
            range.Contains(range3_sameend).Is(true);
            range.Contains(range4_subset).Is(true);
        }

        [Test]
        public void ContainsTest_Range_is_False_IPv4()
        {
            var range = IPAddressRange.Parse("192.168.60.29-192.168.60.32");
            var range1_overLeft = IPAddressRange.Parse("192.168.60.26-192.168.70.1");
            var range2_overRight = IPAddressRange.Parse("192.168.50.1-192.168.60.37");
            var range3_outOfLeft = IPAddressRange.Parse("192.168.50.30-192.168.50.31");
            var range4_outOfRight = IPAddressRange.Parse("192.168.70.30-192.168.70.31");

            range.Contains(range1_overLeft).Is(false);
            range.Contains(range2_overRight).Is(false);
            range.Contains(range3_outOfLeft).Is(false);
            range.Contains(range4_outOfRight).Is(false);
        }

        [Test]
        public void ParseTest_IPv6_CIDR()
        {
            var range = IPAddressRange.Parse("fe80::/10");
            range.Begin.AddressFamily.Is(AddressFamily.InterNetworkV6);
            range.Begin.ToString().Is("fe80::");
            range.End.AddressFamily.Is(AddressFamily.InterNetworkV6);
            range.End.ToString().Is("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        }

        [Test]
        public void ContainsTest_IPv6()
        {
            var range = IPAddressRange.Parse("FE80::/10");

            range.Contains(IPAddress.Parse("::1")).Is(false);
            range.Contains(IPAddress.Parse("fe80::d503:4ee:3882:c586")).Is(true);
            range.Contains(IPAddress.Parse("fe80::d503:4ee:3882:c586%3")).Is(true);

            range = IPAddressRange.Parse("::/0");
            range.Contains(IPAddress.Parse("::1")).Is(true);
        }

        [Test]
        public void ContainsTest_IPv6_with_ScopeId()
        {
            var range = IPAddressRange.Parse("FE80::%eth0/10");

            range.Contains(IPAddress.Parse("::1")).Is(false);
            range.Contains(IPAddress.Parse("fe80::d503:4ee:3882:c586")).Is(true);
            range.Contains(IPAddress.Parse("fe80::d503:4ee:3882:c586%4")).Is(true);
        }

        [Test]
        public void ContainsTest_Range_is_True_IPv6()
        {
            var range = IPAddressRange.Parse("fe80::/10");
            var range1_same = IPAddressRange.Parse("fe80::/10");
            var range2_samestart = IPAddressRange.Parse("fe80::-fe80::d503:4ee:3882:c586");
            var range3_sameend = IPAddressRange.Parse("fe80::d503:4ee:3882:c586-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
            var range4_subset = IPAddressRange.Parse("fe80::d503:4ee:3882:c586-fe80::d504:4ee:3882:c586");

            range.Contains(range1_same).Is(true);
            range.Contains(range2_samestart).Is(true);
            range.Contains(range3_sameend).Is(true);
            range.Contains(range4_subset).Is(true);
        }

        [Test]
        public void ContainsTest_Range_is_False_IPv6()
        {
            var range = IPAddressRange.Parse("fe80::d503:4ee:3882:c586-fe80::d504:4ee:3882:c586");
            var range1_overLeft = IPAddressRange.Parse("fe80::d502:4ee:3882:c586-fe80::d503:4ee:3882:c586");
            var range2_overRight = IPAddressRange.Parse("fe80::d503:4ef:3882:c586-fe80::d505:4ee:3882:c586");
            var range3_outOfLeft = IPAddressRange.Parse("fe80::d501:4ee:3882:c586-fe80::d502:4ee:3882:c586");
            var range4_outOfRight = IPAddressRange.Parse("fe80::d505:4ee:3882:c586-fe80::d506:4ee:3882:c586");

            range.Contains(range1_overLeft).Is(false);
            range.Contains(range2_overRight).Is(false);
            range.Contains(range3_outOfLeft).Is(false);
            range.Contains(range4_outOfRight).Is(false);
        }

        [Test]
        public void ContainsTest_IPv4_mappedTo_IPv6()
        {
            var range = IPAddressRange.Parse("::ffff:192.168.10.20-::ffff:192.168.11.20");

            range.Contains(IPAddress.Parse("::ffff:192.168.10.19")).Is(false);
            range.Contains(IPAddress.Parse("::ffff:192.168.10.20")).Is(true);
            range.Contains(IPAddress.Parse("::ffff:192.168.11.20")).Is(true);
            range.Contains(IPAddress.Parse("::ffff:192.168.11.21")).Is(false);

            range.Contains(IPAddress.Parse("fe80::d503:4ee:3882:c586")).Is(false);
            range.Contains(IPAddress.Parse("192.168.10.20")).Is(true);

            var range1_overLeft = IPAddressRange.Parse("::ffff:192.168.10.19-::ffff:192.168.10.21");
            var range2_overRight = IPAddressRange.Parse("::ffff:192.168.11.19-::ffff:192.168.11.21");
            var range3_outOfLeft = IPAddressRange.Parse("::ffff:192.168.10.18-::ffff:192.168.10.19");
            var range4_outOfRight = IPAddressRange.Parse("::ffff:192.168.11.21-::ffff:192.168.11.22");
            var range5_justInside = IPAddressRange.Parse("::ffff:192.168.10.20-::ffff:192.168.11.20");
            range.Contains(range1_overLeft).Is(false);
            range.Contains(range2_overRight).Is(false);
            range.Contains(range3_outOfLeft).Is(false);
            range.Contains(range4_outOfRight).Is(false);
            range.Contains(range5_justInside).Is(true);
        }

        [Test]
        public void SubnetMaskLengthTest_Valid()
        {
            var range = new IPAddressRange(IPAddress.Parse("192.168.75.23"), IPAddressRange.SubnetMaskLength(IPAddress.Parse("255.255.254.0")));
            range.Begin.ToString().Is("192.168.74.0");
            range.End.ToString().Is("192.168.75.255");
        }

        [Test]
        public void SubnetMaskLengthTest_Invalid()
        {
            Assert.Throws<ArgumentException>(() =>
                new IPAddressRange(IPAddress.Parse("192.168.75.23"), IPAddressRange.SubnetMaskLength(IPAddress.Parse("255.255.54.0"))));
        }

        [Test]
        public void Enumerate_IPv4()
        {
            var ips = IPAddressRange.Parse("192.168.60.253-192.168.61.2").AsEnumerable().ToArray();
            ips.Is(new IPAddress[]
            {
            IPAddress.Parse("192.168.60.253"),
            IPAddress.Parse("192.168.60.254"),
            IPAddress.Parse("192.168.60.255"),
            IPAddress.Parse("192.168.61.0"),
            IPAddress.Parse("192.168.61.1"),
            IPAddress.Parse("192.168.61.2"),
            });
        }

        [Test]
        public void Enumerate_IPv6()
        {
            var ips = IPAddressRange.Parse("fe80::d503:4ee:3882:c586/120").AsEnumerable().ToArray();
            ips.Length.Is(256);
            ips.First().Is(IPAddress.Parse("fe80::d503:4ee:3882:c500"));
            ips.Last().Is(IPAddress.Parse("fe80::d503:4ee:3882:c5ff"));
        }

        [Test]
        public void EnumerateTest_With_Foreach()
        {
            foreach (var ip in IPAddressRange.Parse("192.168.60.2"))
            {
                ip.Is(IPAddress.Parse("192.168.60.2"));
            }

        }


        [Test]
        [TestCase("192.168.60.2", "192.168.60.2")]
        [TestCase("192.168.60.2/24", "192.168.60.0/24")]
        [TestCase("fe80::d503:4ee:3882:c586", "fe80::d503:4ee:3882:c586")]
        [TestCase("fe80::d503:4ee:3882:c586/120", "fe80::d503:4ee:3882:c500/120")]
        public void ToString_Output(string input, string expected)
        {
            Console.WriteLine("TestCase: \"{0}\", Expected: \"{1}\"", input, expected);
            var output = IPAddressRange.Parse(input).ToString();
            Console.WriteLine("  Result: \"{0}\"", output);
            output.Is(expected);

            var parsed = IPAddressRange.Parse(output).ToString();
            parsed.Is(expected, "Output of ToString() should be usable by Parse() and result in the same output");
        }

        [Test]
        [TestCase("fe80::/10", 10)]
        [TestCase("192.168.0.0/24", 24)]
        [TestCase("192.168.0.0", 32)]
        [TestCase("192.168.0.0-192.168.0.0", 32)]
        [TestCase("fe80::", 128)]
        [TestCase("192.168.0.0-192.168.0.255", 24)]
        [TestCase("fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 16)]
        public void GetPrefixLength_Success(string input, int expected)
        {
            Console.WriteLine("TestCase: \"{0}\", Expected: \"{1}\"", input, expected);
            var output = IPAddressRange.Parse(input).GetPrefixLength();
            Console.WriteLine("  Result: \"{0}\"", output);
            output.Is(expected);
        }

        [Test]
        [TestCase("fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 10)]
        [TestCase("192.168.0.0", "192.168.0.255", 24)]
        [TestCase("192.168.0.0", "192.168.0.0", 32)]
        [TestCase("192.168.0.0", "192.168.0.0", 32)]
        [TestCase("fe80::", "fe80::", 128)]
        [TestCase("192.168.0.0", "192.168.0.255", 24)]
        [TestCase("fe80::", "fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 16)]
        public void GetPrefixLength_with_RewriteBeginEndProperties_Success(string begin, string end, int expected)
        {
            var range = new IPAddressRange(IPAddress.Parse(begin), IPAddress.Parse(end));
            Console.WriteLine($"TestCase: \"{begin}\"~\"{end}\", Expected: \"{expected}\"");
            var output = range.GetPrefixLength();
            Console.WriteLine($"  Result: \"{output}\"");
            output.Is(expected);
        }

        [Test]
        [TestCase("192.168.0.0-192.168.0.254", typeof(FormatException))]
        [TestCase("fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffe", typeof(FormatException))]
        public void GetPrefixLength_Failures(string input, Type expectedException)
        {
            Console.WriteLine("TestCase: \"{0}\", Expected Exception: {1}", input, expectedException.Name);
            try
            {
                IPAddressRange.Parse(input).GetPrefixLength();
                Assert.Fail("Expected exception of type {0} to be thrown for input \"{1}\"", expectedException.Name, input);
            }
            catch (AssertionException)
            {
                throw; // allow Assert.Fail to pass through 
            }
            catch (Exception ex)
            {
                ex.GetType().Is(expectedException);
            }
        }

        [Test]
        [TestCase("192.168.0.0", "192.168.0.254", typeof(FormatException), "fe80::", "fe80::", 128)]
        [TestCase("fe80::", "fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffe", typeof(FormatException), "192.168.0.0", "192.168.0.255", 24)]
        public void GetPrefixLength_with_RewriteBeginEndProperties_Failures(string begin, string end, Type expectedException, string begin2, string end2, int expected)
        {
            Console.WriteLine($"TestCase: \"{begin}\"~\"{end}\", Expected Exception: \"{expectedException.Name}\"");
            IPAddressRange range;
            try
            {
                range = new IPAddressRange(IPAddress.Parse(begin), IPAddress.Parse(end));
                range.GetPrefixLength();
                Assert.Fail($"Expected exception of type {expectedException.Name} to be thrown for input \"{begin}\"~\"{end}\"");
            }
            catch (AssertionException)
            {
                throw; // allow Assert.Fail to pass through 
            }
            catch (Exception ex)
            {
                ex.GetType().Is(expectedException);
            }

            // Once it was failed, but it will be recovered with valid begin/end property.
            Console.WriteLine($"TestCase: \"{begin2}\"~\"{end2}\", Expected: \"{expected}\"");
            range = new IPAddressRange(IPAddress.Parse(begin2), IPAddress.Parse(end2));
            var output = range.GetPrefixLength();
            Console.WriteLine($"  Result: \"{output}\"");
            output.Is(expected);
        }

        [Test]
        [TestCase("fe80::/10", "fe80::/10")]
        [TestCase("192.168.0.0/24", "192.168.0.0/24")]
        [TestCase("192.168.0.0", "192.168.0.0/32")]
        [TestCase("192.168.0.0-192.168.0.0", "192.168.0.0/32")]
        [TestCase("fe80::", "fe80::/128")]
        [TestCase("192.168.0.0-192.168.0.255", "192.168.0.0/24")]
        [TestCase("fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::/16")]
        public void ToCidrString_Output(string input, string expected)
        {
            Console.WriteLine("TestCase: \"{0}\", Expected: \"{1}\"", input, expected);
            var output = IPAddressRange.Parse(input).ToCidrString();
            Console.WriteLine("  Result: \"{0}\"", output);
            output.Is(expected);
        }

        [Test]
        [TestCase("192.168.0.0-192.168.0.254", "192.168.0.0-192.168.0.254")]
        [TestCase("fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffe")]
        public void ToCidrString_NonCidrRanges(string input, string output)
        {
            Console.WriteLine("TestCase: \"{0}\", Expected output: {1}", input, output);
            string s = IPAddressRange.Parse(input).ToCidrString();
            Assert.AreEqual(output, s);
        }

        [Test]
        [TestCase("192.168.0.0-192.168.0.254")]
        [TestCase("fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffe")]
        public void GetHashCode_SameRange_HashCodesAreSame(string input)
        {
            Console.WriteLine("TestCase: \"{0}\"", input);
            var range1 = IPAddressRange.Parse(input);
            var range2 = IPAddressRange.Parse(input);
            range1.GetHashCode().Is(range2.GetHashCode());
        }

        [Test]
        [TestCase("192.168.0.0-192.168.0.254", "192.168.0.1-192.168.0.254")]
        [TestCase("fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffd")]
        public void GetHashCode_DifferentRanges_HashCodesAreDifferent(string input1, string input2)
        {
            Console.WriteLine("TestCase: \"{0}\" and \"{1}\"", input1, input2);
            var range1 = IPAddressRange.Parse(input1);
            var range2 = IPAddressRange.Parse(input2);
            range1.GetHashCode().IsNot(range2.GetHashCode());
        }

        [Test]
        [TestCase("192.168.0.0-192.168.0.254")]
        [TestCase("fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffe")]
        public void Equals_SameRange_ReturnsTrue(string input)
        {
            Console.WriteLine("TestCase: \"{0}\"", input);
            var range1 = IPAddressRange.Parse(input);
            var range2 = IPAddressRange.Parse(input);
            range1.Equals(range2).Is(true);
        }

        [Test]
        [TestCase("192.168.0.0-192.168.0.254", "192.168.0.1-192.168.0.254")]
        [TestCase("fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "fe80::-fe80:ffff:ffff:ffff:ffff:ffff:ffff:fffd")]
        public void Equals_SameRange_ReturnsFalse(string input1, string input2)
        {
            Console.WriteLine("TestCase: \"{0}\" and \"{1}\"", input1, input2);
            var range1 = IPAddressRange.Parse(input1);
            var range2 = IPAddressRange.Parse(input2);
            range1.Equals(range2).Is(false);
        }

        [Test]
        public void Equals_WithNull_ReturnsFalse()
        {
            var range1 = IPAddressRange.Parse("192.168.0.0/24");
            var range2 = default(IPAddressRange);
            range1.Equals(range2).Is(false);
        }

        [Test]
        public void Count_IPv4_Test()
        {
            var ipAddressRange = IPAddressRange.Parse("10.0.0.0/8");
            ipAddressRange.AsEnumerable().Count().Is(16777216);
        }

        [Test]
        public void Count_IPv6_Test()
        {
            var ipAddressRange = IPAddressRange.Parse("fe80::0000:0000-fe80::0100:0001");
            ipAddressRange.AsEnumerable().Count().Is(16777218);
        }

        [Test]
        [TestCase("192.168.60.13", "192.168.60.13", "192.168.60.13")]
        [TestCase("  192.168.60.13  ", "192.168.60.13", "192.168.60.13")]
        [TestCase("fe80::d503:4ee:3882:c586", "fe80::d503:4ee:3882:c586", "fe80::d503:4ee:3882:c586")]
        [TestCase("  fe80::d503:4ee:3882:c586  ", "fe80::d503:4ee:3882:c586", "fe80::d503:4ee:3882:c586")]
        [TestCase("::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
        [TestCase("3232252004", "192.168.64.100", "192.168.64.100")] // decimal - new 
        [TestCase("  3232252004  ", "192.168.64.100", "192.168.64.100")] // decimal - new 

        [TestCase("219.165.64.0/19", "219.165.64.0", "219.165.95.255")]
        [TestCase("  219.165.64.0  /  19  ", "219.165.64.0", "219.165.95.255")]
        [TestCase("192.168.1.0/255.255.255.0", "192.168.1.0", "192.168.1.255")]
        [TestCase("  192.168.1.0  /  255.255.255.0  ", "192.168.1.0", "192.168.1.255")]
        [TestCase("3232252004/24", "192.168.64.0", "192.168.64.255")] // decimal - new 
        [TestCase("  3232252004  /  24  ", "192.168.64.0", "192.168.64.255")] // decimal - new 

        [TestCase("192.168.60.26–192.168.60.37", "192.168.60.26", "192.168.60.37")]
        [TestCase("  192.168.60.26  –  192.168.60.37  ", "192.168.60.26", "192.168.60.37")]
        [TestCase("fe80::c586-fe80::c600", "fe80::c586", "fe80::c600")]
        [TestCase("  fe80::c586  -  fe80::c600  ", "fe80::c586", "fe80::c600")]
        [TestCase("3232252004-3232252504", "192.168.64.100", "192.168.66.88")]
        [TestCase("  3232252004  -  3232252504  ", "192.168.64.100", "192.168.66.88")]
        [TestCase("192.168.1- 192.168.1111", "192.168.0.1", "192.168.4.87")] // 3 part IPv4
        [TestCase("173.1 -173.1111", "173.0.0.1", "173.0.4.87")] // 2 part IPv4

        // with "dash (–)" (0x2013) is also support.
        [TestCase("192.168.61.26–192.168.61.37", "192.168.61.26", "192.168.61.37")]
        [TestCase("  192.168.61.26  –  192.168.61.37  ", "192.168.61.26", "192.168.61.37")]
        [TestCase("fe80::c586–fe80::c600", "fe80::c586", "fe80::c600")]
        [TestCase("  fe80::c586  –  fe80::c600  ", "fe80::c586", "fe80::c600")]
        [TestCase("3232252004–3232252504", "192.168.64.100", "192.168.66.88")]
        [TestCase("  3232252004  –  3232252504  ", "192.168.64.100", "192.168.66.88")]
        [TestCase("192.168.1.1-7", "192.168.1.1", "192.168.1.7")]

        // IPv6 with scope id (scope id should be stripped in begin/end properties.)
        [TestCase("fe80::0%eth0/112", "fe80::", "fe80::ffff")]
        [TestCase("fe80::8000%12-fe80::80ff%12", "fe80::8000", "fe80::80ff")]
        [TestCase("fe80::1%lo1", "fe80::1", "fe80::1")]

        // IPv4 mapped to IPv6
        [TestCase("::ffff:10.0.0.0/120", "10.0.0.0", "10.0.0.255")]
        [TestCase("::ffff:192.168.10.20-::ffff:192.168.11.20", "192.168.10.20", "192.168.11.20")]
        [TestCase("::ffff:10.0.0.203", "10.0.0.203", "10.0.0.203")]
        [TestCase("::ffff:10.0.2.0/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", "10.0.2.0", "10.0.2.255")]
        public void ParseSucceeds(string input, string expectedBegin, string expectedEnd)
        {
            Console.WriteLine("TestCase: \"{0}\", Expected Begin: {1}, End: {2}", input, expectedBegin, expectedEnd);
            var range = IPAddressRange.Parse(input);
            range.IsNot(null);
            Console.WriteLine("  Result: Begin: {0}, End: {1}", range.Begin, range.End);
            range.Begin.ToString().Is(expectedBegin);
            range.End.ToString().Is(expectedEnd);
        }

        [Test]
        [TestCase(null, typeof(ArgumentNullException))]
        [TestCase("", typeof(ArgumentNullException))]
        [TestCase(" ", typeof(ArgumentNullException))]
        [TestCase("gvvdv", typeof(FormatException))]
        [TestCase("192.168.0.10/48", typeof(FormatException))] // out of CIDR range 
        [TestCase("192.168.0.10-192.168.0.5", typeof(ArgumentException))] // bigger to lower
        [TestCase("fe80::2%eth1-fe80::1%eth1", typeof(ArgumentException))] // bigger to lower
        [TestCase("10.256.1.1", typeof(FormatException))] // invalid ip
        [TestCase("127.0.0.1%1", typeof(FormatException))] // ipv4, but with scope id
        [TestCase("192.168.0.10/2.3.4", typeof(FormatException))] // ipv4, but subnet mask isn't linear 
        [TestCase("192.168.0.0-192.168.0.1%1", typeof(FormatException))] // ipv4, but with scope id at end of range
        [TestCase("192.168.0.0%1-192.168.0.1", typeof(FormatException))] // ipv4, but with scope id at begin of range
        [TestCase("192.168.0.0%1-192.168.0.1%1", typeof(FormatException))] // ipv4, but with scope id at both of begin and end
        [TestCase("192.168.0.0%1/24", typeof(FormatException))] // CIDR ipv4, but with scope id
        [TestCase("192.168.0.0%1/255.255.255.0", typeof(FormatException))] // ipv4 and subnet mask, but with scope id
        [TestCase("192.168-::1", typeof(FormatException))] // Invalid comibination of IPv4 and IPv6
        [TestCase("192.168.0.0-256", typeof(FormatException))] // shortcut notation, but out of range
        [TestCase("192.168.0.0-1%1", typeof(FormatException))] // ipv4 shortcut, but with scope id at end of range
        [TestCase("192.168.0.0%1-1", typeof(FormatException))] // ipv4 shortcut, but with scope id at begin of range
        [TestCase("172. 13.0.0/24", typeof(FormatException))] // ipv4, but include spaces
        [TestCase("fe80::0-fe80: :ffff", typeof(FormatException))] // ipv4, but include spaces
        public void ParseFails(string input, Type expectedException)
        {
            Console.WriteLine("TestCase: \"{0}\", Expected Exception: {1}", input, expectedException.Name);
            try
            {
                IPAddressRange.Parse(input);
                Assert.Fail("Expected exception of type {0} to be thrown for input \"{1}\"", expectedException.Name, input);
            }
            catch (AssertionException)
            {
                throw; // allow Assert.Fail to pass through 
            }
            catch (Exception ex)
            {
                ex.GetType().Is(expectedException);
            }
        }

        [Test]
        [TestCase(null, false)] // bug3
        [TestCase("", false)]
        [TestCase(" ", false)]
        [TestCase("fdfv", false)]
        [TestCase("192.168.0.10/48", false)] // CIDR out of range
        [TestCase("192.168.60.26-192.168.60.22", false)] // big to lower

        [TestCase("192.168.60.13", true)]
        [TestCase("fe80::d503:4ee:3882:c586", true)]
        [TestCase("fe80:db8::dead:beaf%eth2", true)]
        [TestCase("219.165.64.0/19", true)]
        [TestCase("219.165.64.73/32", true)]
        [TestCase("192.168.1.0/255.255.255.0", true)]
        [TestCase("192.168.60.26-192.168.60.37", true)]
        [TestCase("fe80:dead::beaf:a%eth2-fe80:dead::beaf:f%eth2", true)]
        [TestCase("fe80:dead::beaf:f%eth2-fe80:dead::beaf:a%eth2", false)]
        public void TryParse(string input, bool expectedReturn)
        {
            Console.WriteLine("TestCase: \"{0}\", Expected: {1}", input, expectedReturn);
            var result = IPAddressRange.TryParse(input, out IPAddressRange temp);
            result.Is(expectedReturn);
            if (expectedReturn)
            {
                temp.IsNot(null);
            }
            else
            {
                temp.Is(null);
            }
        }

        [Test]
        public void TestFilterIPAddressRanges()
        {
            IPAddressRange[] expected = new IPAddressRange[]
            {
                "1.1.1.1-1.1.1.3",
                "2.2.2.2",
                "3.3.3.1-3.3.3.3",
                "3.3.3.10-3.3.3.15",
                "6.6.6.6-6.6.6.12",
                "6.6.6.18-6.6.6.19",
                "6.6.6.31-6.6.6.98",
                "2620:0:2d0:2df::1-2620:0:2d0:2df::6",
                "2620:0:2d0:2df::78-2620:0:2d0:2df::79"
            };

            IPAddressRange[] filter = new IPAddressRange[]
            {
                "0.0.0.0-1.1.1.0",
                "1.1.1.4-2.2.2.1",
                "2.2.2.3-3.3.3.0",
                "3.3.3.4-3.3.3.9",
                "3.3.3.16-5.5.5.255",
                "6.6.6.13-6.6.6.17",
                "6.6.6.20-6.6.6.30",
                "6.6.6.99-255.255.255.255",
                "2620:0:2d0:2df::7-2620:0:2d0:2df::77"
            };

            IPAddressRange[] ranges = new IPAddressRange[]
            {
                "0.0.0.1-1.1.1.0", // filtered out
                "1.1.1.1-2.2.2.1", // filtered down
                "2.2.2.2-2.2.2.255", // filtered down
                "3.3.3.0-5.5.5.5", // filtered 2x
                "6.6.6.6-7.7.7.7", // filtered 3x
                "10.10.10.10-11.11.11.11", // filtered out
                "2620:0:2d0:2df::1-2620:0:2d0:2df::79" // filtered down
            };

            TestFilterIPAddressRangesHelper(expected, null, filter, ranges);
        }

        [Test]
        public void TestFilterIPAddressRangesNulls()
        {
            TestFilterIPAddressRangesHelper(System.Array.Empty<IPAddressRange>(), null, null, null);
            TestFilterIPAddressRangesHelper(System.Array.Empty<IPAddressRange>(), null, new IPAddressRange[] { "1.1.1.1-2.2.2.2" }, null);
            TestFilterIPAddressRangesHelper(new IPAddressRange[] { "1.1.1.1-2.2.2.2" }, null, null, new IPAddressRange[] { "1.1.1.1-2.2.2.2" });
        }

        [Test]
        public void TestFilterIPAddressRangeFilterNoIntersect()
        {
            TestFilterIPAddressRangesHelper
            (
                new IPAddressRange[] { "1.1.1.1-2.2.2.2" },
                null,
                new IPAddressRange[] { "0.0.0.0-1.1.1.0", "2.2.2.3-2.2.2.255" },
                new IPAddressRange[] { "1.1.1.1-2.2.2.2" }
            );
        }

        [Test]
        public void TestFilterAllIPV4()
        {
            TestFilterIPAddressRangesHelper
            (
                System.Array.Empty<IPAddressRange>(),
                null,
                new IPAddressRange[] { "0.0.0.0-255.255.255.255" },
                new IPAddressRange[] { "0.0.0.0-2.2.2.2", "5.5.5.5-6.6.6.6" }
            );
        }

        [Test]
        public void TestIPAddressIsLocalHost()
        {
            Assert.IsTrue(System.Net.IPAddress.Parse("127.0.0.1").IsLocalHost());
            Assert.IsTrue(System.Net.IPAddress.Parse("::1").IsLocalHost());
            Assert.IsFalse(System.Net.IPAddress.Parse("127.0.0.2").IsLocalHost());
            Assert.IsFalse(System.Net.IPAddress.Parse("::2").IsLocalHost());
            Assert.IsFalse(((System.Net.IPAddress)null).IsLocalHost());
        }

        [Test]
        public void TestTryCreateIPAddressRangeFromIPAddresses()
        {
            var ip1 = System.Net.IPAddress.Parse("1.1.1.1");
            var ip2 = System.Net.IPAddress.Parse("1.1.1.2");
            var ip3 = System.Net.IPAddress.Parse("1.1.1.3");
            var ip4 = System.Net.IPAddress.Parse("1.1.1.4");
            var ip5 = IPAddressRange.Parse("1.1.1.5-1.1.1.10");
            var ip6 = System.Net.IPAddress.Parse("255.255.255.254");
            var ip7 = System.Net.IPAddress.Parse("255.255.255.255");
            var ip8 = IPAddressRange.Parse("1.1.1.11-1.1.1.22");

            IPAddressRange range = IPAddressRange.TryCreateFromIPAddressRanges(ip1, ip2, ip3, ip4);
            Assert.AreEqual("1.1.1.1-1.1.1.4", range.ToString());
            range = IPAddressRange.TryCreateFromIPAddresses(ip1, ip2, ip3, ip4);
            Assert.AreEqual("1.1.1.1-1.1.1.4", range.ToString());

            range = IPAddressRange.TryCreateFromIPAddressRanges(ip1, ip2, ip3, ip4, ip5);
            Assert.AreEqual("1.1.1.1-1.1.1.10", range.ToString());

            range = IPAddressRange.TryCreateFromIPAddressRanges(ip4, ip7);
            Assert.IsNull(range);
            range = IPAddressRange.TryCreateFromIPAddresses(ip6, ip7);
            Assert.AreEqual("255.255.255.254/31", range.ToString());
            range = IPAddressRange.TryCreateFromIPAddressRanges(ip5, ip8);
            Assert.AreEqual("1.1.1.5-1.1.1.22", range.ToString());

            range = IPAddressRange.TryCreateFromIPAddressRanges(ip1, ip3);
            Assert.IsNull(range);
            range = IPAddressRange.TryCreateFromIPAddresses(ip1, ip3);
            Assert.IsNull(range);
        }

        [TestCase("10.10.10.10-10.10.10.20", "9.9.9.9-10.10.10.9", false, null, null)]
        [TestCase("9.9.9.9-10.10.10.9", "10.10.10.10-10.10.10.20", false, null, null)]
        [TestCase("10.10.10.10-10.10.10.20", "9.9.9.9-11.11.11.11", false, null, null)]
        [TestCase("10.10.10.10-10.10.10.20", "10.10.10.10-10.10.10.20", true, null, null)]
        [TestCase("10.10.10.10-10.10.10.20", "10.10.10.15-10.10.10.20", true, "10.10.10.10-10.10.10.14", null)]
        [TestCase("10.10.10.10-10.10.10.20", "10.10.10.10-10.10.10.15", true, null, "10.10.10.16-10.10.10.20")]
        [TestCase("10.10.10.10-10.10.10.20", "10.10.10.15-10.10.10.25", true, "10.10.10.10-10.10.10.14", null)]
        [TestCase("10.10.10.10-10.10.10.20", "10.10.10.5-10.10.10.15", true, null, "10.10.10.16-10.10.10.20")]
        [TestCase("10.10.10.10-10.10.10.20", "10.10.10.11-10.10.10.19", true, "10.10.10.10", "10.10.10.20")]
        [TestCase("10.10.10.10-10.10.10.20", "::1", false, null, null, typeof(InvalidOperationException))]
        [TestCase("::1", "10.10.10.10-10.10.10.20", false, null, null, typeof(InvalidOperationException))]
        [TestCase("10.10.10.10-10.10.10.20", null, false, null, null, typeof(ArgumentNullException))]
        [TestCase("125.0.0.1-128.0.0.0", "127.0.0.0-127.255.255.255", true, "125.0.0.1-126.255.255.255", "128.0.0.0")]
        [TestCase("5.5.5.5-6.6.6.6", "5.5.5.5-6.6.6.6", true, null, null)]

        public void TestChomp(string baseRange, string range, bool expectedResult, string expectedLeft, string expectedRight,
            Type expectedException = null)
        {
            bool result;
            IPAddressRange leftObj, rightObj;
            try
            {
                IPAddressRange baseRangeObj = IPAddressRange.Parse(baseRange);
                IPAddressRange rangeObj = IPAddressRange.Parse(range);
                result = baseRangeObj.Chomp(rangeObj, out leftObj, out rightObj);
            }
            catch (Exception ex)
            {
                Assert.AreEqual(ex.GetType(), expectedException);
                return;
            }
            if (expectedException is not null)
            {
                Assert.Fail("Failed to throw expected exception type {0}", expectedException.Name);
            }
            Assert.AreEqual(expectedResult, result);
            Assert.AreEqual(expectedLeft, leftObj?.ToString());
            Assert.AreEqual(expectedRight, rightObj?.ToString());
        }

        [TestCase("2.19.128.0/20", "2.19.144.0/20", "2.19.128.0-2.19.159.255")]
        [TestCase("2.19.144.0/20", "2.19.128.0/20", "2.19.128.0-2.19.159.255")]
        [TestCase("1.1.1.1-2.2.2.2", "3.3.3.3-4.4.4.4", null)]
        [TestCase("3.3.3.3-4.4.4.4", "1.1.1.1-2.2.2.2", null)]
        public void TestCombine(string baseRange, string otherRange, string expected)
        {
            var r1 = IPAddressRange.Parse(baseRange);
            var r2 = IPAddressRange.Parse(otherRange);
            r1.TryCombine(r2, out IPAddressRange combined);
            if (combined is null)
            {
                Assert.IsNull(expected);
            }
            else
            {
                string actual = combined.ToString('-');
                Assert.AreEqual(expected, actual);
            }
        }

        private static void TestFilterIPAddressRangesHelper(IPAddressRange[] expected, string message, IPAddressRange[] filter, params IPAddressRange[] ranges)
        {
            int index = 0;
            foreach (IPAddressRange range in IPBanFirewallUtility.FilterRanges(ranges, filter))
            {
                if (index >= expected.Length)
                {
                    Assert.Fail("Too many filtered results, expected max count of {0}", expected.Length - 1);
                }

                // nunit areequal is strange, it calls enumerators and other crap, why it doesn't just do .Equals is beyond me...
                IPAddressRange existing = expected[index++];
                IPAddressRange actual = range;
                Assert.That(existing.Equals(actual), message);
            }
        }
    }
}
