using System;
using System.Runtime.InteropServices;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// Test unmanaged memory
    /// </summary>
    [TestFixture]
    public class IPBanUnmanagedMemoryTests
    {
        [Test]
        public void TestFree()
        {
            UnmanagedMemory mem = new(4);
            VerifyNotDisposed(mem);
            mem.Dispose();
            VerifyDisposed(mem);
        }

        [Test]
        public void TestCustomFree()
        {
            bool customFreeCalled = false;
            UnmanagedMemory mem = new(new IntPtr(4), 4, ptr =>
            {
                customFreeCalled = true;
            });
            VerifyNotDisposed(mem);
            mem.Dispose();
            VerifyDisposed(mem);
            Assert.That(customFreeCalled, Is.True);
        }

        [Test]
        public void TestNotOwn()
        {
            IntPtr ptr = Marshal.AllocHGlobal(4);
            Marshal.StructureToPtr(5, ptr, false);
            {
                using UnmanagedMemory mem = new(ptr, 4);
                VerifyNotDisposed(mem);
            }
            int value = Marshal.PtrToStructure<int>(ptr);
            Assert.That(value, Is.EqualTo(5));
        }

        [Test]
        public void TestAddRef()
        {
            UnmanagedMemory mem = new(4);
            VerifyNotDisposed(mem);
            mem.AddRef();
            Assert.That(mem.RefCount, Is.EqualTo(2));
            mem.Dispose();
            VerifyNotDisposed(mem);
            Assert.That(mem.RefCount, Is.EqualTo(1));
            mem.Dispose();
            VerifyDisposed(mem);
        }

        private static void VerifyDisposed(UnmanagedMemory mem)
        {
            mem.AddRef();
            Assert.That(mem.Pointer, Is.EqualTo(IntPtr.Zero));
            Assert.That(mem.Size, Is.EqualTo(0));
            Assert.That(mem.RefCount, Is.EqualTo(0));
        }

        private static void VerifyNotDisposed(UnmanagedMemory mem)
        {
            Assert.That(mem.Pointer, Is.Not.EqualTo(IntPtr.Zero));
            Assert.That(mem.Size, Is.Not.EqualTo(0));
            Assert.That(mem.RefCount, Is.Not.EqualTo(0));
        }
    }
}
