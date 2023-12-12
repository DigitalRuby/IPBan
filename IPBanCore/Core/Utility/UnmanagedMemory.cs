using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Unmanaged memory management with dispose pattern
    /// </summary>
    public sealed class UnmanagedMemory : IDisposable
    {
        private static readonly Action<IntPtr> noFree = ptr => { };
        private static readonly Action<IntPtr> freeHGlobal = ptr => { Marshal.FreeHGlobal(ptr); };

        private Action<IntPtr> free;
        private int refCount = 1;

        /// <summary>
        /// Refcount. Call Dispose to decrement. Will be 0 if freed.
        /// </summary>
        public int RefCount => refCount;

        /// <summary>
        /// Pointer to unmanaged memory. Will be IntPtr.Zero if freed.
        /// </summary>
        public IntPtr Pointer { get; private set; }

        /// <summary>
        /// Size of unmanaged memory. Will be 0 if freed.
        /// </summary>
        public int Size { get; private set; }
                
        /// <summary>
        /// Constructor. Allocates unmanaged memory with Marshal.AllocHGlobal.
        /// </summary>
        /// <param name="size"></param>
        public UnmanagedMemory(int size)
        {
            Pointer = Marshal.AllocHGlobal(size);
            Size = size;
            free = freeHGlobal;
        }

        /// <summary>
        /// Unmanaged memory to a pointer that is freed somewhere else
        /// </summary>
        /// <param name="pointer">Pointer</param>
        /// <param name="size">Size</param>
        public UnmanagedMemory(IntPtr pointer, int size)
        {
            Pointer = pointer;
            Size = size;
            free = noFree;
        }

        /// <summary>
        /// Constructor. Takes a pointer of existing unmanaged memory and size.
        /// </summary>
        /// <param name="pointer">Pointer</param>
        /// <param name="size">Size</param>
        /// <param name="free">Action to free the pointer</param>
        public UnmanagedMemory(IntPtr pointer, int size, Action<IntPtr> free)
        {
            Pointer = pointer;
            Size = size;
            this.free = free;
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~UnmanagedMemory()
        {
            InternalDispose();
        }

        /// <inheritdoc />
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            InternalDispose();
        }

        /// <summary>
        /// Acquire a reference. Call dispose to decrement the ref count. If ref count hits zero, the unmanaged memory is freed.
        /// </summary>
        /// <returns>This</returns>
        public UnmanagedMemory AddRef()
        {
            if (Pointer != IntPtr.Zero)
            {
                Interlocked.Increment(ref refCount);
            }
            return this;
        }

        private void InternalDispose()
        {
            if (Interlocked.Decrement(ref refCount) == 0)
            {
                free.Invoke(Pointer);
                free = null;
                Pointer = IntPtr.Zero;
                Size = 0;
            }
        }
    }
}
