using System;
using System.Buffers;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Rented bytes
    /// </summary>
    public sealed class RentedBytes : IDisposable
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="length">Length</param>
        public RentedBytes(byte[] bytes, int length)
        {
            Bytes = bytes;
            Length = length;
        }

        /// <summary>
        /// Return bytes
        /// </summary>
        public void Dispose()
        {
            if (Bytes is not null)
            {
                ArrayPool<byte>.Shared.Return(Bytes);
                Bytes = null;
            }
        }

        /// <summary>
        /// Index into operator
        /// </summary>
        /// <param name="index">Index</param>
        /// <returns>Value</returns>
        public byte this[int index]
        {
            get => Bytes[index];
            set => Bytes[index] = value;
        }

        /// <summary>
        /// Get span
        /// </summary>
        /// <returns>Span</returns>
        public ReadOnlySpan<byte> AsSpan()
        {
            return Bytes.AsSpan(0, Length);
        }

        /// <summary>
        /// Get span
        /// </summary>
        /// <param name="index">Index</param>
        /// <param name="count">Count</param>
        /// <returns>Span</returns>
        public ReadOnlySpan<byte> AsSpan(int index, int count)
        {
            return Bytes.AsSpan(index, count);
        }

        /// <summary>
        /// Convert to span
        /// </summary>
        /// <param name="bytes">Bytes</param>
        public static implicit operator ReadOnlySpan<byte>(RentedBytes bytes) => bytes.Bytes.AsSpan(0, bytes.Length);

        /// <summary>
        /// Convert to byte array
        /// </summary>
        /// <param name="bytes">Bytes</param>
        public static implicit operator byte[](RentedBytes bytes) => bytes.Bytes;

        /// <summary>
        /// Bytes
        /// </summary>
        public byte[] Bytes { get; private set; }

        /// <summary>
        /// The length of data that should be used in Bytes - may be smaller than Bytes.Length
        /// </summary>
        public int Length { get; }
    }

    /// <summary>
    /// Rent/return bytes automatically
    /// </summary>
    public static class BytePool
    {
        /// <summary>
        /// Rent a byte buffer - ensure this is disposed or you will leak memory, i.e. using var bytes = BytePool.Rent(...);
        /// This is meant for very short term use, i.e. the scope of a function call.
        /// </summary>
        /// <param name="length">Number of bytes needed</param>
        /// <returns>Rented bytes, may be larger than length, be careful with using Length property</returns>
        public static RentedBytes Rent(int length)
        {
            return new RentedBytes(ArrayPool<byte>.Shared.Rent(length), length);
        }
    }
}
