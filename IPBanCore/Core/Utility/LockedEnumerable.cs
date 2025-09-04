﻿/*
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

using System;
using System.Collections.Generic;
using System.Threading;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Allows locking a collection during enumeration
    /// </summary>
    /// <typeparam name="T">Type of object being enumerated</typeparam>
    public class LockedEnumerable<T> : IEnumerator<T>
    {
        private readonly SemaphoreSlim locker = new(1, 1);
        private readonly IEnumerator<T> e;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="obj">Enumerable</param>
        public LockedEnumerable(IEnumerable<T> obj)
        {
            obj.ThrowIfNull();
            locker.Wait();
            e = obj.GetEnumerator();
        }

        /// <inheritdoc />
        T IEnumerator<T>.Current => e.Current;

        /// <inheritdoc />
        public object Current => e.Current;

        /// <inheritdoc />
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            locker.Release();
        }

        /// <inheritdoc />
        public bool MoveNext()
        {
            return e.MoveNext();
        }

        /// <inheritdoc />
        public void Reset()
        {
            e.Reset();
        }
    }
}
