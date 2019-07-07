/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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

#region Imports

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

#endregion Imports

namespace DigitalRuby.IPBan
{
    public partial class IPBanService
    {
        protected enum UrlType
        {
            Start,
            Update,
            Stop,
            Config
        }

        private class IPAddressPendingEvent
        {
            public string IPAddress { get; set; }
            public string Source { get; set; }
            public string UserName { get; set; }
            public DateTime DateTime { get; set; }
            public int Count { get; set; }
        }
    }

    /// <summary>
    /// Allows updating periodically
    /// </summary>
    public interface IUpdater : IDisposable
    {
        /// <summary>
        /// Update
        /// </summary>
        Task Update();
    }

    /// <summary>
    /// IP address event types
    /// </summary>
    public enum IPAddressEventType
    {
        /// <summary>
        /// No event
        /// </summary>
        None = 0,

        /// <summary>
        /// Successful login
        /// </summary>
        SuccessfulLogin = 1,

        /// <summary>
        /// Blocked / banned ip address
        /// </summary>
        Blocked = 2,

        /// <summary>
        /// Unblocked ip address
        /// </summary>
        Unblocked = 3,

        /// <summary>
        /// Failed login
        /// </summary>
        FailedLogin = 4,
    }

    /// <summary>
    /// IP address event flags
    /// </summary>
    [Flags]
    public enum IPAddressEventFlags
    {
        /// <summary>
        /// No event
        /// </summary>
        None = 0,

        /// <summary>
        /// Successful login
        /// </summary>
        SuccessfulLogin = 1,

        /// <summary>
        /// Blocked / banned ip address
        /// </summary>
        BlockedIPAddress = 2,

        /// <summary>
        /// Unblocked ip address
        /// </summary>
        UnblockedIPAddress = 4,

        /// <summary>
        /// Failed login of matched user name
        /// </summary>
        FailedLogin = 8,
    }
}
