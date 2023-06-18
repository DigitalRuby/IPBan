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

#region Imports

using System;
using System.Threading;
using System.Threading.Tasks;

#endregion Imports

namespace DigitalRuby.IPBanCore
{
    public partial class IPBanService
    {
        /// <summary>
        /// Url type
        /// </summary>
        protected enum UrlType
        {
            /// <summary>
            /// Start
            /// </summary>
            Start,

            /// <summary>
            /// Update
            /// </summary>
            Update,

            /// <summary>
            /// Stop
            /// </summary>
            Stop,

            /// <summary>
            /// Config
            /// </summary>
            Config
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
        /// <param name="cancelToken">Cancel token</param>
        Task Update(CancellationToken cancelToken = default) => throw new NotImplementedException();
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

        /// <summary>
        /// Notify whois for domains
        /// </summary>
        WhoIs = 16,

        /// <summary>
        /// Send daily report of all ip addresses
        /// </summary>
        DailyReport = 32,

        /// <summary>
        /// Send weekly report of all ip addresses
        /// </summary>
        WeeklyReport = 64,

        /// <summary>
        /// Send monthly report of all ip addresses
        /// </summary>
        MonthlyReport = 128,

        /// <summary>
        /// Successful login to web admin
        /// </summary>
        SuccessfulWebAdminLogin = 256,

        /// <summary>
        /// All flags
        /// </summary>
        All = SuccessfulLogin | BlockedIPAddress | UnblockedIPAddress | FailedLogin | WhoIs | DailyReport | WeeklyReport | MonthlyReport | SuccessfulWebAdminLogin
    }
}
