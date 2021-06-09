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

using Microsoft.Data.Sqlite;

using System;
using System.Collections.Generic;
using System.Net;

namespace DigitalRuby.IPBanCore
{
    public class IPBanDB : SqliteDB
    {
        /// <summary>
        /// State of ip addresses
        /// </summary>
        public enum IPAddressState
        {
            /// <summary>
            /// Active and in firewall
            /// </summary>
            Active = 0,

            /// <summary>
            /// Pending add to firewall
            /// </summary>
            AddPending = 1,

            /// <summary>
            /// Pending remove from firewall
            /// </summary>
            RemovePending = 2,

            /// <summary>
            /// Failed login only, no ban yet
            /// </summary>
            FailedLogin = 3,

            /// <summary>
            /// Remove from firewall is pending, but ip address should stay in database as a failed login
            /// This is used for tiered ban times where ip addresses can be banned for longer and longer times
            /// </summary>
            RemovePendingBecomeFailedLogin = 4
        }

        /// <summary>
        /// An ip address entry in the database
        /// </summary>
        public class IPAddressEntry
        {
            /// <summary>
            /// IP address
            /// </summary>
            public string IPAddress { get; set; }

            /// <summary>
            /// User name if known
            /// </summary>
            public string UserName { get; set; }

            /// <summary>
            /// Source if known
            /// </summary>
            public string Source { get; set; }

            /// <summary>
            /// Last failed login
            /// </summary>
            public DateTime LastFailedLogin { get; set; }

            /// <summary>
            /// Failed login count
            /// </summary>
            public int FailedLoginCount { get; set; }

            /// <summary>
            /// Ban start date, null if not banned
            /// </summary>
            public DateTime? BanStartDate { get; set; }

            /// <summary>
            /// Ban end date, null if not banned
            /// </summary>
            public DateTime? BanEndDate { get; set; }

            /// <summary>
            /// IP address state
            /// </summary>
            public IPAddressState State { get; set; }
        }

        /// <summary>
        /// IPBan database file name, not including directory
        /// </summary>
        public const string FileName = "ipban.sqlite";

        private static long GetInt64(object value)
        {
            try
            {
                return (value is null || value == DBNull.Value ? 0 : Convert.ToInt64(value));
            }
            catch
            {
                Logger.Info("Unable to convert value '{0}' to Int64, using default value of 0", value);
                return 0;
            }
        }

        private static IPAddressEntry ParseIPAddressEntry(SqliteDataReader reader)
        {
            string ipAddress = reader.GetString(0);
            long lastFailedLogin = reader.GetInt64(1);
            long failedLoginCount = reader.GetInt64(2);
            object banDateObj = reader.GetValue(3);
            IPAddressState state = (IPAddressState)(int)reader.GetInt32(4);
            object banEndDateObj = reader.GetValue(5);
            string userName = reader.GetString(6);
            string source = reader.GetString(7);
            long banDateLong = GetInt64(banDateObj);
            long banEndDateLong = GetInt64(banEndDateObj);
            DateTime? banDate = (banDateLong == 0 ? (DateTime?)null : banDateLong.ToDateTimeUnixMilliseconds());
            DateTime? banEndDate = (banDateLong == 0 ? (DateTime?)null : banEndDateLong.ToDateTimeUnixMilliseconds());
            DateTime lastFailedLoginDt = lastFailedLogin.ToDateTimeUnixMilliseconds();
            return new IPAddressEntry
            {
                IPAddress = ipAddress,
                LastFailedLogin = lastFailedLoginDt,
                FailedLoginCount = (int)failedLoginCount,
                BanStartDate = banDate,
                State = state,
                BanEndDate = banEndDate,
                UserName = userName,
                Source = source
            };
        }

        private int SetBanDateInternal(IPAddress ipAddressObj, DateTime banDate, DateTime banEndDate, DateTime now, SqliteConnection conn, SqliteTransaction tran)
        {
            if (ipAddressObj is null)
            {
                return 0;
            }

            string ipAddress = ipAddressObj.ToString();
            byte[] ipBytes = ipAddressObj.GetAddressBytes();
            long timestampBegin = banDate.ToUnixMillisecondsLong();
            long timestampEnd = banEndDate.ToUnixMillisecondsLong();
            long currentTimestamp = now.ToUnixMillisecondsLong();

            // if the ip address already exists, it can be updated provided that the state is not in a pending remove state (2) and
            // there is no ban end date yet or the ban end date has expired
            // state will stay at 0 if it was 0 else it will become 1 which means the ban is pending, state 0 means ban is already active in firewall
            int count = ExecuteNonQuery(@"INSERT INTO IPAddresses(IPAddress, IPAddressText, LastFailedLogin, FailedLoginCount, BanDate, State, BanEndDate, Source, UserName)
                VALUES(@Param0, @Param1, @Param2, 0, @Param2, 1, @Param3, '', '')
                ON CONFLICT(IPAddress)
                DO UPDATE SET BanDate = @Param2, State = CASE WHEN State = 0 THEN 0 ELSE 1 END, BanEndDate = @Param3 WHERE State <> 2 AND (BanEndDate IS NULL OR BanEndDate <= @Param4); ",
                conn, tran, ipBytes, ipAddress, timestampBegin, timestampEnd, currentTimestamp);
            return count;
        }

        protected override void OnInitialize()
        {
            base.OnInitialize();
            Logger.Info("Initializing IPBan database at {0}", ConnectionString);
            ExecuteNonQuery("PRAGMA auto_vacuum = INCREMENTAL;");
            ExecuteNonQuery("PRAGMA journal_mode = WAL;");
            ExecuteNonQuery("CREATE TABLE IF NOT EXISTS IPAddresses (IPAddress VARBINARY(16) NOT NULL, IPAddressText VARCHAR(64) NOT NULL, LastFailedLogin BIGINT NOT NULL, FailedLoginCount BIGINT NOT NULL, BanDate BIGINT NULL, PRIMARY KEY (IPAddress))");
            ExecuteNonQueryIgnoreExceptions("ALTER TABLE IPAddresses ADD COLUMN State INT NOT NULL DEFAULT 0");
            ExecuteNonQueryIgnoreExceptions("ALTER TABLE IPAddresses ADD COLUMN BanEndDate BIGINT NULL");
            ExecuteNonQueryIgnoreExceptions("ALTER TABLE IPAddresses ADD COLUMN UserName Text NOT NULL DEFAULT ''");
            ExecuteNonQueryIgnoreExceptions("ALTER TABLE IPAddresses ADD COLUMN Source Text NOT NULL DEFAULT ''");
            ExecuteNonQuery("CREATE INDEX IF NOT EXISTS IPAddresses_LastFailedLoginDate ON IPAddresses (LastFailedLogin)");
            ExecuteNonQuery("CREATE INDEX IF NOT EXISTS IPAddresses_BanDate ON IPAddresses (BanDate)");
            ExecuteNonQuery("CREATE INDEX IF NOT EXISTS IPAddresses_BanEndDate ON IPAddresses (BanEndDate)");
            ExecuteNonQuery("CREATE INDEX IF NOT EXISTS IPAddresses_State ON IPAddresses (State)");

            // set to failed login state if no ban date
            ExecuteNonQuery("UPDATE IPAddresses SET State = 3 WHERE State IN (0, 1) AND BanDate IS NULL");
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public IPBanDB(string dbPath = null) : base(dbPath ?? FileName) { }

        /// <summary>
        /// Delete all data from the database but keep the database file
        /// </summary>
        /// <param name="confirm">Pass true to actually truncate</param>
        public void Truncate(bool confirm)
        {
            if (confirm)
            {
                ExecuteNonQuery("DELETE FROM IPAddresses");
            }
        }

        /// <summary>
        /// Get the count of all ip addresses in the database
        /// </summary>
        /// <returns>IP address count</returns>
        public int GetIPAddressCount()
        {
            if (ExecuteScalar<int>("SELECT COUNT(*) FROM IPAddresses", out int count))
            {
                return count;
            }
            return 0;
        }

        /// <summary>
        /// Get the count of all banned ip addresses in the database
        /// </summary>
        /// <returns>Banned ip address count</returns>
        public int GetBannedIPAddressCount()
        {
            if (ExecuteScalar<int>("SELECT COUNT(*) FROM IPAddresses WHERE BanDate IS NOT NULL", out int count))
            {
                return count;
            }
            return 0;
        }

        /// <summary>
        /// Increment the failed login count for an ip address
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="userName">User name</param>
        /// <param name="source">Source</param>
        /// <param name="dateTime">DateTime to set for failed login</param>
        /// <param name="increment">Amount to increment</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>New failed login count</returns>
        public int IncrementFailedLoginCount(string ipAddress, string userName, string source, DateTime dateTime, int increment, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                ipAddressObj = ipAddressObj.Clean();
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                long timestamp = dateTime.ToUnixMillisecondsLong();
                SqliteDBTransaction tran = transaction as SqliteDBTransaction;

                // only increment failed login for new rows or for existing rows with state 3 (failed login only, no ban bending)
                string command = @"INSERT INTO IPAddresses(IPAddress, IPAddressText, LastFailedLogin, FailedLoginCount, BanDate, State, BanEndDate, UserName, Source)
                    VALUES (@Param0, @Param1, @Param2, @Param3, NULL, 3, NULL, @Param4, @Param5)
                    ON CONFLICT(IPAddress)
                    DO UPDATE SET LastFailedLogin = @Param2, FailedLoginCount = FailedLoginCount + @Param3 WHERE State = 3;
                    SELECT FailedLoginCount FROM IPAddresses WHERE IPAddress = @Param0;";
                if (ExecuteScalar<int>(command, tran?.DBConnection, tran?.DBTransaction, out int count, ipBytes, ipAddress, timestamp, increment,
                    (userName ?? string.Empty), (source ?? string.Empty)))
                {
                    return count;
                }
            }
            return 0;
        }

        /// <summary>
        /// Get ip address entry from the database
        /// </summary>
        /// <param name="ipAddress">IP address to lookup</param>
        /// <param name="entry">IP address entry or default if not found</param>
        /// <returns>True if ip address found, false if not</returns>
        public bool TryGetIPAddress(string ipAddress, out IPAddressEntry entry, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                ipAddressObj = ipAddressObj.Clean();
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                SqliteDBTransaction tran = transaction as SqliteDBTransaction;
                using SqliteDataReader reader = ExecuteReader("SELECT IPAddressText, LastFailedLogin, FailedLoginCount, BanDate," +
                    "State, BanEndDate, UserName, Source FROM IPAddresses WHERE IPAddress = @Param0",
                    tran?.DBConnection, tran?.DBTransaction, ipBytes);
                if (reader.Read())
                {
                    entry = ParseIPAddressEntry(reader);
                    return true;
                }
            }
            entry = null;
            return false;
        }

        /// <summary>
        /// Set ban date for an ip address. If the ip address exists, the ban date will be set only if the existing ban date is expired.
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="banStartDate">Ban start date</param>
        /// <param name="banEndDate">Ban end date</param>
        /// <param name="now">Current date/time</param>
        /// <param name="state">State</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>True if ban date set, false if it was already set or ip address is not in the database</returns>
        public bool SetBanDates(string ipAddress, DateTime banStartDate, DateTime banEndDate, DateTime now, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                ipAddressObj = ipAddressObj.Clean();
                SqliteDBTransaction tran = transaction as SqliteDBTransaction;
                int count = SetBanDateInternal(ipAddressObj, banStartDate, banEndDate, now, tran?.DBConnection, tran?.DBTransaction);
                return (count != 0);
            }
            return false;
        }

        /// <summary>
        /// Get the ban date and ban end date for an ip address
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="banDates">Ban dates, default if not found</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>Ban date. Key and/or value will ber null if not banned or not in the database</returns>
        public bool TryGetBanDates(string ipAddress, out KeyValuePair<DateTime?, DateTime?> banDates, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                ipAddressObj = ipAddressObj.Clean();
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                SqliteDBTransaction tran = transaction as SqliteDBTransaction;
                using SqliteDataReader reader = ExecuteReader("SELECT BanDate, BanEndDate FROM IPAddresses WHERE IPAddress = @Param0", tran?.DBConnection, tran?.DBTransaction, ipBytes);
                if (reader.Read())
                {
                    DateTime? banDate = null;
                    DateTime? banEndDate = null;
                    object val = reader.GetValue(0);
                    object val2 = reader.GetValue(1);
                    if (val != null && val != DBNull.Value)
                    {
                        banDate = ((long)val).ToDateTimeUnixMilliseconds();
                    }
                    if (val2 != null && val2 != DBNull.Value)
                    {
                        banEndDate = ((long)val2).ToDateTimeUnixMilliseconds();
                    }
                    banDates = new KeyValuePair<DateTime?, DateTime?>(banDate, banEndDate);
                    return true;
                }
            }
            banDates = new KeyValuePair<DateTime?, DateTime?>(null, null);
            return false;
        }

        /// <summary>
        /// Set banned ip addresses. If the ip address is not in the database, it will be added,
        /// otherwise it will be updated with the ban date if the existing ban date is expired.
        /// </summary>
        /// <param name="ipAddresses">IP addresses, ban date and ban end dates to set as banned</param>
        /// <param name="now">Current date/time</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>Count of newly banned ip addresses</returns>
        public int SetBannedIPAddresses(IEnumerable<Tuple<string, DateTime, DateTime>> ipAddresses, DateTime now, object transaction = null)
        {
            int count = 0;
            SqliteDBTransaction tran = transaction as SqliteDBTransaction;
            bool commit = (tran is null);
            tran ??= BeginTransaction() as SqliteDBTransaction;
            try
            {
                foreach (Tuple<string, DateTime, DateTime> ipAddress in ipAddresses)
                {
                    if (IPAddress.TryParse(ipAddress.Item1, out IPAddress ipAddressObj))
                    {
                        ipAddressObj = ipAddressObj.Clean();
                        count += SetBanDateInternal(ipAddressObj, ipAddress.Item2, ipAddress.Item3, now, tran.DBConnection, tran.DBTransaction);
                    }
                }
            }
            catch
            {
                if (commit)
                {
                    commit = false;
                    RollbackTransaction(tran);
                }
                throw;
            }
            finally
            {
                if (commit)
                {
                    CommitTransaction(tran);
                }
            }
            return count;
        }

        /// <summary>
        /// Get an ip address state
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="state">Receives ip address state or default if not found</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>True if ip address found, false otherwise</returns>
        public bool TryGetIPAddressState(string ipAddress, out IPAddressState? state, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                ipAddressObj = ipAddressObj.Clean();
                SqliteDBTransaction tran = transaction as SqliteDBTransaction;
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                if (ExecuteScalar<int>("SELECT State FROM IPAddresses WHERE IPAddress = @Param0",
                    tran?.DBConnection, tran?.DBTransaction, out int stateInt, ipBytes))
                {
                    state = (IPAddressState)stateInt;
                    return true;
                }
            }
            state = null;
            return false;
        }

        /// <summary>
        /// Set state of ip addresses
        /// </summary>
        /// <param name="ipAddresses">IP addresses to set state for. Pass null to set the entire database.</param>
        /// <param name="state">State to set</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>Number of rows affected</returns>
        public int SetIPAddressesState(IEnumerable<string> ipAddresses, IPAddressState state, object transaction = null)
        {
            if (ipAddresses is null)
            {
                return 0;
            }

            int count = 0;
            int stateInt = (int)state;
            SqliteDBTransaction tran = transaction as SqliteDBTransaction;
            bool commit = (transaction is null);
            tran ??= BeginTransaction() as SqliteDBTransaction;
            try
            {
                foreach (string ipAddress in ipAddresses)
                {
                    if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                    {
                        ipAddressObj = ipAddressObj.Clean();
                        byte[] ipBytes = ipAddressObj.GetAddressBytes();
                        count += ExecuteNonQuery("UPDATE IPAddresses SET State = @Param0 WHERE IPAddress = @Param1", tran.DBConnection, tran.DBTransaction, stateInt, ipBytes);
                    }
                }
            }
            catch
            {
                if (commit)
                {
                    commit = false;
                    RollbackTransaction(tran);
                }
                throw;
            }
            finally
            {
                if (commit)
                {
                    CommitTransaction(tran);
                }
            }
            return count;
        }

        /// <summary>
        /// Enumerate any pending add or remove operations. When enumeration is complete, any returned ip addresses are either deleted (remove state), set to active (add state)
        /// or set to failed login state (ban expired set as failed login).
        /// </summary>
        /// <param name="commit">Whether to commit changes (alter states and delete pending removals) when enumeration is complete</param>
        /// <param name="now">Current date/time</param>
        /// <param name="resetFailedLoginCount">Whether to reset failed login count to 0 for un-banned ip addresses</param>
        /// <param name="transaction">Transaction</param>
        /// <returns></returns>
        public IEnumerable<IPBanFirewallIPAddressDelta> EnumerateIPAddressesDeltaAndUpdateState(bool commit, DateTime now, bool resetFailedLoginCount = true, object transaction = null)
        {
            string ipAddress;
            bool added;
            SqliteDBTransaction tran = transaction as SqliteDBTransaction;
            bool dispose = (tran is null);
            tran ??= BeginTransaction() as SqliteDBTransaction;
            SqliteDataReader reader;

            // C# can't yield inside a try/catch, so we have to split it up
            try
            {
                // select ip in add pending, remove pending, or remove pending become failed login state
                reader = ExecuteReader("SELECT IPAddressText, State FROM IPAddresses WHERE State IN (1, 2, 4) ORDER BY IPAddressText", tran.DBConnection, tran.DBTransaction);
            }
            catch
            {
                RollbackTransaction(tran);
                throw;
            }

            while (true)
            {
                try
                {
                    if (!reader.Read())
                    {
                        break;
                    }
                    ipAddress = reader.GetString(0);
                    added = (reader.GetInt32(1) == (int)IPAddressState.AddPending);
                }
                catch
                {
                    RollbackTransaction(tran);
                    throw;
                }

                // if add pending, this is an add, otherwise it is a remove
                yield return new IPBanFirewallIPAddressDelta { IPAddress = ipAddress, Added = added };
            }

            try
            {
                if (commit)
                {
                    // add pending (1) becomes active (0)
                    // remove pending no delete (4) becomes failed login (3)
                    // remove pending (2) is deleted entirely
                    // last failed login is set to current date/time if state goes from 4 to 3
                    long timestamp = now.ToUnixMillisecondsLong();
                    ExecuteNonQuery(@"UPDATE IPAddresses SET FailedLoginCount = CASE WHEN @Param0 = 1 THEN 0 ELSE FailedLoginCount END,
                        LastFailedLogin = CASE WHEN State = 4 THEN @Param1 ELSE LastFailedLogin END,
                        State = CASE WHEN State = 1 THEN 0 WHEN State = 4 THEN 3 ELSE State END WHERE State IN (1, 4);
                        DELETE FROM IPAddresses WHERE State = 2;", tran.DBConnection, tran.DBTransaction, resetFailedLoginCount, timestamp);
                }
            }
            catch
            {
                if (commit)
                {
                    commit = dispose = false;
                    RollbackTransaction(tran);
                }
                throw;
            }
            finally
            {
                if (commit)
                {
                    CommitTransaction(tran);
                }
                else if (dispose)
                {
                    RollbackTransaction(tran);
                }
            }
        }

        /// <summary>
        /// Delete an ip address from the database
        /// </summary>
        /// <param name="ipAddress">IP address to delete</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>True if deleted, false if not exists</returns>
        public bool DeleteIPAddress(string ipAddress, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                ipAddressObj = ipAddressObj.Clean();
                SqliteDBTransaction ipDBTransaction = transaction as SqliteDBTransaction;
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                return (ExecuteNonQuery("DELETE FROM IPAddresses WHERE IPAddress = @Param0", ipDBTransaction?.DBConnection, ipDBTransaction?.DBTransaction, ipBytes) != 0);
            }
            return false;
        }

        /// <summary>
        /// Get all ip addresses
        /// </summary>
        /// <param name="failLoginCutOff">Fail login cut off, only return entries with last failed login before this timestamp, null to not query this</param>
        /// <param name="banCutOff">Ban cut off date, only return entries with ban end date less than or equal to this, null to not query this</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>IP addresses that match the query</returns>
        public IEnumerable<IPAddressEntry> EnumerateIPAddresses(DateTime? failLoginCutOff = null, DateTime? banCutOff = null, object transaction = null)
        {
            long? failLoginCutOffUnix = null;
            long? banCutOffUnix = null;
            if (failLoginCutOff != null)
            {
                failLoginCutOffUnix = failLoginCutOff.Value.ToUnixMillisecondsLong();
            }
            if (banCutOff != null)
            {
                banCutOffUnix = banCutOff.Value.ToUnixMillisecondsLong();
            }
            SqliteDBTransaction tran = transaction as SqliteDBTransaction;
            using SqliteDataReader reader = ExecuteReader(@"SELECT IPAddressText, LastFailedLogin, FailedLoginCount, BanDate, State, BanEndDate, UserName, Source
                FROM IPAddresses
                WHERE (@Param0 IS NULL AND @Param1 IS NULL) OR (@Param0 IS NOT NULL AND State = 3 AND LastFailedLogin <= @Param0) OR (@Param1 IS NOT NULL AND State IN (0, 1) AND BanEndDate <= @Param1)
                ORDER BY IPAddress",
                tran?.DBConnection, tran?.DBTransaction, failLoginCutOffUnix, banCutOffUnix);
            while (reader.Read())
            {
                yield return ParseIPAddressEntry(reader);
            }
        }

        /// <summary>
        /// Get all banned ip addresses
        /// </summary>
        /// <returns>IP addresses with non-null ban dates</returns>
        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            using SqliteDataReader reader = ExecuteReader("SELECT IPAddressText FROM IPAddresses WHERE BanDate IS NOT NULL AND State = 0 ORDER BY IPAddress", null, null);
            while (reader.Read())
            {
                yield return reader.GetString(0);// ParseIPAddressEntry(reader);
            }
        }

        /// <summary>
        /// Delete ip addresses from the database
        /// </summary>
        /// <param name="ipAddresses">IP addresses to delete</param>
        /// <returns>Number of deleted ip addresses</returns>
        public int DeleteIPAddresses(IEnumerable<string> ipAddresses)
        {
            int count = 0;

            SqliteConnection conn = CreateConnection();
            try
            {
                OpenConnection(conn);
                using SqliteTransaction tran = conn.BeginTransaction(TransactionLevel);
                foreach (string ipAddress in ipAddresses)
                {
                    if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                    {
                        ipAddressObj = ipAddressObj.Clean();
                        count += ExecuteNonQuery("DELETE FROM IPAddresses WHERE IPAddress = @Param0", conn, tran, ipAddressObj.GetAddressBytes());
                    }
                }
                tran.Commit();
            }
            finally
            {
                CloseConnection(conn);
            }
            return count;
        }

        /// <summary>
        /// Delete all ip addresses in the specified range
        /// </summary>
        /// <param name="range">Range</param>
        /// <returns>List of deleted ip</returns>
        public IEnumerable<string> DeleteIPAddresses(IPAddressRange range)
        {
            byte[] start = range.Begin.GetAddressBytes();
            byte[] end = range.End.GetAddressBytes();
            using SqliteDataReader reader = ExecuteReader("SELECT IPAddressText FROM IPAddresses WHERE IPAddress BETWEEN @Param0 AND @Param1 AND length(IPAddress) = length(@Param0) AND length(IPAddress) = length(@Param1); " +
                "DELETE FROM IPAddresses WHERE IPAddress BETWEEN @Param0 AND @Param1 AND length(IPAddress) = length(@Param0) AND length(IPAddress) = length(@Param1);", null, null, start, end);
            while (reader.Read())
            {
                yield return reader.GetString(0);
            }
        }

        /// <summary>
        /// Delete ip addresses that are pending deletion from the database
        /// </summary>
        /// <returns>Number of rows modified</returns>
        public int DeletePendingRemoveIPAddresses()
        {
            return ExecuteNonQuery("DELETE FROM IPAddresses WHERE State = 2");
        }
    }
}
