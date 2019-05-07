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

using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Net;
using System.Text;

namespace DigitalRuby.IPBan
{
    public class IPBanDB : IDisposable
    {
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
            /// Last failed login
            /// </summary>
            public DateTime LastFailedLogin { get; set; }

            /// <summary>
            /// Failed login count
            /// </summary>
            public int FailedLoginCount { get; set; }

            /// <summary>
            /// Ban date, null if not yet banned
            /// </summary>
            public DateTime? BanDate { get; set; }
        }

        private class IPBanDBTransaction : IDisposable
        {
            public IPBanDBTransaction(string connString)
            {
                DBConnection = new SQLiteConnection(connString);
                DBConnection.Open();
                DBTransaction = DBConnection.BeginTransaction(System.Data.IsolationLevel.ReadCommitted);
            }

            public void Dispose()
            {
                if (DBTransaction != null)
                {
                    DBTransaction.Commit();
                    DBTransaction.Dispose();
                    DBTransaction = null;
                }
                if (DBConnection != null)
                {
                    DBConnection.Dispose();
                    DBConnection = null;
                }
            }

            public void Rollback()
            {
                if (DBTransaction != null)
                {
                    DBTransaction.Rollback();
                    DBTransaction = null;
                }
                Dispose();
            }

            public SQLiteConnection DBConnection { get; private set; }
            public SQLiteTransaction DBTransaction { get; private set; }
        }

        /// <summary>
        /// IPBan database file name, not including directory
        /// </summary>
        public const string FileName = "ipban.sqlite";

        // note that an ip that has a block count may not yet be in the ipAddressesAndBanDate dictionary
        // for locking, always use ipAddressesAndBanDate
        private readonly string dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, FileName);
        private readonly string connString;

        private int ExecuteNonQuery(string cmdText, params object[] param)
        {
            return ExecuteNonQuery(null, null, cmdText, param);
        }

        private int ExecuteNonQuery(SQLiteConnection conn, SQLiteTransaction tran, string cmdText, params object[] param)
        {
            bool closeConn = false;
            if (conn == null)
            {
                conn = new SQLiteConnection(connString);
                conn.Open();
                closeConn = true;
            }
            try
            {
                using (SQLiteCommand command = conn.CreateCommand())
                {
                    command.CommandText = cmdText;
                    command.Transaction = tran;
                    for (int i = 0; i < param.Length; i++)
                    {
                        command.Parameters.Add(new SQLiteParameter("@Param" + i, param[i]));
                    }
                    return command.ExecuteNonQuery();
                }
            }
            finally
            {
                if (closeConn)
                {
                    conn.Close();
                }
            }
        }

        private T ExecuteScalar<T>(string cmdText, params object[] param)
        {
            using (SQLiteConnection connection = new SQLiteConnection(connString))
            {
                connection.Open();
                using (SQLiteCommand command = connection.CreateCommand())
                {
                    command.CommandText = cmdText;
                    for (int i = 0; i < param.Length; i++)
                    {
                        command.Parameters.Add(new SQLiteParameter("@Param" + i, param[i]));
                    }
                    return (T)Convert.ChangeType(command.ExecuteScalar(), typeof(T));
                }
            }
        }

        private SQLiteDataReader ExecuteReader(string query, SQLiteConnection conn, params object[] param)
        {
            bool closeConnection = false;
            if (conn == null)
            {
                conn = new SQLiteConnection(connString);
                conn.Open();
                closeConnection = true;
            }
            SQLiteCommand command = conn.CreateCommand();
            command.CommandText = query;
            for (int i = 0; i < param.Length; i++)
            {
                command.Parameters.Add(new SQLiteParameter("@Param" + i.ToStringInvariant(), param[i]));
            }
            return command.ExecuteReader((closeConnection ? System.Data.CommandBehavior.CloseConnection : System.Data.CommandBehavior.Default));
        }

        private IPAddressEntry ParseIPAddressEntry(SQLiteDataReader reader)
        {
            string ipAddress = reader.GetString(0);
            long lastFailedLogin = reader.GetInt64(1);
            long failedLoginCount = reader.GetInt64(2);
            object banDateObj = reader.GetValue(3);
            long banDateLong = (banDateObj == null || banDateObj == DBNull.Value ? 0 : Convert.ToInt64(banDateObj));
            DateTime? banDate = (banDateLong == 0 ? (DateTime?)null : IPBanExtensionMethods.UnixTimeStampToDateTimeMilliseconds(banDateLong));
            DateTime lastFailedLoginDt = IPBanExtensionMethods.UnixTimeStampToDateTimeMilliseconds(lastFailedLogin);
            return new IPAddressEntry
            {
                IPAddress = ipAddress,
                LastFailedLogin = lastFailedLoginDt,
                FailedLoginCount = (int)failedLoginCount,
                BanDate = banDate
            };
        }

        private int SetBanDateInternal(string ipAddress, DateTime banDate, SQLiteConnection conn, SQLiteTransaction tran)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                long timestamp = (long)banDate.UnixTimestampFromDateTimeMilliseconds();
                int count = ExecuteNonQuery(conn, tran, @"INSERT INTO IPAddresses(IPAddress, IPAddressText, LastFailedLogin, FailedLoginCount, BanDate)
                    VALUES(@Param0, @Param1, @Param2, 0, @Param2)
                    ON CONFLICT(IPAddress)
                    DO UPDATE SET BanDate = @Param2 WHERE BanDate IS NULL; ", ipBytes, ipAddress, timestamp);
                return count;
            }
            return 0;
        }

        private void Initialize()
        {
            if (!File.Exists(dbPath))
            {
                SQLiteConnection.CreateFile(dbPath);
            }
            ExecuteNonQuery("PRAGMA auto_vacuum = INCREMENTAL;");
            ExecuteNonQuery("PRAGMA journal_mode = WAL;");
            ExecuteNonQuery("CREATE TABLE IF NOT EXISTS IPAddresses (IPAddress VARBINARY(16) NOT NULL, IPAddressText VARCHAR(64), LastFailedLogin BIGINT NOT NULL, FailedLoginCount BIGINT NOT NULL, BanDate BIGINT, PRIMARY KEY (IPAddress))");
            ExecuteNonQuery("CREATE INDEX IF NOT EXISTS IPAddresses_LastFailedLoginDate ON IPAddresses (LastFailedLogin)");
            ExecuteNonQuery("CREATE INDEX IF NOT EXISTS IPAddresses_BanDate ON IPAddresses (BanDate)");
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public IPBanDB()
        {
            connString = "Data Source=" + dbPath + ";Version=3;";
            Initialize();
        }

        /// <summary>
        /// Dispose of all resources, does not delete the database file
        /// </summary>
        public void Dispose()
        {
            SQLiteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        /// <summary>
        /// Begin a transaction
        /// </summary>
        /// <returns>Transaction</returns>
        public object BeginTransaction()
        {
            return new IPBanDBTransaction(connString);
        }

        /// <summary>
        /// Commit a transaction
        /// </summary>
        /// <param name="transaction">Transaction</param>
        public void CommitTransaction(object transaction)
        {
            if (transaction is IPBanDBTransaction tran)
            {
                tran.Dispose();
            }
        }

        /// <summary>
        /// Rollback a transaction. If the transaction is already commited, nothing happens.
        /// </summary>
        /// <param name="transaction">Transaction to rollback</param>
        public void RollbackTransaction(object transaction)
        {
            if (transaction is IPBanDBTransaction tran && tran.DBConnection != null)
            {
                tran.Rollback();
            }
        }

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
            return ExecuteScalar<int>("SELECT COUNT(*) FROM IPAddresses");
        }

        /// <summary>
        /// Get the count of all banned ip addresses in the database
        /// </summary>
        /// <returns>Banned ip address count</returns>
        public int GetBannedIPAddressCount()
        {
            return ExecuteScalar<int>("SELECT COUNT(*) FROM IPAddresses WHERE BanDate IS NOT NULL");
        }

        /// <summary>
        /// Increment the failed login count for an ip address
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="dateTime">DateTime to set for failed login</param>
        /// <param name="increment">Amount to increment</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>New failed login count</returns>
        public int IncrementFailedLoginCount(string ipAddress, DateTime dateTime, int increment, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                long timestamp = (long)dateTime.UnixTimestampFromDateTimeMilliseconds();
                string command = @"INSERT INTO IPAddresses(IPAddress, IPAddressText, LastFailedLogin, FailedLoginCount, BanDate)
                    VALUES (@Param0, @Param1, @Param2, @Param3, NULL)
                    ON CONFLICT(IPAddress)
                    DO UPDATE SET LastFailedLogin = @Param2, FailedLoginCount = FailedLoginCount + @Param3;
                    SELECT FailedLoginCount FROM IPAddresses WHERE IPAddress = @Param0;";
                IPBanDBTransaction tran = transaction as IPBanDBTransaction;
                if (tran == null)
                {
                    command = "BEGIN TRANSACTION; " + command + " COMMIT;";
                }
                using (SQLiteDataReader reader = ExecuteReader(command, tran?.DBConnection, ipBytes, ipAddress, timestamp, increment))
                {
                    if (reader.Read())
                    {
                        return (int)reader.GetInt64(0);
                    }
                }
            }
            return 0;
        }

        /// <summary>
        /// Get ip address info from the database
        /// </summary>
        /// <param name="ipAddress">IP address to lookup</param>
        /// <returns>IP address info or null if not found</returns>
        public IPAddressEntry GetIPAddress(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                using (SQLiteDataReader reader = ExecuteReader("SELECT IPAddressText, LastFailedLogin, FailedLoginCount, BanDate FROM IPAddresses WHERE IPAddress = @Param0", null, ipBytes))
                {
                    if (reader.Read())
                    {
                        return ParseIPAddressEntry(reader);
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Set ban date for an ip address. If the ip address exists, the ban date will be set only if the existing ban date is null.
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="banDate">Ban date</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>True if ban date set, false if it was already set or ip address is not in the database</returns>
        public bool SetBanDate(string ipAddress, DateTime banDate, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                long timestamp = (long)banDate.UnixTimestampFromDateTimeMilliseconds();
                int count;
                if (transaction is IPBanDBTransaction tran)
                {
                    count = SetBanDateInternal(ipAddress, banDate, tran.DBConnection, tran.DBTransaction);
                }
                else
                {
                    count = SetBanDateInternal(ipAddress, banDate, null, null);
                }
                return (count != 0);
            }
            return false;
        }

        /// <summary>
        /// Get the ban date for an ip address
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="transaction">Transaction</param>
        /// <returns>Ban date or null if not banned or not in the database</returns>
        public DateTime? GetBanDate(string ipAddress, object transaction = null)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                IPBanDBTransaction tran = transaction as IPBanDBTransaction;
                using (SQLiteDataReader reader = ExecuteReader("SELECT BanDate FROM IPAddresses WHERE IPAddress = @Param0", tran?.DBConnection, ipBytes))
                {
                    if (reader.Read())
                    {
                        object val = reader.GetValue(0);
                        if (val != null && val != DBNull.Value)
                        {
                            return IPBanExtensionMethods.UnixTimeStampToDateTimeMilliseconds((long)val);
                        }
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Set banned ip addresses. If the ip address is not in the database, it will be added,
        /// otherwise it will be updated with the ban date if the existing ban date is null.
        /// </summary>
        /// <param name="ipAddresses">IP addresses and ban dates to set as banned</param>
        /// <returns>Count of newly banned ip addresses</returns>
        public int SetBannedIPAddresses(IEnumerable<KeyValuePair<string, DateTime>> ipAddresses)
        {
            int count = 0;
            using (SQLiteConnection conn = new SQLiteConnection(connString))
            {
                conn.Open();
                using (SQLiteTransaction tran = conn.BeginTransaction(System.Data.IsolationLevel.ReadCommitted))
                {
                    foreach (KeyValuePair<string, DateTime> ipAddress in ipAddresses)
                    {
                        count += SetBanDateInternal(ipAddress.Key, ipAddress.Value, conn, tran);
                    }
                    tran.Commit();
                }
            }
            return count;
        }

        /// <summary>
        /// Delete on ip address from the database
        /// </summary>
        /// <param name="ipAddress">IP address to delete</param>
        /// <returns>True if deleted, false if not exists</returns>
        public bool DeleteIPAddress(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                return (ExecuteNonQuery("DELETE FROM IPAddresses WHERE IPAddress = @Param0", ipBytes) != 0);
            }
            return false;
        }

        /// <summary>
        /// Get all ip addresses
        /// </summary>
        /// <param name="cutOff">Fail login cut off, only return entries with last failed login before this timestamp, null to not query this</param>
        /// <param name="banCutOff">Ban cut off, only return entries with a ban before this timestamp, null to not query this</param>
        /// <returns>IP addresses that match the query</returns>
        public IEnumerable<IPAddressEntry> EnumerateIPAddresses(DateTime? failLoginCutOff = null, DateTime? banCutOff = null)
        {
            long? failLoginCutOffUnix = null;
            long? banCutOffUnix = null;
            if (failLoginCutOff != null)
            {
                failLoginCutOffUnix = (long)failLoginCutOff.Value.UnixTimestampFromDateTimeMilliseconds();
            }
            if (banCutOff != null)
            {
                banCutOffUnix = (long)banCutOff.Value.UnixTimestampFromDateTimeMilliseconds();
            }
            using (SQLiteDataReader reader = ExecuteReader(@"SELECT IPAddressText, LastFailedLogin, FailedLoginCount, BanDate
                FROM IPAddresses
                WHERE (@Param0 IS NULL AND @Param1 IS NULL) OR (@Param0 IS NOT NULL AND LastFailedLogin <= @Param0) OR (@Param1 IS NOT NULL AND BanDate <= @Param1)
                ORDER BY IPAddress",
                null, failLoginCutOffUnix, banCutOffUnix))
            {
                while (reader.Read())
                {
                    yield return ParseIPAddressEntry(reader);
                }
            }
        }

        /// <summary>
        /// Get all banned ip addresses
        /// </summary>
        /// <returns>IP addresses with non-null ban dates</returns>
        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            using (SQLiteDataReader reader = ExecuteReader("SELECT IPAddressText /*, LastFailedLogin, FailedLoginCount, BanDate */ FROM IPAddresses WHERE BanDate IS NOT NULL ORDER BY IPAddress", null))
            {
                while (reader.Read())
                {
                    yield return reader.GetString(0);// ParseIPAddressEntry(reader);
                }
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

            using (SQLiteConnection conn = new SQLiteConnection(connString))
            {
                conn.Open();
                using (SQLiteTransaction tran = conn.BeginTransaction(System.Data.IsolationLevel.ReadCommitted))
                {
                    foreach (string ipAddress in ipAddresses)
                    {
                        if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                        {
                            count += ExecuteNonQuery(conn, tran, "DELETE FROM IPAddresses WHERE IPAddress = @Param0", ipAddressObj.GetAddressBytes());
                        }
                    }
                    tran.Commit();
                }
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
            using (SQLiteDataReader reader = ExecuteReader("SELECT IPAddressText FROM IPAddresses WHERE IPAddress BETWEEN @Param0 AND @Param1 AND length(IPAddress) = length(@Param0) AND length(IPAddress) = length(@Param1); " +
                "DELETE FROM IPAddresses WHERE IPAddress BETWEEN @Param0 AND @Param1 AND length(IPAddress) = length(@Param0) AND length(IPAddress) = length(@Param1);", null, start, end))
            {
                while (reader.Read())
                {
                    yield return reader.GetString(0);
                }
            }
        }
    }
}
