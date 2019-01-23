using System;
using System.Collections.Generic;
using System.Text;

using System.Data.SQLite;
using System.IO;
using System.Net;

namespace IPBan
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
                    return command.ExecuteNonQuery();
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

        private SQLiteDataReader ExecuteReader(string query, params object[] param)
        {
            SQLiteConnection connection = new SQLiteConnection(connString);
            connection.Open();
            SQLiteCommand command = connection.CreateCommand();
            command.CommandText = query;
            for (int i = 0; i < param.Length; i++)
            {
                command.Parameters.Add(new SQLiteParameter("@Param" + i.ToStringInvariant(), param[i]));
            }
            return command.ExecuteReader(System.Data.CommandBehavior.CloseConnection);
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

        private void Initialize()
        {
            if (!File.Exists(dbPath))
            {
                SQLiteConnection.CreateFile(dbPath);
            }
            ExecuteNonQuery("PRAGMA auto_vacuum = INCREMENTAL;"); // PRAGMA journal_mode=WAL; // mostly single threaded, don't need WAL optimizations
            ExecuteNonQuery("CREATE TABLE IF NOT EXISTS IPAddresses (IPAddress VARBINARY(16) NOT NULL, IPAddressText VARCHAR(64), LastFailedLogin BIGINT NOT NULL, FailedLoginCount BIGINT NOT NULL, BanDate BIGINT, PRIMARY KEY (IPAddress))");

            // no indexes for now, maybe in the future if more features are added
            //ExecuteNonQuery("CREATE INDEX IF NOT EXISTS IPAddresses_LastFailedLogin ON IPAddresses (BanDate)");
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
        /// <returns>New failed login count</returns>
        public int IncrementFailedLoginCount(string ipAddress, DateTime dateTime, int increment)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                long timestamp = (long)dateTime.UnixTimestampFromDateTimeMilliseconds();
                using (SQLiteDataReader reader = ExecuteReader(@"BEGIN TRANSACTION;
                    INSERT INTO IPAddresses(IPAddress, IPAddressText, LastFailedLogin, FailedLoginCount, BanDate)
                    VALUES (@Param0, @Param1, @Param2, @Param3, NULL)
                    ON CONFLICT(IPAddress)
                    DO UPDATE SET LastFailedLogin = @Param2, FailedLoginCount = FailedLoginCount + @Param3;
                    SELECT FailedLoginCount FROM IPAddresses WHERE IPAddress = @Param0;
                    COMMIT;",
                    ipBytes, ipAddress, timestamp, increment))
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
                using (SQLiteDataReader reader = ExecuteReader("SELECT IPAddressText, LastFailedLogin, FailedLoginCount, BanDate FROM IPAddresses WHERE IPAddress = @Param0", ipBytes))
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
        /// <returns>True if ban date set, false if it was already set or ip address is not in the database</returns>
        public bool SetBanDate(string ipAddress, DateTime banDate)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                long timestamp = (long)banDate.UnixTimestampFromDateTimeMilliseconds();
                int count = ExecuteNonQuery(@"INSERT INTO IPAddresses(IPAddress, IPAddressText, LastFailedLogin, FailedLoginCount, BanDate)
                    VALUES(@Param0, @Param1, @Param2, 0, @Param2)
                    ON CONFLICT(IPAddress)
                    DO UPDATE SET BanDate = @Param2 WHERE BanDate IS NULL; ", ipBytes, ipAddress, timestamp);
                return (count != 0);
            }
            return false;
        }

        /// <summary>
        /// Get the ban date for an ip address
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <returns>Ban date or null if not banned or not in the database</returns>
        public DateTime? GetBanDate(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                byte[] ipBytes = ipAddressObj.GetAddressBytes();
                using (SQLiteDataReader reader = ExecuteReader("SELECT BanDate FROM IPAddresses WHERE IPAddress = @Param0", ipBytes))
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
        /// <param name="ipAddresses">IP addresses to set as banned</param>
        /// <param name="banDate">Ban date to set</param>
        public void SetBannedIPAddresses(IEnumerable<string> ipAddresses, DateTime banDate)
        {
            foreach (string ipAddress in ipAddresses)
            {
                SetBanDate(ipAddress, banDate);
            }
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
        /// <returns>IP addresses with expired ban date</returns>
        public IEnumerable<IPAddressEntry> EnumerateIPAddresses()
        {
            using (SQLiteDataReader reader = ExecuteReader("SELECT IPAddressText, LastFailedLogin, FailedLoginCount, BanDate FROM IPAddresses"))
            {
                while (reader.Read())
                {
                    yield return ParseIPAddressEntry(reader);
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

            foreach (string ipAddress in ipAddresses)
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                {
                    count += ExecuteNonQuery("DELETE FROM IPAddresses WHERE IPAddress = @Param0", ipAddressObj.GetAddressBytes());
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
                "DELETE FROM IPAddresses WHERE IPAddress BETWEEN @Param0 AND @Param1 AND length(IPAddress) = length(@Param0) AND length(IPAddress) = length(@Param1);", start, end))
            {
                while (reader.Read())
                {
                    yield return reader.GetString(0);
                }
            }
        }

        /// <summary>
        /// Get all banned ip addresses
        /// </summary>
        /// <returns>IP addresses with non-null ban dates</returns>
        public IEnumerable<IPAddressEntry> EnumerateBannedIPAddresses()
        {
            using (SQLiteDataReader reader = ExecuteReader("SELECT IPAddressText, LastFailedLogin, FailedLoginCount, BanDate FROM IPAddresses WHERE BanDate IS NOT NULL"))
            {
                while (reader.Read())
                {
                    yield return ParseIPAddressEntry(reader);
                }
            }
        }
    }
}
