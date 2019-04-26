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
    /// <summary>
    /// Stores a set of strings in a memory efficient way using disk and caching
    /// </summary>
    public class IPBanStringSet : IDisposable
    {
        private readonly string dbPath;
        private readonly string connString;
        private readonly bool autoDelete;

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

        private void Initialize()
        {
            if (!File.Exists(dbPath))
            {
                SQLiteConnection.CreateFile(dbPath);
            }
            ExecuteNonQuery("PRAGMA auto_vacuum = INCREMENTAL;"); // PRAGMA journal_mode=WAL; // mostly single threaded, don't need WAL optimizations
            ExecuteNonQuery("CREATE TABLE IF NOT EXISTS Strings (String VARCHAR(64), PRIMARY KEY (String))");
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Name of the set - must only have valid file chars</param>
        /// <param name="autoDelete">True to delete the backing file on close</param>
        public IPBanStringSet(string name, bool autoDelete = false)
        {
            this.autoDelete = autoDelete;
            dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, name + ".sqlite");
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
            if (autoDelete)
            {
                File.Delete(dbPath);
            }
        }

        /// <summary>
        /// Delete all strings from the set
        /// </summary>
        /// <returns>Number of cleared strings</returns>
        public int Clear()
        {
            return ExecuteNonQuery("DELETE FROM Strings");
        }

        /// <summary>
        /// Get the count of all strings in the set
        /// </summary>
        /// <returns>Count</returns>
        public int GetCount()
        {
            return ExecuteScalar<int>("SELECT COUNT(*) FROM Strings");
        }

        /// <summary>
        /// Check if a string exists in the set
        /// </summary>
        /// <param name="text">String</param>
        /// <returns>True if exists, false otherwise</returns>
        public bool Contains(string text)
        {
            return (ExecuteScalar<object>("SELECT 1 FROM Strings WHERE String = @Param0", text) != null);
        }

        /// <summary>
        /// Add a string to the set. If you have many to add, call AddMany.
        /// </summary>
        /// <param name="text">String to add</param>
        /// <returns>True if added, false if already exists</returns>
        public bool Add(string text)
        {
            return (ExecuteNonQuery("INSERT OR IGNORE INTO Strings (String) VALUES (@Param0)", text) == 1);
        }

        /// <summary>
        /// Delete a string from the set. If you have many to remove, call DeleteMany.
        /// </summary>
        /// <param name="text">String to remove</param>
        /// <returns>True if removed, false if not exists</returns>
        public bool Delete(string text)
        {
            return (ExecuteNonQuery("DELETE FROM Strings WHERE String = @Param0", text) == 1);
        }

        /// <summary>
        /// Get all strings
        /// </summary>
        /// <returns>Strings</returns>
        public IEnumerable<string> Enumerate()
        {
            using (SQLiteDataReader reader = ExecuteReader("SELECT String FROM Strings ORDER BY String"))
            {
                while (reader.Read())
                {
                    yield return reader.GetString(0);
                }
            }
        }

        /// <summary>
        /// Add strings to the set, more efficient than add one by one
        /// </summary>
        /// <param name="texts"></param>
        /// <returns>Count of newly added strings</returns>
        public int AddMany(IEnumerable<string> texts)
        {
            int count = 0;
            using (SQLiteConnection conn = new SQLiteConnection(connString))
            {
                conn.Open();
                using (SQLiteTransaction tran = conn.BeginTransaction(System.Data.IsolationLevel.ReadCommitted))
                {
                    foreach (string text in texts)
                    {
                        count += ExecuteNonQuery(conn, tran, "INSERT OR IGNORE INTO Strings (String) VALUES(@Param0)", text);
                    }
                    tran.Commit();
                }
            }
            return count;
        }

        /// <summary>
        /// Delete strings from the set, more efficient than delete one by one
        /// </summary>
        /// <param name="texts">Strings to delete</param>
        /// <returns>Number of deleted strings</returns>
        public int DeleteMany(IEnumerable<string> texts)
        {
            int count = 0;
            using (SQLiteConnection conn = new SQLiteConnection(connString))
            {
                conn.Open();
                using (SQLiteTransaction tran = conn.BeginTransaction(System.Data.IsolationLevel.ReadCommitted))
                {
                    foreach (string text in texts)
                    {
                        count += ExecuteNonQuery(conn, tran, "DELETE FROM Strings WHERE String = @Param0", text);
                    }
                    tran.Commit();
                }
            }
            return count;
        }
    }
}
