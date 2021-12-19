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

//#define CONNECTION_LEAK_DEBUG // turn on for connection leak debugging

using System;
using System.Collections.Generic;
using System.IO;

using Microsoft.Data.Sqlite;

namespace DigitalRuby.IPBanCore
{
    public abstract class SqliteDB : IDisposable
    {
        private readonly string additionalPragmas;

#if CONNECTION_LEAK_DEBUG

        private readonly Dictionary<SqliteConnection, string> connections = new();

#endif

        protected class SqliteDataReaderWrapper : IDisposable
        {
            private readonly SqliteDB db;
            private readonly SqliteConnection conn;
            private readonly SqliteDataReader reader;
            private readonly bool closeConn;

            public SqliteDataReaderWrapper(SqliteDB db, SqliteConnection conn, SqliteDataReader reader, bool closeConn)
            {
                this.db = db;
                this.conn = conn;
                this.reader = reader;
                this.closeConn = closeConn;
            }

            public void Dispose()
            {
                reader.Dispose();
                if (closeConn)
                {
                    db.CloseConnection(conn);
                }
            }

            public SqliteDataReader Reader => reader;
        }

        /// <summary>
        /// Wraps a transaction
        /// </summary>
        protected class SqliteDBTransaction : IDisposable
        {
            private readonly SqliteDB db;
            private readonly bool disposeConnection;

            public SqliteDBTransaction(SqliteDB db, SqliteConnection conn, bool disposeConnection)
            {
                this.db = db;
                DBConnection = conn;
                this.disposeConnection = disposeConnection;
                DBTransaction = DBConnection.BeginTransaction(TransactionLevel);
            }

            ~SqliteDBTransaction()
            {
                // calls dispose
                Rollback();
            }

            /// <summary>
            /// Close transaction and connection. If transaction has not been rolled back, it is committed
            /// </summary>
            public void Dispose()
            {
                GC.SuppressFinalize(this);

                try
                {
                    if (DBTransaction != null)
                    {
                        DBTransaction.Commit();
                        DBTransaction.Dispose();
                        DBTransaction = null;
                    }
                    if (disposeConnection)
                    {
                        db.CloseConnection(DBConnection);
                    }
                    DBConnection = null;
                }
                catch
                {
                    // don't care
                }
            }

            /// <summary>
            /// Rollback the transaction then calls Dispose
            /// </summary>
            public void Rollback()
            {
                if (DBTransaction != null)
                {
                    DBTransaction.Rollback();
                    DBTransaction.Dispose();
                    DBTransaction = null;
                }
                Dispose();
            }

            public SqliteConnection DBConnection { get; private set; }
            public SqliteTransaction DBTransaction { get; private set; }
        }

        /// <summary>
        /// Default transaction level
        /// </summary>
        protected const System.Data.IsolationLevel TransactionLevel = System.Data.IsolationLevel.Serializable;

        /// <summary>
        /// In memory connection, mainly for testing
        /// </summary>
        protected SqliteConnection InMemoryConnection { get; set; }

        /// <summary>
        /// Connection string
        /// </summary>
        public string ConnectionString { get; private set; }

        /// <summary>
        /// Execute non query
        /// </summary>
        /// <param name="cmdText">Command text</param>
        /// <param name="parameters">Parameters</param>
        /// <returns>Number of rows modified</returns>
        protected int ExecuteNonQuery(string cmdText, params object[] parameters)
        {
            return ExecuteNonQuery(cmdText, null, null, parameters);
        }

        /// <summary>
        /// Execute non query and eat exceptions
        /// </summary>
        /// <param name="cmdText">Command text</param>
        /// <param name="parameters">Parameters</param>
        /// <returns>Number of rows modified</returns>
        protected int ExecuteNonQueryIgnoreExceptions(string cmdText, params object[] parameters)
        {
            try
            {
                return ExecuteNonQuery(cmdText, parameters);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Execute non query
        /// </summary>
        /// <param name="cmdText">Command text</param>
        /// <param name="conn">Connection</param>
        /// <param name="tran">Transaction</param>
        /// <param name="parameters">Parameters</param>
        /// <returns>Number of rows modified</returns>
        protected int ExecuteNonQuery(string cmdText, SqliteConnection conn, SqliteTransaction tran, params object[] parameters)
        {
            bool closeConn = false;
            if (conn is null)
            {
                conn = CreateConnection();
                OpenConnection(conn);
                closeConn = true;
            }
            try
            {
                using SqliteCommand command = conn.CreateCommand();
                if (command.Transaction != null && tran != null && tran != command.Transaction)
                {
                    throw new InvalidOperationException("Connection created a command with an existing transaction that does not match passed transaction, this is an error condition");
                }
                command.CommandText = cmdText;
                command.Transaction ??= tran;
                for (int i = 0; i < parameters.Length; i++)
                {
                    command.Parameters.Add(new SqliteParameter("@Param" + i, parameters[i] ?? DBNull.Value));
                }
                return command.ExecuteNonQuery();
            }
            finally
            {
                if (closeConn)
                {
                    CloseConnection(conn);
                }
            }
        }

        /// <summary>
        /// Execute scalar
        /// </summary>
        /// <typeparam name="T">Type of scalar</typeparam>
        /// <param name="cmdText">Command text</param>
        /// <param name="result">Result</param>
        /// <param name="parameters">Parameters</param>
        /// <returns>True if value, false if not</returns>
        protected bool ExecuteScalar<T>(string cmdText, out T result,
            params object[] parameters)
        {
            return ExecuteScalar<T>(cmdText, null, null, out result, parameters);
        }

        /// <summary>
        /// Execute scalar
        /// </summary>
        /// <typeparam name="T">Type of scalar</typeparam>
        /// <param name="cmdText">Command text</param>
        /// <param name="conn">Connection</param>
        /// <param name="tran">Transaction</param>
        /// <param name="result">Result</param>
        /// <param name="parameters">Parameters</param>
        /// <returns>True if value, false if not</returns>
        protected bool ExecuteScalar<T>(string cmdText, SqliteConnection conn, SqliteTransaction tran, out T result,
            params object[] parameters)
        {
            bool closeConn = false;
            if (conn is null)
            {
                conn = CreateConnection();
                OpenConnection(conn);
                closeConn = true;
            }
            try
            {
                using SqliteCommand command = conn.CreateCommand();
                command.CommandText = cmdText;
                command.Transaction = tran;
                for (int i = 0; i < parameters.Length; i++)
                {
                    command.Parameters.Add(new SqliteParameter("@Param" + i, parameters[i] ?? DBNull.Value));
                }
                object resultObj = command.ExecuteScalar();
                if (resultObj is null || resultObj == DBNull.Value)
                {
                    result = default;
                    return false;
                }
                result = (T)Convert.ChangeType(resultObj, typeof(T));
                return true;
            }
            finally
            {
                if (closeConn)
                {
                    CloseConnection(conn);
                }
            }
        }

        /// <summary>
        /// Execute reader
        /// </summary>
        /// <param name="cmdText">Query text</param>
        /// <param name="conn">Connection</param>
        /// <param name="tran">Transaction</param>
        /// <param name="rollbackTransactionIfException">Whether to rollback transaction if there is an exception</param>
        /// <param name="parameters">Parameters</param>
        /// <returns>Data reader</returns>
        protected SqliteDataReaderWrapper ExecuteReader(string cmdText, SqliteConnection conn = null, SqliteTransaction tran = null,
            bool rollbackTransactionIfException = false, params object[] parameters)
        {
            try
            {
                bool closeConnection = false;
                if (conn is null)
                {
                    conn = CreateConnection();
                    OpenConnection(conn);
                    closeConnection = true;
                }
                SqliteCommand command = conn.CreateCommand();
                command.CommandText = cmdText;
                command.Transaction = tran;
                for (int i = 0; i < parameters.Length; i++)
                {
                    command.Parameters.Add(new SqliteParameter("@Param" + i.ToStringInvariant(), parameters[i] ?? DBNull.Value));
                }
                var reader = command.ExecuteReader();
                return new(this, conn, reader, closeConnection);
            }
            catch
            {
                if (rollbackTransactionIfException)
                {
                    tran?.Rollback();
                }
                throw;
            }
        }

        /// <summary>
        /// Create a connection
        /// </summary>
        /// <returns>Connection</returns>
        protected SqliteConnection CreateConnection()
        {
            if (InMemoryConnection is not null)
            {
                return InMemoryConnection;
            }
            var conn = new SqliteConnection(ConnectionString);

#if CONNECTION_LEAK_DEBUG

            connections[conn] = Environment.StackTrace;

#endif

            return conn;
        }

        /// <summary>
        /// Open a connection
        /// </summary>
        /// <param name="conn">Connection</param>
        protected void OpenConnection(SqliteConnection conn)
        {
            if (conn != InMemoryConnection && conn is not null)
            {
                conn.Open();
                ExecuteNonQuery($"PRAGMA auto_vacuum = INCREMENTAL; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 30000; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY; {additionalPragmas}", conn, (SqliteTransaction)null);
            }
        }

        /// <summary>
        /// Close a connection
        /// </summary>
        /// <param name="conn">Connection</param>
        protected void CloseConnection(SqliteConnection conn)
        {
            if (conn != InMemoryConnection && conn is not null

#if CONNECTION_LEAK_DEBUG

                && connections.ContainsKey(conn)
                
#endif

            )
            {
                conn.Close();

#if CONNECTION_LEAK_DEBUG

                connections.Remove(conn);

#endif

            }
        }

        /// <summary>
        /// Initialize db, derived class should call base first
        /// </summary>
        protected virtual void OnInitialize()
        {

        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="dbPath">Database full path or just the file name. Can use SqliteDB.DbPathInMemory for in memory db.</param>
        /// <param name="additionalPragmas">Pragma statements for new connection (semi-colon delimited), or null for none</param>
        public SqliteDB(string dbPath, string additionalPragmas = null)
        {
            if (dbPath == ":memory:")
            {
                InMemoryConnection = new SqliteConnection(ConnectionString = ($"Data Source={dbPath}"));
                InMemoryConnection.Open();
            }
            else
            {
                dbPath.ThrowIfNullOrEmpty(nameof(dbPath));
                dbPath = (Path.IsPathRooted(dbPath) ? dbPath : Path.Combine(AppContext.BaseDirectory, dbPath));
                if (!dbPath.EndsWith(".sqlite", StringComparison.OrdinalIgnoreCase))
                {
                    dbPath += ".sqlite";
                }
                ConnectionString = $"Data Source={dbPath};Cache=Shared;";
            }
            this.additionalPragmas = (additionalPragmas ?? string.Empty).Trim();
            OnInitialize();
        }

        /// <summary>
        /// Cleanup all resources
        /// </summary>
        public virtual void Dispose()
        {
            GC.SuppressFinalize(this);
            InMemoryConnection?.Dispose();

#if CONNECTION_LEAK_DEBUG

            if (connections.Count != 0)
            {
                throw new ApplicationException("Leaked connections were not disposed of properly, check connections and transactions are disposed");
            }

#endif

            SqliteConnection.ClearAllPools();
        }

        /// <summary>
        /// Begin a transaction
        /// </summary>
        /// <returns>Transaction</returns>
        public object BeginTransaction()
        {
            SqliteConnection conn = CreateConnection();
            OpenConnection(conn);
            return new SqliteDBTransaction(this, conn, conn != InMemoryConnection);
        }

        /// <summary>
        /// Commit a transaction
        /// </summary>
        /// <param name="transaction">Transaction</param>
        public static void CommitTransaction(object transaction)
        {
            if (transaction is SqliteDBTransaction tran)
            {
                tran.Dispose();
            }
        }

        /// <summary>
        /// Rollback a transaction. If the transaction is already commited, nothing happens.
        /// </summary>
        /// <param name="transaction">Transaction to rollback</param>
        public static void RollbackTransaction(object transaction)
        {
            if (transaction is SqliteDBTransaction tran && tran.DBConnection != null)
            {
                tran.Rollback();
            }
        }
    }
}
