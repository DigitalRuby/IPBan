using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Microsoft.Data.Sqlite;

namespace DigitalRuby.IPBan
{
    public abstract class SqliteDB : IDisposable
    {
        /// <summary>
        /// Wraps a transaction
        /// </summary>
        protected class SqliteDBTransaction : IDisposable
        {
            private readonly bool disposeConnection;

            public SqliteDBTransaction(SqliteConnection conn, bool disposeConnection)
            {
                DBConnection = conn;
                this.disposeConnection = disposeConnection;
                using (SqliteCommand command = DBConnection.CreateCommand())
                {
                    command.CommandText = "PRAGMA auto_vacuum = INCREMENTAL;";
                    command.ExecuteNonQuery();
                }
                using (SqliteCommand command = DBConnection.CreateCommand())
                {
                    command.CommandText = "PRAGMA journal_mode = WAL;";
                    command.ExecuteNonQuery();
                }
                DBTransaction = DBConnection.BeginTransaction(TransactionLevel);
            }

            ~SqliteDBTransaction()
            {
                Rollback();
                Dispose();
            }

            /// <summary>
            /// Close transaction and connection. If transaction has not been rolled back, it is committed
            /// </summary>
            public void Dispose()
            {
                try
                {
                    if (DBTransaction != null)
                    {
                        DBTransaction.Commit();
                        DBTransaction.Dispose();
                        DBTransaction = null;
                    }
                    if (DBConnection != null)
                    {
                        if (disposeConnection)
                        {
                            DBConnection.Dispose();
                        }
                        DBConnection = null;
                    }
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
        /// In memory db path
        /// </summary>
        public const string DbPathInMemory = ":memory:";

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
                using (SqliteCommand command = conn.CreateCommand())
                {
                    command.CommandText = cmdText;
                    command.Transaction = tran;
                    for (int i = 0; i < parameters.Length; i++)
                    {
                        command.Parameters.Add(new SqliteParameter("@Param" + i, parameters[i] ?? DBNull.Value));
                    }
                    return command.ExecuteNonQuery();
                }
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
        /// <param name="parameters">Parameters</param>
        /// <returns>Return value</returns>
        protected T ExecuteScalar<T>(string cmdText, params object[] parameters)
        {
            return ExecuteScalar<T>(cmdText, null, null, parameters);
        }

        /// <summary>
        /// Execute scalar
        /// </summary>
        /// <typeparam name="T">Type of scalar</typeparam>
        /// <param name="cmdText">Command text</param>
        /// <param name="conn">Connection</param>
        /// <param name="tran">Transaction</param>
        /// <param name="parameters">Parameters</param>
        /// <returns>Return value</returns>
        protected T ExecuteScalar<T>(string cmdText, SqliteConnection conn, SqliteTransaction tran, params object[] parameters)
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
                using (SqliteCommand command = conn.CreateCommand())
                {
                    command.CommandText = cmdText;
                    command.Transaction = tran;
                    for (int i = 0; i < parameters.Length; i++)
                    {
                        command.Parameters.Add(new SqliteParameter("@Param" + i, parameters[i] ?? DBNull.Value));
                    }
                    return (T)Convert.ChangeType(command.ExecuteScalar(), typeof(T));
                }
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
        /// <param name="parameters">Parameters</param>
        /// <returns>Data reader</returns>
        protected SqliteDataReader ExecuteReader(string cmdText, SqliteConnection conn = null, SqliteTransaction tran = null, params object[] parameters)
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
            return command.ExecuteReader((closeConnection && conn != InMemoryConnection ? System.Data.CommandBehavior.CloseConnection : System.Data.CommandBehavior.Default));
        }

        /// <summary>
        /// Create a connection
        /// </summary>
        /// <returns>Connection</returns>
        protected SqliteConnection CreateConnection()
        {
            return (InMemoryConnection ?? new SqliteConnection(ConnectionString));
        }

        /// <summary>
        /// Open a connection
        /// </summary>
        /// <param name="conn">Connection</param>
        protected void OpenConnection(SqliteConnection conn)
        {
            if (conn != InMemoryConnection)
            {
                conn.Open();
                ExecuteNonQuery("PRAGMA auto_vacuum = INCREMENTAL;", conn, null);
                ExecuteNonQuery("PRAGMA journal_mode = WAL;", conn, null);
            }
        }

        /// <summary>
        /// Close a connection
        /// </summary>
        /// <param name="conn">Connection</param>
        protected void CloseConnection(SqliteConnection conn)
        {
            if (conn != InMemoryConnection)
            {
                conn.Close();
            }
        }

        /// <summary>
        /// Initialize db, derived class should call base first
        /// </summary>
        protected virtual void OnInitialize()
        {
            ExecuteNonQuery("PRAGMA auto_vacuum = INCREMENTAL;");
            ExecuteNonQuery("PRAGMA journal_mode = WAL;");
        }

        /// <summary>
        /// Static constructor
        /// </summary>
        static SqliteDB()
        {
            SQLitePCL.Batteries.Init();
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    // net core 3, fails to load sqlite dll without a delay
                    using (SqliteCommand tmp = new SqliteCommand()) { }
                    break;
                }
                catch
                {
                    System.Threading.Thread.Sleep(500);
                }
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="dbPath">Database full path or just the file name. Can use </param>
        public SqliteDB(string dbPath)
        {
            if (dbPath == DbPathInMemory)
            {
                InMemoryConnection = new SqliteConnection(ConnectionString = ("Data Source=" + dbPath));
                InMemoryConnection.Open();
            }
            else
            {
                dbPath.ThrowIfNullOrEmpty(nameof(dbPath));
                dbPath = (Path.IsPathRooted(dbPath) ? dbPath : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, dbPath));
                ConnectionString = "Data Source=" + dbPath;
            }
            OnInitialize();
        }

        /// <summary>
        /// Cleanup all resources
        /// </summary>
        public virtual void Dispose()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            InMemoryConnection?.Dispose();
        }

        /// <summary>
        /// Begin a transaction
        /// </summary>
        /// <returns>Transaction</returns>
        public object BeginTransaction()
        {
            SqliteConnection conn = CreateConnection();
            OpenConnection(conn);
            return new SqliteDBTransaction(conn, conn != InMemoryConnection);
        }

        /// <summary>
        /// Commit a transaction
        /// </summary>
        /// <param name="transaction">Transaction</param>
        public void CommitTransaction(object transaction)
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
        public void RollbackTransaction(object transaction)
        {
            if (transaction is SqliteDBTransaction tran && tran.DBConnection != null)
            {
                tran.Rollback();
            }
        }
    }
}
