#region Imports

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

#endregion Imports

namespace IPBan
{
    public class IPBlockCount
    {
        private int count;

        public int Count
        {
            get { return count; }
            set { count = value; }
        }

        public DateTime LastFailedLogin { get; set; }

        public IPBlockCount()
        {
        }

        public IPBlockCount(DateTime lastFailedLogin, int count) : this()
        {
            Count = count;
            LastFailedLogin = lastFailedLogin;
        }

        public int IncrementCount(DateTime lastFailedLogin, int amount = 1)
        {
            LastFailedLogin = lastFailedLogin;
            return Interlocked.Add(ref count, amount);
        }
    }
}
