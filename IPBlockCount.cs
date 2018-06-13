#region Imports

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

#endregion Imports

namespace IPBan
{
    public class IPBlockCount
    {
        public int Count { get; set; }
        public DateTime LastFailedLogin { get; set; }

        public IPBlockCount()
        {
        }

        public IPBlockCount(DateTime lastFailedLogin, int count) : this()
        {
            Count = count;
            LastFailedLogin = lastFailedLogin;
        }

        public void IncrementCount(DateTime lastFailedLogin, int amount = 1)
        {
            Count += amount;
            LastFailedLogin = lastFailedLogin;
        }
    }
}
