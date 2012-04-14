using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPBan
{
    public class IPBlockCount
    {
        public int Count { get; set; }
        public DateTime LastFailedLogin { get; set; }

        public IPBlockCount()
        {
        }

        public IPBlockCount(int count)
            : this()
        {
            Count = count;
            LastFailedLogin = DateTime.UtcNow;
        }

        public void IncrementCount()
        {
            Count++;
            LastFailedLogin = DateTime.UtcNow;
        }
    }
}
