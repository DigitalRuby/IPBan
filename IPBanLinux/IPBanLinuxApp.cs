using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace IPBan
{
    public class IPBanLinuxApp
    {
        public static void Main(string[] args)
        {
            // string line = "Feb 21 08:35:22 localhost sshd[5774]: Failed password for root from 116.31.116.24 port 29160 ssh2";
            IPBanService service = IPBanService.CreateService();
            service.Start();
            Console.WriteLine("IPBan Linux Service Running, Press Ctrl-C or ENTER to quit.");
            Console.ReadLine();
        }
    }
}


