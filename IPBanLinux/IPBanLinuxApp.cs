using System;

namespace IPBan
{
    public class IPBanLinuxApp
    {
        public static void Main(string[] args)
        {
            IPBanService service = IPBanService.CreateService();
            service.Start();
        }
    }
}


