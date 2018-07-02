using System;

namespace IPBan
{
    public class IPBanLinuxApp
    {
        public static void Main(string[] args)
        {
            // https://linuxconfig.org/how-to-setup-ftp-server-on-ubuntu-18-04-bionic-beaver-with-vsftpd
            // ipset create IPBanBlacklist iphash maxelem 1048576
            // ipset destroy IPBanBlacklist // clear everything
            // ipset -A IPBanBlacklist 10.10.10.10
            // ipset -A IPBanBlacklist 10.10.10.11
            // ipset save > file.txt
            // ipset restore < file.txt
            // iptables -A INPUT -m set --match-set IPBanBlacklist dst -j DROP
            // iptables -F // clear all rules - this may break SSH permanently!
            // iptables-save > file.txt
            // iptables-restore < file.txt
        }
    }
}
