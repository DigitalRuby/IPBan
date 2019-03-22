using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IPBan
{
    public class IPBanUnblockIPAddressesUpdater : IUpdater
    {
        private IUnblockIPAddresses service;
        private readonly string textFilePath;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="service">Service</param>
        /// <param name="textFilePath">Path to text file to unban ip addresses from or null to require manual unban call</param>
        public IPBanUnblockIPAddressesUpdater(IUnblockIPAddresses service, string textFilePath)
        {
            service.ThrowIfNull();
            this.service = service;
            this.textFilePath = textFilePath;
        }

        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
        }

        /// <summary>
        /// Update - if the text file path exists, all ip addresses from each line will be unbanned
        /// </summary>
        public void Update()
        {
            try
            {
                if (File.Exists(textFilePath))
                {
                    UnbanIPAddresses(File.ReadLines(textFilePath));
                    File.Delete(textFilePath);
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
            }
        }

        /// <summary>
        /// Unban ip addresses
        /// </summary>
        /// <param name="ipAddresses">IP addresses to unban</param>
        public void UnbanIPAddresses(IEnumerable<string> ipAddresses)
        {
            service.UnblockIPAddresses(ipAddresses);
        }
    }
}
