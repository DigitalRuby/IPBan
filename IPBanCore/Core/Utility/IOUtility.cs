using System;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// IO utilities
/// </summary>
public static class IOUtility
{
    /// <summary>
    /// Get lines from file or url.
    /// </summary>
    /// <param name="fileNameOrUrl">File name or url</param>
    /// <param name="maxBytes">Max bytes or less than 1 for no limit</param>
    /// <returns>Lines or empty array if more than maxBytes returned and maxBytes &gt; 0</returns>
    public static string[] GetLines(string fileNameOrUrl, int maxBytes = 0)
    {
        try
        {
            if ((fileNameOrUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                fileNameOrUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) &&
                Uri.TryCreate(fileNameOrUrl, UriKind.Absolute, out var url))
            {
                using var client = new System.Net.Http.HttpClient() { Timeout = TimeSpan.FromSeconds(10) };
                var response = client.GetAsync(url).Sync();
                if (response.IsSuccessStatusCode)
                {
                    if (maxBytes > 0 && response.Content.Headers.ContentLength > maxBytes)
                    {
                        Logger.Warn("Skipping regex file replace '{0}' because it is greater than {1} bytes", fileNameOrUrl, maxBytes);
                        return [];
                    }
                    var content = response.Content.ReadAsStringAsync().Sync();
                    return content.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                }
            }
            else if (System.IO.File.Exists(fileNameOrUrl))
            {
                if (maxBytes > 0 && new System.IO.FileInfo(fileNameOrUrl).Length > maxBytes)
                {
                    Logger.Warn("Skipping regex file replace '{0}' because it is greater than {1} bytes", fileNameOrUrl, maxBytes);
                    return [];
                }
                return System.IO.File.ReadAllLines(fileNameOrUrl);
            }
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Error getting lines from '{0}'", fileNameOrUrl);
        }
        return [];
    }
}
