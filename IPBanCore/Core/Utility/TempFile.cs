using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// A temp file
/// </summary>
public sealed class TempFile : IDisposable
{
    /// <summary>
    /// Gets the full path of the temp directory used for storing temporary files.
    /// </summary>
    public static string TempDirectory { get; }

    static TempFile()
    {
        var tempFolder = Path.GetTempPath();
        if (string.IsNullOrWhiteSpace(tempFolder))
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                tempFolder = @"c:\temp";
            }
            else
            {
                tempFolder = "/tmp";
            }
        }

        var exeLoc = System.Reflection.Assembly.GetEntryAssembly()?.Location ?? Guid.NewGuid().ToString("N");
        
        // generate sub dir name from exeLoc using hash
        var hashBytes = MD5.HashData(System.Text.Encoding.UTF8.GetBytes(exeLoc));
        var hashString = Convert.ToHexString(hashBytes);
        
        TempDirectory = Path.Combine(tempFolder, hashString);
        DeleteTempDirectory();
        Directory.CreateDirectory(TempDirectory);
        AppDomain.CurrentDomain.ProcessExit += (s, e) => DeleteTempDirectory();
    }

    /// <summary>
    /// Constructor. Creates the file name but does not create the file itself.
    /// </summary>
    /// <param name="name">File name without path (null to generate one)</param>
    public TempFile(string name = null)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            name = Guid.NewGuid().ToString("N") + ".tmp";
        }
        FullName = Path.Combine(TempDirectory, name);
    }

    /// <summary>
    /// Finalizer (calls Dispose)
    /// </summary>
    ~TempFile()
    {
        Dispose();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        GC.SuppressFinalize(this);
        try
        {
            ExtensionMethods.FileDeleteWithRetry(FullName);
        }
        catch
        {
        }
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return FullName;
    }

    /// <summary>
    /// Implicit conversion to string (full path)
    /// </summary>
    /// <param name="tempFile">Temp file</param>
    public static implicit operator string(TempFile tempFile)
    {
        return tempFile.FullName;
    }

    /// <summary>
    /// Get temp file name with full path. The file is not created, just the name is generated. Caller is responsible for deleting the file when done.
    /// </summary>
    /// <returns>Temp file name</returns>
    public static string GetTempFileName()
    {
        return Path.Combine(TempDirectory, Guid.NewGuid().ToString("N") + ".tmp");
    }

    /// <summary>
    /// Deletes the TempDirectory.
    /// </summary>
    private static void DeleteTempDirectory()
    {
        if (Directory.Exists(TempDirectory))
        {
            try
            {
                Directory.Delete(TempDirectory, true);
            }
            catch
            {
            }
        }
    }

    /// <summary>
    /// Full path to the temp file
    /// </summary>
    public string FullName { get; }
}
