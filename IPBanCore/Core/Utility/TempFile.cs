using System;
using System.IO;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// A temp file
/// </summary>
public sealed class TempFile : IDisposable
{
    /// <summary>
    /// Constructor. Creates the file name but does not create the file itself.
    /// </summary>
    /// <param name="name">File name (null to generate one)</param>
    public TempFile(string name = null)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            FullName = OSUtility.GetTempFileName();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
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
    /// Full path to the temp file
    /// </summary>
    public string FullName { get; }
}
