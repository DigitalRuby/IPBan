using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("8267BBE3-F890-491C-B7B6-2DB1EF0E5D2B")]
    [ComImport]
    internal interface INetFwServiceRestriction
    {
        [DispId(1)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        // ReSharper disable once TooManyArguments
        void RestrictService(
            [MarshalAs(UnmanagedType.BStr)][In] string serviceName,
            [MarshalAs(UnmanagedType.BStr)][In] string appName,
            [In] bool restrictService,
            [In] bool serviceSIDRestricted
        );

        [DispId(2)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        bool ServiceRestricted(
            [MarshalAs(UnmanagedType.BStr)][In] string serviceName,
            [MarshalAs(UnmanagedType.BStr)][In] string appName
        );

        [DispId(3)]
        INetFwRules Rules
        {
            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
    }
}