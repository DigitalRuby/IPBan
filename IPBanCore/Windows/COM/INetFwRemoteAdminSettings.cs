using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("D4BECDDF-6F73-4A83-B832-9C66874CD20E")]
    [ComImport]
    internal interface INetFwRemoteAdminSettings
    {
        [DispId(1)]
        NetFwIPVersion IpVersion
        {
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(2)]
        NetFwScope Scope
        {
            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(3)]
        string RemoteAddresses
        {
            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(4)]
        bool Enabled
        {
            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }
    }
}