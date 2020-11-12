using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("79FD57C8-908E-4A36-9888-D5B3F0A444CF")]
    [ComImport]
    internal interface INetFwService
    {
        [DispId(1)]
        string Name
        {
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }

        [DispId(2)]
        NetFwServiceType Type
        {
            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
        }

        [DispId(3)]
        bool Customized
        {
            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
        }

        [DispId(4)]
        NetFwIPVersion IpVersion
        {
            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(5)]
        NetFwScope Scope
        {
            [DispId(5)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(5)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(6)]
        string RemoteAddresses
        {
            [DispId(6)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(6)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(7)]
        bool Enabled
        {
            [DispId(7)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(7)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(8)]
        INetFwOpenPorts GloballyOpenPorts
        {
            [DispId(8)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
    }
}