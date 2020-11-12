using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("E0483BA0-47FF-4D9C-A6D6-7741D0B195F7")]
    [ComImport]
    [ComClassProgId("HNetCfg.FwOpenPort")]
    public interface INetFwOpenPort
    {
        [DispId(1)]
        string Name
        {
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(2)]
        NetFwIPVersion IpVersion
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
        NetFwIPProtocol Protocol
        {
            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(4)]
        int Port
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
        bool BuiltIn
        {
            [DispId(8)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
        }
    }
}