using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
    [ComImport]
    [ComClassProgId("HNetCfg.FWRule")]
    public interface INetFwRule
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
        string Description
        {
            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(3)]
        string ApplicationName
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
        string serviceName
        {
            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(5)]
        int Protocol
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
        string LocalPorts
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
        string RemotePorts
        {
            [DispId(7)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(7)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(8)]
        string LocalAddresses
        {
            [DispId(8)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(8)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(9)]
        string RemoteAddresses
        {
            [DispId(9)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(9)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(10)]
        string IcmpTypesAndCodes
        {
            [DispId(10)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(10)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(11)]
        NetFwRuleDirection Direction
        {
            [DispId(11)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(11)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(12)]
        object Interfaces
        {
            [DispId(12)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(12)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(13)]
        string InterfaceTypes
        {
            [DispId(13)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(13)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(14)]
        bool Enabled
        {
            [DispId(14)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(14)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(15)]
        string Grouping
        {
            [DispId(15)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [DispId(15)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: MarshalAs(UnmanagedType.BStr)]
            [param: In]
            set;
        }

        [DispId(16)]
        int Profiles
        {
            [DispId(16)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(16)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(17)]
        bool EdgeTraversal
        {
            [DispId(17)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(17)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(18)]
        NetFwAction Action
        {
            [DispId(18)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(18)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }
    }
}