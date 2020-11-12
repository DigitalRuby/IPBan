using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("9C27C8DA-189B-4DDE-89F7-8B39A316782C")]
    [ComImport]
    public interface INetFwRule2 : INetFwRule
    {
        [DispId(1)]
        new string Name
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
        new string Description
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
        new string ApplicationName
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
        new string serviceName
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
        new int Protocol
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
        new string LocalPorts
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
        new string RemotePorts
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
        new string LocalAddresses
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
        new string RemoteAddresses
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
        new string IcmpTypesAndCodes
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
        new NetFwRuleDirection Direction
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
        new object Interfaces
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
        new string InterfaceTypes
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
        new bool Enabled
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
        new string Grouping
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
        new int Profiles
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
        new bool EdgeTraversal
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
        new NetFwAction Action
        {
            [DispId(18)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(18)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }

        [DispId(19)]
        int EdgeTraversalOptions
        {
            [DispId(19)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
            [DispId(19)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [param: In]
            set;
        }
    }
}