using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("F7898AF5-CAC4-4632-A2EC-DA06E5111AF2")]
    [ComImport]
    [ComClassProgId("HNetCfg.FwMgr")]
    internal interface INetFwMgr
    {
        [DispId(1)]
        INetFwPolicy LocalPolicy
        {
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(2)]
        NetFwProfileType CurrentProfileType
        {
            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
        }

        [DispId(3)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void RestoreDefaults();

        [DispId(4)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        // ReSharper disable once TooManyArguments
        void IsPortAllowed(
            [MarshalAs(UnmanagedType.BStr)][In] string imageFileName,
            [In] NetFwIPVersion ipVersion,
            [In] int portNumber,
            [MarshalAs(UnmanagedType.BStr)][In] string localAddress,
            [In] NetFwIPProtocol ipProtocol,
            out object allowed,
            out object restricted
        );

        [DispId(5)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        // ReSharper disable once TooManyArguments
        void IsIcmpTypeAllowed(
            [In] NetFwIPVersion ipVersion,
            [MarshalAs(UnmanagedType.BStr)][In] string localAddress,
            [In] byte type,
            out object allowed,
            out object restricted
        );
    }
}