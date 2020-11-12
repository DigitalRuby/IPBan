using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("D46D2478-9AC9-4008-9DC7-5563CE5536CC")]
    [ComImport]
    internal interface INetFwPolicy
    {
        [DispId(1)]
        INetFwProfile CurrentProfile
        {
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(2)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwProfile GetProfileByType([In] NetFwProfileType profileType);
    }
}