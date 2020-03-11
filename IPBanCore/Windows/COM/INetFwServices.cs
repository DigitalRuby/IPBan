using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace IPBanCore.Windows.COM
{
    [Guid("79649BB4-903E-421B-94C9-79848E79F6EE")]
    [ComImport]
    internal interface INetFwServices : IEnumerable
    {
        [DispId(1)]
        int Count
        {
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
        }

        [DispId(2)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwService Item([In] NetFwServiceType svcType);

        [DispId(-4)]
        IEnumVARIANT GetEnumeratorVariant();
    }
}