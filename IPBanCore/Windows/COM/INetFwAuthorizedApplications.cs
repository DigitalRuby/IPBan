using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("644EFD52-CCF9-486C-97A2-39F352570B30")]
    [ComImport]
    internal interface INetFwAuthorizedApplications : IEnumerable
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
        // ReSharper disable once MethodNameNotMeaningful
        void Add(
            [MarshalAs(UnmanagedType.Interface)] [In]
            INetFwAuthorizedApplication app
        );

        [DispId(3)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void Remove([MarshalAs(UnmanagedType.BStr)][In] string imageFileName);

        [DispId(4)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwAuthorizedApplication Item([MarshalAs(UnmanagedType.BStr)][In] string imageFileName);

        [DispId(-4)]
        IEnumVARIANT GetEnumeratorVariant();
    }
}