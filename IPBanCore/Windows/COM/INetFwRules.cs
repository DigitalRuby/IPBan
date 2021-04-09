using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
    [ComImport]
    internal interface INetFwRules : IEnumerable
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
            INetFwRule rule
        );

        [DispId(3)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void Remove([MarshalAs(UnmanagedType.BStr)][In] string name);

        [DispId(4)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwRule Item([MarshalAs(UnmanagedType.BStr)][In] string name);

        [DispId(-4)]
        IEnumVARIANT GetEnumeratorVariant();
    }
}