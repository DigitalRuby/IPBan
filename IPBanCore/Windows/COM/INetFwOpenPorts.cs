using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("C0E9D7FA-E07E-430A-B19A-090CE82D92E2")]
    [ComImport]
    internal interface INetFwOpenPorts : IEnumerable
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
            INetFwOpenPort port
        );

        [DispId(3)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void Remove([In] int portNumber, [In] NetFwIPProtocol ipProtocol);

        [DispId(4)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwOpenPort Item([In] int portNumber, [In] NetFwIPProtocol ipProtocol);

        [DispId(-4)]
        IEnumVARIANT GetEnumeratorVariant();
    }
}