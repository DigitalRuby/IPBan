using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NetFwTypeLib
{
    [ComImport]
    [TypeLibType(4160)]
    [Guid("B5E64FFA-C2C5-444E-A301-FB5E00018050")]
    public interface INetFwAuthorizedApplication
    {
        [DispId(1)]
        string Name
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(2)]
        string ProcessImageFileName
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(3)]
        NET_FW_IP_VERSION_ IpVersion
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            set;
        }

        [DispId(4)]
        NET_FW_SCOPE_ Scope
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            set;
        }

        [DispId(5)]
        string RemoteAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(6)]
        bool Enabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [param: In]
            set;
        }
    }

    [ComImport]
    [TypeLibType(4160)]
    [Guid("644EFD52-CCF9-486C-97A2-39F352570B30")]
    public interface INetFwAuthorizedApplications : IEnumerable
    {
        [DispId(1)]
        int Count
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(2)]
        void Add([In] [MarshalAs(UnmanagedType.Interface)] INetFwAuthorizedApplication app);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(3)]
        void Remove([In] [MarshalAs(UnmanagedType.BStr)] string imageFileName);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(4)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwAuthorizedApplication Item([In] [MarshalAs(UnmanagedType.BStr)] string imageFileName);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [TypeLibFunc(1)]
        [DispId(-4)]
        [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalType = "System.Runtime.InteropServices.CustomMarshalers.EnumeratorToEnumVariantMarshaler")]
        new IEnumerator GetEnumerator();
    }

    [ComImport]
    [Guid("A6207B2E-7CDD-426A-951E-5E1CBC5AFEAD")]
    [TypeLibType(4160)]
    public interface INetFwIcmpSettings
    {
        [DispId(1)]
        bool AllowOutboundDestinationUnreachable
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [param: In]
            set;
        }

        [DispId(2)]
        bool AllowRedirect
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            set;
        }

        [DispId(3)]
        bool AllowInboundEchoRequest
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            set;
        }

        [DispId(4)]
        bool AllowOutboundTimeExceeded
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            set;
        }

        [DispId(5)]
        bool AllowOutboundParameterProblem
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            set;
        }

        [DispId(6)]
        bool AllowOutboundSourceQuench
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [param: In]
            set;
        }

        [DispId(7)]
        bool AllowInboundRouterRequest
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [param: In]
            set;
        }

        [DispId(8)]
        bool AllowInboundTimestampRequest
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [param: In]
            set;
        }

        [DispId(9)]
        bool AllowInboundMaskRequest
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            [param: In]
            set;
        }

        [DispId(10)]
        bool AllowOutboundPacketTooBig
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            [param: In]
            set;
        }
    }

    [ComImport]
    [TypeLibType(4160)]
    [Guid("F7898AF5-CAC4-4632-A2EC-DA06E5111AF2")]
    public interface INetFwMgr
    {
        [DispId(1)]
        INetFwPolicy LocalPolicy
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(2)]
        NET_FW_PROFILE_TYPE_ CurrentProfileType
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(3)]
        void RestoreDefaults();

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(4)]
        void IsPortAllowed([In] [MarshalAs(UnmanagedType.BStr)] string imageFileName, [In] NET_FW_IP_VERSION_ IpVersion, [In] int portNumber, [In] [MarshalAs(UnmanagedType.BStr)] string localAddress, [In] NET_FW_IP_PROTOCOL_ ipProtocol, /*[MarshalAs(UnmanagedType.Struct)]*/ out object allowed, /*[MarshalAs(UnmanagedType.Struct)]*/ out object restricted);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(5)]
        void IsIcmpTypeAllowed([In] NET_FW_IP_VERSION_ IpVersion, [In] [MarshalAs(UnmanagedType.BStr)] string localAddress, [In] byte Type, /*[MarshalAs(UnmanagedType.Struct)]*/ out object allowed, /*[MarshalAs(UnmanagedType.Struct)]*/ out object restricted);
    }

    [ComImport]
    [TypeLibType(4160)]
    [Guid("E0483BA0-47FF-4D9C-A6D6-7741D0B195F7")]
    public interface INetFwOpenPort
    {
        [DispId(1)]
        string Name
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(2)]
        NET_FW_IP_VERSION_ IpVersion
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            set;
        }

        [DispId(3)]
        NET_FW_IP_PROTOCOL_ Protocol
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            set;
        }

        [DispId(4)]
        int Port
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            set;
        }

        [DispId(5)]
        NET_FW_SCOPE_ Scope
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            set;
        }

        [DispId(6)]
        string RemoteAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(7)]
        bool Enabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [param: In]
            set;
        }

        [DispId(8)]
        bool BuiltIn
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            get;
        }
    }

    [ComImport]
    [Guid("C0E9D7FA-E07E-430A-B19A-090CE82D92E2")]
    [TypeLibType(4160)]
    public interface INetFwOpenPorts : IEnumerable
    {
        [DispId(1)]
        int Count
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(2)]
        void Add([In] [MarshalAs(UnmanagedType.Interface)] INetFwOpenPort Port);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(3)]
        void Remove([In] int portNumber, [In] NET_FW_IP_PROTOCOL_ ipProtocol);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(4)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwOpenPort Item([In] int portNumber, [In] NET_FW_IP_PROTOCOL_ ipProtocol);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(-4)]
        [TypeLibFunc(1)]
        [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalType = "System.Runtime.InteropServices.CustomMarshalers.EnumeratorToEnumVariantMarshaler")]
        new IEnumerator GetEnumerator();
    }

    [ComImport]
    [TypeLibType(4160)]
    [Guid("D46D2478-9AC9-4008-9DC7-5563CE5536CC")]
    public interface INetFwPolicy
    {
        [DispId(1)]
        INetFwProfile CurrentProfile
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(2)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwProfile GetProfileByType([In] NET_FW_PROFILE_TYPE_ profileType);
    }

    [ComImport]
    [TypeLibType(4160)]
    [Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
    public interface INetFwPolicy2
    {
        [DispId(1)]
        int CurrentProfileTypes
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
        }

        [DispId(2)]
        bool FirewallEnabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            set;
        }

        [DispId(3)]
        object ExcludedInterfaces
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            //[return: MarshalAs(UnmanagedType.Struct)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            //[param: MarshalAs(UnmanagedType.Struct)]
            set;
        }

        [DispId(4)]
        bool BlockAllInboundTraffic
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            set;
        }

        [DispId(5)]
        bool NotificationsDisabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            set;
        }

        [DispId(6)]
        bool UnicastResponsesToMulticastBroadcastDisabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [param: In]
            set;
        }

        [DispId(7)]
        INetFwRules Rules
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(8)]
        INetFwServiceRestriction ServiceRestriction
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(12)]
        NET_FW_ACTION_ DefaultInboundAction
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(12)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(12)]
            [param: In]
            set;
        }

        [DispId(13)]
        NET_FW_ACTION_ DefaultOutboundAction
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(13)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(13)]
            [param: In]
            set;
        }

        [DispId(14)]
        bool IsRuleGroupCurrentlyEnabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(14)]
            get;
        }

        [DispId(15)]
        NET_FW_MODIFY_STATE_ LocalPolicyModifyState
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(15)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(9)]
        void EnableRuleGroup([In] int profileTypesBitmask, [In] [MarshalAs(UnmanagedType.BStr)] string group, [In] bool enable);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(10)]
        bool IsRuleGroupEnabled([In] int profileTypesBitmask, [In] [MarshalAs(UnmanagedType.BStr)] string group);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(11)]
        void RestoreLocalFirewallDefaults();
    }

    [ComImport]
    [Guid("71881699-18F4-458B-B892-3FFCE5E07F75")]
    [TypeLibType(4160)]
    public interface INetFwProduct
    {
        [DispId(1)]
        object RuleCategories
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            //[return: MarshalAs(UnmanagedType.Struct)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [param: In]
            //[param: MarshalAs(UnmanagedType.Struct)]
            set;
        }

        [DispId(2)]
        string DisplayName
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(3)]
        string PathToSignedProductExe
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }
    }

    [ComImport]
    [Guid("39EB36E0-2097-40BD-8AF2-63A13B525362")]
    [TypeLibType(4160)]
    public interface INetFwProducts : IEnumerable
    {
        [DispId(1)]
        int Count
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(2)]
        [return: MarshalAs(UnmanagedType.IUnknown)]
        object Register([In] [MarshalAs(UnmanagedType.Interface)] INetFwProduct product);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(3)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwProduct Item([In] int index);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [TypeLibFunc(1)]
        [DispId(-4)]
        [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalType = "System.Runtime.InteropServices.CustomMarshalers.EnumeratorToEnumVariantMarshaler")]
        new IEnumerator GetEnumerator();
    }

    [ComImport]
    [Guid("174A0DDA-E9F9-449D-993B-21AB667CA456")]
    [TypeLibType(4160)]
    public interface INetFwProfile
    {
        [DispId(1)]
        NET_FW_PROFILE_TYPE_ Type
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
        }

        [DispId(2)]
        bool FirewallEnabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            set;
        }

        [DispId(3)]
        bool ExceptionsNotAllowed
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            set;
        }

        [DispId(4)]
        bool NotificationsDisabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            set;
        }

        [DispId(5)]
        bool UnicastResponsesToMulticastBroadcastDisabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            set;
        }

        [DispId(6)]
        INetFwRemoteAdminSettings RemoteAdminSettings
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(7)]
        INetFwIcmpSettings IcmpSettings
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(8)]
        INetFwOpenPorts GloballyOpenPorts
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(9)]
        INetFwServices Services
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(10)]
        INetFwAuthorizedApplications AuthorizedApplications
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
    }


    [ComImport]
    [TypeLibType(4160)]
    [Guid("D4BECDDF-6F73-4A83-B832-9C66874CD20E")]
    public interface INetFwRemoteAdminSettings
    {
        [DispId(1)]
        NET_FW_IP_VERSION_ IpVersion
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [param: In]
            set;
        }

        [DispId(2)]
        NET_FW_SCOPE_ Scope
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            set;
        }

        [DispId(3)]
        string RemoteAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(4)]
        bool Enabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            set;
        }
    }

    [ComImport]
    [TypeLibType(4160)]
    [Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
    public interface INetFwRule
    {
        [DispId(1)]
        string Name
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(2)]
        string Description
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(3)]
        string ApplicationName
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(4)]
        string serviceName
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(5)]
        int Protocol
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            set;
        }

        [DispId(6)]
        string LocalPorts
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(7)]
        string RemotePorts
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(8)]
        string LocalAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(9)]
        string RemoteAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(10)]
        string IcmpTypesAndCodes
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(11)]
        NET_FW_RULE_DIRECTION_ Direction
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(11)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(11)]
            [param: In]
            set;
        }

        [DispId(12)]
        object Interfaces
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(12)]
            //[return: MarshalAs(UnmanagedType.Struct)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(12)]
            [param: In]
            //[param: MarshalAs(UnmanagedType.Struct)]
            set;
        }

        [DispId(13)]
        string InterfaceTypes
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(13)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(13)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(14)]
        bool Enabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(14)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(14)]
            [param: In]
            set;
        }

        [DispId(15)]
        string Grouping
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(15)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(15)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(16)]
        int Profiles
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(16)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(16)]
            [param: In]
            set;
        }

        [DispId(17)]
        bool EdgeTraversal
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(17)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(17)]
            [param: In]
            set;
        }

        [DispId(18)]
        NET_FW_ACTION_ Action
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(18)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(18)]
            [param: In]
            set;
        }
    }

    [ComImport]
    [Guid("9C27C8DA-189B-4DDE-89F7-8B39A316782C")]
    [TypeLibType(4160)]
    public interface INetFwRule2 : INetFwRule
    {
        [DispId(1)]
        new string Name
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(2)]
        new string Description
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(3)]
        new string ApplicationName
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(4)]
        new string serviceName
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(5)]
        new int Protocol
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            set;
        }

        [DispId(6)]
        new string LocalPorts
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(7)]
        new string RemotePorts
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(8)]
        new string LocalAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(9)]
        new string RemoteAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(10)]
        new string IcmpTypesAndCodes
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(11)]
        new NET_FW_RULE_DIRECTION_ Direction
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(11)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(11)]
            [param: In]
            set;
        }

        [DispId(12)]
        new object Interfaces
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(12)]
            //[return: MarshalAs(UnmanagedType.Struct)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(12)]
            [param: In]
            //[param: MarshalAs(UnmanagedType.Struct)]
            set;
        }

        [DispId(13)]
        new string InterfaceTypes
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(13)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(13)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(14)]
        new bool Enabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(14)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(14)]
            [param: In]
            set;
        }

        [DispId(15)]
        new string Grouping
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(15)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(15)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(16)]
        new int Profiles
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(16)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(16)]
            [param: In]
            set;
        }

        [DispId(17)]
        new bool EdgeTraversal
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(17)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(17)]
            [param: In]
            set;
        }

        [DispId(18)]
        new NET_FW_ACTION_ Action
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(18)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(18)]
            [param: In]
            set;
        }

        [DispId(19)]
        int EdgeTraversalOptions
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(19)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(19)]
            [param: In]
            set;
        }
    }

    [ComImport]
    [Guid("B21563FF-D696-4222-AB46-4E89B73AB34A")]
    [TypeLibType(4160)]
    public interface INetFwRule3 : INetFwRule2
    {
        [DispId(1)]
        new string Name
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(2)]
        new string Description
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(3)]
        new string ApplicationName
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(4)]
        new string serviceName
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(5)]
        new int Protocol
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            set;
        }

        [DispId(6)]
        new string LocalPorts
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(7)]
        new string RemotePorts
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(8)]
        new string LocalAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(9)]
        new string RemoteAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(9)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(10)]
        new string IcmpTypesAndCodes
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(10)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(11)]
        new NET_FW_RULE_DIRECTION_ Direction
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(11)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(11)]
            [param: In]
            set;
        }

        [DispId(12)]
        new object Interfaces
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(12)]
            //[return: MarshalAs(UnmanagedType.Struct)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(12)]
            [param: In]
            //[param: MarshalAs(UnmanagedType.Struct)]
            set;
        }

        [DispId(13)]
        new string InterfaceTypes
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(13)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(13)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(14)]
        new bool Enabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(14)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(14)]
            [param: In]
            set;
        }

        [DispId(15)]
        new string Grouping
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(15)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(15)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(16)]
        new int Profiles
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(16)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(16)]
            [param: In]
            set;
        }

        [DispId(17)]
        new bool EdgeTraversal
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(17)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(17)]
            [param: In]
            set;
        }

        [DispId(18)]
        new NET_FW_ACTION_ Action
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(18)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(18)]
            [param: In]
            set;
        }

        [DispId(19)]
        new int EdgeTraversalOptions
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(19)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(19)]
            [param: In]
            set;
        }

        [DispId(20)]
        string LocalAppPackageId
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(20)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(20)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(21)]
        string LocalUserOwner
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(21)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(21)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(22)]
        string LocalUserAuthorizedList
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(22)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(22)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(23)]
        string RemoteUserAuthorizedList
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(23)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(23)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(24)]
        string RemoteMachineAuthorizedList
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(24)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(24)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(25)]
        int SecureFlags
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(25)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(25)]
            [param: In]
            set;
        }
    }

    [ComImport]
    [Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
    [TypeLibType(4160)]
    public interface INetFwRules : IEnumerable
    {
        [DispId(1)]
        int Count
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(2)]
        void Add([In] [MarshalAs(UnmanagedType.Interface)] INetFwRule rule);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(3)]
        void Remove([In] [MarshalAs(UnmanagedType.BStr)] string Name);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(4)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwRule Item([In] [MarshalAs(UnmanagedType.BStr)] string Name);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(-4)]
        [TypeLibFunc(1)]
        [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalType = "System.Runtime.InteropServices.CustomMarshalers.EnumeratorToEnumVariantMarshaler")]
        new IEnumerator GetEnumerator();
    }

    [ComImport]
    [TypeLibType(4160)]
    [Guid("79FD57C8-908E-4A36-9888-D5B3F0A444CF")]
    public interface INetFwService
    {
        [DispId(1)]
        string Name
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }

        [DispId(2)]
        NET_FW_SERVICE_TYPE_ Type
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(2)]
            get;
        }

        [DispId(3)]
        bool Customized
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            get;
        }

        [DispId(4)]
        NET_FW_IP_VERSION_ IpVersion
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(4)]
            [param: In]
            set;
        }

        [DispId(5)]
        NET_FW_SCOPE_ Scope
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(5)]
            [param: In]
            set;
        }

        [DispId(6)]
        string RemoteAddresses
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(6)]
            [param: In]
            [param: MarshalAs(UnmanagedType.BStr)]
            set;
        }

        [DispId(7)]
        bool Enabled
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            get;
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(7)]
            [param: In]
            set;
        }

        [DispId(8)]
        INetFwOpenPorts GloballyOpenPorts
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(8)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
    }

    [ComImport]
    [TypeLibType(4160)]
    [Guid("8267BBE3-F890-491C-B7B6-2DB1EF0E5D2B")]
    public interface INetFwServiceRestriction
    {
        [DispId(3)]
        INetFwRules Rules
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(3)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(1)]
        void RestrictService([In] [MarshalAs(UnmanagedType.BStr)] string serviceName, [In] [MarshalAs(UnmanagedType.BStr)] string appName, [In] bool RestrictService, [In] bool serviceSidRestricted);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(2)]
        bool ServiceRestricted([In] [MarshalAs(UnmanagedType.BStr)] string serviceName, [In] [MarshalAs(UnmanagedType.BStr)] string appName);
    }

    [ComImport]
    [Guid("79649BB4-903E-421B-94C9-79848E79F6EE")]
    [TypeLibType(4160)]
    public interface INetFwServices : IEnumerable
    {
        [DispId(1)]
        int Count
        {
            [MethodImpl(MethodImplOptions.InternalCall)]
            [DispId(1)]
            get;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [DispId(2)]
        [return: MarshalAs(UnmanagedType.Interface)]
        INetFwService Item([In] NET_FW_SERVICE_TYPE_ svcType);

        [MethodImpl(MethodImplOptions.InternalCall)]
        [TypeLibFunc(1)]
        [DispId(-4)]
        [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalType = "System.Runtime.InteropServices.CustomMarshalers.EnumeratorToEnumVariantMarshaler")]
        new IEnumerator GetEnumerator();
    }

    // NetFwTypeLib.NET_FW_ACTION_
    public enum NET_FW_ACTION_
    {
        NET_FW_ACTION_BLOCK,
        NET_FW_ACTION_ALLOW,
        NET_FW_ACTION_MAX
    }

    // NetFwTypeLib.NET_FW_IP_PROTOCOL_
    public enum NET_FW_IP_PROTOCOL_
    {
        NET_FW_IP_PROTOCOL_TCP = 6,
        NET_FW_IP_PROTOCOL_UDP = 17,
        NET_FW_IP_PROTOCOL_ANY = 0x100
    }

    // NetFwTypeLib.NET_FW_IP_VERSION_
    public enum NET_FW_IP_VERSION_
    {
        NET_FW_IP_VERSION_V4,
        NET_FW_IP_VERSION_V6,
        NET_FW_IP_VERSION_ANY,
        NET_FW_IP_VERSION_MAX
    }

    // NetFwTypeLib.NET_FW_MODIFY_STATE_
    public enum NET_FW_MODIFY_STATE_
    {
        NET_FW_MODIFY_STATE_OK,
        NET_FW_MODIFY_STATE_GP_OVERRIDE,
        NET_FW_MODIFY_STATE_INBOUND_BLOCKED
    }

    // NetFwTypeLib.NET_FW_PROFILE_TYPE_
    public enum NET_FW_PROFILE_TYPE_
    {
        NET_FW_PROFILE_DOMAIN,
        NET_FW_PROFILE_STANDARD,
        NET_FW_PROFILE_CURRENT,
        NET_FW_PROFILE_TYPE_MAX
    }

    // NetFwTypeLib.NET_FW_PROFILE_TYPE2_
    public enum NET_FW_PROFILE_TYPE2_
    {
        NET_FW_PROFILE2_DOMAIN = 1,
        NET_FW_PROFILE2_PRIVATE = 2,
        NET_FW_PROFILE2_PUBLIC = 4,
        NET_FW_PROFILE2_ALL = int.MaxValue
    }

    // NetFwTypeLib.NET_FW_RULE_DIRECTION_
    public enum NET_FW_RULE_DIRECTION_
    {
        NET_FW_RULE_DIR_IN = 1,
        NET_FW_RULE_DIR_OUT,
        NET_FW_RULE_DIR_MAX
    }

    // NetFwTypeLib.NET_FW_SCOPE_
    public enum NET_FW_SCOPE_
    {
        NET_FW_SCOPE_ALL,
        NET_FW_SCOPE_LOCAL_SUBNET,
        NET_FW_SCOPE_CUSTOM,
        NET_FW_SCOPE_MAX
    }

    // NetFwTypeLib.NET_FW_SERVICE_TYPE_
    public enum NET_FW_SERVICE_TYPE_
    {
        NET_FW_SERVICE_FILE_AND_PRINT,
        NET_FW_SERVICE_UPNP,
        NET_FW_SERVICE_REMOTE_DESKTOP,
        NET_FW_SERVICE_NONE,
        NET_FW_SERVICE_TYPE_MAX
    }
}
