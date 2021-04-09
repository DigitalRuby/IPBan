using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    [Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
    [ComImport]
    [ComClassProgId("HNetCfg.FwPolicy2")]
    internal interface INetFwPolicy2
    {
        [DispId(1)]
        int CurrentProfileTypes
        {
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
        }

        [DispId(2)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        bool get_FirewallEnabled([In] NetFwProfileType2 profileType);

        [DispId(2)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void set_FirewallEnabled([In] NetFwProfileType2 profileType, [In] bool enabled);

        [DispId(3)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        object get_ExcludedInterfaces([In] NetFwProfileType2 profileType);

        [DispId(3)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void set_ExcludedInterfaces(
            [In] NetFwProfileType2 profileType,
            [In] object interfaces);

        [DispId(4)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        bool get_BlockAllInboundTraffic([In] NetFwProfileType2 profileType);

        [DispId(4)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void set_BlockAllInboundTraffic([In] NetFwProfileType2 profileType, [In] bool block);

        [DispId(5)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        bool get_NotificationsDisabled([In] NetFwProfileType2 profileType);

        [DispId(5)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void set_NotificationsDisabled([In] NetFwProfileType2 profileType, [In] bool disabled);

        [DispId(6)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        bool get_UnicastResponsesToMulticastBroadcastDisabled([In] NetFwProfileType2 profileType);

        [DispId(6)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void set_UnicastResponsesToMulticastBroadcastDisabled(
            [In] NetFwProfileType2 profileType,
            [In] bool disabled
        );

        [DispId(7)]
        INetFwRules Rules
        {
            [DispId(7)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(8)]
        INetFwServiceRestriction ServiceRestriction
        {
            [DispId(8)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }

        [DispId(9)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void EnableRuleGroup(
            [In] int profileTypesBitmask,
            [MarshalAs(UnmanagedType.BStr)][In] string group,
            [In] bool enable
        );

        [DispId(10)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        bool IsRuleGroupEnabled([In] int profileTypesBitmask, [MarshalAs(UnmanagedType.BStr)][In] string group);

        [DispId(11)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void RestoreLocalFirewallDefaults();

        [DispId(12)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        NetFwAction get_DefaultInboundAction([In] NetFwProfileType2 profileType);

        [DispId(12)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void set_DefaultInboundAction([In] NetFwProfileType2 profileType, [In] NetFwAction action);

        [DispId(13)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        NetFwAction get_DefaultOutboundAction([In] NetFwProfileType2 profileType);

        [DispId(13)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void set_DefaultOutboundAction([In] NetFwProfileType2 profileType, [In] NetFwAction action);

        [DispId(14)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        bool get_IsRuleGroupCurrentlyEnabled([MarshalAs(UnmanagedType.BStr)][In] string group);

        [DispId(15)]
        NetFwModifyState LocalPolicyModifyState
        {
            [DispId(15)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            get;
        }
    }
}