/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * Event methods and classes literally pulled from the .NET 4.0 implementation.
 * None of this is original work. It comes straight from decompiled Microsoft
 * assemblies.
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#if NEEDS_EVENT_LOG_TYPES

using Microsoft.Win32.SafeHandles;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace System.Diagnostics.Eventing.Reader
{
    /// <summary>
    /// Defines the default access permissions for the event log. The Application and System values indicate that the log shares the access
    /// control list (ACL) with the appropriate Windows log (the Application or System event logs) and share the Event Tracing for Windows
    /// (ETW) session with other logs of the same isolation. All channels with Custom isolation use a private ETW session.
    /// </summary>
    public enum EventLogIsolation
    {
        /// <summary>
        /// The log shares the access control list with the Application event log and shares the ETW session with other logs that have
        /// Application isolation.
        /// </summary>
        Application,

        /// <summary>
        /// The log shares the access control list with the System event log and shares the ETW session with other logs that have System isolation.
        /// </summary>
        System,

        /// <summary>The event log is a custom event log that uses its own private ETW session.</summary>
        Custom
    }

    /// <summary>
    /// Determines the behavior for the event log service handles an event log when the log reaches its maximum allowed size (when the event
    /// log is full).
    /// </summary>
    public enum EventLogMode
    {
        /// <summary>
        /// New events continue to be stored when the log file is full. Each new incoming event replaces the oldest event in the log.
        /// </summary>
        Circular,

        /// <summary>
        /// Archive the log when full, do not overwrite events. The log is automatically archived when necessary. No events are overwritten.
        /// </summary>
        AutoBackup,

        /// <summary>Do not overwrite events. Clear the log manually rather than automatically.</summary>
        Retain
    }

    /// <summary>Defines the type of events that are logged in an event log. Each log can only contain one type of event.</summary>
    public enum EventLogType
    {
        /// <summary>
        /// These events are primarily for end users, administrators, and support. The events that are found in the Administrative type logs
        /// indicate a problem and a well-defined solution that an administrator can act on. An example of an administrative event is an
        /// event that occurs when an application fails to connect to a printer.
        /// </summary>
        Administrative,

        /// <summary>
        /// Events in an operational type event log are used for analyzing and diagnosing a problem or occurrence. They can be used to
        /// trigger tools or tasks based on the problem or occurrence. An example of an operational event is an event that occurs when a
        /// printer is added or removed from a system.
        /// </summary>
        Operational,

        /// <summary>
        /// Events in an analytic event log are published in high volume. They describe program operation and indicate problems that cannot
        /// be handled by user intervention.
        /// </summary>
        Analytical,

        /// <summary>Events in a debug type event log are used solely by developers to diagnose a problem for debugging.</summary>
        Debug
    }

    /// <summary>Specifies that a string contains a name of an event log or the file system path to an event log file.</summary>
    public enum PathType
    {
        /// <summary>A path parameter contains the file system path to an event log file.</summary>
        FilePath = 2,

        /// <summary>A path parameter contains the name of the event log.</summary>
        LogName = 1
    }

    /// <summary>
    /// Defines values for the type of authentication used during a Remote Procedure Call (RPC) login to a server. This login occurs when you
    /// create a EventLogSession object that specifies a connection to a remote computer.
    /// </summary>
    public enum SessionAuthentication
    {
        /// <summary>Use the default authentication method during RPC login. The default authentication is equivalent to Negotiate.</summary>
        Default,

        /// <summary>
        /// Use the Negotiate authentication method during RPC login. This allows the client application to select the most appropriate
        /// authentication method (NTLM or Kerberos) for the situation.
        /// </summary>
        Negotiate,

        /// <summary>Use Kerberos authentication during RPC login.</summary>
        Kerberos,

        /// <summary>Use Windows NT LAN Manager (NTLM) authentication during RPC login.</summary>
        Ntlm
    }

    /// <summary>
    /// Defines the standard keywords that are attached to events by the event provider. For more information about keywords, see <see cref="EventKeyword"/>.
    /// </summary>
    [Flags]
    public enum StandardEventKeywords : long
    {
        /// <summary>This value indicates that no filtering on keyword is performed when the event is published.</summary>
        None = 0L,

        /// <summary>Attached to all failed security audit events. This keyword should only be used for events in the Security log.</summary>
        AuditFailure = 0x10000000000000L,

        /// <summary>Attached to all successful security audit events. This keyword should only be used for events in the Security log.</summary>
        AuditSuccess = 0x20000000000000L,

        /// <summary>
        /// Attached to transfer events where the related Activity ID (Correlation ID) is a computed value and is not guaranteed to be unique
        /// (not a real GUID).
        /// </summary>
        [Obsolete("Incorrect value: use CorrelationHint2 instead", false)]
        CorrelationHint = 0x10000000000000L,

        /// <summary>
        /// Attached to transfer events where the related Activity ID (Correlation ID) is a computed value and is not guaranteed to be unique
        /// (not a real GUID).
        /// </summary>
        CorrelationHint2 = 0x40000000000000L,

        /// <summary>Attached to events which are raised using the RaiseEvent function.</summary>
        EventLogClassic = 0x80000000000000L,

        /// <summary>Attached to all response time events.</summary>
        ResponseTime = 0x01000000000000L,

        /// <summary>Attached to all Service Quality Mechanism (SQM) events.</summary>
        Sqm = 0x08000000000000L,

        /// <summary>Attached to all Windows Diagnostic Infrastructure (WDI) context events.</summary>
        WdiContext = 0x02000000000000L,

        /// <summary>Attached to all Windows Diagnostic Infrastructure (WDI) diagnostic events.</summary>
        WdiDiagnostic = 0x04000000000000L
    }

    /// <summary>
    /// Defines the standard event levels that are used in the Event Log service. The level defines the severity of the event. Custom event
    /// levels can be defined beyond these standard levels. For more information about levels, see <see cref="EventLevel"/>.
    /// </summary>
    public enum StandardEventLevel
    {
        /// <summary>This value indicates that not filtering on the level is done during the event publishing.</summary>
        LogAlways = 0,

        /// <summary>This level corresponds to critical errors, which is a serious error that has caused a major failure.</summary>
        Critical,

        /// <summary>This level corresponds to normal errors that signify a problem.</summary>
        Error,

        /// <summary>
        /// This level corresponds to warning events. For example, an event that gets published because a disk is nearing full capacity is a
        /// warning event.
        /// </summary>
        Warning,

        /// <summary>
        /// This level corresponds to informational events or messages that are not errors. These events can help trace the progress or state
        /// of an application.
        /// </summary>
        Informational,

        /// <summary>This level corresponds to lengthy events or messages.</summary>
        Verbose
    }

    /// <summary>
    /// Defines the standard opcodes that are attached to events by the event provider. For more information about opcodes, see <see cref="EventOpcode"/>.
    /// </summary>
    public enum StandardEventOpcode
    {
        /// <summary>An event with this opcode is an informational event.</summary>
        Info = 0,

        /// <summary>
        /// An event with this opcode is published when an application starts a new transaction or activity. This can be embedded into
        /// another transaction or activity when multiple events with the Start opcode follow each other without an event with a Stop opcode.
        /// </summary>
        Start,

        /// <summary>
        /// An event with this opcode is published when an activity or a transaction in an application ends. The event corresponds to the
        /// last unpaired event with a Start opcode.
        /// </summary>
        Stop,

        /// <summary>An event with this opcode is a trace collection start event.</summary>
        DataCollectionStart,

        /// <summary>An event with this opcode is a trace collection stop event.</summary>
        DataCollectionStop,

        /// <summary>An event with this opcode is an extension event.</summary>
        Extension,

        /// <summary>An event with this opcode is published after an activity in an application replies to an event.</summary>
        Reply,

        /// <summary>
        /// An event with this opcode is published after an activity in an application resumes from a suspended state. The event should
        /// follow an event with the Suspend opcode.
        /// </summary>
        Resume,

        /// <summary>An event with this opcode is published when an activity in an application is suspended.</summary>
        Suspend,

        /// <summary>
        /// An event with this opcode is published when one activity in an application transfers data or system resources to another activity.
        /// </summary>
        Send,

        /// <summary>An event with this opcode is published when one activity in an application receives data.</summary>
        Receive = 240
    }

    /// <summary>
    /// Defines the standard tasks that are attached to events by the event provider. For more information about tasks, see <see cref="EventTask"/>.
    /// </summary>
    public enum StandardEventTask
    {
        /// <summary>No task is used to identify a portion of an application that publishes an event.</summary>
        None = 0
    }

    /// <summary>
    /// Represents a placeholder (bookmark) within an event stream. You can use the placeholder to mark a position and return to this
    /// position in a stream of events. An instance of this object can be obtained from an EventRecord object, in which case it corresponds
    /// to the position of that event record.
    /// </summary>
    [Serializable]
    public class EventBookmark : ISerializable
    {
        internal EventBookmark(string bookmarkText) => BookmarkText = bookmarkText ?? throw new ArgumentNullException(nameof(bookmarkText));

        /// <summary>
        /// Initializes a new instance of the <see cref="EventBookmark"/> class from the specified <see cref="SerializationInfo"/> and <see
        /// cref="StreamingContext"/> instances.
        /// </summary>
        /// <param name="info">
        /// A <see cref="SerializationInfo"/> object that contains the information required to serialize the new <see cref="EventBookmark"/> object.
        /// </param>
        /// <param name="context">
        /// A <see cref="StreamingContext"/> object that contains the source of the serialized stream that is associated with the new <see cref="EventBookmark"/>.
        /// </param>
        protected EventBookmark(SerializationInfo info, StreamingContext context)
        {
            if (info is null)
                throw new ArgumentNullException(nameof(info));
            BookmarkText = info.GetString("BookmarkText");
        }

        internal string BookmarkText { get; private set; }

        /// <summary>Populates a <see cref="SerializationInfo"/> object with the data required to serialize the target object.</summary>
        /// <param name="info">The <see cref="SerializationInfo"/> object to populate with data.</param>
        /// <param name="context">The destination for this serialization.</param>
        [SecurityCritical, SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)]
        void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context) => GetObjectData(info, context);

        /// <summary>Populates a <see cref="SerializationInfo"/> object with the data required to serialize the target object.</summary>
        /// <param name="info">The <see cref="SerializationInfo"/> object to populate with data.</param>
        /// <param name="context">The destination for this serialization.</param>
        [SecurityCritical, SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)]
        protected virtual void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info is null)
                throw new ArgumentNullException(nameof(info));
            info.AddValue("BookmarkText", BookmarkText);
        }
    }

    /// <summary>
    /// Represents a keyword for an event. Keywords are defined in an event provider and are used to group the event with other similar
    /// events (based on the usage of the events).
    /// </summary>
    /// <remarks>
    /// This class cannot be instantiated. A <see cref="ProviderMetadata"/> object defies a list of <see cref="EventKeyword"/> objects, one
    /// for each keyword used by the provider events. Each keyword is a bit in a 64-bit mask. Predefined bit values and reserved bits occupy
    /// the top 16 positions of this mask, leaving the manifest to use any bits between 0x0000000000000001 and 0x0000800000000000.
    /// <para>The standard event keywords are defined in the <see cref="StandardEventKeywords"/> enumeration.</para>
    /// </remarks>
    public sealed class EventKeyword
    {
        private readonly object syncObject;
        private bool dataReady;
        private string displayName;
        private string name;
        private ProviderMetadata pmReference;

        internal EventKeyword(long value, ProviderMetadata pmReference)
        {
            Value = value;
            this.pmReference = pmReference;
            syncObject = new object();
        }

        internal EventKeyword(string name, long value, string displayName)
        {
            Value = value;
            this.name = name;
            this.displayName = displayName;
            dataReady = true;
            syncObject = new object();
        }

        /// <summary>Gets the localized name of the keyword.</summary>
        /// <value>Returns a string that contains a localized name for this keyword.</value>
        public string DisplayName
        {
            get
            {
                PrepareData();
                return displayName;
            }
        }

        /// <summary>Gets the non-localized name of the keyword.</summary>
        /// <value>Returns a string that contains the non-localized name of this keyword.</value>
        public string Name
        {
            get
            {
                PrepareData();
                return name;
            }
        }

        /// <summary>Gets the numeric value associated with the keyword.</summary>
        /// <value>
        /// Returns a
        /// <code>
        /// long
        /// </code>
        /// value.
        /// </value>
        /// <remarks>
        /// Each keyword is a bit in a 64-bit mask. Predefined bit values and reserved bits occupy the top 16 positions of this mask, leaving
        /// the manifest to use any bits between 0x0000000000000001 and 0x0000800000000000.
        /// </remarks>
        public long Value { get; private set; }

        internal void PrepareData()
        {
            if (!dataReady)
            {
                lock (syncObject)
                {
                    if (!dataReady)
                    {
                        IEnumerable<EventKeyword> keywords = pmReference.Keywords;
                        name = null;
                        displayName = null;
                        dataReady = true;
                        foreach (var keyword in keywords)
                        {
                            if (keyword.Value == Value)
                            {
                                name = keyword.Name;
                                displayName = keyword.DisplayName;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// <summary>Contains an event level that is defined in an event provider. The level signifies the severity of the event.</summary>
    /// <remarks>
    /// This class cannot be instantiated. A <see cref="ProviderMetadata"/> object defies a list of <see cref="EventLevel"/> objects, one for
    /// each level defined in the provider. The standard level values and their meanings are defined in the <see cref="StandardEventLevel"/> enumeration.
    /// </remarks>
    public sealed class EventLevel
    {
        private readonly object syncObject;
        private bool dataReady;
        private string displayName;
        private string name;
        private ProviderMetadata pmReference;

        internal EventLevel(int value, ProviderMetadata pmReference)
        {
            Value = value;
            this.pmReference = pmReference;
            syncObject = new object();
        }

        internal EventLevel(string name, int value, string displayName)
        {
            Value = value;
            this.name = name;
            this.displayName = displayName;
            dataReady = true;
            syncObject = new object();
        }

        /// <summary>
        /// Gets the localized name for the event level. The name describes what severity level of events this level is used for.
        /// </summary>
        /// <value>Returns a string that contains the localized name for the event level.</value>
        public string DisplayName
        {
            get
            {
                PrepareData();
                return displayName;
            }
        }

        /// <summary>Gets the non-localized name of the event level.</summary>
        /// <value>Returns a string that contains the non-localized name of the event level.</value>
        public string Name
        {
            get
            {
                PrepareData();
                return name;
            }
        }

        /// <summary>Gets the numeric value of the event level.</summary>
        /// <value>Returns an integer value.</value>
        public int Value { get; private set; }

        internal void PrepareData()
        {
            if (!dataReady)
            {
                lock (syncObject)
                {
                    if (!dataReady)
                    {
                        IEnumerable<EventLevel> levels = pmReference.Levels;
                        name = null;
                        displayName = null;
                        dataReady = true;
                        foreach (var level in levels)
                        {
                            if (level.Value == Value)
                            {
                                name = level.Name;
                                displayName = level.DisplayName;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// <summary>
    /// Contains static information and configuration settings for an event log. Many of the configurations settings were defined by the
    /// event provider that created the log.
    /// </summary>
    /// <example>
    /// For example code using this class, see <a href="https://msdn.microsoft.com/library/2d2b00b3-2d1d-4567-a47e-3f5a7c1955ac">How to:
    /// Configure and Read Event Log Properties.</a>
    /// </example>
    /// <remarks>If a property is changed for this object, call the <see cref="SaveChanges"/> method to save the changes.</remarks>
    public class EventLogConfiguration : IDisposable
    {
        private readonly EventLogSession session;
        private EventLogHandle handle;

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogConfiguration"/> class by specifying the local event log for which to get
        /// information and configuration settings..
        /// </summary>
        /// <param name="logName">The name of the local event log for which to get information and configuration settings.</param>
        public EventLogConfiguration(string logName) : this(logName, null) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogConfiguration"/> class by specifying the name of the log for which to get
        /// information and configuration settings. The log can be on the local computer or a remote computer, based on the event log session specified.
        /// </summary>
        /// <param name="logName">The name of the event log for which to get information and configuration settings.</param>
        /// <param name="session">
        /// The event log session used to determine the event log service that the specified log belongs to. The session is either connected
        /// to the event log service on the local computer or a remote computer.
        /// </param>
        [SecurityCritical]
        public EventLogConfiguration(string logName, EventLogSession session = null)
        {
            handle = EventLogHandle.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            this.session = session ?? EventLogSession.GlobalSession;
            LogName = logName;
            handle = NativeWrapper.EvtOpenChannelConfig(this.session.Handle, LogName, 0);
        }

        /// <summary>
        /// Gets the flag that indicates if the event log is a classic event log. A classic event log is one that has its events defined in a
        /// .mc file instead of a manifest (.xml file) used by the event provider.
        /// </summary>
        /// <value>Returns <c>true</c> if the event log is a classic log; otherwise, <c>false</c>.</value>
        public bool IsClassicLog => (bool)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigClassicEventlog);

        /// <summary>
        /// Gets or sets a Boolean value that determines whether the event log is enabled or disabled. An enabled log is one in which events
        /// can be logged, and a disabled log is one in which events cannot be logged.
        /// </summary>
        /// <value>Returns <see langword="true"/> if the log is enabled, and returns <see langword="false"/> if the log is disabled.</value>
        /// <remarks>If the value of this property is changed, call the <see cref="SaveChanges"/> method to save the changes.</remarks>
        public bool IsEnabled
        {
            get => (bool)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigEnabled);
            set => NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigEnabled, value);
        }

        /// <summary>Gets or sets the file directory path to the location of the file where the events are stored for the log.</summary>
        /// <value>Returns a string that contains the path to the event log file.</value>
        /// <remarks>If the value of this property is changed, call the <see cref="SaveChanges"/> method to save the changes.</remarks>
        public string LogFilePath
        {
            get => (string)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigLogFilePath);
            set => NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigLogFilePath, value);
        }

        /// <summary>
        /// Gets an <see cref="EventLogIsolation"/> value that specifies whether the event log is an application, system, or custom event log.
        /// </summary>
        /// <value>Returns an <see cref="EventLogIsolation"/> value.</value>
        public EventLogIsolation LogIsolation => (EventLogIsolation)(uint)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigIsolation);

        /// <summary>
        /// Gets or sets an <see cref="EventLogMode"/> value that determines how events are handled when the event log becomes full.
        /// </summary>
        /// <value>Returns an <see cref="EventLogMode"/> value.</value>
        public EventLogMode LogMode
        {
            get
            {
                var obj2 = NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigRetention);
                var obj3 = NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigAutoBackup);
                var flag = obj2 != null && (bool)obj2;
                if (obj3 != null && (bool)obj3)
                {
                    return EventLogMode.AutoBackup;
                }
                return flag ? EventLogMode.Retain : EventLogMode.Circular;
            }
            set
            {
                switch (value)
                {
                    case EventLogMode.Circular:
                        NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigAutoBackup, false);
                        NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigRetention, false);
                        return;

                    case EventLogMode.AutoBackup:
                        NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigAutoBackup, true);
                        NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigRetention, true);
                        return;

                    case EventLogMode.Retain:
                        NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigAutoBackup, false);
                        NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigRetention, true);
                        return;
                }
            }
        }

        /// <summary>Gets the name of the event log.</summary>
        /// <value>Returns a string that contains the name of the event log.</value>
        public string LogName { get; private set; }

        /// <summary>Gets an <see cref="EventLogType"/> value that determines the type of the event log.</summary>
        /// <value>Returns an <see cref="EventLogType"/> value.</value>
        public EventLogType LogType => (EventLogType)(uint)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigType);

        /// <summary>
        /// Gets or sets the maximum size, in bytes, that the event log file is allowed to be. When the file reaches this maximum size, it is
        /// considered full.
        /// </summary>
        /// <value>Returns a long value that represents the maximum size, in bytes, that the event log file is allowed to be.</value>
        /// <remarks>If the value of this property is changed, call the <see cref="SaveChanges"/> method to save the changes.</remarks>
        public long MaximumSizeInBytes
        {
            get => (long)(ulong)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigMaxSize);
            set => NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigMaxSize, value);
        }

        /// <summary>Gets the name of the event provider that created this event log.</summary>
        /// <value>Returns a string that contains the name of the event provider that created this event log.</value>
        public string OwningProviderName => (string)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigOwningPublisher);

        /// <summary>Gets the size of the buffer that the event provider uses for publishing events to the log.</summary>
        /// <value>Returns an integer value that can be null.</value>
        public int? ProviderBufferSize
        {
            get
            {
                var nullable = (uint?)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigBufferSize);
                return !nullable.HasValue ? null : new int?((int)nullable.GetValueOrDefault());
            }
        }

        /// <summary>
        /// Gets the control globally unique identifier (GUID) for the event log if the log is a debug log. If this log is not a debug log,
        /// this value will be null.
        /// </summary>
        /// <value>Returns a GUID value or null.</value>
        public Guid? ProviderControlGuid => (Guid?)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigControlGuid);

        /// <summary>Gets or sets keyword mask used by the event provider.</summary>
        /// <value>Returns a long value that can be null if the event provider did not define any keywords.</value>
        /// <remarks>If the value of this property is changed, call the <see cref="SaveChanges"/> method to save the changes.</remarks>
        public long? ProviderKeywords
        {
            get
            {
                var nullable = (ulong?)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigKeywords);
                return !nullable.HasValue ? null : new long?((long)nullable.GetValueOrDefault());
            }
            set => NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigKeywords, value);
        }

        /// <summary>Gets the maximum latency time used by the event provider when publishing events to the log.</summary>
        /// <value>Returns an integer value that can be null if no latency time was specified by the event provider.</value>
        public int? ProviderLatency
        {
            get
            {
                var nullable = (uint?)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigLatency);
                return !nullable.HasValue ? null : new int?((int)nullable.GetValueOrDefault());
            }
        }

        /// <summary>
        /// Gets or sets the maximum event level (which defines the severity of the event) that is allowed to be logged in the event log.
        /// This value is defined by the event provider.
        /// </summary>
        /// <value>Returns an integer value that can be null if the maximum event level was not defined in the event provider.</value>
        /// <remarks>If the value of this property is changed, call the <see cref="SaveChanges"/> method to save the changes.</remarks>
        public int? ProviderLevel
        {
            get
            {
                var nullable = (uint?)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigLevel);
                return !nullable.HasValue ? null : new int?((int)nullable.GetValueOrDefault());
            }
            set => NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigLevel, value);
        }

        /// <summary>Gets the maximum number of buffers used by the event provider to publish events to the event log.</summary>
        /// <value>
        /// Returns an integer value that is the maximum number of buffers used by the event provider to publish events to the event log.
        /// This value can be null.
        /// </value>
        public int? ProviderMaximumNumberOfBuffers
        {
            get
            {
                var nullable = (uint?)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigMaxBuffers);
                return !nullable.HasValue ? null : new int?((int)nullable.GetValueOrDefault());
            }
        }

        /// <summary>Gets the minimum number of buffers used by the event provider to publish events to the event log.</summary>
        /// <value>
        /// Returns an integer value that is the minimum number of buffers used by the event provider to publish events to the event log.
        /// This value can be null.
        /// </value>
        public int? ProviderMinimumNumberOfBuffers
        {
            get
            {
                var nullable = (uint?)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigMinBuffers);
                return !nullable.HasValue ? null : new int?((int)nullable.GetValueOrDefault());
            }
        }

        /// <summary>Gets an enumerable collection of the names of all the event providers that can publish events to this event log.</summary>
        /// <value>Returns an enumerable collection of strings that contain the event provider names.</value>
        public IEnumerable<string> ProviderNames => (string[])NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublisherList);

        /// <summary>
        /// Gets or sets the security descriptor of the event log. The security descriptor defines the users and groups of users that can
        /// read and write to the event log.
        /// </summary>
        /// <value>Returns a string that contains the security descriptor for the event log.</value>
        /// <remarks>If the value of this property is changed, call the <see cref="SaveChanges"/> method to save the changes.</remarks>
        public string SecurityDescriptor
        {
            get => (string)NativeWrapper.EvtGetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigAccess);
            set => NativeWrapper.EvtSetChannelConfigProperty(handle, UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigAccess, value);
        }

        /// <summary>Releases all the resources used by this object.</summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Saves the configuration settings.</summary>
        public void SaveChanges() => NativeWrapper.EvtSaveChannelConfig(handle, 0);

        /// <summary>Releases the unmanaged resources used by this object, and optionally releases the managed resources.</summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.
        /// </param>
        [SecuritySafeCritical]
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                EventLogPermissionHolder.GetEventLogPermission().Demand();
            }
            if (handle != null && !handle.IsInvalid)
            {
                handle.Dispose();
            }
        }
    }

    /// <summary>
    /// Represents the base class for all the exceptions that are thrown when an error occurs while reading event log related information.
    /// </summary>
    /// <seealso cref="System.Exception"/>
    /// <seealso cref="System.Runtime.Serialization.ISerializable"/>
    [Serializable]
    public class EventLogException : Exception, ISerializable
    {
        private readonly int errorCode;

        /// <summary>Initializes a new instance of the <see cref="EventLogException"/> class.</summary>
        public EventLogException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogException"/> class by specifying the error message that describes the
        /// current exception.
        /// </summary>
        /// <param name="message">The error message that describes the current exception.</param>
        public EventLogException(string message)
            : base(message)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogException"/> class with an error message and inner exception.</summary>
        /// <param name="message">The error message that describes the current exception.</param>
        /// <param name="innerException">The Exception instance that caused the current exception.</param>
        public EventLogException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogException"/> class with the error code for the exception.</summary>
        /// <param name="errorCode">
        /// The error code for the error that occurred while reading or configuring event log related information. For more information and a
        /// list of event log related error codes, see http://go.microsoft.com/fwlink/?LinkId=82629.
        /// </param>
        protected EventLogException(int errorCode) => this.errorCode = errorCode;

        /// <summary>Initializes a new instance of the <see cref="EventLogException"/> class with serialized data.</summary>
        /// <param name="serializationInfo">
        /// The <see cref="SerializationInfo"/> object that holds the serialized object data about the exception being thrown.
        /// </param>
        /// <param name="streamingContext">
        /// The <see cref="StreamingContext"/> object that contains contextual information about the source or destination.
        /// </param>
        protected EventLogException(SerializationInfo serializationInfo, StreamingContext streamingContext)
            : base(serializationInfo, streamingContext)
        {
        }

        /// <summary>Gets the error message that describes the current exception.</summary>
        /// <value>Returns a string that contains the error message that describes the current exception.</value>
        public override string Message
        {
            [SecurityCritical]
            get
            {
                EventLogPermissionHolder.GetEventLogPermission().Demand();
                var exception = new Win32Exception(errorCode);
                return exception.Message;
            }
        }

        /// <summary>Sets the SerializationInfo object with information about the exception.</summary>
        /// <param name="info">
        /// The <see cref="SerializationInfo"/> object that holds the serialized object data about the exception being thrown.
        /// </param>
        /// <param name="context">The <see cref="StreamingContext"/> object that contains contextual information about the source or destination.</param>
        /// <exception cref="System.ArgumentNullException">info</exception>
        [SecurityCritical, SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info is null)
            {
                throw new ArgumentNullException(nameof(info));
            }
            info.AddValue("errorCode", errorCode);
            base.GetObjectData(info, context);
        }

        internal static void Throw(int errorCode)
        {
            switch (errorCode)
            {
                case 0x4c7:
                case 0x71a:
                    throw new OperationCanceledException();

                case 2:
                case 3:
                case 0x3a9f:
                case 0x3a9a:
                case 0x3ab3:
                case 0x3ab4:
                    throw new EventLogNotFoundException(errorCode);

                case 5:
                    throw new UnauthorizedAccessException();

                case 13:
                case 0x3a9d:
                    throw new EventLogInvalidDataException(errorCode);

                case 0x3aa3:
                case 0x3aa4:
                    throw new EventLogReadingException(errorCode);

                case 0x3abd:
                    throw new EventLogProviderDisabledException(errorCode);
            }
            throw new EventLogException(errorCode);
        }
    }

    /// <summary>
    /// Allows you to access the run-time properties of active event logs and event log files. These properties include the number of events
    /// in the log, the size of the log, a value that determines whether the log is full, and the last time the log was written to or accessed.
    /// </summary>
    public sealed class EventLogInformation
    {
        [SecurityCritical]
        internal EventLogInformation(EventLogSession session, string channelName, PathType pathType)
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var handle = NativeWrapper.EvtOpenLog(session.Handle, channelName, pathType);
            using (handle)
            {
                CreationTime = (DateTime?)NativeWrapper.EvtGetLogInfo(handle, UnsafeNativeMethods.EvtLogPropertyId.EvtLogCreationTime);
                LastAccessTime = (DateTime?)NativeWrapper.EvtGetLogInfo(handle, UnsafeNativeMethods.EvtLogPropertyId.EvtLogLastAccessTime);
                LastWriteTime = (DateTime?)NativeWrapper.EvtGetLogInfo(handle, UnsafeNativeMethods.EvtLogPropertyId.EvtLogLastWriteTime);
                var nullable = (ulong?)NativeWrapper.EvtGetLogInfo(handle, UnsafeNativeMethods.EvtLogPropertyId.EvtLogFileSize);
                FileSize = nullable.HasValue ? (long?)nullable.GetValueOrDefault() : null;
                var nullable3 = (uint?)NativeWrapper.EvtGetLogInfo(handle, UnsafeNativeMethods.EvtLogPropertyId.EvtLogAttributes);
                Attributes = nullable3.HasValue ? (int?)nullable3.GetValueOrDefault() : null;
                var nullable5 = (ulong?)NativeWrapper.EvtGetLogInfo(handle, UnsafeNativeMethods.EvtLogPropertyId.EvtLogNumberOfLogRecords);
                RecordCount = nullable5.HasValue ? (long?)nullable5.GetValueOrDefault() : null;
                var nullable7 = (ulong?)NativeWrapper.EvtGetLogInfo(handle, UnsafeNativeMethods.EvtLogPropertyId.EvtLogOldestRecordNumber);
                OldestRecordNumber = nullable7.HasValue ? (long?)nullable7.GetValueOrDefault() : null;
                IsLogFull = (bool?)NativeWrapper.EvtGetLogInfo(handle, UnsafeNativeMethods.EvtLogPropertyId.EvtLogFull);
            }
        }

        /// <summary>Gets the file attributes of the log file associated with the log.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public int? Attributes { get; private set; }

        /// <summary>Gets the time that the log file associated with the event log was created.</summary>
        /// <value>Returns a <see cref="DateTime"/> object. This value can be null.</value>
        public DateTime? CreationTime { get; private set; }

        /// <summary>Gets the size of the file, in bytes, associated with the event log.</summary>
        /// <value>Returns a long value.</value>
        public long? FileSize { get; private set; }

        /// <summary>Gets a Boolean value that determines whether the log file has reached its maximum size (the log is full).</summary>
        /// <value>Returns <see langword="true"/> if the log is full, and returns <see langword="false"/> if the log is not full.</value>
        public bool? IsLogFull { get; private set; }

        /// <summary>Gets the last time the log file associated with the event log was accessed.</summary>
        /// <value>Returns a <see cref="DateTime"/> object. This value can be null.</value>
        public DateTime? LastAccessTime { get; private set; }

        /// <summary>Gets the last time data was written to the log file associated with the event log.</summary>
        /// <value>Returns a <see cref="DateTime"/> object. This value can be null.</value>
        public DateTime? LastWriteTime { get; private set; }

        /// <summary>Gets the number of the oldest event record in the event log.</summary>
        /// <value>Returns a long value that represents the number of the oldest event record in the event log. This value can be null.</value>
        public long? OldestRecordNumber { get; private set; }

        /// <summary>Gets the number of event records in the event log.</summary>
        /// <value>Returns a long value that represents the number of event records in the event log. This value can be null.</value>
        public long? RecordCount { get; private set; }
    }

    /// <summary>Represents the exception thrown when an event provider publishes invalid data in an event.</summary>
    [Serializable]
    public class EventLogInvalidDataException : EventLogException
    {
        /// <summary>Initializes a new instance of the <see cref="EventLogInvalidDataException"/> class.</summary>
        public EventLogInvalidDataException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogInvalidDataException"/> class by specifying the error message that describes
        /// the current exception.
        /// </summary>
        /// <param name="message">The error message that describes the current exception.</param>
        public EventLogInvalidDataException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogInvalidDataException"/> class with an error message and inner exception.
        /// </summary>
        /// <param name="message">The error message that describes the current exception.</param>
        /// <param name="innerException">The Exception instance that caused the current exception.</param>
        public EventLogInvalidDataException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogInvalidDataException"/> class.</summary>
        /// <param name="errorCode">
        /// The error code for the error that occurred while reading or configuring event log related information. For more information and a
        /// list of event log related error codes, see http://go.microsoft.com/fwlink/?LinkId=82629.
        /// </param>
        internal EventLogInvalidDataException(int errorCode)
            : base(errorCode)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogInvalidDataException"/> class.</summary>
        /// <param name="serializationInfo">
        /// The <see cref="SerializationInfo"/> object that holds the serialized object data about the exception being thrown.
        /// </param>
        /// <param name="streamingContext">
        /// The <see cref="StreamingContext"/> object that contains contextual information about the source or destination.
        /// </param>
        protected EventLogInvalidDataException(SerializationInfo serializationInfo, StreamingContext streamingContext)
            : base(serializationInfo, streamingContext)
        {
        }
    }

    /// <summary>
    /// Represents a link between an event provider and an event log that the provider publishes events into. This object cannot be instantiated.
    /// </summary>
    public sealed class EventLogLink
    {
        private readonly object syncObject;
        private string channelName;
        private bool dataReady;
        private string displayName;
        private bool isImported;
        private ProviderMetadata pmReference;

        internal EventLogLink(uint channelId, ProviderMetadata pmReference)
        {
            ChannelId = channelId;
            this.pmReference = pmReference;
            syncObject = new object();
        }

        internal EventLogLink(string channelName, bool isImported, string displayName, uint channelId)
        {
            this.channelName = channelName;
            this.isImported = isImported;
            this.displayName = displayName;
            ChannelId = channelId;
            dataReady = true;
            syncObject = new object();
        }

        /// <summary>Gets the localized name of the event log.</summary>
        /// <value>Returns a string that contains the localized name of the event log.</value>
        public string DisplayName
        {
            get
            {
                PrepareData();
                return displayName;
            }
        }

        /// <summary>
        /// Gets a Boolean value that determines whether the event log is imported, rather than defined in the event provider.An imported
        /// event log is defined in a different provider.
        /// </summary>
        /// <value>
        /// Returns <see langword="true"/> if the event log is imported by the event provider, and returns <see langword="false"/> if the
        /// event log is not imported by the event provider.
        /// </value>
        public bool IsImported
        {
            get
            {
                PrepareData();
                return isImported;
            }
        }

        /// <summary>Gets the non-localized name of the event log associated with this object.</summary>
        /// <value>Returns a string that contains the non-localized name of the event log associated with this object.</value>
        public string LogName
        {
            get
            {
                PrepareData();
                return channelName;
            }
        }

        internal uint ChannelId { get; private set; }

        private void PrepareData()
        {
            if (!dataReady)
            {
                lock (syncObject)
                {
                    if (!dataReady)
                    {
                        IEnumerable<EventLogLink> logLinks = pmReference.LogLinks;
                        channelName = null;
                        isImported = false;
                        displayName = null;
                        dataReady = true;
                        foreach (var link in logLinks)
                        {
                            if (link.ChannelId == ChannelId)
                            {
                                channelName = link.LogName;
                                isImported = link.IsImported;
                                displayName = link.DisplayName;
                                dataReady = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// <summary>
    /// Represents the exception that is thrown when a requested event log (usually specified by the name of the event log or the path to the
    /// event log file) does not exist.
    /// </summary>
    [Serializable]
    public class EventLogNotFoundException : EventLogException
    {
        /// <summary>Initializes a new instance of the <see cref="EventLogNotFoundException"/> class.</summary>
        public EventLogNotFoundException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogNotFoundException"/> class by specifying the error message that describes
        /// the current exception.
        /// </summary>
        /// <param name="message">The error message that describes the current exception.</param>
        public EventLogNotFoundException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogNotFoundException"/> class with an error message and inner exception.
        /// </summary>
        /// <param name="message">The error message that describes the current exception.</param>
        /// <param name="innerException">The Exception instance that caused the current exception.</param>
        public EventLogNotFoundException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogNotFoundException"/> class.</summary>
        /// <param name="errorCode">
        /// The error code for the error that occurred while reading or configuring event log related information. For more information and a
        /// list of event log related error codes, see http://go.microsoft.com/fwlink/?LinkId=82629.
        /// </param>
        internal EventLogNotFoundException(int errorCode)
            : base(errorCode)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogNotFoundException"/> class with serialized data.</summary>
        /// <param name="serializationInfo">
        /// The <see cref="SerializationInfo"/> object that holds the serialized object data about the exception being thrown.
        /// </param>
        /// <param name="streamingContext">
        /// The <see cref="StreamingContext"/> object that contains contextual information about the source or destination.
        /// </param>
        protected EventLogNotFoundException(SerializationInfo serializationInfo, StreamingContext streamingContext)
            : base(serializationInfo, streamingContext)
        {
        }
    }

    /// <summary>
    /// Contains an array of strings that represent XPath queries for elements in the XML representation of an event, which is based on the
    /// Event Schema. The queries in this object are used to extract values from the event.
    /// </summary>
    /// <remarks>
    /// This object can keep the string to be used as required or preprocess the strings to prepare them for extraction. This preparation can
    /// be done before an event processing loop.
    /// </remarks>
    /// <seealso cref="System.IDisposable"/>
    public class EventLogPropertySelector : IDisposable
    {
        /// <summary>Initializes a new instance of the <see cref="EventLogPropertySelector"/> class.</summary>
        /// <param name="propertyQueries">XPath queries used to extract values from the XML representation of the event.</param>
        [SecurityCritical]
        public EventLogPropertySelector(IEnumerable<string> propertyQueries)
        {
            string[] strArray;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            if (propertyQueries is null)
            {
                throw new ArgumentNullException(nameof(propertyQueries));
            }
            if (propertyQueries is ICollection<string> is2)
            {
                strArray = new string[is2.Count];
                is2.CopyTo(strArray, 0);
            }
            else
            {
                strArray = new List<string>(propertyQueries).ToArray();
            }
            Handle = NativeWrapper.EvtCreateRenderContext(strArray.Length, strArray, UnsafeNativeMethods.EvtRenderContextFlags.EvtRenderContextValues);
        }

        internal EventLogHandle Handle { get; private set; }

        /// <summary>Releases all the resources used by this object.</summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Releases the unmanaged resources used by this object, and optionally releases the managed resources.</summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.
        /// </param>
        [SecurityCritical]
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                EventLogPermissionHolder.GetEventLogPermission().Demand();
            }
            if (Handle != null && !Handle.IsInvalid)
            {
                Handle.Dispose();
            }
        }
    }

    /// <summary>
    /// Represents the exception that is thrown when a specified event provider name references a disabled event provider. A disabled event
    /// provider cannot publish events.
    /// </summary>
    [Serializable]
    public class EventLogProviderDisabledException : EventLogException
    {
        /// <summary>Initializes a new instance of the <see cref="EventLogProviderDisabledException"/> class.</summary>
        public EventLogProviderDisabledException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogProviderDisabledException"/> class by specifying the error message that
        /// describes the current exception.
        /// </summary>
        /// <param name="message">The error message that describes the current exception.</param>
        public EventLogProviderDisabledException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogProviderDisabledException"/> class with an error message and inner exception.
        /// </summary>
        /// <param name="message">The error message that describes the current exception.</param>
        /// <param name="innerException">The Exception instance that caused the current exception.</param>
        public EventLogProviderDisabledException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogProviderDisabledException"/> class.</summary>
        /// <param name="errorCode">
        /// The error code for the error that occurred while reading or configuring event log related information. For more information and a
        /// list of event log related error codes, see http://go.microsoft.com/fwlink/?LinkId=82629.
        /// </param>
        internal EventLogProviderDisabledException(int errorCode)
            : base(errorCode)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogProviderDisabledException"/> class with serialized data.</summary>
        /// <param name="serializationInfo">
        /// The <see cref="SerializationInfo"/> object that holds the serialized object data about the exception being thrown.
        /// </param>
        /// <param name="streamingContext">
        /// The <see cref="StreamingContext"/> object that contains contextual information about the source or destination.
        /// </param>
        protected EventLogProviderDisabledException(SerializationInfo serializationInfo, StreamingContext streamingContext)
            : base(serializationInfo, streamingContext)
        {
        }
    }

    /// <summary>
    /// Represents a query for events in an event log and the settings that define how the query is executed and on what computer the query
    /// is executed on.
    /// </summary>
    public class EventLogQuery
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogQuery"/> class by specifying the target of the query. The target can be an
        /// active event log or a log file.
        /// </summary>
        /// <param name="path">The name of the event log to query, or the path to the event log file to query.</param>
        /// <param name="pathType">
        /// Specifies whether the string used in the path parameter specifies the name of an event log, or the path to an event log file.
        /// </param>
        public EventLogQuery(string path, PathType pathType) : this(path, pathType, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogQuery"/> class by specifying the target of the query and the event query.
        /// The target can be an active event log or a log file.
        /// </summary>
        /// <param name="path">The name of the event log to query, or the path to the event log file to query.</param>
        /// <param name="pathType">
        /// Specifies whether the string used in the path parameter specifies the name of an event log, or the path to an event log file.
        /// </param>
        /// <param name="query">The event query used to retrieve events that match the query conditions.</param>
        /// <exception cref="System.ArgumentNullException">path</exception>
        public EventLogQuery(string path, PathType pathType, string query)
        {
            Session = EventLogSession.GlobalSession;
            Path = path;
            ThePathType = pathType;
            if (query is null)
            {
                if (path is null)
                {
                    throw new ArgumentNullException(nameof(path));
                }
            }
            else
            {
                Query = query;
            }
        }

        /// <summary>
        /// Gets or sets the Boolean value that determines whether to read events from the newest event in an event log to the oldest event
        /// in the log.
        /// </summary>
        /// <value>
        /// Returns <see langword="true"/> if events are read from the newest event in the log to the oldest event, and returns <see
        /// langword="false"/> if events are read from the oldest event in the log to the newest event.
        /// </value>
        public bool ReverseDirection { get; set; }

        /// <summary>
        /// Gets or sets the session that access the Event Log service on the local computer or a remote computer. This object can be set to
        /// access a remote event log by creating a <see cref="EventLogReader"/> object or an <see cref="EventLogWatcher"/> object with this
        /// <see cref="EventLogQuery"/> object.
        /// </summary>
        /// <value>Returns an <see cref="EventLogSession"/> object.</value>
        public EventLogSession Session { get; set; }

        /// <summary>
        /// Gets or sets a Boolean value that determines whether this query will continue to retrieve events when the query has an error.
        /// </summary>
        /// <value>
        /// <see langword="true"/> indicates that the query will continue to retrieve events even if the query fails for some logs, and <see
        /// langword="false"/> indicates that this query will not continue to retrieve events when the query fails.
        /// </value>
        public bool TolerateQueryErrors { get; set; }

        internal string Path { get; private set; }

        internal string Query { get; private set; }

        internal PathType ThePathType { get; private set; }
    }

    /// <summary>
    /// Enables you to read events from an event log based on an event query. The events that are read by this object are returned as <see
    /// cref="EventRecord"/> objects.
    /// </summary>
    /// <seealso cref="System.IDisposable"/>
    public class EventLogReader : IDisposable
    {
        private readonly ProviderMetadataCachedInformation cachedMetadataInformation;
        private int batchSize;
        private int currentIndex;
        private int eventCount;
        private EventLogQuery eventQuery;
        private IntPtr[] eventsBuffer;
        private EventLogHandle handle;
        private bool isEof;

        /// <summary>Initializes a new instance of the <see cref="EventLogReader"/> class by specifying an event query.</summary>
        /// <param name="eventQuery">The event query used to retrieve events.</param>
        public EventLogReader(EventLogQuery eventQuery)
            : this(eventQuery, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogReader"/> class by specifying an active event log to retrieve events from.
        /// </summary>
        /// <param name="path">The name of the event log to retrieve events from.</param>
        public EventLogReader(string path)
            : this(new EventLogQuery(path, PathType.LogName), null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogReader"/> class by specifying an event query and a bookmark that is used as
        /// starting position for the query.
        /// </summary>
        /// <param name="eventQuery">The event query used to retrieve events.</param>
        /// <param name="bookmark">
        /// The bookmark (placeholder) used as a starting position in the event log or stream of events. Only events logged after the
        /// bookmark event will be returned by the query.
        /// </param>
        /// <exception cref="System.ArgumentNullException">eventQuery</exception>
        [SecurityCritical]
        public EventLogReader(EventLogQuery eventQuery, EventBookmark bookmark)
        {
            if (eventQuery is null)
            {
                throw new ArgumentNullException(nameof(eventQuery));
            }
            string logfile = null;
            if (eventQuery.ThePathType == PathType.FilePath)
            {
                logfile = eventQuery.Path;
            }
            cachedMetadataInformation = new ProviderMetadataCachedInformation(eventQuery.Session, logfile, 50);
            this.eventQuery = eventQuery;
            batchSize = 0x40;
            eventsBuffer = new IntPtr[batchSize];
            var flags = 0;
            if (this.eventQuery.ThePathType == PathType.LogName)
            {
                flags |= 1;
            }
            else
            {
                flags |= 2;
            }
            if (this.eventQuery.ReverseDirection)
            {
                flags |= 0x200;
            }
            if (this.eventQuery.TolerateQueryErrors)
            {
                flags |= 0x1000;
            }
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            handle = NativeWrapper.EvtQuery(this.eventQuery.Session.Handle, this.eventQuery.Path, this.eventQuery.Query, flags);
            var bookmarkHandleFromBookmark = EventLogRecord.GetBookmarkHandleFromBookmark(bookmark);
            if (!bookmarkHandleFromBookmark.IsInvalid)
            {
                using (bookmarkHandleFromBookmark)
                {
                    NativeWrapper.EvtSeek(handle, 1L, bookmarkHandleFromBookmark, 0, UnsafeNativeMethods.EvtSeekFlags.EvtSeekRelativeToBookmark);
                }
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogReader"/> class by specifying the name of an event log to retrieve events
        /// from or the path to a log file to retrieve events from.
        /// </summary>
        /// <param name="path">
        /// The name of the event log to retrieve events from, or the path to the event log file to retrieve events from.
        /// </param>
        /// <param name="pathType">
        /// Specifies whether the string used in the path parameter specifies the name of an event log, or the path to an event log file.
        /// </param>
        public EventLogReader(string path, PathType pathType)
            : this(new EventLogQuery(path, pathType), null)
        {
        }

        /// <summary>Gets or sets the number of events retrieved from the stream of events on every read operation.</summary>
        /// <value>Returns an integer value.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">value</exception>
        public int BatchSize
        {
            get => batchSize;
            set
            {
                if (value < 1)
                {
                    throw new ArgumentOutOfRangeException(nameof(value));
                }
                batchSize = value;
            }
        }

        /// <summary>Gets the status of each event log or log file associated with the event query in this object.</summary>
        /// <value>
        /// Returns a list of <see cref="EventLogStatus"/> objects that each contain status information about an event log associated with
        /// the event query in this object.
        /// </value>
        public IList<EventLogStatus> LogStatus
        {
            [SecurityCritical]
            get
            {
                EventLogPermissionHolder.GetEventLogPermission().Demand();
                List<EventLogStatus> list = null;
                string[] strArray = null;
                int[] numArray = null;
                var handle = this.handle;
                if (handle.IsInvalid)
                {
                    throw new InvalidOperationException();
                }
                strArray = (string[])NativeWrapper.EvtGetQueryInfo(handle, UnsafeNativeMethods.EvtQueryPropertyId.EvtQueryNames);
                numArray = (int[])NativeWrapper.EvtGetQueryInfo(handle, UnsafeNativeMethods.EvtQueryPropertyId.EvtQueryStatuses);
                if (strArray.Length != numArray.Length)
                {
                    throw new InvalidOperationException();
                }
                list = new List<EventLogStatus>(strArray.Length);
                for (var i = 0; i < strArray.Length; i++)
                {
                    var item = new EventLogStatus(strArray[i], numArray[i]);
                    list.Add(item);
                }
                return list.AsReadOnly();
            }
        }

        /// <summary>Cancels the current query operation.</summary>
        public void CancelReading() => NativeWrapper.EvtCancel(handle);

        /// <summary>Releases all the resources used by this object.</summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Reads the next event that is returned from the event query in this object.</summary>
        /// <returns>Returns an <see cref="EventRecord"/> object.</returns>
        public EventRecord ReadEvent() => ReadEvent(TimeSpan.MaxValue);

        /// <summary>Reads the next event that is returned from the event query in this object.</summary>
        /// <param name="timeout">The maximum time to allow the read operation to run before canceling the operation.</param>
        /// <returns>Returns an <see cref="EventRecord"/> object.</returns>
        [SecurityCritical]
        public EventRecord ReadEvent(TimeSpan timeout)
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            if (isEof)
            {
                throw new InvalidOperationException();
            }
            if (currentIndex >= eventCount)
            {
                GetNextBatch(timeout);
                if (currentIndex >= eventCount)
                {
                    isEof = true;
                    return null;
                }
            }
            var record = new EventLogRecord(new EventLogHandle(eventsBuffer[currentIndex], true), eventQuery.Session, cachedMetadataInformation);
            currentIndex++;
            return record;
        }

        /// <summary>
        /// Changes the position in the event stream where the next event that is read will come from by specifying a bookmark event. No
        /// events logged before the bookmark event will be retrieved.
        /// </summary>
        /// <param name="bookmark">
        /// The bookmark (placeholder) used as a starting position in the event log or stream of events. Only events that have been logged
        /// after the bookmark event will be returned by the query.
        /// </param>
        /// <remarks>
        /// You can use this function only on result sets from an Admin or Operational channel, or from .evtx log files. This function is not
        /// supported on analytic and debug channels, or for ETL files.
        /// </remarks>
        public void Seek(EventBookmark bookmark) => Seek(bookmark, 0L);

        /// <summary>
        /// Changes the position in the event stream where the next event that is read will come from by specifying a bookmark event and an
        /// offset number of events from the bookmark. No events logged before the bookmark plus the offset will be retrieved.
        /// </summary>
        /// <param name="bookmark">
        /// The bookmark (placeholder) used as a starting position in the event log or stream of events. Only events that have been logged
        /// after the bookmark event will be returned by the query.
        /// </param>
        /// <param name="offset">The offset number of events to change the position of the bookmark.</param>
        /// <remarks>
        /// You can use this function only on result sets from an Admin or Operational channel, or from .evtx log files. This function is not
        /// supported on analytic and debug channels, or for ETL files.
        /// </remarks>
        [SecurityCritical]
        public void Seek(EventBookmark bookmark, long offset)
        {
            if (bookmark is null)
            {
                throw new ArgumentNullException(nameof(bookmark));
            }
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            SeekReset();
            using (var handle = EventLogRecord.GetBookmarkHandleFromBookmark(bookmark))
            {
                NativeWrapper.EvtSeek(this.handle, offset, handle, 0, UnsafeNativeMethods.EvtSeekFlags.EvtSeekRelativeToBookmark);
            }
        }

        /// <summary>
        /// Changes the position in the event stream where the next event that is read will come from by specifying a starting position and
        /// an offset from the starting position. No events logged before the starting position plus the offset will be retrieved.
        /// </summary>
        /// <param name="origin">
        /// A value from the <see cref="SeekOrigin"/> enumeration defines where in the stream of events to start querying for events.
        /// </param>
        /// <param name="offset">The offset number of events to add to the origin.</param>
        /// <remarks>
        /// You can use this function only on result sets from an Admin or Operational channel, or from .evtx log files. This function is not
        /// supported on analytic and debug channels, or for ETL files.
        /// </remarks>
        [SecurityCritical]
        public void Seek(SeekOrigin origin, long offset)
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            switch (origin)
            {
                case SeekOrigin.Begin:
                    SeekReset();
                    NativeWrapper.EvtSeek(handle, offset, EventLogHandle.Zero, 0, UnsafeNativeMethods.EvtSeekFlags.EvtSeekRelativeToFirst);
                    return;

                case SeekOrigin.Current:
                    if (offset < 0L)
                    {
                        if (currentIndex + offset >= 0L)
                        {
                            SeekCommon(offset);
                        }
                        else
                        {
                            SeekCommon(offset);
                        }
                        return;
                    }
                    if (currentIndex + offset >= eventCount)
                    {
                        SeekCommon(offset);
                        return;
                    }
                    for (var i = currentIndex; i < currentIndex + offset; i++)
                    {
                        NativeWrapper.EvtClose(eventsBuffer[i]);
                    }
                    currentIndex += (int)offset;
                    return;

                case SeekOrigin.End:
                    SeekReset();
                    NativeWrapper.EvtSeek(handle, offset, EventLogHandle.Zero, 0, UnsafeNativeMethods.EvtSeekFlags.EvtSeekRelativeToLast);
                    return;
            }
        }

        [SecurityCritical]
        internal void SeekCommon(long offset)
        {
            offset -= eventCount - currentIndex;
            SeekReset();
            NativeWrapper.EvtSeek(handle, offset, EventLogHandle.Zero, 0, UnsafeNativeMethods.EvtSeekFlags.EvtSeekRelativeToCurrent);
        }

        [SecurityCritical]
        internal void SeekReset()
        {
            while (currentIndex < eventCount)
            {
                NativeWrapper.EvtClose(eventsBuffer[currentIndex]);
                currentIndex++;
            }
            currentIndex = 0;
            eventCount = 0;
            isEof = false;
        }

        /// <summary>Releases the unmanaged resources used by this object, and optionally releases the managed resources.</summary>
        /// <param name="disposing"><see langword="true" /> to release both managed and unmanaged resources; <see langword="false" /> to release only unmanaged resources.</param>
        [SecurityCritical]
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                EventLogPermissionHolder.GetEventLogPermission().Demand();
            }
            while (currentIndex < eventCount)
            {
                NativeWrapper.EvtClose(eventsBuffer[currentIndex]);
                currentIndex++;
            }
            if (handle != null && !handle.IsInvalid)
            {
                handle.Dispose();
            }
        }

        [SecurityCritical]
        private bool GetNextBatch(TimeSpan ts)
        {
            int totalMilliseconds;
            if (ts == TimeSpan.MaxValue)
            {
                totalMilliseconds = -1;
            }
            else
            {
                totalMilliseconds = (int)ts.TotalMilliseconds;
            }
            if (batchSize != eventsBuffer.Length)
            {
                eventsBuffer = new IntPtr[batchSize];
            }
            var returned = 0;
            if (!NativeWrapper.EvtNext(handle, batchSize, eventsBuffer, totalMilliseconds, 0, ref returned))
            {
                eventCount = 0;
                currentIndex = 0;
                return false;
            }
            currentIndex = 0;
            eventCount = returned;
            return true;
        }
    }

    /// <summary>
    /// Represents an exception that is thrown when an error occurred while reading, querying, or subscribing to the events in an event log.
    /// </summary>
    /// <seealso cref="System.Diagnostics.Eventing.Reader.EventLogException"/>
    [Serializable]
    public class EventLogReadingException : EventLogException
    {
        /// <summary>Initializes a new instance of the <see cref="EventLogReadingException"/> class.</summary>
        public EventLogReadingException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogReadingException"/> class by specifying the error message that describes the
        /// current exception.
        /// </summary>
        /// <param name="message">The error message that describes the current exception.</param>
        public EventLogReadingException(string message)
            : base(message)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogReadingException"/> class with an error message and inner exception.</summary>
        /// <param name="message">The error message that describes the current exception.</param>
        /// <param name="innerException">The Exception instance that caused the current exception.</param>
        public EventLogReadingException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogReadingException"/> class.</summary>
        /// <param name="errorCode">
        /// The error code for the error that occurred while reading or configuring event log related information. For more information and a
        /// list of event log related error codes, see http://go.microsoft.com/fwlink/?LinkId=82629.
        /// </param>
        internal EventLogReadingException(int errorCode)
            : base(errorCode)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogReadingException"/> class with serialized data.</summary>
        /// <param name="serializationInfo">
        /// The <see cref="SerializationInfo"/> object that holds the serialized object data about the exception being thrown.
        /// </param>
        /// <param name="streamingContext">
        /// The <see cref="StreamingContext"/> object that contains contextual information about the source or destination.
        /// </param>
        protected EventLogReadingException(SerializationInfo serializationInfo, StreamingContext streamingContext)
            : base(serializationInfo, streamingContext)
        {
        }
    }

    /// <summary>
    /// Contains the properties of an event instance for an event that is received from an <see cref="EventLogReader"/> object. The event
    /// properties provide information about the event such as the name of the computer where the event was logged and the time that the
    /// event was created.
    /// </summary>
    /// <seealso cref="System.Diagnostics.Eventing.Reader.EventRecord"/>
    public class EventLogRecord : EventRecord
    {
        private const int SYSTEM_PROPERTY_COUNT = 0x12;

        private readonly object syncObject;
        private ProviderMetadataCachedInformation cachedMetadataInformation;
        private string containerChannel;
        private IEnumerable<string> keywordsNames;
        private string levelName;
        private bool levelNameReady;
        private int[] matchedQueryIds;
        private string opcodeName;
        private bool opcodeNameReady;
        private EventLogSession session;
        private NativeWrapper.SystemProperties systemProperties;
        private string taskName;
        private bool taskNameReady;

        internal EventLogRecord(EventLogHandle handle, EventLogSession session, ProviderMetadataCachedInformation cachedMetadataInfo)
        {
            cachedMetadataInformation = cachedMetadataInfo;
            Handle = handle;
            this.session = session;
            systemProperties = new NativeWrapper.SystemProperties();
            syncObject = new object();
        }

        /// <summary>
        /// Gets the globally unique identifier (GUID) for the activity in process for which the event is involved. This allows consumers to
        /// group related activities.
        /// </summary>
        /// <value>Returns a GUID value.</value>
        public override Guid? ActivityId
        {
            get
            {
                PrepareSystemData();
                return systemProperties.ActivityId;
            }
        }

        /// <summary>Gets a placeholder (bookmark) that corresponds to this event. This can be used as a placeholder in a stream of events.</summary>
        /// <value>Returns a <see cref="EventBookmark"/> object.</value>
        public override EventBookmark Bookmark
        {
            [SecurityCritical]
            get
            {
                EventLogPermissionHolder.GetEventLogPermission().Demand();
                var bookmark = NativeWrapper.EvtCreateBookmark(null);
                NativeWrapper.EvtUpdateBookmark(bookmark, Handle);
                return new EventBookmark(NativeWrapper.EvtRenderBookmark(bookmark));
            }
        }

        /// <summary>Gets the name of the event log or the event log file in which the event is stored.</summary>
        /// <value>Returns a string that contains the name of the event log or the event log file in which the event is stored.</value>
        public string ContainerLog
        {
            get
            {
                if (containerChannel != null)
                {
                    return containerChannel;
                }
                lock (syncObject)
                {
                    if (containerChannel is null)
                    {
                        containerChannel = (string)NativeWrapper.EvtGetEventInfo(Handle, UnsafeNativeMethods.EvtEventPropertyId.EvtEventPath);
                    }
                    return containerChannel;
                }
            }
        }

        /// <summary>Gets the identifier for this event. All events with this identifier value represent the same type of event.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public override int Id
        {
            get
            {
                PrepareSystemData();
                var id = systemProperties.Id;
                var nullable3 = id.HasValue ? new int?(id.GetValueOrDefault()) : null;
                return !nullable3.HasValue ? 0 : systemProperties.Id.Value;
            }
        }

        /// <summary>
        /// Gets the keyword mask of the event. Get the value of the <see cref="KeywordsDisplayNames"/> property to get the name of the
        /// keywords used in this mask.
        /// </summary>
        /// <value>Returns a long value. This value can be null.</value>
        /// <remarks>
        /// <para>
        /// The keywords for an event are used to group the event with other similar events based on the usage of the events. Each keyword is
        /// a bit in a 64-bit mask. Predefined bit values and reserved bits occupy the top 16 positions of this mask, leaving the manifest to
        /// use any bits between 0x0000000000000001 and 0x0000800000000000.
        /// </para>
        /// <para>The standard event keywords are defined in the <see cref="StandardEventKeywords"/> enumeration.</para>
        /// </remarks>
        public override long? Keywords
        {
            get
            {
                PrepareSystemData();
                var keywords = systemProperties.Keywords;
                return !keywords.HasValue ? null : (long?)(long)keywords.GetValueOrDefault();
            }
        }

        /// <summary>Gets the display names of the keywords used in the keyword mask for this event.</summary>
        /// <value>
        /// Returns an enumerable collection of strings that contain the display names of the keywords used in the keyword mask for this event.
        /// </value>
        /// <remarks>The standard event keywords are defined in the <see cref="StandardEventKeywords"/> enumeration.</remarks>
        public override IEnumerable<string> KeywordsDisplayNames
        {
            get
            {
                if (keywordsNames != null)
                {
                    return keywordsNames;
                }
                lock (syncObject)
                {
                    if (keywordsNames is null)
                    {
                        keywordsNames = cachedMetadataInformation.GetKeywordDisplayNames(ProviderName, Handle);
                    }
                    return keywordsNames;
                }
            }
        }

        /// <summary>
        /// Gets the level of the event. The level signifies the severity of the event. For the name of the level, get the value of the <see
        /// cref="LevelDisplayName"/> property.
        /// </summary>
        /// <value>Returns a byte value. This value can be null.</value>
        public override byte? Level
        {
            get
            {
                PrepareSystemData();
                return systemProperties.Level;
            }
        }

        /// <summary>Gets the display name of the level for this event.</summary>
        /// <value>Returns a string that contains the display name of the level for this event.</value>
        /// <remarks>The standard event levels are defined in the <see cref="StandardEventLevel"/> enumeration.</remarks>
        public override string LevelDisplayName
        {
            get
            {
                if (levelNameReady)
                {
                    return levelName;
                }
                lock (syncObject)
                {
                    if (!levelNameReady)
                    {
                        levelNameReady = true;
                        levelName = cachedMetadataInformation.GetLevelDisplayName(ProviderName, Handle);
                    }
                    return levelName;
                }
            }
        }

        /// <summary>Gets the name of the event log where this event is logged.</summary>
        /// <value>Returns a string that contains a name of the event log that contains this event.</value>
        public override string LogName
        {
            get
            {
                PrepareSystemData();
                return systemProperties.ChannelName;
            }
        }

        /// <summary>Gets the name of the computer on which this event was logged.</summary>
        /// <value>Returns a string that contains the name of the computer on which this event was logged.</value>
        public override string MachineName
        {
            get
            {
                PrepareSystemData();
                return systemProperties.ComputerName;
            }
        }

        /// <summary>
        /// Gets a list of query identifiers that this event matches. This event matches a query if the query would return this event.
        /// </summary>
        /// <value>Returns an enumerable collection of integer values.</value>
        public IEnumerable<int> MatchedQueryIds
        {
            get
            {
                if (matchedQueryIds != null)
                {
                    return matchedQueryIds;
                }
                lock (syncObject)
                {
                    if (matchedQueryIds is null)
                    {
                        matchedQueryIds = (int[])NativeWrapper.EvtGetEventInfo(Handle, UnsafeNativeMethods.EvtEventPropertyId.EvtEventQueryIDs);
                    }
                    return matchedQueryIds;
                }
            }
        }

        /// <summary>
        /// Gets the opcode of the event. The opcode defines a numeric value that identifies the activity or a point within an activity that
        /// the application was performing when it raised the event. For the name of the opcode, get the value of the OpcodeDisplayName property.
        /// </summary>
        /// <value>Returns a short value. This value can be null.</value>
        /// <remarks>The standard event opcodes are defined in the <see cref="StandardEventOpcode"/> enumeration.</remarks>
        public override short? Opcode
        {
            get
            {
                PrepareSystemData();
                var opcode = systemProperties.Opcode;
                var nullable3 = opcode.HasValue ? new ushort?(opcode.GetValueOrDefault()) : null;
                return !nullable3.HasValue ? null : new short?((short)nullable3.GetValueOrDefault());
            }
        }

        /// <summary>Gets the display name of the opcode for this event.</summary>
        /// <value>Returns a string that contains the display name of the opcode for this event.</value>
        /// <remarks>The standard event opcodes are defined in the <see cref="StandardEventOpcode"/> enumeration.</remarks>
        public override string OpcodeDisplayName
        {
            get
            {
                lock (syncObject)
                {
                    if (!opcodeNameReady)
                    {
                        opcodeNameReady = true;
                        opcodeName = cachedMetadataInformation.GetOpcodeDisplayName(ProviderName, Handle);
                    }
                    return opcodeName;
                }
            }
        }

        /// <summary>Gets the process identifier for the event provider that logged this event.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public override int? ProcessId
        {
            get
            {
                PrepareSystemData();
                var processId = systemProperties.ProcessId;
                return !processId.HasValue ? null : (int?)(int)processId.GetValueOrDefault();
            }
        }

        /// <summary>Gets the user-supplied properties of the event.</summary>
        /// <value>Returns a list of <see cref="EventProperty"/> objects.</value>
        public override IList<EventProperty> Properties
        {
            get
            {
                session.SetupUserContext();
                var list = NativeWrapper.EvtRenderBufferWithContextUserOrValues(session.renderContextHandleUser, Handle);
                var list2 = new List<EventProperty>();
                foreach (var obj2 in list)
                {
                    list2.Add(new EventProperty(obj2));
                }
                return list2;
            }
        }

        /// <summary>Gets the globally unique identifier (GUID) of the event provider that published this event.</summary>
        /// <value>Returns a GUID value. This value can be null.</value>
        public override Guid? ProviderId
        {
            get
            {
                PrepareSystemData();
                return systemProperties.ProviderId;
            }
        }

        /// <summary>Gets the name of the event provider that published this event.</summary>
        /// <value>Returns a string that contains the name of the event provider that published this event.</value>
        public override string ProviderName
        {
            get
            {
                PrepareSystemData();
                return systemProperties.ProviderName;
            }
        }

        /// <summary>Gets qualifier numbers that are used for event identification.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public override int? Qualifiers
        {
            get
            {
                PrepareSystemData();
                var qualifiers = systemProperties.Qualifiers;
                var nullable3 = qualifiers.HasValue ? new uint?(qualifiers.GetValueOrDefault()) : null;
                return !nullable3.HasValue ? null : (int?)(int)nullable3.GetValueOrDefault();
            }
        }

        /// <summary>Gets the event record identifier of the event in the log.</summary>
        /// <value>Returns a long value. This value can be null.</value>
        public override long? RecordId
        {
            get
            {
                PrepareSystemData();
                var recordId = systemProperties.RecordId;
                return !recordId.HasValue ? null : (long?)(long)recordId.GetValueOrDefault();
            }
        }

        /// <summary>Gets a globally unique identifier (GUID) for a related activity in a process for which an event is involved.</summary>
        /// <value>Returns a GUID value. This value can be null.</value>
        /// <remarks>
        /// An event provider can set the value of the ActivityID attribute before publishing events. All the events that are published after
        /// this ID is set will have the ActivityID attribute set to the specified value. This allows providers to specify simple
        /// relationships between events. The events that are published are part of the same activity. When a provider must start a new, but
        /// related activity, the publisher can publish a transfer event and specify the new activity ID. This new ID will appear as a
        /// RelatedActivityID attribute. This allows consumers to group related activities.
        /// </remarks>
        public override Guid? RelatedActivityId
        {
            get
            {
                PrepareSystemData();
                return systemProperties.RelatedActivityId;
            }
        }

        /// <summary>
        /// Gets a task identifier for a portion of an application or a component that publishes an event. A task is a 16-bit value with 16
        /// top values reserved. This type allows any value between 0x0000 and 0xffef to be used. For the name of the task, get the value of
        /// the <see cref="TaskDisplayName"/> property.
        /// </summary>
        /// <value>Returns an integer value. This value can be null.</value>
        /// <remarks>The standard event tasks are defined in the <see cref="StandardEventTask"/> enumeration.</remarks>
        public override int? Task
        {
            get
            {
                PrepareSystemData();
                var task = systemProperties.Task;
                var nullable3 = task.HasValue ? new uint?(task.GetValueOrDefault()) : null;
                return !nullable3.HasValue ? null : (int?)(int)nullable3.GetValueOrDefault();
            }
        }

        /// <summary>Gets the display name of the task for the event.</summary>
        /// <value>Returns a string that contains the display name of the task for the event.</value>
        /// <remarks>The standard event tasks are defined in the <see cref="StandardEventTask"/> enumeration.</remarks>
        public override string TaskDisplayName
        {
            get
            {
                if (taskNameReady)
                {
                    return taskName;
                }
                lock (syncObject)
                {
                    if (!taskNameReady)
                    {
                        taskNameReady = true;
                        taskName = cachedMetadataInformation.GetTaskDisplayName(ProviderName, Handle);
                    }
                    return taskName;
                }
            }
        }

        /// <summary>Gets the thread identifier for the thread that the event provider is running in.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public override int? ThreadId
        {
            get
            {
                PrepareSystemData();
                var threadId = systemProperties.ThreadId;
                return !threadId.HasValue ? null : (int?)(int)threadId.GetValueOrDefault();
            }
        }

        /// <summary>Gets the time, in <see cref="DateTime"/> format, that the event was created.</summary>
        /// <value>Returns a <see cref="DateTime"/> value. The value can be null.</value>
        public override DateTime? TimeCreated
        {
            get
            {
                PrepareSystemData();
                return systemProperties.TimeCreated;
            }
        }

        /// <summary>Gets the security descriptor of the user whose context is used to publish the event.</summary>
        /// <value>Returns a <see cref="SecurityIdentifier"/> value.</value>
        public override SecurityIdentifier UserId
        {
            get
            {
                PrepareSystemData();
                return systemProperties.UserId;
            }
        }

        /// <summary>Gets the version number for the event.</summary>
        /// <value>Returns a byte value. This value can be null.</value>
        public override byte? Version
        {
            get
            {
                PrepareSystemData();
                return systemProperties.Version;
            }
        }

        internal EventLogHandle Handle { get; private set; }

        /// <summary>Gets the event message in the current locale.</summary>
        /// <returns>Returns a string that contains the event message in the current locale.</returns>
        public override string FormatDescription() => cachedMetadataInformation.GetFormatDescription(ProviderName, Handle);

        /// <summary>Gets the event message, replacing variables in the message with the specified values.</summary>
        /// <param name="values">
        /// The values used to replace variables in the event message. Variables are represented by %n, where n is a number.
        /// </param>
        /// <returns>Returns a string that contains the event message in the current locale.</returns>
        public override string FormatDescription(IEnumerable<object> values)
        {
            if (values is null)
            {
                return FormatDescription();
            }
            var array = new string[0];
            var index = 0;
            foreach (var obj2 in values)
            {
                if (array.Length == index)
                {
                    Array.Resize<string>(ref array, index + 1);
                }
                array[index] = obj2.ToString();
                index++;
            }
            return cachedMetadataInformation.GetFormatDescription(ProviderName, Handle, array);
        }

        /// <summary>
        /// Gets the enumeration of the values of the user-supplied event properties, or the results of XPath-based data if the event has XML representation.
        /// </summary>
        /// <param name="propertySelector">Selects the property values to return.</param>
        /// <returns>Returns a list of objects.</returns>
        public IList<object> GetPropertyValues(EventLogPropertySelector propertySelector) =>
            propertySelector != null ? NativeWrapper.EvtRenderBufferWithContextUserOrValues(propertySelector.Handle, Handle) : throw new ArgumentNullException(nameof(propertySelector));

        /// <summary>
        /// Gets the XML representation of the event. All of the event properties are represented in the event's XML. The XML conforms to the
        /// event schema.
        /// </summary>
        /// <returns>Returns a string that contains the XML representation of the event.</returns>
        [SecurityCritical]
        public override string ToXml()
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var buffer = new StringBuilder(0x7d0);
            NativeWrapper.EvtRender(EventLogHandle.Zero, Handle, UnsafeNativeMethods.EvtRenderFlags.EvtRenderEventXml, buffer);
            return buffer.ToString();
        }

        [SecurityCritical]
        internal static EventLogHandle GetBookmarkHandleFromBookmark(EventBookmark bookmark) => bookmark is null ? EventLogHandle.Zero : NativeWrapper.EvtCreateBookmark(bookmark.BookmarkText);

        internal void PrepareSystemData()
        {
            if (!systemProperties.filled)
            {
                session.SetupSystemContext();
                lock (syncObject)
                {
                    if (!systemProperties.filled)
                    {
                        NativeWrapper.EvtRenderBufferWithContextSystem(session.renderContextHandleSystem, Handle, UnsafeNativeMethods.EvtRenderFlags.EvtRenderEventValues, systemProperties, 0x12);
                        systemProperties.filled = true;
                    }
                }
            }
        }

        /// <summary>Releases the unmanaged resources used by this object, and optionally releases the managed resources.</summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.
        /// </param>
        [SecurityCritical]
        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    EventLogPermissionHolder.GetEventLogPermission().Demand();
                }
                if (Handle != null && !Handle.IsInvalid)
                {
                    Handle.Dispose();
                }
            }
            finally
            {
            }
        }
    }

    /// <summary>
    /// Used to access the Event Log service on the local computer or a remote computer so you can manage and gather information about the
    /// event logs and event providers on the computer.
    /// </summary>
    public class EventLogSession : IDisposable
    {
        internal EventLogHandle renderContextHandleSystem;
        internal EventLogHandle renderContextHandleUser;
        private readonly string domain;
        private readonly SessionAuthentication logOnType;
        private readonly string server;
        private readonly object syncObject;
        private readonly string user;

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogSession"/> class, establishes a connection with the local Event Log service.
        /// </summary>
        [SecurityCritical]
        public EventLogSession()
        {
            renderContextHandleSystem = EventLogHandle.Zero;
            renderContextHandleUser = EventLogHandle.Zero;
            Handle = EventLogHandle.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            syncObject = new object();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogSession"/> class, and establishes a connection with the Event Log service on
        /// the specified computer. The credentials (user name and password) of the user who calls the method is used for the credentials to
        /// access the remote computer.
        /// </summary>
        /// <param name="server">The name of the computer on which to connect to the Event Log service.</param>
        public EventLogSession(string server) : this(server, null, null, null, SessionAuthentication.Default)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogSession"/> class, and establishes a connection with the Event Log service on
        /// the specified computer. The specified credentials (user name and password) are used for the credentials to access the remote computer.
        /// </summary>
        /// <param name="server">The name of the computer on which to connect to the Event Log service.</param>
        /// <param name="domain">The domain of the specified user.</param>
        /// <param name="user">The user name used to connect to the remote computer.</param>
        /// <param name="password">The password used to connect to the remote computer.</param>
        /// <param name="logOnType">The type of connection to use for the connection to the remote computer.</param>
        [SecurityCritical]
        public EventLogSession(string server, string domain, string user, SecureString password, SessionAuthentication logOnType)
        {
            renderContextHandleSystem = EventLogHandle.Zero;
            renderContextHandleUser = EventLogHandle.Zero;
            Handle = EventLogHandle.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            if (server is null)
            {
                server = "localhost";
            }
            syncObject = new object();
            this.server = server;
            this.domain = domain;
            this.user = user;
            this.logOnType = logOnType;
            var login = new UnsafeNativeMethods.EvtRpcLogin
            {
                Server = this.server,
                User = this.user,
                Domain = this.domain,
                Flags = (int)this.logOnType,
                Password = CoTaskMemUnicodeSafeHandle.Zero
            };
            try
            {
                if (password != null)
                {
                    login.Password.SetMemory(Marshal.SecureStringToCoTaskMemUnicode(password));
                }
                Handle = NativeWrapper.EvtOpenSession(UnsafeNativeMethods.EvtLoginClass.EvtRpcLogin, ref login, 0, 0);
            }
            finally
            {
                login.Password.Close();
            }
        }

        /// <summary>Gets a static predefined session object that is connected to the Event Log service on the local computer.</summary>
        /// <value>
        /// Returns an <see cref="EventLogSession"/> object that is a predefined session object that is connected to the Event Log service on
        /// the local computer.
        /// </value>
        public static EventLogSession GlobalSession { get; } = new EventLogSession();

        internal EventLogHandle Handle { get; private set; }

        /// <summary>
        /// Cancels any operations (such as reading an event log or subscribing to an event log) that are currently active for the Event Log
        /// service that this session object is connected to.
        /// </summary>
        public void CancelCurrentOperations() => NativeWrapper.EvtCancel(Handle);

        /// <summary>Clears events from the specified event log.</summary>
        /// <param name="logName">The name of the event log to clear all the events from.</param>
        public void ClearLog(string logName) => ClearLog(logName, null);

        /// <summary>Clears events from the specified event log, and saves the cleared events to the specified file.</summary>
        /// <param name="logName">The name of the event log to clear all the events from.</param>
        /// <param name="backupPath">The path to the file in which the cleared events will be saved. The file should end in .evtx.</param>
        /// <exception cref="System.ArgumentNullException">logName</exception>
        public void ClearLog(string logName, string backupPath)
        {
            if (logName is null)
            {
                throw new ArgumentNullException(nameof(logName));
            }
            NativeWrapper.EvtClearLog(Handle, logName, backupPath, 0);
        }

        /// <summary>Releases all the resources used by this object.</summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Exports events into an external log file. The events are stored without the event messages.</summary>
        /// <param name="path">The name of the event log to export events from, or the path to the event log file to export events from.</param>
        /// <param name="pathType">
        /// Specifies whether the string used in the path parameter specifies the name of an event log, or the path to an event log file.
        /// </param>
        /// <param name="query">The query used to select the events to export. Only the events returned from the query will be exported.</param>
        /// <param name="targetFilePath">
        /// The path to the log file (ends in .evtx) in which the exported events will be stored after this method is executed.
        /// </param>
        public void ExportLog(string path, PathType pathType, string query, string targetFilePath) => ExportLog(path, pathType, query, targetFilePath, false);

        /// <summary>
        /// Exports events into an external log file. A flag can be set to indicate that the method will continue exporting events even if
        /// the specified query fails for some logs. The events are stored without the event messages.
        /// </summary>
        /// <param name="path">The name of the event log to export events from, or the path to the event log file to export events from.</param>
        /// <param name="pathType">
        /// Specifies whether the string used in the path parameter specifies the name of an event log, or the path to an event log file.
        /// </param>
        /// <param name="query">The query used to select the events to export. Only the events returned from the query will be exported.</param>
        /// <param name="targetFilePath">
        /// The path to the log file (ends in .evtx) in which the exported events will be stored after this method is executed.
        /// </param>
        /// <param name="tolerateQueryErrors">
        /// <see langword="true"/> indicates that the method will continue exporting events even if the specified query fails for some logs,
        /// and <see langword="false"/> indicates that this method will not continue to export events when the specified query fails.
        /// </param>
        /// <exception cref="System.ArgumentNullException">path or targetFilePath</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">pathType</exception>
        public void ExportLog(string path, PathType pathType, string query, string targetFilePath, bool tolerateQueryErrors)
        {
            UnsafeNativeMethods.EvtExportLogFlags evtExportLogChannelPath;
            if (path is null)
            {
                throw new ArgumentNullException(nameof(path));
            }
            if (targetFilePath is null)
            {
                throw new ArgumentNullException(nameof(targetFilePath));
            }
            switch (pathType)
            {
                case PathType.LogName:
                    evtExportLogChannelPath = UnsafeNativeMethods.EvtExportLogFlags.EvtExportLogChannelPath;
                    break;

                case PathType.FilePath:
                    evtExportLogChannelPath = UnsafeNativeMethods.EvtExportLogFlags.EvtExportLogFilePath;
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(pathType));
            }
            if (!tolerateQueryErrors)
            {
                NativeWrapper.EvtExportLog(Handle, path, query, targetFilePath, (int)evtExportLogChannelPath);
            }
            else
            {
                NativeWrapper.EvtExportLog(Handle, path, query, targetFilePath, ((int)evtExportLogChannelPath) | 0x1000);
            }
        }

        /// <summary>Exports events and their messages into an external log file.</summary>
        /// <param name="path">The name of the event log to export events from, or the path to the event log file to export events from.</param>
        /// <param name="pathType">
        /// Specifies whether the string used in the path parameter specifies the name of an event log, or the path to an event log file.
        /// </param>
        /// <param name="query">The query used to select the events to export. Only the events returned from the query will be exported.</param>
        /// <param name="targetFilePath">
        /// The path to the log file (ends in .evtx) in which the exported events will be stored after this method is executed.
        /// </param>
        public void ExportLogAndMessages(string path, PathType pathType, string query, string targetFilePath) => ExportLogAndMessages(path, pathType, query, targetFilePath, false, CultureInfo.CurrentCulture);

        /// <summary>
        /// Exports events and their messages into an external log file. A flag can be set to indicate that the method will continue
        /// exporting events even if the specified query fails for some logs. The event messages are exported in the specified language.
        /// </summary>
        /// <param name="path">The name of the event log to export events from, or the path to the event log file to export events from.</param>
        /// <param name="pathType">
        /// Specifies whether the string used in the path parameter specifies the name of an event log, or the path to an event log file.
        /// </param>
        /// <param name="query">The query used to select the events to export. Only the events returned from the query will be exported.</param>
        /// <param name="targetFilePath">
        /// The path to the log file (ends in .evtx) in which the exported events will be stored after this method is executed.
        /// </param>
        /// <param name="tolerateQueryErrors">
        /// <see langword="true"/> indicates that the method will continue exporting events even if the specified query fails for some logs,
        /// and <see langword="false"/> indicates that this method will not continue to export events when the specified query fails.
        /// </param>
        /// <param name="targetCultureInfo">The culture that specifies which language that the exported event messages will be in.</param>
        public void ExportLogAndMessages(string path, PathType pathType, string query, string targetFilePath, bool tolerateQueryErrors, CultureInfo targetCultureInfo)
        {
            if (targetCultureInfo is null)
            {
                targetCultureInfo = CultureInfo.CurrentCulture;
            }
            ExportLog(path, pathType, query, targetFilePath, tolerateQueryErrors);
            NativeWrapper.EvtArchiveExportedLog(Handle, targetFilePath, targetCultureInfo.LCID, 0);
        }

        /// <summary>Gets an object that contains runtime information for the specified event log.</summary>
        /// <param name="logName">
        /// The name of the event log to get information about, or the path to the event log file to get information about.
        /// </param>
        /// <param name="pathType">
        /// Specifies whether the string used in the path parameter specifies the name of an event log, or the path to an event log file.
        /// </param>
        /// <returns>Returns an <see cref="EventLogInformation"/> object that contains information about the specified log.</returns>
        /// <exception cref="System.ArgumentNullException">logName</exception>
        public EventLogInformation GetLogInformation(string logName, PathType pathType)
        {
            if (logName is null)
            {
                throw new ArgumentNullException(nameof(logName));
            }
            return new EventLogInformation(this, logName, pathType);
        }

        /// <summary>Gets an enumerable collection of all the event log names that are registered with the Event Log service.</summary>
        /// <returns>Returns an enumerable collection of strings that contain the event log names.</returns>
        [SecurityCritical]
        public IEnumerable<string> GetLogNames()
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var list = new List<string>(100);
            using (var handle = NativeWrapper.EvtOpenChannelEnum(Handle, 0))
            {
                var finish = false;
                do
                {
                    var item = NativeWrapper.EvtNextChannelPath(handle, ref finish);
                    if (!finish)
                    {
                        list.Add(item);
                    }
                }
                while (!finish);
                return list;
            }
        }

        /// <summary>
        /// Gets an enumerable collection of all the event provider names that are registered with the Event Log service. An event provider
        /// is an application that publishes events to an event log.
        /// </summary>
        /// <returns>Returns an enumerable collection of strings that contain the event provider names.</returns>
        [SecurityCritical]
        public IEnumerable<string> GetProviderNames()
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var list = new List<string>(100);
            using (var handle = NativeWrapper.EvtOpenProviderEnum(Handle, 0))
            {
                var finish = false;
                do
                {
                    var item = NativeWrapper.EvtNextPublisherId(handle, ref finish);
                    if (!finish)
                    {
                        list.Add(item);
                    }
                }
                while (!finish);
                return list;
            }
        }

        [SecurityCritical]
        internal void SetupSystemContext()
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            if (renderContextHandleSystem.IsInvalid)
            {
                lock (syncObject)
                {
                    if (renderContextHandleSystem.IsInvalid)
                    {
                        renderContextHandleSystem = NativeWrapper.EvtCreateRenderContext(0, null, UnsafeNativeMethods.EvtRenderContextFlags.EvtRenderContextSystem);
                    }
                }
            }
        }

        [SecurityCritical]
        internal void SetupUserContext()
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            lock (syncObject)
            {
                if (renderContextHandleUser.IsInvalid)
                {
                    renderContextHandleUser = NativeWrapper.EvtCreateRenderContext(0, null, UnsafeNativeMethods.EvtRenderContextFlags.EvtRenderContextUser);
                }
            }
        }

        /// <summary>Releases the unmanaged resources used by this object, and optionally releases the managed resources.</summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.
        /// </param>
        /// <exception cref="System.InvalidOperationException"></exception>
        [SecurityCritical]
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (this == GlobalSession)
                {
                    throw new InvalidOperationException();
                }
                EventLogPermissionHolder.GetEventLogPermission().Demand();
            }
            if (renderContextHandleSystem != null && !renderContextHandleSystem.IsInvalid)
            {
                renderContextHandleSystem.Dispose();
            }
            if (renderContextHandleUser != null && !renderContextHandleUser.IsInvalid)
            {
                renderContextHandleUser.Dispose();
            }
            if (Handle != null && !Handle.IsInvalid)
            {
                Handle.Dispose();
            }
        }
    }

    /// <summary>
    /// Contains the status code or error code for a specific event log. This status can be used to determine if the event log is available
    /// for an operation.
    /// </summary>
    public sealed class EventLogStatus
    {
        internal EventLogStatus(string channelName, int win32ErrorCode)
        {
            LogName = channelName;
            StatusCode = win32ErrorCode;
        }

        /// <summary>Gets the name of the event log for which the status code is obtained.</summary>
        /// <value>Returns a string that contains the name of the event log for which the status code is obtained.</value>
        public string LogName { get; private set; }

        /// <summary>
        /// Gets the status code or error code for the event log. This status or error is the result of a read or subscription operation on
        /// the event log.
        /// </summary>
        /// <value>Returns an integer value.</value>
        public int StatusCode { get; private set; }
    }

    /// <summary>
    /// Allows you to subscribe to incoming events. Each time a desired event is published to an event log, the <see
    /// cref="EventRecordWritten"/> event is raised, and the method that handles this event will be executed.
    /// </summary>
    public class EventLogWatcher : IDisposable
    {
        private readonly EventBookmark bookmark;
        private readonly ProviderMetadataCachedInformation cachedMetadataInformation;
        private readonly bool readExistingEvents;
        private EventLogException asyncException;
        private int callbackThreadId;
        private EventLogQuery eventQuery;
        private IntPtr[] eventsBuffer;
        private EventLogHandle handle;
        private bool isSubscribing;
        private int numEventsInBuffer;
        private RegisteredWaitHandle registeredWaitHandle;
        private AutoResetEvent subscriptionWaitHandle;
        private AutoResetEvent unregisterDoneHandle;

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogWatcher"/> class by specifying the name or path to an event log.
        /// </summary>
        /// <param name="path">
        /// The path or name of the event log monitor for events. If any event is logged in this event log, then the <see
        /// cref="EventRecordWritten"/> event is raised.
        /// </param>
        public EventLogWatcher(string path)
            : this(new EventLogQuery(path, PathType.LogName), null, false)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EventLogWatcher"/> class by specifying an event query.</summary>
        /// <param name="eventQuery">
        /// Specifies a query for the event subscription. When an event is logged that matches the criteria expressed in the query, then the
        /// <see cref="EventRecordWritten"/> event is raised.
        /// </param>
        public EventLogWatcher(EventLogQuery eventQuery)
            : this(eventQuery, null, false)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogWatcher"/> class by specifying an event query and a bookmark that is used as
        /// starting position for the query.
        /// </summary>
        /// <param name="eventQuery">
        /// Specifies a query for the event subscription. When an event is logged that matches the criteria expressed in the query, then the
        /// <see cref="EventRecordWritten"/> event is raised.
        /// </param>
        /// <param name="bookmark">
        /// The bookmark (placeholder) used as a starting position in the event log or stream of events. Only events that have been logged
        /// after the bookmark event will be returned by the query.
        /// </param>
        public EventLogWatcher(EventLogQuery eventQuery, EventBookmark bookmark)
            : this(eventQuery, bookmark, false)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EventLogWatcher"/> class by specifying an event query, a bookmark that is used as
        /// starting position for the query, and a Boolean value that determines whether to read the events that already exist in the event log.
        /// </summary>
        /// <param name="eventQuery">
        /// Specifies a query for the event subscription. When an event is logged that matches the criteria expressed in the query, then the
        /// <see cref="EventRecordWritten"/> event is raised.
        /// </param>
        /// <param name="bookmark">
        /// The bookmark (placeholder) used as a starting position in the event log or stream of events. Only events that have been logged
        /// after the bookmark event will be returned by the query.
        /// </param>
        /// <param name="readExistingEvents">
        /// A Boolean value that determines whether to read the events that already exist in the event log. If this value is <see
        /// langword="true"/>, then the existing events are read and if this value is <see langword="false"/>, then the existing events are
        /// not read.
        /// </param>
        /// <exception cref="System.ArgumentNullException">eventQuery</exception>
        /// <exception cref="System.InvalidOperationException"></exception>
        public EventLogWatcher(EventLogQuery eventQuery, EventBookmark bookmark, bool readExistingEvents)
        {
            if (bookmark != null)
                readExistingEvents = false;

            //explicit data
            this.eventQuery = eventQuery ?? throw new ArgumentNullException(nameof(eventQuery));
            this.readExistingEvents = readExistingEvents;

            if (this.eventQuery.ReverseDirection)
                throw new InvalidOperationException();

            eventsBuffer = new IntPtr[64];
            cachedMetadataInformation = new ProviderMetadataCachedInformation(eventQuery.Session, null, 50);
            this.bookmark = bookmark;
        }

        /// <summary>
        /// Allows setting a delegate (event handler method) that gets called every time an event is published that matches the criteria
        /// specified in the event query for this object.
        /// </summary>
        public event EventHandler<EventRecordWrittenEventArgs> EventRecordWritten;

        /// <summary>Determines whether this object starts delivering events to the event delegate.</summary>
        /// <value>
        /// Returns <see langword="true"/> when this object can deliver events to the event delegate, and returns <see langword="false"/>
        /// when this object has stopped delivery.
        /// </value>
        public bool Enabled
        {
            get => isSubscribing;
            set
            {
                if (value && !isSubscribing)
                {
                    StartSubscribing();
                }
                else if (!value && isSubscribing)
                {
                    StopSubscribing();
                }
            }
        }

        /// <summary>Releases the resources used by this object.</summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        [System.Security.SecuritySafeCritical]
        internal void StartSubscribing()
        {
            if (isSubscribing)
                throw new InvalidOperationException();

            var flag = 0;
            if (bookmark != null)
                flag |= (int)UnsafeNativeMethods.EvtSubscribeFlags.EvtSubscribeStartAfterBookmark;
            else if (readExistingEvents)
                flag |= (int)UnsafeNativeMethods.EvtSubscribeFlags.EvtSubscribeStartAtOldestRecord;
            else
                flag |= (int)UnsafeNativeMethods.EvtSubscribeFlags.EvtSubscribeToFutureEvents;

            if (eventQuery.TolerateQueryErrors)
                flag |= (int)UnsafeNativeMethods.EvtSubscribeFlags.EvtSubscribeTolerateQueryErrors;

            EventLogPermissionHolder.GetEventLogPermission().Demand();

            callbackThreadId = -1;
            unregisterDoneHandle = new AutoResetEvent(false);
            subscriptionWaitHandle = new AutoResetEvent(false);

            var bookmarkHandle = EventLogRecord.GetBookmarkHandleFromBookmark(bookmark);

            using (bookmarkHandle)
            {
                handle = NativeWrapper.EvtSubscribe(eventQuery.Session.Handle,
                    subscriptionWaitHandle.SafeWaitHandle,
                    eventQuery.Path,
                    eventQuery.Query,
                    bookmarkHandle,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    flag);
            }

            isSubscribing = true;

            RequestEvents();

            registeredWaitHandle = ThreadPool.RegisterWaitForSingleObject(
                subscriptionWaitHandle,
                new WaitOrTimerCallback(SubscribedEventsAvailableCallback),
                null,
                -1,
                false);
        }

        [System.Security.SecuritySafeCritical]
        internal void StopSubscribing()
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();

            isSubscribing = false;

            if (registeredWaitHandle != null)
            {
                registeredWaitHandle.Unregister(unregisterDoneHandle);

                if (callbackThreadId != Thread.CurrentThread.ManagedThreadId)
                {
                    if (unregisterDoneHandle != null)
                        unregisterDoneHandle.WaitOne();
                }

                registeredWaitHandle = null;
            }

            if (unregisterDoneHandle != null)
            {
                unregisterDoneHandle.Close();
                unregisterDoneHandle = null;
            }

            if (subscriptionWaitHandle != null)
            {
                subscriptionWaitHandle.Close();
                subscriptionWaitHandle = null;
            }

            for (var i = 0; i < numEventsInBuffer; i++)
            {
                if (eventsBuffer[i] != IntPtr.Zero)
                {
                    NativeWrapper.EvtClose(eventsBuffer[i]);
                    eventsBuffer[i] = IntPtr.Zero;
                }
            }

            numEventsInBuffer = 0;

            if (handle != null && !handle.IsInvalid)
                handle.Dispose();
        }

        internal void SubscribedEventsAvailableCallback(object state, bool timedOut)
        {
            callbackThreadId = Thread.CurrentThread.ManagedThreadId;
            try
            {
                RequestEvents();
            }
            finally
            {
                callbackThreadId = -1;
            }
        }

        /// <summary>Releases the unmanaged resources used by this object, and optionally releases the managed resources.</summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.
        /// </param>
        [System.Security.SecuritySafeCritical]
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                StopSubscribing();
                return;
            }

            for (var i = 0; i < numEventsInBuffer; i++)
            {
                if (eventsBuffer[i] != IntPtr.Zero)
                {
                    NativeWrapper.EvtClose(eventsBuffer[i]);
                    eventsBuffer[i] = IntPtr.Zero;
                }
            }

            numEventsInBuffer = 0;
        }

        [System.Security.SecurityCritical]
        private void HandleEventsRequestCompletion()
        {
            if (asyncException != null)
            {
                var args = new EventRecordWrittenEventArgs(asyncException);
                IssueCallback(args);
            }

            for (var i = 0; i < numEventsInBuffer; i++)
            {
                if (!isSubscribing)
                    break;
                var record = new EventLogRecord(new EventLogHandle(eventsBuffer[i], true), eventQuery.Session, cachedMetadataInformation);
                var args = new EventRecordWrittenEventArgs(record);
                eventsBuffer[i] = IntPtr.Zero;  // user is responsible for calling Dispose().
                IssueCallback(args);
            }
        }

        private void IssueCallback(EventRecordWrittenEventArgs eventArgs) => EventRecordWritten?.Invoke(this, eventArgs);

        [System.Security.SecuritySafeCritical]
        private void RequestEvents()
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();

            asyncException = null;
            Debug.Assert(numEventsInBuffer == 0);

            var results = false;

            do
            {
                if (!isSubscribing)
                    break;

                try
                {
                    results = NativeWrapper.EvtNext(handle, eventsBuffer.Length, eventsBuffer, 0, 0, ref numEventsInBuffer);

                    if (!results)
                        return;
                }
                catch (EventLogException e)
                {
                    asyncException = e;
                }

                HandleEventsRequestCompletion();
            } while (results);
        }
    }

    /// <summary>Contains the metadata (properties and settings) for an event that is defined in an event provider.</summary>
    /// <remarks>
    /// This class cannot be instantiated. A <see cref="ProviderMetadata"/> object defines a list of <see cref="EventMetadata"/> objects, one
    /// for each event defined by the provider.
    /// </remarks>
    public sealed class EventMetadata
    {
        private readonly byte channelId;
        private readonly long keywords;
        private readonly byte level;
        private readonly short opcode;
        private readonly ProviderMetadata pmReference;
        private readonly int task;

        internal EventMetadata(uint id, byte version, byte channelId, byte level, byte opcode, short task, long keywords, string template, string description, ProviderMetadata pmReference)
        {
            Id = id;
            Version = version;
            this.channelId = channelId;
            this.level = level;
            this.opcode = opcode;
            this.task = task;
            this.keywords = keywords;
            Template = template;
            Description = description;
            this.pmReference = pmReference;
        }

        /// <summary>Gets the description template associated with the event using the current thread locale for the description language.</summary>
        /// <value>Returns a string that contains the description template associated with the event.</value>
        public string Description { get; private set; }

        /// <summary>Gets the identifier of the event that is defined in the event provider.</summary>
        /// <value>Returns a <see langword="long"/> value that is the event identifier.</value>
        public long Id { get; private set; }

        /// <summary>Gets the keywords associated with the event that is defined in the even provider.</summary>
        /// <value>Returns an enumerable collection of <see cref="EventKeyword"/> objects.</value>
        /// <remarks>
        /// The keywords for an event are used to group the event with other similar events based on the usage of the events. Each keyword is
        /// a bit in a 64-bit mask. Predefined bit values and reserved bits occupy the top 16 positions of this mask, leaving the manifest to
        /// use any bits between 0x0000000000000001 and 0x0000800000000000.
        /// <para>The standard event keywords are defined in the <see cref="StandardEventKeywords"/> enumeration.</para>
        /// </remarks>
        public IEnumerable<EventKeyword> Keywords
        {
            get
            {
                var list = new List<EventKeyword>();
                var keywords = (ulong)this.keywords;
                var num2 = 9223372036854775808L;
                for (var i = 0; i < 0x40; i++)
                {
                    if ((keywords & num2) > 0L)
                    {
                        list.Add(new EventKeyword((long)num2, pmReference));
                    }
                    num2 = num2 >> 1;
                }
                return list;
            }
        }

        /// <summary>
        /// Gets the level associated with the event that is defined in the event provider. The level defines the severity of the event.
        /// </summary>
        /// <value>Returns an <see cref="EventLevel"/> object.</value>
        /// <remarks>The standard event levels are defined in the <see cref="StandardEventLevel"/> enumeration.</remarks>
        public EventLevel Level => new EventLevel(level, pmReference);

        /// <summary>Gets a link to the event log that receives this event when the provider publishes this event.</summary>
        /// <value>Returns a <see cref="EventLogLink"/> object.</value>
        public EventLogLink LogLink => new EventLogLink(channelId, pmReference);

        /// <summary>
        /// Gets the opcode associated with this event that is defined by an event provider. The opcode defines a numeric value that
        /// identifies the activity or a point within an activity that the application was performing when it raised the event.
        /// </summary>
        /// <value>Returns a <see cref="EventOpcode"/> object.</value>
        public EventOpcode Opcode => new EventOpcode(opcode, pmReference);

        /// <summary>
        /// Gets the task associated with the event. A task identifies a portion of an application or a component that publishes an event.
        /// </summary>
        /// <value>Returns a <see cref="EventTask"/> object.</value>
        public EventTask Task => new EventTask(task, pmReference);

        /// <summary>
        /// Gets the template string for the event. Templates are used to describe data that is used by a provider when an event is
        /// published. Templates optionally specify XML that provides the structure of an event. The XML allows values that the event
        /// publisher provides to be inserted during the rendering of an event.
        /// </summary>
        /// <value>Returns a string that contains the template for the event.</value>
        public string Template { get; private set; }

        /// <summary>Gets the version of the event that qualifies the event identifier.</summary>
        /// <value>Returns a byte value.</value>
        public byte Version { get; private set; }
    }

    /// <summary>
    /// Contains an event opcode that is defined in an event provider. An opcode defines a numeric value that identifies the activity or a
    /// point within an activity that the application was performing when it raised the event.
    /// </summary>
    /// <remarks>
    /// This class cannot be instantiated. A <see cref="ProviderMetadata"/> object defies a list of <see cref="EventOpcode"/> objects, one
    /// for each opcode defined in the provider.
    /// <para>The standard event opcodes are defined in the <see cref="StandardEventOpcode"/> enumeration.</para>
    /// </remarks>
    public sealed class EventOpcode
    {
        private readonly object syncObject;
        private bool dataReady;
        private string displayName;
        private string name;
        private ProviderMetadata pmReference;

        internal EventOpcode(int value, ProviderMetadata pmReference)
        {
            Value = value;
            this.pmReference = pmReference;
            syncObject = new object();
        }

        internal EventOpcode(string name, int value, string displayName)
        {
            Value = value;
            this.name = name;
            this.displayName = displayName;
            dataReady = true;
            syncObject = new object();
        }

        /// <summary>Gets the localized name for an event opcode.</summary>
        /// <value>Returns a string that contains the localized name for an event opcode.</value>
        public string DisplayName
        {
            get
            {
                PrepareData();
                return displayName;
            }
        }

        /// <summary>Gets the non-localized name for an event opcode.</summary>
        /// <value>Returns a string that contains the non-localized name for an event opcode.</value>
        public string Name
        {
            get
            {
                PrepareData();
                return name;
            }
        }

        /// <summary>Gets the numeric value associated with the event opcode.</summary>
        /// <value>Returns an integer value.</value>
        public int Value { get; private set; }

        internal void PrepareData()
        {
            lock (syncObject)
            {
                if (!dataReady)
                {
                    IEnumerable<EventOpcode> opcodes = pmReference.Opcodes;
                    name = null;
                    displayName = null;
                    dataReady = true;
                    foreach (var opcode in opcodes)
                    {
                        if (opcode.Value == Value)
                        {
                            name = opcode.Name;
                            displayName = opcode.DisplayName;
                            dataReady = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    /// <summary>Contains the value of an event property that is specified by the event provider when the event is published.</summary>
    public sealed class EventProperty
    {
        internal EventProperty(object value) => Value = value;

        /// <summary>Gets the value of the event property that is specified by the event provider when the event is published.</summary>
        /// <value>Returns an object.</value>
        public object Value { get; private set; }
    }

    /// <summary>
    /// Defines the properties of an event instance for an event that is received from an <see cref="EventLogReader"/> object. The event
    /// properties provide information about the event such as the name of the computer where the event was logged and the time the event was
    /// created. This class is an abstract class. The <see cref="EventLogRecord"/> class implements this class.
    /// </summary>
    public abstract class EventRecord : IDisposable
    {
        /// <summary>Initializes a new instance of the <see cref="EventRecord"/> class.</summary>
        protected EventRecord()
        {
        }

        /// <summary>
        /// Gets the globally unique identifier (GUID) for the activity in process for which the event is involved. This allows consumers to
        /// group related activities.
        /// </summary>
        /// <value>Returns a GUID value.</value>
        public abstract Guid? ActivityId { get; }

        /// <summary>Gets a placeholder (bookmark) that corresponds to this event. This can be used as a placeholder in a stream of events.</summary>
        /// <value>Returns a <see cref="EventBookmark"/> object.</value>
        public abstract EventBookmark Bookmark { get; }

        /// <summary>Gets the identifier for this event. All events with this identifier value represent the same type of event.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public abstract int Id { get; }

        /// <summary>
        /// Gets the keyword mask of the event. Get the value of the <see cref="KeywordsDisplayNames"/> property to get the name of the
        /// keywords used in this mask.
        /// </summary>
        /// <value>Returns a long value. This value can be null.</value>
        /// <remarks>
        /// <para>
        /// The keywords for an event are used to group the event with other similar events based on the usage of the events. Each keyword is
        /// a bit in a 64-bit mask. Predefined bit values and reserved bits occupy the top 16 positions of this mask, leaving the manifest to
        /// use any bits between 0x0000000000000001 and 0x0000800000000000.
        /// </para>
        /// <para>The standard event keywords are defined in the <see cref="StandardEventKeywords"/> enumeration.</para>
        /// </remarks>
        public abstract long? Keywords { get; }

        /// <summary>Gets the display names of the keywords used in the keyword mask for this event.</summary>
        /// <value>
        /// Returns an enumerable collection of strings that contain the display names of the keywords used in the keyword mask for this event.
        /// </value>
        /// <remarks>The standard event keywords are defined in the <see cref="StandardEventKeywords"/> enumeration.</remarks>
        public abstract IEnumerable<string> KeywordsDisplayNames { get; }

        /// <summary>
        /// Gets the level of the event. The level signifies the severity of the event. For the name of the level, get the value of the <see
        /// cref="LevelDisplayName"/> property.
        /// </summary>
        /// <value>Returns a byte value. This value can be null.</value>
        public abstract byte? Level { get; }

        /// <summary>Gets the display name of the level for this event.</summary>
        /// <value>Returns a string that contains the display name of the level for this event.</value>
        /// <remarks>The standard event levels are defined in the <see cref="StandardEventLevel"/> enumeration.</remarks>
        public abstract string LevelDisplayName { get; }

        /// <summary>Gets the name of the event log where this event is logged.</summary>
        /// <value>Returns a string that contains a name of the event log that contains this event.</value>
        public abstract string LogName { get; }

        /// <summary>Gets the name of the computer on which this event was logged.</summary>
        /// <value>Returns a string that contains the name of the computer on which this event was logged.</value>
        public abstract string MachineName { get; }

        /// <summary>
        /// Gets the opcode of the event. The opcode defines a numeric value that identifies the activity or a point within an activity that
        /// the application was performing when it raised the event. For the name of the opcode, get the value of the OpcodeDisplayName property.
        /// </summary>
        /// <value>Returns a short value. This value can be null.</value>
        /// <remarks>The standard event opcodes are defined in the <see cref="StandardEventOpcode"/> enumeration.</remarks>
        public abstract short? Opcode { get; }

        /// <summary>Gets the display name of the opcode for this event.</summary>
        /// <value>Returns a string that contains the display name of the opcode for this event.</value>
        /// <remarks>The standard event opcodes are defined in the <see cref="StandardEventOpcode"/> enumeration.</remarks>
        public abstract string OpcodeDisplayName { get; }

        /// <summary>Gets the process identifier for the event provider that logged this event.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public abstract int? ProcessId { get; }

        /// <summary>Gets the user-supplied properties of the event.</summary>
        /// <value>Returns a list of <see cref="EventProperty"/> objects.</value>
        public abstract IList<EventProperty> Properties { get; }

        /// <summary>Gets the globally unique identifier (GUID) of the event provider that published this event.</summary>
        /// <value>Returns a GUID value. This value can be null.</value>
        public abstract Guid? ProviderId { get; }

        /// <summary>Gets the name of the event provider that published this event.</summary>
        /// <value>Returns a string that contains the name of the event provider that published this event.</value>
        public abstract string ProviderName { get; }

        /// <summary>Gets qualifier numbers that are used for event identification.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public abstract int? Qualifiers { get; }

        /// <summary>Gets the event record identifier of the event in the log.</summary>
        /// <value>Returns a long value. This value can be null.</value>
        public abstract long? RecordId { get; }

        /// <summary>Gets a globally unique identifier (GUID) for a related activity in a process for which an event is involved.</summary>
        /// <value>Returns a GUID value. This value can be null.</value>
        /// <remarks>
        /// An event provider can set the value of the ActivityID attribute before publishing events. All the events that are published after
        /// this ID is set will have the ActivityID attribute set to the specified value. This allows providers to specify simple
        /// relationships between events. The events that are published are part of the same activity. When a provider must start a new, but
        /// related activity, the publisher can publish a transfer event and specify the new activity ID. This new ID will appear as a
        /// RelatedActivityID attribute. This allows consumers to group related activities.
        /// </remarks>
        public abstract Guid? RelatedActivityId { get; }

        /// <summary>
        /// Gets a task identifier for a portion of an application or a component that publishes an event. A task is a 16-bit value with 16
        /// top values reserved. This type allows any value between 0x0000 and 0xffef to be used. For the name of the task, get the value of
        /// the <see cref="TaskDisplayName"/> property.
        /// </summary>
        /// <value>Returns an integer value. This value can be null.</value>
        /// <remarks>The standard event tasks are defined in the <see cref="StandardEventTask"/> enumeration.</remarks>
        public abstract int? Task { get; }

        /// <summary>Gets the display name of the task for the event.</summary>
        /// <value>Returns a string that contains the display name of the task for the event.</value>
        /// <remarks>The standard event tasks are defined in the <see cref="StandardEventTask"/> enumeration.</remarks>
        public abstract string TaskDisplayName { get; }

        /// <summary>Gets the thread identifier for the thread that the event provider is running in.</summary>
        /// <value>Returns an integer value. This value can be null.</value>
        public abstract int? ThreadId { get; }

        /// <summary>Gets the time, in <see cref="DateTime"/> format, that the event was created.</summary>
        /// <value>Returns a <see cref="DateTime"/> value. The value can be null.</value>
        public abstract DateTime? TimeCreated { get; }

        /// <summary>Gets the security descriptor of the user whose context is used to publish the event.</summary>
        /// <value>Returns a <see cref="SecurityIdentifier"/> value.</value>
        public abstract SecurityIdentifier UserId { get; }

        /// <summary>Gets the version number for the event.</summary>
        /// <value>Returns a byte value. This value can be null.</value>
        public abstract byte? Version { get; }

        /// <summary>Releases unmanaged and - optionally - managed resources.</summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Gets the event message in the current locale.</summary>
        /// <returns>Returns a string that contains the event message in the current locale.</returns>
        public abstract string FormatDescription();

        /// <summary>Gets the event message, replacing variables in the message with the specified values.</summary>
        /// <param name="values">
        /// The values used to replace variables in the event message. Variables are represented by %n, where n is a number.
        /// </param>
        /// <returns>Returns a string that contains the event message in the current locale.</returns>
        public abstract string FormatDescription(IEnumerable<object> values);

        /// <summary>
        /// Gets the XML representation of the event. All of the event properties are represented in the event's XML. The XML conforms to the
        /// event schema.
        /// </summary>
        /// <returns>Returns a string that contains the XML representation of the event.</returns>
        public abstract string ToXml();

        /// <summary>Releases the unmanaged resources used by this object, and optionally releases the managed resources.</summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
        }
    }

    /// <summary>
    /// When the <see cref="EventLogWatcher.EventRecordWritten"/> event is raised, an instance of this object is passed to the delegate method that handles
    /// the event. This object contains the event that was published to the event log or the exception that occurred when the event
    /// subscription failed.
    /// </summary>
    public sealed class EventRecordWrittenEventArgs : EventArgs
    {
        internal EventRecordWrittenEventArgs(EventLogRecord record) => EventRecord = record;

        internal EventRecordWrittenEventArgs(EventLogException exception) => EventException = exception;

        /// <summary>
        /// Gets the exception that occurred when the event subscription failed. The exception has a description of why the subscription failed.
        /// </summary>
        /// <value>Returns a <see cref="Exception"/> object.</value>
        public Exception EventException { get; private set; }

        /// <summary>
        /// Gets the event record that is published to the event log. This event matches the criteria from the query specified in the event subscription.
        /// </summary>
        /// <value>Returns a <see cref="EventRecord"/> object.</value>
        public EventRecord EventRecord { get; private set; }
    }

    /// <summary>
    /// Contains an event task that is defined in an event provider. The task identifies a portion of an application or a component that
    /// publishes an event. A task is a 16-bit value with 16 top values reserved.
    /// </summary>
    /// <remarks>
    /// This class cannot be instantiated. A <see cref="ProviderMetadata"/> object defies a list of <see cref="EventTask"/> objects, one for
    /// each task defined in the provider. The standard task values and their meanings are defined in the <see cref="StandardEventLevel"/> enumeration.
    /// </remarks>
    public sealed class EventTask
    {
        private readonly object syncObject;
        private bool dataReady;
        private string displayName;
        private Guid guid;
        private string name;
        private ProviderMetadata pmReference;

        internal EventTask(int value, ProviderMetadata pmReference)
        {
            Value = value;
            this.pmReference = pmReference;
            syncObject = new object();
        }

        internal EventTask(string name, int value, string displayName, Guid guid)
        {
            Value = value;
            this.name = name;
            this.displayName = displayName;
            this.guid = guid;
            dataReady = true;
            syncObject = new object();
        }

        /// <summary>Gets the localized name for the event task.</summary>
        /// <value>Returns a string that contains the localized name for the event task.</value>
        public string DisplayName
        {
            get
            {
                PrepareData();
                return displayName;
            }
        }

        /// <summary>Gets the event globally unique identifier (GUID) associated with the task.</summary>
        /// <value>Returns a GUID value.</value>
        public Guid EventGuid
        {
            get
            {
                PrepareData();
                return guid;
            }
        }

        /// <summary>Gets the non-localized name of the event task.</summary>
        /// <value>Returns a string that contains the non-localized name of the event task.</value>
        public string Name
        {
            get
            {
                PrepareData();
                return name;
            }
        }

        /// <summary>Gets the numeric value associated with the task.</summary>
        /// <value>Returns an integer value.</value>
        public int Value { get; private set; }

        internal void PrepareData()
        {
            lock (syncObject)
            {
                if (!dataReady)
                {
                    IEnumerable<EventTask> tasks = pmReference.Tasks;
                    name = null;
                    displayName = null;
                    guid = Guid.Empty;
                    dataReady = true;
                    foreach (var task in tasks)
                    {
                        if (task.Value == Value)
                        {
                            name = task.Name;
                            displayName = task.DisplayName;
                            guid = task.EventGuid;
                            dataReady = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    /// <summary>
    /// Contains static information about an event provider, such as the name and id of the provider, and the collection of events defined in
    /// the provider.
    /// </summary>
    /// <seealso cref="System.IDisposable"/>
    public class ProviderMetadata : IDisposable
    {
        private readonly string logFilePath;
        private readonly object syncObject;
        private IList<EventLogLink> channelReferences;
        private CultureInfo cultureInfo;
        private EventLogHandle defaultProviderHandle;
        private IList<EventKeyword> keywords;
        private IList<EventLevel> levels;
        private IList<EventOpcode> opcodes;
        private EventLogSession session;
        private IList<EventKeyword> standardKeywords;
        private IList<EventLevel> standardLevels;
        private IList<EventOpcode> standardOpcodes;
        private IList<EventTask> standardTasks;
        private IList<EventTask> tasks;

        /// <summary>
        /// Initializes a new instance of the <see cref="ProviderMetadata"/> class by specifying the name of the provider that you want to
        /// retrieve information about.
        /// </summary>
        /// <param name="providerName">The name of the event provider that you want to retrieve information about.</param>
        public ProviderMetadata(string providerName) : this(providerName, null, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ProviderMetadata"/> class by specifying the name of the provider that you want to
        /// retrieve information about, the event log service that the provider is registered with, and the language that you want to return
        /// the information in.
        /// </summary>
        /// <param name="providerName">The name of the event provider that you want to retrieve information about.</param>
        /// <param name="session">
        /// The <see cref="EventLogSession"/> object that specifies whether to get the provider information from a provider on the local
        /// computer or a provider on a remote computer.
        /// </param>
        /// <param name="targetCultureInfo">The culture that specifies the language that the information should be returned in.</param>
        public ProviderMetadata(string providerName, EventLogSession session, CultureInfo targetCultureInfo)
            : this(providerName, session, targetCultureInfo, null)
        {
        }

        [SecurityCritical]
        internal ProviderMetadata(string providerName, EventLogSession session, CultureInfo targetCultureInfo, string logFilePath)
        {
            Handle = EventLogHandle.Zero;
            defaultProviderHandle = EventLogHandle.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            if (targetCultureInfo is null)
            {
                targetCultureInfo = CultureInfo.CurrentCulture;
            }
            if (session is null)
            {
                session = EventLogSession.GlobalSession;
            }
            this.session = session;
            Name = providerName;
            cultureInfo = targetCultureInfo;
            this.logFilePath = logFilePath;
            Handle = NativeWrapper.EvtOpenProviderMetadata(this.session.Handle, Name, this.logFilePath, cultureInfo.LCID, 0);
            syncObject = new object();
        }

        internal enum ObjectTypeName
        {
            Level,
            Opcode,
            Task,
            Keyword
        }

        /// <summary>Gets the localized name of the event provider.</summary>
        /// <value>Returns a string that contains the localized name of the event provider.</value>
        public string DisplayName
        {
            [SecurityCritical]
            get
            {
                var providerMessageID = ProviderMessageID;
                if (providerMessageID == uint.MaxValue)
                {
                    return null;
                }
                EventLogPermissionHolder.GetEventLogPermission().Demand();
                return NativeWrapper.EvtFormatMessage(Handle, providerMessageID);
            }
        }

        /// <summary>
        /// Gets an enumerable collection of <see cref="EventMetadata"/> objects, each of which represents an event that is defined in the provider.
        /// </summary>
        /// <value>Returns an enumerable collection of <see cref="EventMetadata"/> objects.</value>
        public IEnumerable<EventMetadata> Events
        {
            [SecurityCritical]
            get
            {
                EventLogPermissionHolder.GetEventLogPermission().Demand();
                var list = new List<EventMetadata>();
                var eventMetadataEnum = NativeWrapper.EvtOpenEventMetadataEnum(Handle, 0);
                using (eventMetadataEnum)
                {
                    EventLogHandle handle2;
                Label_0020:
                    handle2 = handle2 = NativeWrapper.EvtNextEventMetadata(eventMetadataEnum, 0);
                    if (handle2 != null)
                    {
                        using (handle2)
                        {
                            string str2;
                            var id = (uint)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventID);
                            var version = (byte)(uint)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventVersion);
                            var channelId = (byte)(uint)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventChannel);
                            var level = (byte)(uint)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventLevel);
                            var opcode = (byte)(uint)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventOpcode);
                            var task = (short)(uint)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventTask);
                            var keywords = (long)(ulong)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventKeyword);
                            var template = (string)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventTemplate);
                            var num8 = (int)(uint)NativeWrapper.EvtGetEventMetadataProperty(handle2, UnsafeNativeMethods.EvtEventMetadataPropertyId.EventMetadataEventMessageID);
                            if (num8 == -1)
                            {
                                str2 = null;
                            }
                            else
                            {
                                str2 = NativeWrapper.EvtFormatMessage(Handle, (uint)num8);
                            }
                            var item = new EventMetadata(id, version, channelId, level, opcode, task, keywords, template, str2, this);
                            list.Add(item);
                            goto Label_0020;
                        }
                    }
                    return list.AsReadOnly();
                }
            }
        }

        /// <summary>Gets the base of the URL used to form help requests for the events in this event provider.</summary>
        /// <value>Returns a <see cref="Uri"/> value.</value>
        public Uri HelpLink
        {
            get
            {
                var uriString = (string)NativeWrapper.EvtGetPublisherMetadataProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataHelpLink);
                return uriString != null && uriString.Length != 0 ? new Uri(uriString) : null;
            }
        }

        /// <summary>Gets the globally unique identifier (GUID) for the event provider.</summary>
        /// <value>Returns the GUID value for the event provider.</value>
        public Guid Id => (Guid)NativeWrapper.EvtGetPublisherMetadataProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataPublisherGuid);

        /// <summary>
        /// Gets an enumerable collection of <see cref="EventKeyword"/> objects, each of which represent an event keyword that is defined in
        /// the event provider.
        /// </summary>
        /// <value>Returns an enumerable collection of <see cref="EventKeyword"/> objects.</value>
        public IList<EventKeyword> Keywords
        {
            get
            {
                lock (syncObject)
                {
                    if (keywords != null)
                    {
                        return keywords;
                    }
                    keywords = ((List<EventKeyword>)GetProviderListProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataKeywords)).AsReadOnly();
                }
                return keywords;
            }
        }

        /// <summary>
        /// Gets an enumerable collection of <see cref="EventLevel"/> objects, each of which represent a level that is defined in the event provider.
        /// </summary>
        /// <value>Returns an enumerable collection of <see cref="EventLevel"/> objects.</value>
        public IList<EventLevel> Levels
        {
            get
            {
                lock (syncObject)
                {
                    if (levels != null)
                    {
                        return levels;
                    }
                    levels = ((List<EventLevel>)GetProviderListProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataLevels)).AsReadOnly();
                }
                return levels;
            }
        }

        /// <summary>
        /// Gets an enumerable collection of <see cref="EventLogLink"/> objects, each of which represent a link to an event log that is used
        /// by the event provider.
        /// </summary>
        /// <value>Returns an enumerable collection of <see cref="EventLogLink"/> objects.</value>
        public IList<EventLogLink> LogLinks
        {
            [SecurityCritical]
            get
            {
                IList<EventLogLink> channelReferences;
                var zero = EventLogHandle.Zero;
                try
                {
                    lock (syncObject)
                    {
                        if (this.channelReferences != null)
                        {
                            return this.channelReferences;
                        }
                        EventLogPermissionHolder.GetEventLogPermission().Demand();
                        zero = NativeWrapper.EvtGetPublisherMetadataPropertyHandle(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataChannelReferences);
                        var capacity = NativeWrapper.EvtGetObjectArraySize(zero);
                        var list = new List<EventLogLink>(capacity);
                        for (var i = 0; i < capacity; i++)
                        {
                            bool flag;
                            string str2;
                            var strA = (string)NativeWrapper.EvtGetObjectArrayProperty(zero, i, 7);
                            var channelId = (uint)NativeWrapper.EvtGetObjectArrayProperty(zero, i, 9);
                            var num4 = (uint)NativeWrapper.EvtGetObjectArrayProperty(zero, i, 10);
                            if (num4 == 1)
                            {
                                flag = true;
                            }
                            else
                            {
                                flag = false;
                            }
                            var num5 = (int)(uint)NativeWrapper.EvtGetObjectArrayProperty(zero, i, 11);
                            if (num5 == -1)
                            {
                                str2 = null;
                            }
                            else
                            {
                                str2 = NativeWrapper.EvtFormatMessage(Handle, (uint)num5);
                            }
                            if (str2 is null && flag)
                            {
                                if (string.Compare(strA, "Application", StringComparison.OrdinalIgnoreCase) == 0)
                                {
                                    num5 = 0x100;
                                }
                                else if (string.Compare(strA, "System", StringComparison.OrdinalIgnoreCase) == 0)
                                {
                                    num5 = 0x102;
                                }
                                else if (string.Compare(strA, "Security", StringComparison.OrdinalIgnoreCase) == 0)
                                {
                                    num5 = 0x101;
                                }
                                else
                                {
                                    num5 = -1;
                                }
                                if (num5 != -1)
                                {
                                    if (defaultProviderHandle.IsInvalid)
                                    {
                                        defaultProviderHandle = NativeWrapper.EvtOpenProviderMetadata(session.Handle, null, null, cultureInfo.LCID, 0);
                                    }
                                    str2 = NativeWrapper.EvtFormatMessage(defaultProviderHandle, (uint)num5);
                                }
                            }
                            list.Add(new EventLogLink(strA, flag, str2, channelId));
                        }
                        this.channelReferences = list.AsReadOnly();
                    }
                    channelReferences = this.channelReferences;
                }
                finally
                {
                    zero.Close();
                }
                return channelReferences;
            }
        }

        /// <summary>
        /// Gets the path of the file that contains the message table resource that has the strings associated with the provider metadata.
        /// </summary>
        /// <value>Returns a string that contains the path of the provider message file.</value>
        public string MessageFilePath => (string)NativeWrapper.EvtGetPublisherMetadataProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataMessageFilePath);

        /// <summary>Gets the unique name of the event provider.</summary>
        /// <value>Returns a string that contains the unique name of the event provider.</value>
        public string Name { get; private set; }

        /// <summary>
        /// Gets an enumerable collection of <see cref="EventOpcode"/> objects, each of which represent an opcode that is defined in the
        /// event provider.
        /// </summary>
        /// <value>Returns an enumerable collection of <see cref="EventOpcode"/> objects.</value>
        public IList<EventOpcode> Opcodes
        {
            get
            {
                lock (syncObject)
                {
                    if (opcodes != null)
                    {
                        return opcodes;
                    }
                    opcodes = ((List<EventOpcode>)GetProviderListProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataOpcodes)).AsReadOnly();
                }
                return opcodes;
            }
        }

        /// <summary>
        /// Gets the path of the file that contains the message table resource that has the strings used for parameter substitutions in event descriptions.
        /// </summary>
        /// <value>
        /// Returns a string that contains the path of the file that contains the message table resource that has the strings used for
        /// parameter substitutions in event descriptions.
        /// </value>
        public string ParameterFilePath => (string)NativeWrapper.EvtGetPublisherMetadataProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataParameterFilePath);

        /// <summary>Gets the path to the file that contains the metadata associated with the provider.</summary>
        /// <value>Returns a string that contains the path to the file that contains the metadata associated with the provider.</value>
        public string ResourceFilePath => (string)NativeWrapper.EvtGetPublisherMetadataProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataResourceFilePath);

        /// <summary>
        /// Gets an enumerable collection of <see cref="EventTask"/> objects, each of which represent a task that is defined in the event provider.
        /// </summary>
        /// <value>Returns an enumerable collection of <see cref="EventTask"/> objects.</value>
        public IList<EventTask> Tasks
        {
            get
            {
                lock (syncObject)
                {
                    if (tasks != null)
                    {
                        return tasks;
                    }
                    tasks = ((List<EventTask>)GetProviderListProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataTasks)).AsReadOnly();
                }
                return tasks;
            }
        }

        internal EventLogHandle Handle { get; private set; }

        private uint ProviderMessageID => (uint)NativeWrapper.EvtGetPublisherMetadataProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataPublisherMessageID);

        /// <summary>Releases all the resources used by this object.</summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        internal void CheckReleased()
        {
            lock (syncObject)
            {
                GetProviderListProperty(Handle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataTasks);
            }
        }

        internal string FindStandardKeywordDisplayName(string name, long value)
        {
            if (standardKeywords is null)
            {
                standardKeywords = (List<EventKeyword>)GetProviderListProperty(defaultProviderHandle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataKeywords);
            }
            foreach (var keyword in standardKeywords)
            {
                if (keyword.Name == name && keyword.Value == value)
                {
                    return keyword.DisplayName;
                }
            }
            return null;
        }

        internal string FindStandardLevelDisplayName(string name, uint value)
        {
            if (standardLevels is null)
            {
                standardLevels = (List<EventLevel>)GetProviderListProperty(defaultProviderHandle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataLevels);
            }
            foreach (var level in standardLevels)
            {
                if (level.Name == name && level.Value == value)
                {
                    return level.DisplayName;
                }
            }
            return null;
        }

        internal string FindStandardOpcodeDisplayName(string name, uint value)
        {
            if (standardOpcodes is null)
            {
                standardOpcodes = (List<EventOpcode>)GetProviderListProperty(defaultProviderHandle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataOpcodes);
            }
            foreach (var opcode in standardOpcodes)
            {
                if (opcode.Name == name && opcode.Value == value)
                {
                    return opcode.DisplayName;
                }
            }
            return null;
        }

        internal string FindStandardTaskDisplayName(string name, uint value)
        {
            if (standardTasks is null)
            {
                standardTasks = (List<EventTask>)GetProviderListProperty(defaultProviderHandle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataTasks);
            }
            foreach (var task in standardTasks)
            {
                if (task.Name == name && task.Value == value)
                {
                    return task.DisplayName;
                }
            }
            return null;
        }

        [SecurityCritical]
        internal object GetProviderListProperty(EventLogHandle providerHandle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId metadataProperty)
        {
            object obj2;
            var zero = EventLogHandle.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            try
            {
                UnsafeNativeMethods.EvtPublisherMetadataPropertyId evtPublisherMetadataOpcodeName;
                UnsafeNativeMethods.EvtPublisherMetadataPropertyId evtPublisherMetadataOpcodeValue;
                UnsafeNativeMethods.EvtPublisherMetadataPropertyId evtPublisherMetadataOpcodeMessageID;
                ObjectTypeName opcode;
                List<EventLevel> list = null;
                List<EventOpcode> list2 = null;
                List<EventKeyword> list3 = null;
                List<EventTask> list4 = null;
                zero = NativeWrapper.EvtGetPublisherMetadataPropertyHandle(providerHandle, metadataProperty);
                var capacity = NativeWrapper.EvtGetObjectArraySize(zero);
                switch (metadataProperty)
                {
                    case UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataOpcodes:
                        evtPublisherMetadataOpcodeName = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataOpcodeName;
                        evtPublisherMetadataOpcodeValue = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataOpcodeValue;
                        evtPublisherMetadataOpcodeMessageID = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataOpcodeMessageID;
                        opcode = ObjectTypeName.Opcode;
                        list2 = new List<EventOpcode>(capacity);
                        break;

                    case UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataKeywords:
                        evtPublisherMetadataOpcodeName = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataKeywordName;
                        evtPublisherMetadataOpcodeValue = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataKeywordValue;
                        evtPublisherMetadataOpcodeMessageID = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataKeywordMessageID;
                        opcode = ObjectTypeName.Keyword;
                        list3 = new List<EventKeyword>(capacity);
                        break;

                    case UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataLevels:
                        evtPublisherMetadataOpcodeName = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataLevelName;
                        evtPublisherMetadataOpcodeValue = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataLevelValue;
                        evtPublisherMetadataOpcodeMessageID = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataLevelMessageID;
                        opcode = ObjectTypeName.Level;
                        list = new List<EventLevel>(capacity);
                        break;

                    case UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataTasks:
                        evtPublisherMetadataOpcodeName = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataTaskName;
                        evtPublisherMetadataOpcodeValue = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataTaskValue;
                        evtPublisherMetadataOpcodeMessageID = UnsafeNativeMethods.EvtPublisherMetadataPropertyId.EvtPublisherMetadataTaskMessageID;
                        opcode = ObjectTypeName.Task;
                        list4 = new List<EventTask>(capacity);
                        break;

                    default:
                        return null;
                }
                for (var i = 0; i < capacity; i++)
                {
                    var name = (string)NativeWrapper.EvtGetObjectArrayProperty(zero, i, (int)evtPublisherMetadataOpcodeName);
                    uint num3 = 0;
                    var num4 = 0L;
                    if (opcode != ObjectTypeName.Keyword)
                    {
                        num3 = (uint)NativeWrapper.EvtGetObjectArrayProperty(zero, i, (int)evtPublisherMetadataOpcodeValue);
                    }
                    else
                    {
                        num4 = (long)(ulong)NativeWrapper.EvtGetObjectArrayProperty(zero, i, (int)evtPublisherMetadataOpcodeValue);
                    }
                    var num5 = (int)(uint)NativeWrapper.EvtGetObjectArrayProperty(zero, i, (int)evtPublisherMetadataOpcodeMessageID);
                    string displayName = null;
                    if (num5 == -1)
                    {
                        if (providerHandle != defaultProviderHandle)
                        {
                            if (defaultProviderHandle.IsInvalid)
                            {
                                defaultProviderHandle = NativeWrapper.EvtOpenProviderMetadata(session.Handle, null, null, cultureInfo.LCID, 0);
                            }
                            switch (opcode)
                            {
                                case ObjectTypeName.Level:
                                    displayName = FindStandardLevelDisplayName(name, num3);
                                    goto Label_01BA;

                                case ObjectTypeName.Opcode:
                                    displayName = FindStandardOpcodeDisplayName(name, num3 >> 0x10);
                                    goto Label_01BA;

                                case ObjectTypeName.Task:
                                    displayName = FindStandardTaskDisplayName(name, num3);
                                    goto Label_01BA;

                                case ObjectTypeName.Keyword:
                                    displayName = FindStandardKeywordDisplayName(name, num4);
                                    goto Label_01BA;
                            }
                            displayName = null;
                        }
                    }
                    else
                    {
                        displayName = NativeWrapper.EvtFormatMessage(providerHandle, (uint)num5);
                    }
                Label_01BA:
                    switch (opcode)
                    {
                        case ObjectTypeName.Level:
                            list.Add(new EventLevel(name, (int)num3, displayName));
                            break;

                        case ObjectTypeName.Opcode:
                            list2.Add(new EventOpcode(name, (int)(num3 >> 0x10), displayName));
                            break;

                        case ObjectTypeName.Task:
                            {
                                var guid = (Guid)NativeWrapper.EvtGetObjectArrayProperty(zero, i, 0x12);
                                list4.Add(new EventTask(name, (int)num3, displayName, guid));
                                break;
                            }
                        case ObjectTypeName.Keyword:
                            list3.Add(new EventKeyword(name, num4, displayName));
                            break;

                        default:
                            return null;
                    }
                }
                switch (opcode)
                {
                    case ObjectTypeName.Level:
                        return list;

                    case ObjectTypeName.Opcode:
                        return list2;

                    case ObjectTypeName.Task:
                        return list4;

                    case ObjectTypeName.Keyword:
                        return list3;
                }
                obj2 = null;
            }
            finally
            {
                zero.Close();
            }
            return obj2;
        }

        /// <summary>Releases the unmanaged resources used by this object, and optionally releases the managed resources.</summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.
        /// </param>
        [SecurityCritical]
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                EventLogPermissionHolder.GetEventLogPermission().Demand();
            }
            if (Handle != null && !Handle.IsInvalid)
            {
                Handle.Dispose();
            }
        }
    }

    internal static class UnsafeNativeMethods
    {
        internal enum EvtChannelConfigPropertyId
        {
            EvtChannelConfigEnabled,
            EvtChannelConfigIsolation,
            EvtChannelConfigType,
            EvtChannelConfigOwningPublisher,
            EvtChannelConfigClassicEventlog,
            EvtChannelConfigAccess,
            EvtChannelLoggingConfigRetention,
            EvtChannelLoggingConfigAutoBackup,
            EvtChannelLoggingConfigMaxSize,
            EvtChannelLoggingConfigLogFilePath,
            EvtChannelPublishingConfigLevel,
            EvtChannelPublishingConfigKeywords,
            EvtChannelPublishingConfigControlGuid,
            EvtChannelPublishingConfigBufferSize,
            EvtChannelPublishingConfigMinBuffers,
            EvtChannelPublishingConfigMaxBuffers,
            EvtChannelPublishingConfigLatency,
            EvtChannelPublishingConfigClockType,
            EvtChannelPublishingConfigSidType,
            EvtChannelPublisherList,
            EvtChannelConfigPropertyIdEND
        }

        internal enum EvtEventMetadataPropertyId
        {
            EventMetadataEventID,
            EventMetadataEventVersion,
            EventMetadataEventChannel,
            EventMetadataEventLevel,
            EventMetadataEventOpcode,
            EventMetadataEventTask,
            EventMetadataEventKeyword,
            EventMetadataEventMessageID,
            EventMetadataEventTemplate
        }

        internal enum EvtEventPropertyId
        {
            EvtEventQueryIDs,
            EvtEventPath
        }

        internal enum EvtExportLogFlags
        {
            EvtExportLogChannelPath = 1,
            EvtExportLogFilePath = 2,
            EvtExportLogTolerateQueryErrors = 0x1000
        }

        internal enum EvtFormatMessageFlags
        {
            EvtFormatMessageChannel = 6,
            EvtFormatMessageEvent = 1,
            EvtFormatMessageId = 8,
            EvtFormatMessageKeyword = 5,
            EvtFormatMessageLevel = 2,
            EvtFormatMessageOpcode = 4,
            EvtFormatMessageProvider = 7,
            EvtFormatMessageTask = 3,
            EvtFormatMessageXml = 9
        }

        internal enum EvtLoginClass
        {
            EvtRpcLogin = 1
        }

        internal enum EvtLogPropertyId
        {
            EvtLogCreationTime,
            EvtLogLastAccessTime,
            EvtLogLastWriteTime,
            EvtLogFileSize,
            EvtLogAttributes,
            EvtLogNumberOfLogRecords,
            EvtLogOldestRecordNumber,
            EvtLogFull
        }

        internal enum EvtPublisherMetadataPropertyId
        {
            EvtPublisherMetadataPublisherGuid,
            EvtPublisherMetadataResourceFilePath,
            EvtPublisherMetadataParameterFilePath,
            EvtPublisherMetadataMessageFilePath,
            EvtPublisherMetadataHelpLink,
            EvtPublisherMetadataPublisherMessageID,
            EvtPublisherMetadataChannelReferences,
            EvtPublisherMetadataChannelReferencePath,
            EvtPublisherMetadataChannelReferenceIndex,
            EvtPublisherMetadataChannelReferenceID,
            EvtPublisherMetadataChannelReferenceFlags,
            EvtPublisherMetadataChannelReferenceMessageID,
            EvtPublisherMetadataLevels,
            EvtPublisherMetadataLevelName,
            EvtPublisherMetadataLevelValue,
            EvtPublisherMetadataLevelMessageID,
            EvtPublisherMetadataTasks,
            EvtPublisherMetadataTaskName,
            EvtPublisherMetadataTaskEventGuid,
            EvtPublisherMetadataTaskValue,
            EvtPublisherMetadataTaskMessageID,
            EvtPublisherMetadataOpcodes,
            EvtPublisherMetadataOpcodeName,
            EvtPublisherMetadataOpcodeValue,
            EvtPublisherMetadataOpcodeMessageID,
            EvtPublisherMetadataKeywords,
            EvtPublisherMetadataKeywordName,
            EvtPublisherMetadataKeywordValue,
            EvtPublisherMetadataKeywordMessageID
        }

        internal enum EvtQueryPropertyId
        {
            EvtQueryNames,
            EvtQueryStatuses
        }

        internal enum EvtRenderContextFlags
        {
            EvtRenderContextValues,
            EvtRenderContextSystem,
            EvtRenderContextUser
        }

        internal enum EvtRenderFlags
        {
            EvtRenderEventValues,
            EvtRenderEventXml,
            EvtRenderBookmark
        }

        [Flags]
        internal enum EvtSeekFlags
        {
            EvtSeekOriginMask = 7,
            EvtSeekRelativeToBookmark = 4,
            EvtSeekRelativeToCurrent = 3,
            EvtSeekRelativeToFirst = 1,
            EvtSeekRelativeToLast = 2,
            EvtSeekStrict = 0x10000
        }

        [Flags]
        internal enum EvtSubscribeFlags
        {
            EvtSubscribeToFutureEvents = 1,
            EvtSubscribeStartAtOldestRecord = 2,
            EvtSubscribeStartAfterBookmark = 3,
            EvtSubscribeTolerateQueryErrors = 0x1000,
            EvtSubscribeStrict = 0x10000
        }

        internal enum EvtVariantType
        {
            EvtVarTypeAnsiString = 2,
            EvtVarTypeBinary = 14,
            EvtVarTypeBoolean = 13,
            EvtVarTypeByte = 4,
            EvtVarTypeDouble = 12,
            EvtVarTypeEvtHandle = 0x20,
            EvtVarTypeEvtXml = 0x23,
            EvtVarTypeFileTime = 0x11,
            EvtVarTypeGuid = 15,
            EvtVarTypeHexInt32 = 20,
            EvtVarTypeHexInt64 = 0x15,
            EvtVarTypeInt16 = 5,
            EvtVarTypeInt32 = 7,
            EvtVarTypeInt64 = 9,
            EvtVarTypeNull = 0,
            EvtVarTypeSByte = 3,
            EvtVarTypeSid = 0x13,
            EvtVarTypeSingle = 11,
            EvtVarTypeSizeT = 0x10,
            EvtVarTypeString = 1,
            EvtVarTypeStringArray = 0x81,
            EvtVarTypeSysTime = 0x12,
            EvtVarTypeUInt16 = 6,
            EvtVarTypeUInt32 = 8,
            EvtVarTypeUInt32Array = 0x88,
            EvtVarTypeUInt64 = 10
        }

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtArchiveExportedLog(EventLogHandle session, [MarshalAs(UnmanagedType.LPWStr)] string logFilePath, int locale, int flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", SetLastError = true)]
        internal static extern bool EvtCancel(EventLogHandle handle);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtClearLog(EventLogHandle session, [MarshalAs(UnmanagedType.LPWStr)] string channelPath, [MarshalAs(UnmanagedType.LPWStr)] string targetFilePath, int flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success), DllImport("wevtapi.dll")]
        internal static extern bool EvtClose(IntPtr handle);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtCreateBookmark([MarshalAs(UnmanagedType.LPWStr)] string bookmarkXml);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtCreateRenderContext(int valuePathsCount, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] valuePaths, [MarshalAs(UnmanagedType.I4)] EvtRenderContextFlags flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtExportLog(EventLogHandle session, [MarshalAs(UnmanagedType.LPWStr)] string channelPath, [MarshalAs(UnmanagedType.LPWStr)] string query, [MarshalAs(UnmanagedType.LPWStr)] string targetFilePath, int flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtFormatMessage(EventLogHandle publisherMetadataHandle, EventLogHandle eventHandle, uint messageId, int valueCount, EvtStringVariant[] values, [MarshalAs(UnmanagedType.I4)] EvtFormatMessageFlags flags, int bufferSize, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder buffer, out int bufferUsed);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", EntryPoint = "EvtFormatMessage", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtFormatMessageBuffer(EventLogHandle publisherMetadataHandle, EventLogHandle eventHandle, uint messageId, int valueCount, IntPtr values, [MarshalAs(UnmanagedType.I4)] EvtFormatMessageFlags flags, int bufferSize, IntPtr buffer, out int bufferUsed);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtGetChannelConfigProperty(EventLogHandle channelConfig, [MarshalAs(UnmanagedType.I4)] EvtChannelConfigPropertyId propertyId, int flags, int propertyValueBufferSize, IntPtr propertyValueBuffer, out int propertyValueBufferUsed);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtGetEventInfo(EventLogHandle eventHandle, [MarshalAs(UnmanagedType.I4)] EvtEventPropertyId propertyId, int bufferSize, IntPtr bufferPtr, out int bufferUsed);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtGetEventMetadataProperty(EventLogHandle eventMetadata, [MarshalAs(UnmanagedType.I4)] EvtEventMetadataPropertyId propertyId, int flags, int eventMetadataPropertyBufferSize, IntPtr eventMetadataPropertyBuffer, out int eventMetadataPropertyBufferUsed);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtGetLogInfo(EventLogHandle log, [MarshalAs(UnmanagedType.I4)] EvtLogPropertyId propertyId, int propertyValueBufferSize, IntPtr propertyValueBuffer, out int propertyValueBufferUsed);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtGetObjectArrayProperty(EventLogHandle objectArray, int propertyId, int arrayIndex, int flags, int propertyValueBufferSize, IntPtr propertyValueBuffer, out int propertyValueBufferUsed);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtGetObjectArraySize(EventLogHandle objectArray, out int objectArraySize);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtGetPublisherMetadataProperty(EventLogHandle publisherMetadataHandle, [MarshalAs(UnmanagedType.I4)] EvtPublisherMetadataPropertyId propertyId, int flags, int publisherMetadataPropertyBufferSize, IntPtr publisherMetadataPropertyBuffer, out int publisherMetadataPropertyBufferUsed);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtGetQueryInfo(EventLogHandle queryHandle, [MarshalAs(UnmanagedType.I4)] EvtQueryPropertyId propertyId, int bufferSize, IntPtr buffer, ref int bufferRequired);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", SetLastError = true)]
        internal static extern bool EvtNext(EventLogHandle queryHandle, int eventSize, [MarshalAs(UnmanagedType.LPArray)] IntPtr[] events, int timeout, int flags, ref int returned);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtNextChannelPath(EventLogHandle channelEnum, int channelPathBufferSize, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder channelPathBuffer, out int channelPathBufferUsed);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtNextEventMetadata(EventLogHandle eventMetadataEnum, int flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtNextPublisherId(EventLogHandle publisherEnum, int publisherIdBufferSize, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder publisherIdBuffer, out int publisherIdBufferUsed);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtOpenChannelConfig(EventLogHandle session, [MarshalAs(UnmanagedType.LPWStr)] string channelPath, int flags);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtOpenChannelEnum(EventLogHandle session, int flags);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtOpenEventMetadataEnum(EventLogHandle publisherMetadata, int flags);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtOpenLog(EventLogHandle session, [MarshalAs(UnmanagedType.LPWStr)] string path, [MarshalAs(UnmanagedType.I4)] PathType flags);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtOpenPublisherEnum(EventLogHandle session, int flags);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtOpenPublisherMetadata(EventLogHandle session, [MarshalAs(UnmanagedType.LPWStr)] string publisherId, [MarshalAs(UnmanagedType.LPWStr)] string logFilePath, int locale, int flags);

        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern EventLogHandle EvtOpenSession([MarshalAs(UnmanagedType.I4)] EvtLoginClass loginClass, ref EvtRpcLogin login, int timeout, int flags);

        [DllImport("wevtapi.dll", SetLastError = true)]
        internal static extern EventLogHandle EvtQuery(EventLogHandle session, [MarshalAs(UnmanagedType.LPWStr)] string path, [MarshalAs(UnmanagedType.LPWStr)] string query, int flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", SetLastError = true)]
        internal static extern bool EvtRender(EventLogHandle context, EventLogHandle eventHandle, EvtRenderFlags flags, int buffSize, IntPtr buffer, out int buffUsed, out int propCount);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", SetLastError = true)]
        internal static extern bool EvtRender(EventLogHandle context, EventLogHandle eventHandle, EvtRenderFlags flags, int buffSize, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder buffer, out int buffUsed, out int propCount);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtSaveChannelConfig(EventLogHandle channelConfig, int flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtSeek(EventLogHandle resultSet, long position, EventLogHandle bookmark, int timeout, [MarshalAs(UnmanagedType.I4)] EvtSeekFlags flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtSetChannelConfigProperty(EventLogHandle channelConfig, [MarshalAs(UnmanagedType.I4)] EvtChannelConfigPropertyId propertyId, int flags, ref EvtVariant propertyValue);

        [DllImport("wevtapi.dll", SetLastError = true)]
        internal static extern EventLogHandle EvtSubscribe(EventLogHandle session, SafeWaitHandle signalEvent, [MarshalAs(UnmanagedType.LPWStr)] string path, [MarshalAs(UnmanagedType.LPWStr)] string query, EventLogHandle bookmark, IntPtr context, IntPtr callback, int flags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("wevtapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool EvtUpdateBookmark(EventLogHandle bookmark, EventLogHandle eventHandle);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct EvtRpcLogin
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Server;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string User;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string Domain;

            public CoTaskMemUnicodeSafeHandle Password;
            public int Flags;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Auto)]
        internal struct EvtStringVariant
        {
            [FieldOffset(8)]
            public uint Count;

            [MarshalAs(UnmanagedType.LPWStr), FieldOffset(0)]
            public string StringVal;

            [FieldOffset(12)]
            public uint Type;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Auto)]
        internal struct EvtVariant
        {
            [FieldOffset(0)]
            public IntPtr AnsiString;

            [FieldOffset(0)]
            public IntPtr Binary;

            [FieldOffset(0)]
            public uint Bool;

            [FieldOffset(0)]
            public byte ByteVal;

            [FieldOffset(8)]
            public uint Count;

            [FieldOffset(0)]
            public double Double;

            [FieldOffset(0)]
            public ulong FileTime;

            [FieldOffset(0)]
            public IntPtr GuidReference;

            [FieldOffset(0)]
            public IntPtr Handle;

            [FieldOffset(0)]
            public int Integer;

            [FieldOffset(0)]
            public long Long;

            [FieldOffset(0)]
            public IntPtr Reference;

            [FieldOffset(0)]
            public byte SByte;

            [FieldOffset(0)]
            public short Short;

            [FieldOffset(0)]
            public IntPtr SidVal;

            [FieldOffset(0)]
            public IntPtr StringVal;

            [FieldOffset(0)]
            public IntPtr SystemTime;

            [FieldOffset(12)]
            public uint Type;

            [FieldOffset(0)]
            public byte UInt8;

            [FieldOffset(0)]
            public uint UInteger;

            [FieldOffset(0)]
            public ulong ULong;

            [FieldOffset(0)]
            public ushort UShort;
        }
    }

    /// <summary></summary>
    /// <summary></summary>
    [SecurityCritical]
    internal sealed class CoTaskMemSafeHandle : SafeHandle
    {
        internal CoTaskMemSafeHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public static CoTaskMemSafeHandle Zero => new CoTaskMemSafeHandle();
        public override bool IsInvalid => !IsClosed ? handle == IntPtr.Zero : true;

        internal IntPtr GetMemory() => handle;

        internal void SetMemory(IntPtr handle) => SetHandle(handle);

        protected override bool ReleaseHandle()
        {
            Marshal.FreeCoTaskMem(handle);
            handle = IntPtr.Zero;
            return true;
        }
    }

    [SecurityCritical]
    internal sealed class CoTaskMemUnicodeSafeHandle : SafeHandle
    {
        internal CoTaskMemUnicodeSafeHandle()
            : base(IntPtr.Zero, true)
        {
        }

        internal CoTaskMemUnicodeSafeHandle(IntPtr handle, bool ownsHandle)
            : base(IntPtr.Zero, ownsHandle) => SetHandle(handle);

        public static CoTaskMemUnicodeSafeHandle Zero => new CoTaskMemUnicodeSafeHandle();
        public override bool IsInvalid => !IsClosed ? handle == IntPtr.Zero : true;

        internal IntPtr GetMemory() => handle;

        internal void SetMemory(IntPtr handle) => SetHandle(handle);

        protected override bool ReleaseHandle()
        {
            Marshal.ZeroFreeCoTaskMemUnicode(handle);
            handle = IntPtr.Zero;
            return true;
        }
    }

    [SecurityCritical]
    internal sealed class EventLogHandle : SafeHandle
    {
        internal EventLogHandle(IntPtr handle, bool ownsHandle)
            : base(IntPtr.Zero, ownsHandle) => SetHandle(handle);

        private EventLogHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public static EventLogHandle Zero => new EventLogHandle();
        public override bool IsInvalid => !IsClosed ? handle == IntPtr.Zero : true;

        protected override bool ReleaseHandle()
        {
            NativeWrapper.EvtClose(handle);
            handle = IntPtr.Zero;
            return true;
        }
    }

    internal class EventLogPermissionHolder
    {
        public static EventLogPermission GetEventLogPermission()
        {
            return new EventLogPermission(EventLogPermissionAccess.Administer, ".");
            //var permission = new EventLogPermission();
            //var entry = new EventLogPermissionEntry(EventLogPermissionAccess.Administer, ".");
            //permission.PermissionEntries.Add(entry);
            //return permission;
        }
    }

    internal class NativeWrapper
    {
        private static readonly bool s_platformNotSupported = Environment.OSVersion.Version.Major < 6;

        [SecurityCritical]
        public static DateTime ConvertFileTimeToDateTime(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 0x11)
            {
                throw new EventLogInvalidDataException();
            }
            return DateTime.FromFileTime((long)val.FileTime);
        }

        [SecurityCritical]
        public static string ConvertToAnsiString(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 2)
            {
                throw new EventLogInvalidDataException();
            }
            return val.AnsiString == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAuto(val.AnsiString);
        }

        [SecurityCritical]
        public static byte[] ConvertToBinaryArray(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 14)
            {
                throw new EventLogInvalidDataException();
            }
            if (val.Binary == IntPtr.Zero)
            {
                return new byte[0];
            }
            var binary = val.Binary;
            var destination = new byte[val.Count];
            Marshal.Copy(binary, destination, 0, (int)val.Count);
            return destination;
        }

        [SecurityCritical]
        public static Guid ConvertToGuid(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 15)
            {
                throw new EventLogInvalidDataException();
            }
            return val.GuidReference == IntPtr.Zero ? Guid.Empty : (Guid)Marshal.PtrToStructure(val.GuidReference, typeof(Guid));
        }

        [SecurityCritical]
        public static int[] ConvertToIntArray(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 0x88)
            {
                throw new EventLogInvalidDataException();
            }
            if (val.Reference == IntPtr.Zero)
            {
                return new int[0];
            }
            var reference = val.Reference;
            var destination = new int[val.Count];
            Marshal.Copy(reference, destination, 0, (int)val.Count);
            return destination;
        }

        [SecurityCritical]
        public static object ConvertToObject(UnsafeNativeMethods.EvtVariant val, UnsafeNativeMethods.EvtVariantType desiredType)
        {
            if (val.Type == 0)
            {
                return null;
            }
            if (val.Type != (long)desiredType)
            {
                throw new EventLogInvalidDataException();
            }
            return ConvertToObject(val);
        }

        [SecurityCritical]
        public static EventLogHandle ConvertToSafeHandle(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 0x20)
            {
                throw new EventLogInvalidDataException();
            }
            return val.Handle == IntPtr.Zero ? EventLogHandle.Zero : new EventLogHandle(val.Handle, true);
        }

        [SecurityCritical]
        public static SecurityIdentifier ConvertToSid(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 0x13)
            {
                throw new EventLogInvalidDataException();
            }
            return val.SidVal == IntPtr.Zero ? null : new SecurityIdentifier(val.SidVal);
        }

        [SecurityCritical]
        public static string ConvertToString(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 1)
            {
                throw new EventLogInvalidDataException();
            }
            return val.StringVal == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAuto(val.StringVal);
        }

        [SecurityCritical]
        public static string[] ConvertToStringArray(UnsafeNativeMethods.EvtVariant val)
        {
            if (val.Type != 0x81)
            {
                throw new EventLogInvalidDataException();
            }
            if (val.Reference == IntPtr.Zero)
            {
                return new string[0];
            }
            var reference = val.Reference;
            var destination = new IntPtr[val.Count];
            Marshal.Copy(reference, destination, 0, (int)val.Count);
            var strArray = new string[val.Count];
            for (var i = 0; i < val.Count; i++)
            {
                strArray[i] = Marshal.PtrToStringAuto(destination[i]);
            }
            return strArray;
        }

        [SecurityCritical]
        public static void EvtArchiveExportedLog(EventLogHandle session, string logFilePath, int locale, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var flag = UnsafeNativeMethods.EvtArchiveExportedLog(session, logFilePath, locale, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
        }

        [SecurityCritical]
        public static void EvtCancel(EventLogHandle handle)
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            if (!UnsafeNativeMethods.EvtCancel(handle))
            {
                EventLogException.Throw(Marshal.GetLastWin32Error());
            }
        }

        [SecurityCritical]
        public static void EvtClearLog(EventLogHandle session, string channelPath, string targetFilePath, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var flag = UnsafeNativeMethods.EvtClearLog(session, channelPath, targetFilePath, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
        }

        [SecurityCritical]
        public static void EvtClose(IntPtr handle) => UnsafeNativeMethods.EvtClose(handle);

        [SecurityCritical]
        public static EventLogHandle EvtCreateBookmark(string bookmarkXml)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtCreateBookmark(bookmarkXml);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static EventLogHandle EvtCreateRenderContext(int valuePathsCount, string[] valuePaths, UnsafeNativeMethods.EvtRenderContextFlags flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtCreateRenderContext(valuePathsCount, valuePaths, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static void EvtExportLog(EventLogHandle session, string channelPath, string query, string targetFilePath, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var flag = UnsafeNativeMethods.EvtExportLog(session, channelPath, query, targetFilePath, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
        }

        [SecurityCritical]
        public static string EvtFormatMessage(EventLogHandle handle, uint msgId)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var buffer = new StringBuilder(null);
            var flag = UnsafeNativeMethods.EvtFormatMessage(handle, EventLogHandle.Zero, msgId, 0, null, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageId, 0, buffer, out var num);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag && errorCode != 0x3ab5)
            {
                if (errorCode == 0x3ab3)
                {
                    return null;
                }
                if (errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
            }
            buffer.EnsureCapacity(num);
            flag = UnsafeNativeMethods.EvtFormatMessage(handle, EventLogHandle.Zero, msgId, 0, null, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageId, num, buffer, out num);
            errorCode = Marshal.GetLastWin32Error();
            if (!flag && errorCode != 0x3ab5)
            {
                if (errorCode == 0x3ab3)
                {
                    return null;
                }
                if (errorCode == 0x3ab5)
                {
                    return null;
                }
                EventLogException.Throw(errorCode);
            }
            return buffer.ToString();
        }

        [SecurityCritical]
        public static string EvtFormatMessageFormatDescription(EventLogHandle handle, EventLogHandle eventHandle, string[] values)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var variantArray = new UnsafeNativeMethods.EvtStringVariant[values.Length];
            for (var i = 0; i < values.Length; i++)
            {
                variantArray[i].Type = 1;
                variantArray[i].StringVal = values[i];
            }
            var buffer = new StringBuilder(null);
            var flag = UnsafeNativeMethods.EvtFormatMessage(handle, eventHandle, uint.MaxValue, values.Length, variantArray, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageEvent, 0, buffer, out var num);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag && errorCode != 0x3ab5)
            {
                switch (errorCode)
                {
                    case 0x3ab9:
                    case 0x3afc:
                    case 0x3ab3:
                    case 0x3ab4:
                    case 0x717:
                        return null;
                }
                if (errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
            }
            buffer.EnsureCapacity(num);
            flag = UnsafeNativeMethods.EvtFormatMessage(handle, eventHandle, uint.MaxValue, values.Length, variantArray, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageEvent, num, buffer, out num);
            errorCode = Marshal.GetLastWin32Error();
            if (!flag && errorCode != 0x3ab5)
            {
                if (errorCode == 0x3ab3)
                {
                    return null;
                }
                EventLogException.Throw(errorCode);
            }
            return buffer.ToString();
        }

        [SecurityCritical]
        public static IEnumerable<string> EvtFormatMessageRenderKeywords(EventLogHandle pmHandle, EventLogHandle eventHandle, UnsafeNativeMethods.EvtFormatMessageFlags flag)
        {
            IEnumerable<string> enumerable;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var zero = IntPtr.Zero;
            try
            {
                var list = new List<string>();
                var flag2 = UnsafeNativeMethods.EvtFormatMessageBuffer(pmHandle, eventHandle, 0, 0, IntPtr.Zero, flag, 0, IntPtr.Zero, out var num);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag2)
                {
                    switch (errorCode)
                    {
                        case 0x3ab9:
                        case 0x3afc:
                        case 0x3ab3:
                        case 0x3ab4:
                        case 0x717:
                            return list.AsReadOnly();
                    }
                    if (errorCode != 0x7a)
                    {
                        EventLogException.Throw(errorCode);
                    }
                }
                zero = Marshal.AllocHGlobal(num * 2);
                flag2 = UnsafeNativeMethods.EvtFormatMessageBuffer(pmHandle, eventHandle, 0, 0, IntPtr.Zero, flag, num, zero, out num);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag2)
                {
                    switch (errorCode)
                    {
                        case 0x3ab9:
                        case 0x3afc:
                            return list;

                        case 0x3ab3:
                        case 0x3ab4:
                            return list;

                        case 0x717:
                            return list;
                    }
                    EventLogException.Throw(errorCode);
                }
                var ptr = zero;
                while (true)
                {
                    var str = Marshal.PtrToStringAuto(ptr);
                    if (string.IsNullOrEmpty(str))
                    {
                        break;
                    }
                    list.Add(str);
                    ptr = new IntPtr((long)ptr + str.Length * 2 + 2L);
                }
                enumerable = list.AsReadOnly();
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return enumerable;
        }

        [SecurityCritical]
        public static string EvtFormatMessageRenderName(EventLogHandle pmHandle, EventLogHandle eventHandle, UnsafeNativeMethods.EvtFormatMessageFlags flag)
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var buffer = new StringBuilder(null);
            var flag2 = UnsafeNativeMethods.EvtFormatMessage(pmHandle, eventHandle, 0, 0, null, flag, 0, buffer, out var num);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag2 && errorCode != 0x3ab5)
            {
                switch (errorCode)
                {
                    case 0x3ab9:
                    case 0x3afc:
                    case 0x3ab3:
                    case 0x3ab4:
                    case 0x717:
                        return null;
                }
                if (errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
            }
            buffer.EnsureCapacity(num);
            flag2 = UnsafeNativeMethods.EvtFormatMessage(pmHandle, eventHandle, 0, 0, null, flag, num, buffer, out num);
            errorCode = Marshal.GetLastWin32Error();
            if (!flag2 && errorCode != 0x3ab5)
            {
                switch (errorCode)
                {
                    case 0x3ab9:
                    case 0x3afc:
                    case 0x3ab3:
                    case 0x3ab4:
                    case 0x717:
                        return null;
                }
                EventLogException.Throw(errorCode);
            }
            return buffer.ToString();
        }

        [SecurityCritical]
        public static object EvtGetChannelConfigProperty(EventLogHandle handle, UnsafeNativeMethods.EvtChannelConfigPropertyId enumType)
        {
            object obj2;
            var zero = IntPtr.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            try
            {
                var flag = UnsafeNativeMethods.EvtGetChannelConfigProperty(handle, enumType, 0, 0, IntPtr.Zero, out var num);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(num);
                flag = UnsafeNativeMethods.EvtGetChannelConfigProperty(handle, enumType, 0, num, zero, out num);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(zero, typeof(UnsafeNativeMethods.EvtVariant));
                obj2 = ConvertToObject(val);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return obj2;
        }

        [SecurityCritical]
        public static object EvtGetEventInfo(EventLogHandle handle, UnsafeNativeMethods.EvtEventPropertyId enumType)
        {
            object obj2;
            var zero = IntPtr.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            try
            {
                var flag = UnsafeNativeMethods.EvtGetEventInfo(handle, enumType, 0, IntPtr.Zero, out var num);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0 && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(num);
                flag = UnsafeNativeMethods.EvtGetEventInfo(handle, enumType, num, zero, out num);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(zero, typeof(UnsafeNativeMethods.EvtVariant));
                obj2 = ConvertToObject(val);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return obj2;
        }

        [SecurityCritical]
        public static object EvtGetEventMetadataProperty(EventLogHandle handle, UnsafeNativeMethods.EvtEventMetadataPropertyId enumType)
        {
            object obj2;
            var zero = IntPtr.Zero;
            try
            {
                var flag = UnsafeNativeMethods.EvtGetEventMetadataProperty(handle, enumType, 0, 0, IntPtr.Zero, out var num);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(num);
                flag = UnsafeNativeMethods.EvtGetEventMetadataProperty(handle, enumType, 0, num, zero, out num);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(zero, typeof(UnsafeNativeMethods.EvtVariant));
                obj2 = ConvertToObject(val);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return obj2;
        }

        [SecurityCritical]
        public static object EvtGetLogInfo(EventLogHandle handle, UnsafeNativeMethods.EvtLogPropertyId enumType)
        {
            object obj2;
            var zero = IntPtr.Zero;
            try
            {
                var flag = UnsafeNativeMethods.EvtGetLogInfo(handle, enumType, 0, IntPtr.Zero, out var num);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(num);
                flag = UnsafeNativeMethods.EvtGetLogInfo(handle, enumType, num, zero, out num);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(zero, typeof(UnsafeNativeMethods.EvtVariant));
                obj2 = ConvertToObject(val);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return obj2;
        }

        [SecurityCritical]
        public static object EvtGetObjectArrayProperty(EventLogHandle objArrayHandle, int index, int thePropertyId)
        {
            object obj2;
            var zero = IntPtr.Zero;
            try
            {
                var flag = UnsafeNativeMethods.EvtGetObjectArrayProperty(objArrayHandle, thePropertyId, index, 0, 0, IntPtr.Zero, out var num);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(num);
                flag = UnsafeNativeMethods.EvtGetObjectArrayProperty(objArrayHandle, thePropertyId, index, 0, num, zero, out num);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(zero, typeof(UnsafeNativeMethods.EvtVariant));
                obj2 = ConvertToObject(val);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return obj2;
        }

        [SecurityCritical]
        public static int EvtGetObjectArraySize(EventLogHandle objectArray)
        {
            var flag = UnsafeNativeMethods.EvtGetObjectArraySize(objectArray, out var num);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
            return num;
        }

        [SecurityCritical]
        public static object EvtGetPublisherMetadataProperty(EventLogHandle pmHandle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId thePropertyId)
        {
            object obj2;
            var zero = IntPtr.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            try
            {
                var flag = UnsafeNativeMethods.EvtGetPublisherMetadataProperty(pmHandle, thePropertyId, 0, 0, IntPtr.Zero, out var num);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(num);
                flag = UnsafeNativeMethods.EvtGetPublisherMetadataProperty(pmHandle, thePropertyId, 0, num, zero, out num);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(zero, typeof(UnsafeNativeMethods.EvtVariant));
                obj2 = ConvertToObject(val);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return obj2;
        }

        [SecurityCritical]
        public static object EvtGetQueryInfo(EventLogHandle handle, UnsafeNativeMethods.EvtQueryPropertyId enumType)
        {
            object obj2;
            var zero = IntPtr.Zero;
            var bufferRequired = 0;
            try
            {
                var flag = UnsafeNativeMethods.EvtGetQueryInfo(handle, enumType, 0, IntPtr.Zero, ref bufferRequired);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(bufferRequired);
                flag = UnsafeNativeMethods.EvtGetQueryInfo(handle, enumType, bufferRequired, zero, ref bufferRequired);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(zero, typeof(UnsafeNativeMethods.EvtVariant));
                obj2 = ConvertToObject(val);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return obj2;
        }

        [SecurityCritical]
        public static bool EvtNext(EventLogHandle queryHandle, int eventSize, IntPtr[] events, int timeout, int flags, ref int returned)
        {
            var flag = UnsafeNativeMethods.EvtNext(queryHandle, eventSize, events, timeout, flags, ref returned);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag && errorCode != 0x103)
            {
                EventLogException.Throw(errorCode);
            }
            return errorCode == 0;
        }

        [SecurityCritical]
        public static string EvtNextChannelPath(EventLogHandle handle, ref bool finish)
        {
            var channelPathBuffer = new StringBuilder(null);
            var flag = UnsafeNativeMethods.EvtNextChannelPath(handle, 0, channelPathBuffer, out var num);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                if (errorCode == 0x103)
                {
                    finish = true;
                    return null;
                }
                if (errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
            }
            channelPathBuffer.EnsureCapacity(num);
            flag = UnsafeNativeMethods.EvtNextChannelPath(handle, num, channelPathBuffer, out num);
            errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
            return channelPathBuffer.ToString();
        }

        [SecurityCritical]
        public static EventLogHandle EvtNextEventMetadata(EventLogHandle eventMetadataEnum, int flags)
        {
            var handle = UnsafeNativeMethods.EvtNextEventMetadata(eventMetadataEnum, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (!handle.IsInvalid)
            {
                return handle;
            }
            if (errorCode != 0x103)
            {
                EventLogException.Throw(errorCode);
            }
            return null;
        }

        [SecurityCritical]
        public static string EvtNextPublisherId(EventLogHandle handle, ref bool finish)
        {
            var publisherIdBuffer = new StringBuilder(null);
            var flag = UnsafeNativeMethods.EvtNextPublisherId(handle, 0, publisherIdBuffer, out var num);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                if (errorCode == 0x103)
                {
                    finish = true;
                    return null;
                }
                if (errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
            }
            publisherIdBuffer.EnsureCapacity(num);
            flag = UnsafeNativeMethods.EvtNextPublisherId(handle, num, publisherIdBuffer, out num);
            errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
            return publisherIdBuffer.ToString();
        }

        [SecurityCritical]
        public static EventLogHandle EvtOpenChannelConfig(EventLogHandle session, string channelPath, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtOpenChannelConfig(session, channelPath, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static EventLogHandle EvtOpenChannelEnum(EventLogHandle session, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtOpenChannelEnum(session, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static EventLogHandle EvtOpenEventMetadataEnum(EventLogHandle ProviderMetadata, int flags)
        {
            var handle = UnsafeNativeMethods.EvtOpenEventMetadataEnum(ProviderMetadata, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static EventLogHandle EvtOpenLog(EventLogHandle session, string path, PathType flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtOpenLog(session, path, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static EventLogHandle EvtOpenProviderEnum(EventLogHandle session, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtOpenPublisherEnum(session, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static EventLogHandle EvtOpenProviderMetadata(EventLogHandle session, string ProviderId, string logFilePath, int locale, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtOpenPublisherMetadata(session, ProviderId, logFilePath, 0, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static EventLogHandle EvtOpenSession(UnsafeNativeMethods.EvtLoginClass loginClass, ref UnsafeNativeMethods.EvtRpcLogin login, int timeout, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtOpenSession(loginClass, ref login, timeout, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static EventLogHandle EvtQuery(EventLogHandle session, string path, string query, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtQuery(session, path, query, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static void EvtRender(EventLogHandle context, EventLogHandle eventHandle, UnsafeNativeMethods.EvtRenderFlags flags, StringBuilder buffer)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var flag = UnsafeNativeMethods.EvtRender(context, eventHandle, flags, buffer.Capacity, buffer, out var num, out var num2);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                if (errorCode == 0x7a)
                {
                    buffer.Capacity = num;
                    flag = UnsafeNativeMethods.EvtRender(context, eventHandle, flags, buffer.Capacity, buffer, out num, out num2);
                    errorCode = Marshal.GetLastWin32Error();
                }
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
            }
        }

        [SecurityCritical]
        public static string EvtRenderBookmark(EventLogHandle eventHandle)
        {
            string str;
            var zero = IntPtr.Zero;
            var evtRenderBookmark = UnsafeNativeMethods.EvtRenderFlags.EvtRenderBookmark;
            try
            {
                var flag = UnsafeNativeMethods.EvtRender(EventLogHandle.Zero, eventHandle, evtRenderBookmark, 0, IntPtr.Zero, out var num, out var num2);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(num);
                flag = UnsafeNativeMethods.EvtRender(EventLogHandle.Zero, eventHandle, evtRenderBookmark, num, zero, out num, out num2);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                str = Marshal.PtrToStringAuto(zero);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return str;
        }

        [SecurityCritical]
        public static void EvtRenderBufferWithContextSystem(EventLogHandle contextHandle, EventLogHandle eventHandle, UnsafeNativeMethods.EvtRenderFlags flag, SystemProperties systemProperties, int SYSTEM_PROPERTY_COUNT)
        {
            var zero = IntPtr.Zero;
            var ptr = IntPtr.Zero;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            try
            {
                if (!UnsafeNativeMethods.EvtRender(contextHandle, eventHandle, flag, 0, IntPtr.Zero, out var num, out var num2))
                {
                    var num3 = Marshal.GetLastWin32Error();
                    if (num3 != 0x7a)
                    {
                        EventLogException.Throw(num3);
                    }
                }
                zero = Marshal.AllocHGlobal(num);
                var flag2 = UnsafeNativeMethods.EvtRender(contextHandle, eventHandle, flag, num, zero, out num, out num2);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag2)
                {
                    EventLogException.Throw(errorCode);
                }
                if (num2 != SYSTEM_PROPERTY_COUNT)
                {
                    throw new InvalidOperationException("We do not have " + SYSTEM_PROPERTY_COUNT + " variants given for the  UnsafeNativeMethods.EvtRenderFlags.EvtRenderEventValues flag. (System Properties)");
                }
                ptr = zero;
                for (var i = 0; i < num2; i++)
                {
                    var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(ptr, typeof(UnsafeNativeMethods.EvtVariant));
                    switch (i)
                    {
                        case 0:
                            systemProperties.ProviderName = (string)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeString);
                            break;

                        case 1:
                            systemProperties.ProviderId = (Guid?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeGuid);
                            break;

                        case 2:
                            systemProperties.Id = (ushort?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeUInt16);
                            break;

                        case 3:
                            systemProperties.Qualifiers = (ushort?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeUInt16);
                            break;

                        case 4:
                            systemProperties.Level = (byte?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeByte);
                            break;

                        case 5:
                            systemProperties.Task = (ushort?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeUInt16);
                            break;

                        case 6:
                            systemProperties.Opcode = (byte?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeByte);
                            break;

                        case 7:
                            systemProperties.Keywords = (ulong?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeHexInt64);
                            break;

                        case 8:
                            systemProperties.TimeCreated = (DateTime?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeFileTime);
                            break;

                        case 9:
                            systemProperties.RecordId = (ulong?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeUInt64);
                            break;

                        case 10:
                            systemProperties.ActivityId = (Guid?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeGuid);
                            break;

                        case 11:
                            systemProperties.RelatedActivityId = (Guid?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeGuid);
                            break;

                        case 12:
                            systemProperties.ProcessId = (uint?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeUInt32);
                            break;

                        case 13:
                            systemProperties.ThreadId = (uint?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeUInt32);
                            break;

                        case 14:
                            systemProperties.ChannelName = (string)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeString);
                            break;

                        case 15:
                            systemProperties.ComputerName = (string)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeString);
                            break;

                        case 0x10:
                            systemProperties.UserId = (SecurityIdentifier)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeSid);
                            break;

                        case 0x11:
                            systemProperties.Version = (byte?)ConvertToObject(val, UnsafeNativeMethods.EvtVariantType.EvtVarTypeByte);
                            break;
                    }
                    ptr = new IntPtr((long)ptr + Marshal.SizeOf(val));
                }
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
        }

        [SecurityCritical]
        public static IList<object> EvtRenderBufferWithContextUserOrValues(EventLogHandle contextHandle, EventLogHandle eventHandle)
        {
            IList<object> list2;
            var zero = IntPtr.Zero;
            var ptr = IntPtr.Zero;
            var evtRenderEventValues = UnsafeNativeMethods.EvtRenderFlags.EvtRenderEventValues;
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            try
            {
                if (!UnsafeNativeMethods.EvtRender(contextHandle, eventHandle, evtRenderEventValues, 0, IntPtr.Zero, out var num, out var num2))
                {
                    var num3 = Marshal.GetLastWin32Error();
                    if (num3 != 0x7a)
                    {
                        EventLogException.Throw(num3);
                    }
                }
                zero = Marshal.AllocHGlobal(num);
                var flag = UnsafeNativeMethods.EvtRender(contextHandle, eventHandle, evtRenderEventValues, num, zero, out num, out num2);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var list = new List<object>(num2);
                if (num2 > 0)
                {
                    ptr = zero;
                    for (var i = 0; i < num2; i++)
                    {
                        var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(ptr, typeof(UnsafeNativeMethods.EvtVariant));
                        list.Add(ConvertToObject(val));
                        ptr = new IntPtr((long)ptr + Marshal.SizeOf(val));
                    }
                }
                list2 = list;
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return list2;
        }

        [SecurityCritical]
        public static void EvtSaveChannelConfig(EventLogHandle channelConfig, int flags)
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var flag = UnsafeNativeMethods.EvtSaveChannelConfig(channelConfig, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
        }

        [SecurityCritical]
        public static void EvtSeek(EventLogHandle resultSet, long position, EventLogHandle bookmark, int timeout, UnsafeNativeMethods.EvtSeekFlags flags)
        {
            var flag = UnsafeNativeMethods.EvtSeek(resultSet, position, bookmark, timeout, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
        }

        [SecurityCritical]
        public static void EvtSetChannelConfigProperty(EventLogHandle handle, UnsafeNativeMethods.EvtChannelConfigPropertyId enumType, object val)
        {
            EventLogPermissionHolder.GetEventLogPermission().Demand();
            var propertyValue = new UnsafeNativeMethods.EvtVariant();
            var handle2 = new CoTaskMemSafeHandle();
            using (handle2)
            {
                bool flag;
                if (val is null)
                {
                    goto Label_017B;
                }
                switch (enumType)
                {
                    case UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigEnabled:
                        propertyValue.Type = 13;
                        if (!(bool)val)
                        {
                            break;
                        }
                        propertyValue.Bool = 1;
                        goto Label_0183;

                    case UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelConfigAccess:
                        propertyValue.Type = 1;
                        handle2.SetMemory(Marshal.StringToCoTaskMemAuto((string)val));
                        propertyValue.StringVal = handle2.GetMemory();
                        goto Label_0183;

                    case UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigRetention:
                        propertyValue.Type = 13;
                        if (!(bool)val)
                        {
                            goto Label_0146;
                        }
                        propertyValue.Bool = 1;
                        goto Label_0183;

                    case UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigAutoBackup:
                        propertyValue.Type = 13;
                        if (!(bool)val)
                        {
                            goto Label_016B;
                        }
                        propertyValue.Bool = 1;
                        goto Label_0183;

                    case UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigMaxSize:
                        propertyValue.Type = 10;
                        propertyValue.ULong = (ulong)(long)val;
                        goto Label_0183;

                    case UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelLoggingConfigLogFilePath:
                        propertyValue.Type = 1;
                        handle2.SetMemory(Marshal.StringToCoTaskMemAuto((string)val));
                        propertyValue.StringVal = handle2.GetMemory();
                        goto Label_0183;

                    case UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigLevel:
                        propertyValue.Type = 8;
                        propertyValue.UInteger = (uint)(int)val;
                        goto Label_0183;

                    case UnsafeNativeMethods.EvtChannelConfigPropertyId.EvtChannelPublishingConfigKeywords:
                        propertyValue.Type = 10;
                        propertyValue.ULong = (ulong)(long)val;
                        goto Label_0183;

                    default:
                        throw new InvalidOperationException();
                }
                propertyValue.Bool = 0;
                goto Label_0183;
            Label_0146:
                propertyValue.Bool = 0;
                goto Label_0183;
            Label_016B:
                propertyValue.Bool = 0;
                goto Label_0183;
            Label_017B:
                propertyValue.Type = 0;
            Label_0183:
                flag = UnsafeNativeMethods.EvtSetChannelConfigProperty(handle, enumType, 0, ref propertyValue);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
            }
        }

        [SecurityCritical]
        public static EventLogHandle EvtSubscribe(EventLogHandle session, SafeWaitHandle signalEvent, string path, string query, EventLogHandle bookmark, IntPtr context, IntPtr callback, int flags)
        {
            if (s_platformNotSupported)
            {
                throw new PlatformNotSupportedException();
            }
            var handle = UnsafeNativeMethods.EvtSubscribe(session, signalEvent, path, query, bookmark, context, callback, flags);
            var errorCode = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                EventLogException.Throw(errorCode);
            }
            return handle;
        }

        [SecurityCritical]
        public static void EvtUpdateBookmark(EventLogHandle bookmark, EventLogHandle eventHandle)
        {
            var flag = UnsafeNativeMethods.EvtUpdateBookmark(bookmark, eventHandle);
            var errorCode = Marshal.GetLastWin32Error();
            if (!flag)
            {
                EventLogException.Throw(errorCode);
            }
        }

        [SecurityCritical]
        internal static EventLogHandle EvtGetPublisherMetadataPropertyHandle(EventLogHandle pmHandle, UnsafeNativeMethods.EvtPublisherMetadataPropertyId thePropertyId)
        {
            EventLogHandle handle;
            var zero = IntPtr.Zero;
            try
            {
                var flag = UnsafeNativeMethods.EvtGetPublisherMetadataProperty(pmHandle, thePropertyId, 0, 0, IntPtr.Zero, out var num);
                var errorCode = Marshal.GetLastWin32Error();
                if (!flag && errorCode != 0x7a)
                {
                    EventLogException.Throw(errorCode);
                }
                zero = Marshal.AllocHGlobal(num);
                flag = UnsafeNativeMethods.EvtGetPublisherMetadataProperty(pmHandle, thePropertyId, 0, num, zero, out num);
                errorCode = Marshal.GetLastWin32Error();
                if (!flag)
                {
                    EventLogException.Throw(errorCode);
                }
                var val = (UnsafeNativeMethods.EvtVariant)Marshal.PtrToStructure(zero, typeof(UnsafeNativeMethods.EvtVariant));
                handle = ConvertToSafeHandle(val);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return handle;
        }

        [SecurityCritical]
        private static object ConvertToObject(UnsafeNativeMethods.EvtVariant val)
        {
            switch (val.Type)
            {
                case 0:
                    return null;

                case 1:
                    return ConvertToString(val);

                case 2:
                    return ConvertToAnsiString(val);

                case 3:
                    return val.SByte;

                case 4:
                    return val.UInt8;

                case 5:
                    return val.SByte;

                case 6:
                    return val.UShort;

                case 7:
                    return val.Integer;

                case 8:
                    return val.UInteger;

                case 9:
                    return val.Long;

                case 10:
                    return val.ULong;

                case 12:
                    return val.Double;

                case 13:
                    if (val.Bool == 0)
                    {
                        return false;
                    }
                    return true;

                case 14:
                    return ConvertToBinaryArray(val);

                case 15:
                    return ConvertToGuid(val);

                case 0x11:
                    return ConvertFileTimeToDateTime(val);

                case 0x13:
                    return ConvertToSid(val);

                case 20:
                    return val.Integer;

                case 0x15:
                    return val.ULong;

                case 0x20:
                    return ConvertToSafeHandle(val);

                case 0x81:
                    return ConvertToStringArray(val);

                case 0x88:
                    return ConvertToIntArray(val);
            }
            throw new EventLogInvalidDataException();
        }

        internal class SystemProperties
        {
            public Guid? ActivityId = null;
            public string ChannelName;
            public string ComputerName;
            public bool filled;
            public ushort? Id = null;
            public ulong? Keywords = null;
            public byte? Level = null;
            public byte? Opcode = null;
            public uint? ProcessId = null;
            public Guid? ProviderId = null;
            public string ProviderName;
            public ushort? Qualifiers = null;
            public ulong? RecordId = null;
            public Guid? RelatedActivityId = null;
            public ushort? Task = null;
            public uint? ThreadId = null;
            public DateTime? TimeCreated = null;
            public SecurityIdentifier UserId;
            public byte? Version = null;
        }
    }

    internal class ProviderMetadataCachedInformation
    {
        private readonly string logfile;
        private readonly int maximumCacheSize;
        private readonly EventLogSession session;
        private Dictionary<ProviderMetadataId, CacheItem> cache;

        public ProviderMetadataCachedInformation(EventLogSession session, string logfile, int maximumCacheSize)
        {
            this.session = session;
            this.logfile = logfile;
            cache = new Dictionary<ProviderMetadataId, CacheItem>();
            this.maximumCacheSize = maximumCacheSize;
        }

        public string GetFormatDescription(string ProviderName, EventLogHandle eventHandle)
        {
            string str;
            lock (this)
            {
                var key = new ProviderMetadataId(ProviderName, CultureInfo.CurrentCulture);
                try
                {
                    str = NativeWrapper.EvtFormatMessageRenderName(GetProviderMetadata(key).Handle, eventHandle, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageEvent);
                }
                catch (EventLogNotFoundException)
                {
                    str = null;
                }
            }
            return str;
        }

        public string GetFormatDescription(string ProviderName, EventLogHandle eventHandle, string[] values)
        {
            string str;
            lock (this)
            {
                var key = new ProviderMetadataId(ProviderName, CultureInfo.CurrentCulture);
                var providerMetadata = GetProviderMetadata(key);
                try
                {
                    str = NativeWrapper.EvtFormatMessageFormatDescription(providerMetadata.Handle, eventHandle, values);
                }
                catch (EventLogNotFoundException)
                {
                    str = null;
                }
            }
            return str;
        }

        public IEnumerable<string> GetKeywordDisplayNames(string ProviderName, EventLogHandle eventHandle)
        {
            lock (this)
            {
                var key = new ProviderMetadataId(ProviderName, CultureInfo.CurrentCulture);
                return NativeWrapper.EvtFormatMessageRenderKeywords(GetProviderMetadata(key).Handle, eventHandle, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageKeyword);
            }
        }

        public string GetLevelDisplayName(string ProviderName, EventLogHandle eventHandle)
        {
            lock (this)
            {
                var key = new ProviderMetadataId(ProviderName, CultureInfo.CurrentCulture);
                return NativeWrapper.EvtFormatMessageRenderName(GetProviderMetadata(key).Handle, eventHandle, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageLevel);
            }
        }

        public string GetOpcodeDisplayName(string ProviderName, EventLogHandle eventHandle)
        {
            lock (this)
            {
                var key = new ProviderMetadataId(ProviderName, CultureInfo.CurrentCulture);
                return NativeWrapper.EvtFormatMessageRenderName(GetProviderMetadata(key).Handle, eventHandle, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageOpcode);
            }
        }

        public string GetTaskDisplayName(string ProviderName, EventLogHandle eventHandle)
        {
            lock (this)
            {
                var key = new ProviderMetadataId(ProviderName, CultureInfo.CurrentCulture);
                return NativeWrapper.EvtFormatMessageRenderName(GetProviderMetadata(key).Handle, eventHandle, UnsafeNativeMethods.EvtFormatMessageFlags.EvtFormatMessageTask);
            }
        }

        private static void UpdateCacheValueInfoForHit(CacheItem cacheItem) => cacheItem.TheTime = DateTime.Now;

        private void AddCacheEntry(ProviderMetadataId key, ProviderMetadata pm)
        {
            if (IsCacheFull())
            {
                FlushOldestEntry();
            }
            var item = new CacheItem(pm);
            cache.Add(key, item);
        }

        private void DeleteCacheEntry(ProviderMetadataId key)
        {
            if (IsProviderinCache(key))
            {
                var item = cache[key];
                cache.Remove(key);
                item.ProviderMetadata.Dispose();
            }
        }

        private void FlushOldestEntry()
        {
            var totalMilliseconds = -10.0;
            var now = DateTime.Now;
            ProviderMetadataId key = null;
            foreach (var pair in cache)
            {
                var span = now.Subtract(pair.Value.TheTime);
                if (span.TotalMilliseconds >= totalMilliseconds)
                {
                    totalMilliseconds = span.TotalMilliseconds;
                    key = pair.Key;
                }
            }
            if (key != null)
            {
                DeleteCacheEntry(key);
            }
        }

        private ProviderMetadata GetProviderMetadata(ProviderMetadataId key)
        {
            if (!IsProviderinCache(key))
            {
                ProviderMetadata metadata;
                try
                {
                    metadata = new ProviderMetadata(key.ProviderName, session, key.TheCultureInfo, logfile);
                }
                catch (EventLogNotFoundException)
                {
                    metadata = new ProviderMetadata(key.ProviderName, session, key.TheCultureInfo);
                }
                AddCacheEntry(key, metadata);
                return metadata;
            }
            var cacheItem = cache[key];
            var providerMetadata = cacheItem.ProviderMetadata;
            try
            {
                providerMetadata.CheckReleased();
                UpdateCacheValueInfoForHit(cacheItem);
            }
            catch (EventLogException)
            {
                DeleteCacheEntry(key);
                try
                {
                    providerMetadata = new ProviderMetadata(key.ProviderName, session, key.TheCultureInfo, logfile);
                }
                catch (EventLogNotFoundException)
                {
                    providerMetadata = new ProviderMetadata(key.ProviderName, session, key.TheCultureInfo);
                }
                AddCacheEntry(key, providerMetadata);
            }
            return providerMetadata;
        }

        private bool IsCacheFull() => cache.Count == maximumCacheSize;

        private bool IsProviderinCache(ProviderMetadataId key) => cache.ContainsKey(key);

        private class CacheItem
        {
            public CacheItem(ProviderMetadata pm)
            {
                ProviderMetadata = pm;
                TheTime = DateTime.Now;
            }

            public ProviderMetadata ProviderMetadata { get; private set; }

            public DateTime TheTime { get; set; }
        }

        private class ProviderMetadataId
        {
            public ProviderMetadataId(string providerName, CultureInfo cultureInfo)
            {
                ProviderName = providerName;
                TheCultureInfo = cultureInfo;
            }

            public string ProviderName { get; private set; }

            public CultureInfo TheCultureInfo { get; private set; }

            public override bool Equals(object obj) => obj is ProviderMetadataId id ? ProviderName.Equals(id.ProviderName) && TheCultureInfo == id.TheCultureInfo : false;

            public override int GetHashCode() => ProviderName.GetHashCode() ^ TheCultureInfo.GetHashCode();
        }
    }
}

#endif
