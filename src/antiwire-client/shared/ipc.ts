/**
 * The contract between the Electron main process, the preload bridge and the
 * renderer. It is the only list of commands and events: the main process's
 * handler table is typed against `CommandName`, so a command missing a handler,
 * or a handler with no entry here, fails to compile.
 *
 * Nothing in this file may import Node or Electron; the preload and renderer
 * bundle it too.
 */

/** `ipcRenderer.invoke` channel every command goes through. */
export const INVOKE_CHANNEL = 'antiwire:invoke';
/** `webContents.send` channel carrying `{ event, payload }` for every event. */
export const EVENT_CHANNEL = 'antiwire:event';

/** Which kind of window a webContents is. Decides the commands it may call. */
export type WindowRole = 'main' | 'inspector';

/**
 * Commands only the packet inspector needs. The inspector renders untrusted
 * packet bytes, so it gets nothing else: no rules, settings or daemon access.
 */
const INSPECTOR_COMMANDS = [
  'get_packet_inspector_packet',
  'get_packet_inspector_theme',
  'close_window',
  'minimize_window',
] as const;

/** Every command the renderer may invoke. */
export const COMMANDS = [
  // AI decisions
  'get_ai_decisions',
  'delete_ai_decision',
  'refresh_ai_decision',
  'advanced_ai_decision',
  // Alerts
  'get_alerts',
  'dismiss_alert',
  'clear_alerts',
  // Connection
  'get_connection_status',
  'connect_daemon',
  'disconnect_daemon',
  'start_realtime_traffic',
  'stop_realtime_traffic',
  // Files and native dialogs
  'pick_save_path',
  'pick_open_path',
  // Stats
  'get_stats',
  'get_active_applications',
  // Rules
  'get_rules',
  'add_rule',
  'remove_rule',
  'get_country_rules',
  'add_country_rule',
  'remove_country_rule',
  // Settings
  'get_settings',
  'update_settings',
  'sync_hosts_blocklist',
  'refresh_geo_database',
  // Client-only settings (theme, accent, locale, onboarding), stored by the main process
  'get_client_settings',
  'set_client_settings',
  // Records
  'get_connection_logs',
  'get_country_statistics',
  'get_app_summaries',
  'get_activity_buckets',
  'delete_history',
  'export_logs',
  'lookup_domain',
  'lookup_dns_records',
  'get_seen_subdomains',
  'search_certificates',
  'open_domain_reputation',
  // Application icons
  'get_app_icon',
  // Capture
  'list_capture_devices',
  'start_capture',
  'stop_capture',
  'get_capture_status',
  'start_capture_packet_stream',
  'download_capture',
  // Network mapping
  'get_network_mapping_state',
  'scan_network',
  'stop_network_scan',
  'clear_network_devices',
  'save_network_scan_range',
  'remove_network_scan_range',
  'save_network_device_watch',
  'remove_network_device_watch',
  'update_oui_database',
  // Updates
  'get_update_status',
  'check_for_updates',
  'install_update',
  // Window
  'minimize_window',
  'toggle_maximize_window',
  'close_window',
  'hide_window',
  'is_debug_build',
  'open_devtools',
  // Packet inspector
  'open_packet_inspector',
  'get_packet_inspector_packet',
  'get_packet_inspector_theme',
] as const;

export type CommandName = (typeof COMMANDS)[number];

const COMMAND_SET: ReadonlySet<string> = new Set(COMMANDS);
const INSPECTOR_SET: ReadonlySet<string> = new Set(INSPECTOR_COMMANDS);

export function isCommandName(value: unknown): value is CommandName {
  return typeof value === 'string' && COMMAND_SET.has(value);
}

/** Whether a window of `role` may invoke `command`. The main window may call everything. */
export function roleMayInvoke(role: WindowRole, command: CommandName): boolean {
  return role === 'main' || INSPECTOR_SET.has(command);
}

/** Events the main process pushes to renderers, with their payloads. */
export interface EventPayloads {
  /** A daemon notification (alert); see `NotificationEvent`. */
  'daemon-notification': unknown;
  /** The daemon's notification stream ended: the connection is gone. */
  'daemon://stream-closed': null;
  /** Live traffic, coalesced into one batch per tick. */
  'traffic://event': unknown[];
  /** Captured packets for the active capture, batched. */
  'capture://packets': unknown[];
  'capture://stream-error': { captureId: string; message: string };
  /** The main window was shown or hidden (tray, close-to-tray). */
  'window://visibility': boolean;
  /** The main window was maximized or restored. */
  'window://maximized': boolean;
  /** The window entered or left full screen (macOS hides the traffic lights then). */
  'window://fullscreen': boolean;
  'packet-inspector://packet': unknown;
  'packet-inspector://theme': unknown;
}

export type EventName = keyof EventPayloads;

export const EVENTS: readonly EventName[] = [
  'daemon-notification',
  'daemon://stream-closed',
  'traffic://event',
  'capture://packets',
  'capture://stream-error',
  'window://visibility',
  'window://maximized',
  'window://fullscreen',
  'packet-inspector://packet',
  'packet-inspector://theme',
];

const EVENT_SET: ReadonlySet<string> = new Set(EVENTS);

export function isEventName(value: unknown): value is EventName {
  return typeof value === 'string' && EVENT_SET.has(value);
}

/**
 * What a command resolves to across the bridge. Errors travel as data so the
 * renderer sees the handler's own message, not Electron's
 * "Error invoking remote method" wrapper.
 */
export type InvokeResult = { ok: true; value: unknown } | { ok: false; error: string };

/** The API the preload exposes on `window.antiwire`. */
export interface AntiwireBridge {
  invoke(command: CommandName, args?: Record<string, unknown>): Promise<unknown>;
  /** Subscribes to a main-process event; returns the unsubscribe function. */
  on<E extends EventName>(event: E, handler: (payload: EventPayloads[E]) => void): () => void;
  /** `process.platform` of the host, for platform-specific chrome. */
  readonly platform: 'win32' | 'darwin' | 'linux' | string;
}
