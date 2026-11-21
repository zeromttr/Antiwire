use antiwire_policy::display_text;
use antiwire_store::DaemonSetting;
use antiwire_tuning::SIEM_TCP_CONNECT_TIMEOUT;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::warn;

use crate::syslog_message;

/// SIEM export configuration with independent file, syslog, and webhook sinks.
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent user setting"
)]
pub struct SiemConfig {
    pub enabled: bool,
    pub file_enabled: bool,
    pub syslog_enabled: bool,
    pub webhook_enabled: bool,
    pub file_path: PathBuf,
    pub manager_host: String,
    pub manager_port: u16,
    pub protocol: SiemProtocol,
    pub webhook_url: String,
    pub webhook_auth_token: String,
    pub webhook_auth_header: String,
    pub send_allowed: bool,
    pub send_blocked: bool,
    pub send_new_app: bool,
    pub send_new_domain: bool,
    pub send_threats: bool,
}

/// Leaves out the webhook URL and auth token: webhook URLs often carry their
/// secret in the path or query.
impl std::fmt::Debug for SiemConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |value: &str| (!value.is_empty()).then_some("<redacted>");
        formatter
            .debug_struct("SiemConfig")
            .field("enabled", &self.enabled)
            .field("file_enabled", &self.file_enabled)
            .field("syslog_enabled", &self.syslog_enabled)
            .field("webhook_enabled", &self.webhook_enabled)
            .field("file_path", &self.file_path)
            .field("manager_host", &self.manager_host)
            .field("manager_port", &self.manager_port)
            .field("protocol", &self.protocol)
            .field("webhook_url", &redacted(&self.webhook_url))
            .field("webhook_auth_token", &redacted(&self.webhook_auth_token))
            .field("webhook_auth_header", &self.webhook_auth_header)
            .field("send_allowed", &self.send_allowed)
            .field("send_blocked", &self.send_blocked)
            .field("send_new_app", &self.send_new_app)
            .field("send_new_domain", &self.send_new_domain)
            .field("send_threats", &self.send_threats)
            .finish()
    }
}

/// Syslog transport. UDP and TCP send RFC 3164 messages; TLS sends RFC 5424
/// messages as RFC 5425 requires (see `syslog_message`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemProtocol {
    Udp,
    Tcp,
    /// RFC 5425 syslog over TLS, the collector's certificate checked against
    /// the operating system's trust store.
    Tls,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            file_enabled: true,
            syslog_enabled: false,
            webhook_enabled: false,
            file_path: PathBuf::from("antiwire-events.json"),
            manager_host: String::new(),
            manager_port: 514,
            protocol: SiemProtocol::Udp,
            webhook_url: String::new(),
            webhook_auth_token: String::new(),
            webhook_auth_header: String::new(),
            send_allowed: false,
            send_blocked: true,
            send_new_app: true,
            send_new_domain: true,
            send_threats: true,
        }
    }
}

impl SiemConfig {
    pub fn from_settings(settings: &DaemonSetting) -> Self {
        let protocol = match settings.wazuh_protocol.trim().to_ascii_lowercase().as_str() {
            "tcp" => SiemProtocol::Tcp,
            "tls" => SiemProtocol::Tls,
            _ => SiemProtocol::Udp,
        };
        let file_path = resolve_siem_file_path(&settings.wazuh_file_path);

        Self {
            enabled: settings.siem_enabled,
            file_enabled: settings.siem_file_enabled,
            syslog_enabled: settings.siem_syslog_enabled,
            webhook_enabled: settings.siem_webhook_enabled,
            file_path,
            manager_host: settings.wazuh_manager_host.trim().to_owned(),
            manager_port: u16::try_from(settings.wazuh_manager_port)
                .ok()
                .filter(|port| *port > 0)
                .unwrap_or(514),
            protocol,
            webhook_url: settings.siem_url.trim().to_owned(),
            webhook_auth_token: settings.siem_auth_token.clone(),
            webhook_auth_header: settings.siem_auth_header.trim().to_owned(),
            send_allowed: settings.siem_send_allowed,
            send_blocked: settings.siem_send_blocked,
            send_new_app: settings.siem_send_new_app,
            send_new_domain: settings.siem_send_new_domain,
            send_threats: settings.siem_send_threats,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SiemEvent<'a> {
    pub event_type: &'a str,
    pub timestamp: String,
    pub details: serde_json::Value,
}

const SIEM_QUEUE_CAPACITY: usize = 1024;
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);
const SIEM_CONTROL_TIMEOUT: Duration = Duration::from_secs(11);
const SIEM_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DISPLAY_APP_NAME_CHARS: usize = 256;
const MAX_DISPLAY_APP_PATH_CHARS: usize = 4096;
const MAX_DISPLAY_DOMAIN_CHARS: usize = 253;
const MAX_DISPLAY_NETWORK_FIELD_CHARS: usize = 128;
const MAX_DISPLAY_BLOCKLIST_NAME_CHARS: usize = 128;
const MAX_DISPLAY_ALERT_TITLE_CHARS: usize = 256;
const MAX_DISPLAY_ALERT_MESSAGE_CHARS: usize = 1024;
const MAX_DISPLAY_SEVERITY_CHARS: usize = 64;

/// Alert / notification types owned by other SIEM category toggles.
fn is_category_owned_alert(alert_type: &str) -> bool {
    matches!(
        alert_type.to_ascii_uppercase().as_str(),
        // Owned by connection / new-app / new-domain SIEM categories.
        "NEW_APP" | "APP_PATH_CHANGED" | "NEW_DOMAIN" | "MALICIOUS_FLOW"
    )
}

// Connection is the common event; keep its log inline to avoid an additional
// allocation on every flow. The channel already bounds the enum's storage.
#[allow(clippy::large_enum_variant)]
enum SiemCommand {
    Connection {
        log: antiwire_store::NewConnectionLog,
        app_name: String,
        app_path: String,
    },
    NewApp {
        app_name: String,
        app_path: String,
    },
    NewDomain {
        domain: String,
        app_name: String,
        app_path: String,
    },
    Threat {
        alert_type: String,
        title: String,
        message: String,
        severity: String,
    },
    /// Wakes a worker waiting on an empty queue so it sees a config update
    /// or shutdown. A full queue needs none: the worker is busy and checks
    /// both before its next event.
    Wake,
    #[cfg(test)]
    Export(OwnedSiemEvent, SyncSender<std::io::Result<()>>),
    #[cfg(test)]
    BlockForTest(SyncSender<()>, Receiver<()>),
}

struct ConfigUpdate {
    config: SiemConfig,
    deadline: Instant,
    reply: SyncSender<std::io::Result<()>>,
    completion: Arc<Mutex<ConfigCompletion>>,
}

#[derive(Clone, Copy)]
enum ConfigCompletion {
    Pending,
    Applied,
    Cancelled,
}

struct SiemWorker {
    tx: SyncSender<SiemCommand>,
    control_tx: SyncSender<ConfigUpdate>,
    shutdown_deadline: Arc<Mutex<Option<Instant>>>,
    dropped: Arc<AtomicU64>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for SiemWorker {
    fn drop(&mut self) {
        let deadline = Instant::now() + SIEM_SHUTDOWN_TIMEOUT;
        *self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(deadline);
        let _ = self.tx.try_send(SiemCommand::Wake);
        if let Ok(join) = self.join.get_mut() {
            if let Some(join) = join.take() {
                while !join.is_finished() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !join.is_finished() {
                    warn!("SIEM worker did not stop in time; detaching the in-flight export");
                } else if join.join().is_err() {
                    warn!("SIEM worker panicked");
                }
            }
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct OwnedSiemEvent {
    event_type: String,
    timestamp: String,
    details: serde_json::Value,
}

#[cfg(test)]
impl OwnedSiemEvent {
    fn as_event(&self) -> SiemEvent<'_> {
        SiemEvent {
            event_type: &self.event_type,
            timestamp: self.timestamp.clone(),
            details: self.details.clone(),
        }
    }
}

/// Non-blocking handle to a bounded, single-owner SIEM exporter worker.
#[derive(Clone)]
pub struct SiemExporter {
    worker: Arc<SiemWorker>,
}

impl SiemExporter {
    /// Starts the exporter's worker thread.
    ///
    /// # Panics
    ///
    /// When the operating system cannot start the thread.
    #[must_use]
    pub fn new(config: SiemConfig) -> Self {
        let (tx, rx) = mpsc::sync_channel(SIEM_QUEUE_CAPACITY);
        // Control bypasses the event backlog, but remains bounded. At most one
        // update can wait behind an in-flight sink operation.
        let (control_tx, control_rx) = mpsc::sync_channel(1);
        let shutdown_deadline = Arc::new(Mutex::new(None));
        let thread_shutdown = Arc::clone(&shutdown_deadline);
        let dropped = Arc::new(AtomicU64::new(0));
        let thread_dropped = Arc::clone(&dropped);
        let join = std::thread::Builder::new()
            .name("antiwire-siem".to_owned())
            .spawn(move || {
                run_siem_worker(config, &rx, &control_rx, &thread_shutdown, &thread_dropped);
            })
            .expect("failed to start SIEM worker");
        Self {
            worker: Arc::new(SiemWorker {
                tx,
                control_tx,
                shutdown_deadline,
                dropped,
                join: Mutex::new(Some(join)),
            }),
        }
    }

    /// Hands the worker a new configuration and waits for it to take effect.
    ///
    /// # Errors
    ///
    /// [`std::io::ErrorKind::WouldBlock`] while another update is pending,
    /// [`std::io::ErrorKind::TimedOut`] when the worker does not apply it in time (it then
    /// never does), an error when the worker has stopped, and any error from opening the new
    /// sinks.
    pub fn update_config(&self, config: SiemConfig) -> std::io::Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let completion = Arc::new(Mutex::new(ConfigCompletion::Pending));
        self.worker
            .control_tx
            .try_send(ConfigUpdate {
                config,
                deadline: Instant::now() + SIEM_CONTROL_TIMEOUT,
                reply: reply_tx,
                completion: Arc::clone(&completion),
            })
            .map_err(|error| match error {
                TrySendError::Full(_) => std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "SIEM config update already pending",
                ),
                TrySendError::Disconnected(_) => worker_stopped(),
            })?;
        let _ = self.worker.tx.try_send(SiemCommand::Wake);
        match reply_rx.recv_timeout(SIEM_CONTROL_TIMEOUT) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(worker_stopped()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Serialize timeout with application: a reported timeout must
                // never leave a configuration that will silently apply later.
                let mut state = completion
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if matches!(*state, ConfigCompletion::Applied) {
                    Ok(())
                } else {
                    *state = ConfigCompletion::Cancelled;
                    Err(control_timeout())
                }
            }
        }
    }

    pub fn queue_connection_event(
        &self,
        log: &antiwire_store::NewConnectionLog,
        app_name: &str,
        app_path: &str,
    ) {
        self.try_queue(SiemCommand::Connection {
            log: log.clone(),
            app_name: app_name.to_owned(),
            app_path: app_path.to_owned(),
        });
    }

    pub fn queue_new_app_event(&self, app_name: &str, app_path: &str) {
        self.try_queue(SiemCommand::NewApp {
            app_name: app_name.to_owned(),
            app_path: app_path.to_owned(),
        });
    }

    pub fn queue_new_domain_event(&self, domain: &str, app_name: &str, app_path: &str) {
        self.try_queue(SiemCommand::NewDomain {
            domain: domain.to_owned(),
            app_name: app_name.to_owned(),
            app_path: app_path.to_owned(),
        });
    }

    pub fn queue_threat_event(&self, alert_type: &str, title: &str, message: &str, severity: &str) {
        if is_category_owned_alert(alert_type) {
            return;
        }
        self.try_queue(SiemCommand::Threat {
            alert_type: alert_type.to_owned(),
            title: title.to_owned(),
            message: message.to_owned(),
            severity: severity.to_owned(),
        });
    }

    /// Exports one event synchronously, bypassing the bounded queue.
    ///
    /// # Errors
    ///
    /// Any error from a sink.
    #[cfg(test)]
    pub fn export(&self, event: &SiemEvent<'_>) -> std::io::Result<()> {
        let owned = OwnedSiemEvent {
            event_type: event.event_type.to_owned(),
            timestamp: event.timestamp.clone(),
            details: event.details.clone(),
        };
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.worker
            .tx
            .send(SiemCommand::Export(owned, reply_tx))
            .map_err(|_| worker_stopped())?;
        reply_rx.recv().map_err(|_| worker_stopped())?
    }

    #[cfg(test)]
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.worker.dropped.load(Ordering::Relaxed)
    }

    fn try_queue(&self, command: SiemCommand) {
        if let Err(error) = self.worker.tx.try_send(command) {
            if matches!(error, TrySendError::Full(_) | TrySendError::Disconnected(_)) {
                let dropped = self.worker.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // Throttled to powers of two: a sustained overflow logs a
                // handful of lines rather than one per event.
                if dropped.is_power_of_two() {
                    tracing::warn!(dropped, "SIEM export queue full; events dropped");
                }
            }
        }
    }
}

fn worker_stopped() -> std::io::Error {
    std::io::Error::other("siem worker stopped")
}

fn control_timeout() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "SIEM config update timed out")
}

fn run_siem_worker(
    config: SiemConfig,
    rx: &Receiver<SiemCommand>,
    control_rx: &Receiver<ConfigUpdate>,
    shutdown_deadline: &Mutex<Option<Instant>>,
    dropped: &AtomicU64,
) {
    let mut exporter = WorkerState::new(config);
    loop {
        let shutdown = *shutdown_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if shutdown.is_some_and(|deadline| Instant::now() >= deadline) {
            let abandoned = rx
                .try_iter()
                .filter(|command| !matches!(command, SiemCommand::Wake))
                .count() as u64;
            if abandoned > 0 {
                let total = dropped
                    .fetch_add(abandoned, Ordering::Relaxed)
                    .saturating_add(abandoned);
                warn!(
                    abandoned,
                    dropped = total,
                    "SIEM shutdown deadline reached; queued events dropped"
                );
            }
            break;
        }
        // Check before every event, including when the event queue is full.
        if let Ok(update) = control_rx.try_recv() {
            let mut completion = update
                .completion
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if matches!(*completion, ConfigCompletion::Cancelled)
                || Instant::now() >= update.deadline
            {
                *completion = ConfigCompletion::Cancelled;
                let _ = update.reply.send(Err(control_timeout()));
            } else {
                exporter.update_config(update.config);
                *completion = ConfigCompletion::Applied;
                let _ = update.reply.send(Ok(()));
            }
        }
        // Once shutdown has begun, export what is queued and stop. Until then,
        // wait: a config update or shutdown sends a wake-up.
        let next = if shutdown.is_some() {
            rx.try_recv().ok()
        } else {
            rx.recv().ok()
        };
        let Some(command) = next else {
            break;
        };
        match command {
            SiemCommand::Connection {
                log,
                app_name,
                app_path,
            } => exporter.queue_connection_event(&log, &app_name, &app_path),
            SiemCommand::NewApp { app_name, app_path } => {
                exporter.queue_new_app_event(&app_name, &app_path);
            }
            SiemCommand::NewDomain {
                domain,
                app_name,
                app_path,
            } => exporter.queue_new_domain_event(&domain, &app_name, &app_path),
            SiemCommand::Threat {
                alert_type,
                title,
                message,
                severity,
            } => exporter.queue_threat_event(&alert_type, &title, &message, &severity),
            SiemCommand::Wake => {}
            #[cfg(test)]
            SiemCommand::Export(event, reply) => {
                let _ = reply.send(exporter.export(&event.as_event()));
            }
            #[cfg(test)]
            SiemCommand::BlockForTest(ready, release) => {
                let _ = ready.send(());
                let _ = release.recv();
            }
        }
    }
}

struct WorkerState {
    config: SiemConfig,
    /// The open TCP or TLS connection to the syslog collector, reused across
    /// events.
    syslog_stream: Option<Box<dyn Write + Send>>,
    http: antiwire_http::BlockingHttpClient,
}

impl WorkerState {
    fn new(config: SiemConfig) -> Self {
        // A SIEM collector usually runs on the local network or on this
        // machine, so both are reachable; link-local and metadata addresses
        // never are. Redirects are not followed: a custom auth header would be
        // sent on to wherever a redirect points.
        let http = antiwire_http::HttpClientBuilder::new("antiwire-siem")
            .destinations(antiwire_http::Destinations::PublicPrivateAndLoopback)
            .https_only(false)
            .max_redirects(0)
            .timeout(WEBHOOK_TIMEOUT)
            .connect_timeout(WEBHOOK_TIMEOUT)
            .build_blocking()
            .expect("siem http client");
        Self {
            config,
            syslog_stream: None,
            http,
        }
    }

    pub fn update_config(&mut self, config: SiemConfig) {
        self.config = config;
        self.syslog_stream = None;
    }

    pub fn queue_connection_event(
        &mut self,
        log: &antiwire_store::NewConnectionLog,
        app_name: &str,
        app_path: &str,
    ) {
        if !self.config.enabled {
            return;
        }

        let blocked = log.action_taken.eq_ignore_ascii_case("BLOCKED");
        if blocked && !self.config.send_blocked {
            return;
        }
        if !blocked && !self.config.send_allowed {
            return;
        }

        let event = SiemEvent {
            event_type: if blocked {
                "connection_blocked"
            } else {
                "connection_allowed"
            },
            timestamp: rfc3339_timestamp(),
            details: serde_json::json!({
                "integration": "antiwire",
                "action": display_text(&log.action_taken, MAX_DISPLAY_NETWORK_FIELD_CHARS),
                "app_name": display_text(app_name, MAX_DISPLAY_APP_NAME_CHARS),
                "app_path": display_text(app_path, MAX_DISPLAY_APP_PATH_CHARS),
                "protocol": display_text(&log.protocol, MAX_DISPLAY_NETWORK_FIELD_CHARS),
                "src_ip": display_text(&log.src_ip, MAX_DISPLAY_NETWORK_FIELD_CHARS),
                "src_port": log.src_port,
                "dst_ip": display_text(&log.dst_ip, MAX_DISPLAY_NETWORK_FIELD_CHARS),
                "dst_port": log.dst_port,
                "dst_domain": display_text(&log.dst_domain, MAX_DISPLAY_DOMAIN_CHARS),
                "bytes_sent": log.bytes_sent,
                "bytes_received": log.bytes_received,
                "blocklist_names": antiwire_store::decode_blocklist_names(&log.blocklist_names)
                    .into_iter()
                    .map(|name| display_text(&name, MAX_DISPLAY_BLOCKLIST_NAME_CHARS))
                    .collect::<Vec<_>>(),
            }),
        };
        if let Err(error) = self.export(&event) {
            warn!(error = %error, "siem connection export failed");
        }
    }

    pub fn queue_new_app_event(&mut self, app_name: &str, app_path: &str) {
        if !self.config.enabled || !self.config.send_new_app {
            return;
        }
        let event = SiemEvent {
            event_type: "new_application",
            timestamp: rfc3339_timestamp(),
            details: serde_json::json!({
                "integration": "antiwire",
                "app_name": display_text(app_name, MAX_DISPLAY_APP_NAME_CHARS),
                "app_path": display_text(app_path, MAX_DISPLAY_APP_PATH_CHARS),
            }),
        };
        if let Err(error) = self.export(&event) {
            warn!(error = %error, "siem new-app export failed");
        }
    }

    pub fn queue_new_domain_event(&mut self, domain: &str, app_name: &str, app_path: &str) {
        if !self.config.enabled || !self.config.send_new_domain {
            return;
        }
        let event = SiemEvent {
            event_type: "new_domain",
            timestamp: rfc3339_timestamp(),
            details: serde_json::json!({
                "integration": "antiwire",
                "domain": display_text(domain, MAX_DISPLAY_DOMAIN_CHARS),
                "app_name": display_text(app_name, MAX_DISPLAY_APP_NAME_CHARS),
                "app_path": display_text(app_path, MAX_DISPLAY_APP_PATH_CHARS),
            }),
        };
        if let Err(error) = self.export(&event) {
            warn!(error = %error, "siem new-domain export failed");
        }
    }

    pub fn queue_threat_event(
        &mut self,
        alert_type: &str,
        title: &str,
        message: &str,
        severity: &str,
    ) {
        if !self.config.enabled || !self.config.send_threats {
            return;
        }
        let event = SiemEvent {
            event_type: "threat",
            timestamp: rfc3339_timestamp(),
            details: serde_json::json!({
                "integration": "antiwire",
                "alert_type": display_text(alert_type, MAX_DISPLAY_ALERT_TITLE_CHARS),
                "title": display_text(title, MAX_DISPLAY_ALERT_TITLE_CHARS),
                "message": display_text(message, MAX_DISPLAY_ALERT_MESSAGE_CHARS),
                "severity": display_text(severity, MAX_DISPLAY_SEVERITY_CHARS),
            }),
        };
        if let Err(error) = self.export(&event) {
            warn!(error = %error, "siem threat export failed");
        }
    }

    pub fn export(&mut self, event: &SiemEvent<'_>) -> std::io::Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut last_error = None;
        if self.config.file_enabled {
            if let Err(error) = self.write_file(event) {
                warn!(error = %error, "siem file export failed");
                last_error = Some(error);
            }
        }
        if self.config.syslog_enabled {
            if let Err(error) = self.send_syslog(event) {
                warn!(error = %error, "siem syslog export failed");
                last_error = Some(error);
            }
        }
        if self.config.webhook_enabled {
            if let Err(error) = self.send_webhook(event) {
                warn!(error = %error, "siem webhook export failed");
                last_error = Some(error);
            }
        }

        match last_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn write_file(&self, event: &SiemEvent<'_>) -> std::io::Result<()> {
        if let Some(parent) = self.config.file_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.file_path)?;
        let line = serde_json::to_string(event)?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    fn send_syslog(&mut self, event: &SiemEvent<'_>) -> std::io::Result<()> {
        if self.config.manager_host.is_empty() {
            warn!("syslog sink enabled without manager host; skipping event");
            return Ok(());
        }

        let json = serde_json::to_string(event)?;
        let pid = std::process::id();

        match self.config.protocol {
            SiemProtocol::Udp => self.send_udp(&syslog_message::rfc3164(
                local_now(),
                &hostname(),
                pid,
                &json,
            )),
            SiemProtocol::Tcp => self.send_stream(&syslog_message::lf_framed(
                &syslog_message::rfc3164(local_now(), &hostname(), pid, &json),
            )),
            SiemProtocol::Tls => self.send_stream(&syslog_message::octet_counted(
                &syslog_message::rfc5424(OffsetDateTime::now_utc(), &hostname(), pid, &json),
            )),
        }
    }

    fn send_udp(&self, message: &str) -> std::io::Result<()> {
        let target = resolve_target(&self.config.manager_host, self.config.manager_port)?;
        let local: std::net::SocketAddr = if target.is_ipv6() {
            "[::]:0".parse().expect("valid IPv6 wildcard")
        } else {
            "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
        };
        UdpSocket::bind(local)?.send_to(message.as_bytes(), target)?;
        Ok(())
    }

    /// Writes one framed message on the cached TCP or TLS connection, opening
    /// it first if needed, and retries once on a fresh connection when the
    /// cached one has gone away.
    fn send_stream(&mut self, frame: &[u8]) -> std::io::Result<()> {
        if let Err(error) = self.write_stream(frame) {
            self.syslog_stream = None;
            self.write_stream(frame).map_err(|_| error)
        } else {
            Ok(())
        }
    }

    fn write_stream(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let stream = match &mut self.syslog_stream {
            Some(stream) => stream,
            None => self.syslog_stream.insert(self.connect_syslog()?),
        };
        stream.write_all(frame)?;
        stream.flush()
    }

    fn connect_syslog(&self) -> std::io::Result<Box<dyn Write + Send>> {
        let host = &self.config.manager_host;
        let target = resolve_target(host, self.config.manager_port)?;
        let stream = TcpStream::connect_timeout(&target, SIEM_TCP_CONNECT_TIMEOUT)?;
        stream.set_write_timeout(Some(SIEM_TCP_CONNECT_TIMEOUT))?;
        if self.config.protocol != SiemProtocol::Tls {
            return Ok(Box::new(BufWriter::new(stream)));
        }
        // The handshake reads the server's replies, so reads need a bound too.
        stream.set_read_timeout(Some(SIEM_TCP_CONNECT_TIMEOUT))?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let connection = rustls::ClientConnection::new(syslog_tls_config()?, server_name)
            .map_err(std::io::Error::other)?;
        Ok(Box::new(rustls::StreamOwned::new(connection, stream)))
    }

    fn send_webhook(&self, event: &SiemEvent<'_>) -> std::io::Result<()> {
        if self.config.webhook_url.is_empty() {
            warn!("webhook sink enabled without URL; skipping event");
            return Ok(());
        }

        let body = serde_json::to_vec(event).map_err(std::io::Error::other)?;
        let mut request = self
            .http
            .post(&self.config.webhook_url)
            .map_err(std::io::Error::other)?
            .header("content-type", "application/json")
            .body(body);

        if !self.config.webhook_auth_token.is_empty() {
            let header_name = if self.config.webhook_auth_header.is_empty() {
                "Authorization"
            } else {
                self.config.webhook_auth_header.as_str()
            };
            request = request.header(header_name, &self.config.webhook_auth_token);
        }

        let response = request.send().map_err(std::io::Error::other)?;
        if !response.status().is_success() {
            return Err(std::io::Error::other(format!(
                "webhook returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}

/// TLS settings for RFC 5425 syslog: the collector's certificate is checked
/// against the operating system's trust store, so a collector signed by an
/// organisation's own CA works once that CA is installed on the machine.
fn syslog_tls_config() -> std::io::Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        .map_err(std::io::Error::other)?;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Local time for an RFC 3164 timestamp, or UTC when the local offset cannot
/// be read.
fn local_now() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

fn resolve_target(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no syslog addresses"))
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "antiwire".to_owned())
}

/// Directory the file transport is confined to.
///
/// `wazuh_file_path` arrives over the IPC API and the daemon runs as SYSTEM, so an
/// unconstrained path is an arbitrary-file-write primitive for anyone who can reach
/// that API — pointed at a startup script or a service binary it becomes local
/// privilege escalation. Every path the file sink resolves stays under this root.
fn siem_export_root() -> PathBuf {
    default_wazuh_file_path()
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Resolves the configured export path, falling back to the default when it escapes
/// [`siem_export_root`].
///
/// A relative path is taken as relative to the root; an absolute one must already be
/// inside it. Rejection is logged and degrades to the default rather than disabling
/// export, so a bad setting never silently stops security logging.
fn resolve_siem_file_path(configured: &str) -> PathBuf {
    let configured = configured.trim();
    if configured.is_empty() {
        return default_wazuh_file_path();
    }

    let root = siem_export_root();
    let raw = Path::new(configured);
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        root.join(raw)
    };

    match confine_to_root(&candidate, &root) {
        Ok(path) => path,
        Err(reason) => {
            warn!(
                configured,
                root = %root.display(),
                reason,
                "SIEM export path is outside the daemon's export directory; using the default"
            );
            default_wazuh_file_path()
        }
    }
}

/// Returns `candidate` when it is genuinely inside `root`.
fn confine_to_root(candidate: &Path, root: &Path) -> Result<PathBuf, &'static str> {
    // `..` is rejected outright rather than normalised away: normalising would let
    // `<root>/../../Windows/System32/x` reduce to a path that never looked suspicious.
    for component in candidate.components() {
        match component {
            Component::ParentDir => return Err("contains a parent-directory component"),
            // `events.json:payload` addresses an NTFS alternate data stream, which
            // `starts_with` below would happily accept as being "inside" the root.
            Component::Normal(part) if part.to_string_lossy().contains(':') => {
                return Err("contains an alternate-data-stream separator")
            }
            _ => {}
        }
    }

    if !candidate.starts_with(root) {
        return Err("resolves outside the export directory");
    }
    if candidate.file_name().is_none() {
        return Err("has no file name");
    }

    // Lexical containment is not enough on its own: a junction or symlink planted at
    // an intermediate path would still redirect the write. Resolve the deepest part
    // that actually exists and re-check it against the resolved root.
    let Ok(canonical_root) = root.canonicalize() else {
        // The export directory does not exist yet, so there is no link inside it to
        // follow; the lexical checks above are what apply.
        return Ok(candidate.to_path_buf());
    };
    let anchor = deepest_existing_ancestor(candidate);
    let canonical_anchor = anchor.canonicalize().map_err(|_| "could not be resolved")?;
    if !canonical_anchor.starts_with(&canonical_root) {
        return Err("resolves outside the export directory through a link");
    }

    Ok(candidate.to_path_buf())
}

fn deepest_existing_ancestor(path: &Path) -> PathBuf {
    let mut current = path;
    loop {
        if current.exists() {
            return current.to_path_buf();
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return current.to_path_buf(),
        }
    }
}

fn default_wazuh_file_path() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("PROGRAMDATA")
            .map_or_else(|_| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
            .join("Antiwire")
            .join("wazuh")
            .join("antiwire-events.json")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/log/antiwire/wazuh-events.json")
    }
}

fn rfc3339_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_leaves_out_webhook_secrets() {
        let config = SiemConfig {
            webhook_url: "https://hooks.example.com/services/T000/B000/XXSECRET".to_owned(),
            webhook_auth_token: "Bearer hunter2".to_owned(),
            ..SiemConfig::default()
        };
        let shown = format!("{config:?}");
        assert!(!shown.contains("XXSECRET"), "{shown}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }
    use std::io::{Read, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use tempfile::tempdir;

    #[test]
    fn file_export_appends_json_line() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.json");
        let exporter = SiemExporter::new(SiemConfig {
            enabled: true,
            file_enabled: true,
            file_path: path.clone(),
            ..SiemConfig::default()
        });
        let event = SiemEvent {
            event_type: "blocked",
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            details: serde_json::json!({ "domain": "evil.test" }),
        };
        exporter.export(&event).unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.contains("evil.test"));
    }

    /// The escalation primitive: a caller who reaches the IPC API must not be able to
    /// aim the SYSTEM daemon's writes at a path of their choosing.
    #[test]
    fn from_settings_rejects_an_export_path_outside_the_export_directory() {
        let escapes = [
            #[cfg(windows)]
            r"C:\Windows\System32\drivers\etc\hosts",
            #[cfg(not(windows))]
            "/etc/cron.d/antiwire",
            "../../../evil.json",
            "sub/../../../evil.json",
        ];

        for path in escapes {
            let settings = DaemonSetting {
                siem_enabled: true,
                wazuh_file_path: path.to_owned(),
                ..DaemonSetting::default()
            };
            assert_eq!(
                SiemConfig::from_settings(&settings).file_path,
                default_wazuh_file_path(),
                "{path:?} must fall back to the default export path"
            );
        }
    }

    #[test]
    fn from_settings_keeps_a_path_inside_the_export_directory() {
        let expected = siem_export_root().join("team").join("events.json");
        for configured in [
            expected.to_string_lossy().into_owned(),
            "team/events.json".to_owned(),
        ] {
            let settings = DaemonSetting {
                siem_enabled: true,
                wazuh_file_path: configured.clone(),
                ..DaemonSetting::default()
            };
            assert_eq!(
                SiemConfig::from_settings(&settings).file_path,
                expected,
                "{configured:?} is inside the export directory and must be honoured"
            );
        }
    }

    #[test]
    fn empty_export_path_uses_the_default() {
        let settings = DaemonSetting {
            siem_enabled: true,
            wazuh_file_path: "   ".to_owned(),
            ..DaemonSetting::default()
        };
        assert_eq!(
            SiemConfig::from_settings(&settings).file_path,
            default_wazuh_file_path()
        );
    }

    #[cfg(windows)]
    #[test]
    fn alternate_data_stream_suffix_is_rejected() {
        let root = siem_export_root();
        let stream = root.join("events.json:payload");
        assert!(confine_to_root(&stream, &root).is_err());
    }

    /// A link planted mid-path must not redirect the write out of the root.
    #[test]
    fn a_link_out_of_the_export_directory_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path().join("export");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::create_dir_all(&outside).expect("create outside");

        let linked = root.join("linked");
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_dir(&outside, &linked).is_ok();
        #[cfg(not(windows))]
        let created = std::os::unix::fs::symlink(&outside, &linked).is_ok();
        if !created {
            // Creating a symlink on Windows needs Developer Mode or elevation; the
            // lexical checks are covered by the other tests either way.
            return;
        }

        assert!(confine_to_root(&linked.join("events.json"), &root).is_err());
        assert!(confine_to_root(&root.join("events.json"), &root).is_ok());
    }

    #[test]
    fn from_settings_maps_sink_flags_and_syslog() {
        let settings = DaemonSetting {
            siem_enabled: true,
            siem_file_enabled: false,
            siem_syslog_enabled: true,
            wazuh_protocol: "tcp".to_owned(),
            wazuh_manager_host: "127.0.0.1".to_owned(),
            wazuh_manager_port: 5514,
            siem_webhook_enabled: true,
            siem_url: "https://siem.example/hook".to_owned(),
            ..DaemonSetting::default()
        };
        let config = SiemConfig::from_settings(&settings);
        assert!(!config.file_enabled);
        assert!(config.syslog_enabled);
        assert!(config.webhook_enabled);
        assert_eq!(config.protocol, SiemProtocol::Tcp);
        assert_eq!(config.manager_port, 5514);
        assert_eq!(config.webhook_url, "https://siem.example/hook");
    }

    #[test]
    fn syslog_without_host_is_noop() {
        let exporter = SiemExporter::new(SiemConfig {
            enabled: true,
            file_enabled: false,
            syslog_enabled: true,
            manager_host: String::new(),
            manager_port: 514,
            protocol: SiemProtocol::Udp,
            ..SiemConfig::default()
        });
        let event = SiemEvent {
            event_type: "blocked",
            timestamp: rfc3339_timestamp(),
            details: serde_json::json!({}),
        };
        exporter.export(&event).unwrap();
    }

    #[test]
    fn from_settings_maps_the_tls_transport() {
        let settings = DaemonSetting {
            wazuh_protocol: "TLS".to_owned(),
            ..DaemonSetting::default()
        };
        assert_eq!(
            SiemConfig::from_settings(&settings).protocol,
            SiemProtocol::Tls
        );
    }

    fn syslog_exporter(protocol: SiemProtocol, port: u16) -> SiemExporter {
        SiemExporter::new(SiemConfig {
            enabled: true,
            file_enabled: false,
            syslog_enabled: true,
            manager_host: "127.0.0.1".to_owned(),
            manager_port: port,
            protocol,
            ..SiemConfig::default()
        })
    }

    fn blocked_event() -> SiemEvent<'static> {
        SiemEvent {
            event_type: "blocked",
            timestamp: rfc3339_timestamp(),
            details: serde_json::json!({"domain": "ads.example"}),
        }
    }

    /// A valid RFC 3164 header: `<134>Mmm dd hh:mm:ss HOST antiwire[PID]: `.
    fn assert_rfc3164(message: &str) {
        let rest = message.strip_prefix("<134>").expect("PRI");
        let (timestamp, rest) = rest.split_at(15);
        assert_eq!(timestamp.as_bytes()[3], b' ', "{timestamp}");
        assert_eq!(timestamp.as_bytes()[6], b' ', "{timestamp}");
        let (host, rest) = rest[1..].split_once(' ').expect("hostname");
        assert!(!host.is_empty() && !host.contains('.'), "{host}");
        let body = rest
            .strip_prefix(&format!("antiwire[{}]: ", std::process::id()))
            .expect("tag");
        serde_json::from_str::<serde_json::Value>(body).expect("JSON body");
    }

    #[test]
    fn udp_syslog_sends_an_rfc3164_datagram() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        syslog_exporter(SiemProtocol::Udp, port)
            .export(&blocked_event())
            .expect("export");
        let mut buf = [0u8; 2048];
        let len = socket.recv(&mut buf).expect("datagram");
        assert_rfc3164(std::str::from_utf8(&buf[..len]).expect("utf-8"));
    }

    /// Plain TCP carries the same RFC 3164 message as UDP, LF-framed
    /// (RFC 6587 §3.4.2), so a Wazuh manager parses both alike.
    #[test]
    fn tcp_syslog_sends_lf_framed_rfc3164() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let exporter = syslog_exporter(SiemProtocol::Tcp, port);
        exporter.export(&blocked_event()).expect("export");
        exporter.export(&blocked_event()).expect("export again");

        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut lines = std::io::BufRead::lines(std::io::BufReader::new(stream));
        for _ in 0..2 {
            assert_rfc3164(&lines.next().expect("line").expect("read"));
        }
    }

    /// RFC 5425: TLS really is negotiated, and a collector that does not
    /// speak it is an error rather than a silent plaintext fallback.
    #[test]
    fn tls_syslog_starts_a_handshake_and_fails_without_one() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        // Two connections: the sender retries once on a fresh one.
        let server = std::thread::spawn(move || {
            (0..2)
                .map(|_| {
                    let (mut stream, _) = listener.accept().expect("accept");
                    let mut first = [0u8; 1];
                    std::io::Read::read_exact(&mut stream, &mut first).expect("read");
                    // Answer the ClientHello in plaintext, as a non-TLS collector would.
                    stream.write_all(b"not tls\n").expect("write");
                    first[0]
                })
                .collect::<Vec<_>>()
        });
        let result = syslog_exporter(SiemProtocol::Tls, port).export(&blocked_event());
        assert_eq!(
            server.join().expect("server"),
            vec![0x16, 0x16],
            "each connection opens with a TLS handshake record"
        );
        assert!(result.is_err(), "a failed handshake is reported");
    }

    #[test]
    fn webhook_posts_json_with_auth_header() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).expect("read");
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = tx.send(req);
        });

        let exporter = SiemExporter::new(SiemConfig {
            enabled: true,
            file_enabled: false,
            syslog_enabled: false,
            webhook_enabled: true,
            webhook_url: format!("http://{addr}/hook"),
            webhook_auth_header: "X-Api-Key".to_owned(),
            webhook_auth_token: "secret".to_owned(),
            ..SiemConfig::default()
        });
        let event = SiemEvent {
            event_type: "threat",
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            details: serde_json::json!({ "ok": true }),
        };
        exporter.export(&event).expect("webhook export");

        let req = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        let req_lower = req.to_ascii_lowercase();
        assert!(req_lower.contains("post /hook"));
        assert!(req_lower.contains("x-api-key: secret"));
        assert!(req.contains("\"ok\":true"));
    }

    /// The auth header can have any name, so the HTTP client would not know to
    /// strip it on a redirect. The webhook therefore follows none: the token
    /// goes only to the configured URL.
    #[test]
    fn webhook_does_not_follow_a_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel::<usize>();
        std::thread::spawn(move || {
            let mut requests = 0;
            listener.set_nonblocking(true).expect("nonblocking");
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                if let Ok((mut stream, _)) = listener.accept() {
                    stream.set_nonblocking(false).expect("blocking");
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    requests += 1;
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{addr}/elsewhere\r\nContent-Length: 0\r\n\r\n"
                        )
                        .as_bytes(),
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = tx.send(requests);
        });

        let exporter = SiemExporter::new(SiemConfig {
            enabled: true,
            file_enabled: false,
            syslog_enabled: false,
            webhook_enabled: true,
            webhook_url: format!("http://{addr}/hook"),
            webhook_auth_header: "X-Api-Key".to_owned(),
            webhook_auth_token: "secret".to_owned(),
            ..SiemConfig::default()
        });
        let event = SiemEvent {
            event_type: "threat",
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            details: serde_json::json!({ "ok": true }),
        };
        let error = exporter
            .export(&event)
            .expect_err("a redirect is a failure");
        assert!(error.to_string().contains("307"), "{error}");
        assert_eq!(rx.recv_timeout(Duration::from_secs(4)).expect("count"), 1);
    }

    /// The HTTP client refuses these before anything is sent; the webhook has no
    /// URL check of its own.
    #[test]
    fn webhook_refuses_metadata_and_non_http_urls() {
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest",
            "ftp://example.com/x",
        ] {
            let exporter = SiemExporter::new(SiemConfig {
                enabled: true,
                file_enabled: false,
                syslog_enabled: false,
                webhook_enabled: true,
                webhook_url: url.to_owned(),
                ..SiemConfig::default()
            });
            let event = SiemEvent {
                event_type: "threat",
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                details: serde_json::json!({ "ok": true }),
            };
            let error = exporter.export(&event).expect_err("refused");
            let message = error.to_string();
            assert!(message.contains("refused"), "{url}: {message}");
            assert!(
                !message.contains("latest"),
                "the URL is left out: {message}"
            );
        }
    }

    #[test]
    fn category_filters_skip_disabled_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.json");
        let exporter = SiemExporter::new(SiemConfig {
            enabled: true,
            file_enabled: true,
            file_path: path.clone(),
            send_new_app: false,
            send_new_domain: true,
            send_threats: false,
            ..SiemConfig::default()
        });

        exporter.queue_new_app_event("app.exe", r"C:\app.exe");
        exporter.queue_new_domain_event("example.com", "app.exe", r"C:\app.exe");
        exporter.queue_threat_event("MALICIOUS_FLOW", "bad", "msg", "WARNING");
        // Allow the worker to drain.
        std::thread::sleep(Duration::from_millis(50));

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(!contents.contains("new_application"));
        assert!(contents.contains("new_domain"));
        assert!(!contents.contains("\"event_type\":\"threat\""));
    }

    #[test]
    fn queue_events_escape_format_controls_in_display_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.json");
        {
            let exporter = SiemExporter::new(SiemConfig {
                enabled: true,
                file_enabled: true,
                file_path: path.clone(),
                ..SiemConfig::default()
            });
            exporter.queue_new_app_event(
                "Εφαρμογή\u{202E}.exe",
                "C:\\Προγράμματα\\Εφαρμογή.exe\u{200B}",
            );
        }

        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.contains(r"Εφαρμογή\\u{202E}.exe"));
        assert!(contents.contains(r"C:\\Προγράμματα\\Εφαρμογή.exe\\u{200B}"));
        assert!(!contents.contains('\u{202E}'));
        assert!(!contents.contains('\u{200B}'));
    }

    #[test]
    fn update_config_hot_reloads_sinks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.json");
        let exporter = SiemExporter::new(SiemConfig {
            enabled: false,
            file_enabled: true,
            file_path: path.clone(),
            ..SiemConfig::default()
        });

        let event = SiemEvent {
            event_type: "blocked",
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            details: serde_json::json!({ "n": 1 }),
        };
        exporter.export(&event).unwrap();
        assert!(!path.exists() || std::fs::read_to_string(&path).unwrap().is_empty());

        exporter
            .update_config(SiemConfig {
                enabled: true,
                file_enabled: true,
                file_path: path.clone(),
                ..SiemConfig::default()
            })
            .unwrap();
        exporter.export(&event).unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.contains("\"n\":1"));
    }

    #[test]
    fn config_update_bypasses_a_full_event_queue() {
        let exporter = SiemExporter::new(SiemConfig::default());
        let (ready, blocked) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        exporter
            .worker
            .tx
            .send(SiemCommand::BlockForTest(ready, wait))
            .unwrap();
        blocked.recv().unwrap();

        // The next event blocks again, proving the config acknowledgement was
        // sent before any of this backlog was handled.
        let (next_ready, next_blocked) = mpsc::sync_channel(1);
        let (next_release, next_wait) = mpsc::sync_channel(1);
        exporter
            .worker
            .tx
            .send(SiemCommand::BlockForTest(next_ready, next_wait))
            .unwrap();
        for _ in 1..SIEM_QUEUE_CAPACITY {
            exporter.queue_new_app_event("app", "path");
        }
        assert_eq!(exporter.dropped_events(), 0);
        let (reply, applied) = mpsc::sync_channel(1);
        exporter
            .worker
            .control_tx
            .send(ConfigUpdate {
                config: SiemConfig::default(),
                deadline: Instant::now() + SIEM_CONTROL_TIMEOUT,
                reply,
                completion: Arc::new(Mutex::new(ConfigCompletion::Pending)),
            })
            .unwrap();
        release.send(()).unwrap();
        let result = applied.recv_timeout(Duration::from_secs(2));
        let _ = next_release.send(());
        result.unwrap().unwrap();
        next_blocked.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn expired_config_is_not_applied_later() {
        let exporter = SiemExporter::new(SiemConfig::default());
        let dir = tempdir().unwrap();
        let path = dir.path().join("expired.json");
        let (reply, applied) = mpsc::sync_channel(1);
        exporter
            .worker
            .control_tx
            .send(ConfigUpdate {
                config: SiemConfig {
                    enabled: true,
                    file_path: path.clone(),
                    ..SiemConfig::default()
                },
                deadline: Instant::now(),
                reply,
                completion: Arc::new(Mutex::new(ConfigCompletion::Pending)),
            })
            .unwrap();
        // As `update_config` does: an idle worker only checks control when woken.
        exporter.worker.tx.send(SiemCommand::Wake).unwrap();
        assert_eq!(
            applied
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        exporter
            .export(&SiemEvent {
                event_type: "test",
                timestamp: String::new(),
                details: serde_json::json!({}),
            })
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn shutdown_does_not_wait_for_a_stuck_sink_or_its_backlog() {
        let exporter = SiemExporter::new(SiemConfig::default());
        let drops = Arc::clone(&exporter.worker.dropped);
        let (ready, blocked) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        exporter
            .worker
            .tx
            .send(SiemCommand::BlockForTest(ready, wait))
            .unwrap();
        blocked.recv().unwrap();
        for _ in 0..8 {
            exporter.queue_new_app_event("app", "path");
        }
        let (finished, done) = mpsc::sync_channel(1);
        let drop_thread = std::thread::spawn(move || {
            drop(exporter);
            let _ = finished.send(());
        });
        let result = done.recv_timeout(SIEM_SHUTDOWN_TIMEOUT + Duration::from_secs(2));
        let _ = release.send(());
        result.expect("drop must return despite the blocked worker");
        drop_thread.join().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while drops.load(Ordering::Relaxed) < 8 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(drops.load(Ordering::Relaxed), 8);
    }

    #[test]
    fn queue_overflow_increments_visible_drop_counter() {
        let exporter = SiemExporter::new(SiemConfig::default());
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        exporter
            .worker
            .tx
            .send(SiemCommand::BlockForTest(ready_tx, release_rx))
            .expect("block worker");
        ready_rx.recv().expect("worker blocked");

        let log = antiwire_store::NewConnectionLog {
            is_close: false,
            replace_domain: false,
            conn_pid: 0,
            conn_id: 0,
            timestamp: OffsetDateTime::now_utc(),
            app_id: 1,
            app_path: String::new(),
            protocol: "TCP".to_owned(),
            src_ip: "127.0.0.1".to_owned(),
            src_port: 1000,
            dst_ip: "192.0.2.1".to_owned(),
            dst_port: 443,
            dst_domain: String::new(),
            bytes_sent: 0,
            bytes_received: 0,
            action_taken: "BLOCKED".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
            country_code: String::new(),
            isp: String::new(),
            blocklist_names: String::new(),
        };

        for _ in 0..(SIEM_QUEUE_CAPACITY + 8) {
            exporter.queue_connection_event(&log, "app", "path");
        }
        assert!(exporter.dropped_events() > 0);
        let _ = release_tx.send(());
    }
}
