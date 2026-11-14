//! Writing logical rules onto `INetFw` rule objects.

use firew_core::{Action, AddressSetMode, Direction, Error, ErrorKind, Protocol, Rule};
use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwRule, INetFwRule3, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY,
    NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

use super::{map_com_mutation_err, ComInetFwSession, SET_MODE_TOKEN};

impl ComInetFwSession {
    /// Builds an `INetFw` rule object from a logical rule.
    pub(crate) fn build_rule(
        rule: &Rule,
        direction: Direction,
        native_name: &str,
        marker: &str,
        native_group: &str,
    ) -> Result<INetFwRule, Error> {
        firew_sys::reject_unresolved_domains(rule)?;

        // SAFETY: COM is initialized on this worker thread, all BSTR arguments
        // remain alive for each call, and the returned interface stays thread-confined.
        unsafe {
            let fw_rule: INetFwRule = CoCreateInstance(
                &windows::Win32::NetworkManagement::WindowsFirewall::NetFwRule,
                None,
                CLSCTX_INPROC_SERVER,
            )
            .map_err(|e| Error::new(ErrorKind::Internal, format!("NetFwRule: {e}")))?;

            Self::apply_rule_properties(
                &fw_rule,
                rule,
                direction,
                native_name,
                marker,
                native_group,
            )?;
            Ok(fw_rule)
        }
    }

    /// Applies all properties of `rule` onto an `INetFwRule` COM instance.
    ///
    /// Used both when constructing a new COM rule and when updating an existing
    /// owned COM rule in place so replacement never drops enforcement first.
    pub(crate) fn apply_rule_properties(
        fw_rule: &INetFwRule,
        rule: &Rule,
        direction: Direction,
        native_name: &str,
        marker: &str,
        native_group: &str,
    ) -> Result<(), Error> {
        // SAFETY: `fw_rule` is a valid COM object on this worker thread and all
        // BSTR values live for the duration of each property setter call.
        unsafe {
            fw_rule
                .SetName(&BSTR::from(native_name))
                .map_err(|e| map_com_mutation_err(&e, "SetName", rule.logical_key()))?;
            let label = rule.label().unwrap_or("firew-rs managed rule");
            let description = if rule.address_set_mode() == AddressSetMode::Set {
                format!("{marker} {SET_MODE_TOKEN} {label}")
            } else {
                format!("{marker} {label}")
            };
            fw_rule
                .SetDescription(&BSTR::from(description.as_str()))
                .map_err(|e| map_com_mutation_err(&e, "SetDescription", rule.logical_key()))?;
            fw_rule
                .SetEnabled(VARIANT_TRUE)
                .map_err(|e| map_com_mutation_err(&e, "SetEnabled", rule.logical_key()))?;
            fw_rule
                .SetAction(map_action(rule.action()))
                .map_err(|e| map_com_mutation_err(&e, "SetAction", rule.logical_key()))?;
            fw_rule
                .SetDirection(map_direction(direction))
                .map_err(|e| map_com_mutation_err(&e, "SetDirection", rule.logical_key()))?;
            fw_rule
                .SetProfiles(NET_FW_PROFILE2_ALL.0)
                .map_err(|e| map_com_mutation_err(&e, "SetProfiles", rule.logical_key()))?;

            // Clear port matchers before changing protocol so switching from TCP/UDP
            // to a portless protocol (such as Any or ICMP) in place never fails COM validation.
            if rule.remote_ports().is_empty() {
                let _ = fw_rule.SetRemotePorts(&BSTR::from("*"));
            }
            if rule.local_ports().is_empty() {
                let _ = fw_rule.SetLocalPorts(&BSTR::from("*"));
            }

            fw_rule
                .SetProtocol(map_protocol(rule.protocol()))
                .map_err(|e| map_com_mutation_err(&e, "SetProtocol", rule.logical_key()))?;
            fw_rule
                .SetGrouping(&BSTR::from(native_group))
                .map_err(|e| map_com_mutation_err(&e, "SetGrouping", rule.logical_key()))?;

            let remote_addrs = if rule.remote_addresses().is_empty() {
                "*".to_owned()
            } else {
                join_display(rule.remote_addresses())
            };
            fw_rule
                .SetRemoteAddresses(&BSTR::from(remote_addrs.as_str()))
                .map_err(|e| map_com_mutation_err(&e, "SetRemoteAddresses", rule.logical_key()))?;

            let local_addrs = if rule.local_addresses().is_empty() {
                "*".to_owned()
            } else {
                join_display(rule.local_addresses())
            };
            fw_rule
                .SetLocalAddresses(&BSTR::from(local_addrs.as_str()))
                .map_err(|e| map_com_mutation_err(&e, "SetLocalAddresses", rule.logical_key()))?;

            if !rule.remote_ports().is_empty() {
                fw_rule
                    .SetRemotePorts(&BSTR::from(join_ports(rule.remote_ports())))
                    .map_err(|e| map_com_mutation_err(&e, "SetRemotePorts", rule.logical_key()))?;
            }

            if !rule.local_ports().is_empty() {
                fw_rule
                    .SetLocalPorts(&BSTR::from(join_ports(rule.local_ports())))
                    .map_err(|e| map_com_mutation_err(&e, "SetLocalPorts", rule.logical_key()))?;
            }

            let app_str = rule
                .application_path()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            fw_rule
                .SetApplicationName(&BSTR::from(app_str.as_str()))
                .map_err(|e| map_com_mutation_err(&e, "SetApplicationName", rule.logical_key()))?;

            if let Some(package_sid) = rule.package_sid() {
                let fw_rule3: INetFwRule3 = fw_rule.cast().map_err(|source| {
                    Error::new(
                        ErrorKind::UnsupportedMatcher,
                        "INetFwRule3 is unavailable for the package SID matcher",
                    )
                    .with_logical_key(rule.logical_key())
                    .with_source(source)
                })?;
                fw_rule3
                    .SetLocalAppPackageId(&BSTR::from(package_sid))
                    .map_err(|source| {
                        Error::new(ErrorKind::InvalidRule, "INetFw rejected the package SID")
                            .with_logical_key(rule.logical_key())
                            .with_source(source)
                    })?;
            } else if let Ok(fw_rule3) = fw_rule.cast::<INetFwRule3>() {
                let _ = fw_rule3.SetLocalAppPackageId(&BSTR::new());
            }

            Ok(())
        }
    }
}

fn map_action(action: Action) -> windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION {
    match action {
        Action::Allow => NET_FW_ACTION_ALLOW,
        Action::Block | Action::Reject => NET_FW_ACTION_BLOCK,
    }
}

fn map_direction(
    direction: Direction,
) -> windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIRECTION {
    match direction {
        Direction::Inbound => NET_FW_RULE_DIR_IN,
        Direction::Outbound => NET_FW_RULE_DIR_OUT,
        Direction::Both => unreachable!("both directions are split before COM conversion"),
    }
}

/// IANA protocol number, or `NET_FW_IP_PROTOCOL_ANY` for any protocol.
fn map_protocol(protocol: Protocol) -> i32 {
    protocol
        .number()
        .map_or(NET_FW_IP_PROTOCOL_ANY.0, i32::from)
}

fn join_display<T: std::fmt::Display>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn join_ports(ports: &[firew_core::PortRange]) -> String {
    ports
        .iter()
        .map(|port| {
            if port.is_single() {
                port.start().to_string()
            } else {
                format!("{}-{}", port.start(), port.end())
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}
