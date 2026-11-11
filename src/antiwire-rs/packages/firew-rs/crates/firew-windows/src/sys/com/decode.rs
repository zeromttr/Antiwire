//! Reading `INetFw` rule objects back into logical rules.

use std::net::IpAddr;

use firew_core::{Action, Direction, Error, ErrorKind, PortRange, Protocol, Rule, RuleKey};
use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwRule, INetFwRule3, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY,
    NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};

use super::{com_enumeration_error, description_has_set_token, needs_set_mode};

pub(super) fn decode_rule(
    native: &INetFwRule,
    description: &str,
    key: &RuleKey,
) -> Result<Rule, Error> {
    // SAFETY: `native` came from this worker's COM enumerator and all returned
    // values are copied into owned Rust values before this function returns.
    unsafe {
        reject_external_restrictions(native, key)?;
        let (direction, action, protocol) = decode_verdict(native, key)?;
        let remote_addresses = parse_addresses(&bstr_text(native.RemoteAddresses())?, key)?;
        let local_addresses = parse_addresses(&bstr_text(native.LocalAddresses())?, key)?;
        let remote_ports = parse_ports(&bstr_text(native.RemotePorts())?, key)?;
        let local_ports = parse_ports(&bstr_text(native.LocalPorts())?, key)?;

        let mut builder = Rule::builder(key.as_str(), action, direction).protocol(protocol);
        // Select set mode when the rule was written with `[set]` or when its
        // single-direction or bidirectional Cartesian product would exceed caps.
        let use_set = needs_set_mode(
            description_has_set_token(description),
            Direction::Both,
            remote_addresses.len(),
            local_addresses.len(),
            remote_ports.len(),
            local_ports.len(),
        );
        if use_set {
            builder = builder.remote_address_set(remote_addresses);
        } else {
            for address in remote_addresses {
                builder = builder.remote_address(address);
            }
        }
        for address in local_addresses {
            builder = builder.local_address(address);
        }
        for port in remote_ports {
            builder = builder.remote_port(port);
        }
        for port in local_ports {
            builder = builder.local_port(port);
        }

        let application = bstr_text(native.ApplicationName())?;
        if !application.is_empty() {
            builder = builder.application_path(application);
        }
        if let Ok(rule3) = native.cast::<INetFwRule3>() {
            let package = bstr_text(rule3.LocalAppPackageId())?;
            if !package.is_empty() {
                builder = builder.package_sid(package);
            }
        }
        builder.build().map_err(|error| {
            Error::new(
                ErrorKind::CorruptNativeState,
                format!("invalid managed INetFw rule: {error}"),
            )
            .with_logical_key(key)
        })
    }
}

/// A COM string property, copied out.
fn bstr_text(value: windows_core::Result<BSTR>) -> Result<String, Error> {
    Ok(value.map_err(com_enumeration_error)?.to_string())
}

/// Refuses a rule that is disabled, or restricted by a setting the portable
/// rule cannot express: it would not match the traffic the rule describes.
fn reject_external_restrictions(native: &INetFwRule, key: &RuleKey) -> Result<(), Error> {
    // SAFETY: `native` came from this worker's COM enumerator and is used only
    // on this thread; every value read is copied out before returning.
    unsafe {
        if native.Enabled().map_err(com_enumeration_error)? != VARIANT_TRUE {
            return corrupt(key, "INetFw rule is disabled");
        }
        // Managed rows apply on every network profile. One limited to some
        // profiles stops matching when the active network changes.
        if native.Profiles().map_err(com_enumeration_error)? & NET_FW_PROFILE2_ALL.0
            != NET_FW_PROFILE2_ALL.0
        {
            return corrupt(key, "INetFw rule has an external profile restriction");
        }
        if !bstr_text(native.ServiceName())?.is_empty() {
            return corrupt(key, "INetFw rule has an external service restriction");
        }
        let interface_types = bstr_text(native.InterfaceTypes())?;
        if !interface_types.is_empty() && !interface_types.eq_ignore_ascii_case("All") {
            return corrupt(
                key,
                "INetFw rule has an external interface-type restriction",
            );
        }
        Ok(())
    }
}

/// Reads the rule's direction, action, and protocol.
fn decode_verdict(
    native: &INetFwRule,
    key: &RuleKey,
) -> Result<(Direction, Action, Protocol), Error> {
    // SAFETY: `native` came from this worker's COM enumerator and is used only
    // on this thread; every value read is copied out before returning.
    unsafe {
        let direction = match native.Direction().map_err(com_enumeration_error)? {
            value if value == NET_FW_RULE_DIR_IN => Direction::Inbound,
            value if value == NET_FW_RULE_DIR_OUT => Direction::Outbound,
            _ => return corrupt(key, "INetFw rule has an invalid direction"),
        };
        let action = match native.Action().map_err(com_enumeration_error)? {
            value if value == NET_FW_ACTION_ALLOW => Action::Allow,
            value if value == NET_FW_ACTION_BLOCK => Action::Block,
            _ => return corrupt(key, "INetFw rule has an invalid action"),
        };
        let protocol = match native.Protocol().map_err(com_enumeration_error)? {
            value if value == NET_FW_IP_PROTOCOL_ANY.0 => Protocol::Any,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::IcmpV4,
            58 => Protocol::IcmpV6,
            value => match u8::try_from(value) {
                Ok(number) if number != 0 => Protocol::Other(number).canonicalize(),
                _ => return corrupt(key, "INetFw rule has an invalid protocol"),
            },
        };
        Ok((direction, action, protocol))
    }
}

fn parse_addresses(value: &str, key: &RuleKey) -> Result<Vec<ipnet::IpNet>, Error> {
    if value.is_empty() || value == "*" {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|item| parse_address(item.trim(), key))
        .collect()
}

pub(super) fn parse_address(value: &str, key: &RuleKey) -> Result<ipnet::IpNet, Error> {
    if let Ok(network) = value.parse::<ipnet::IpNet>() {
        return Ok(network.trunc());
    }
    if let Ok(addr) = value.parse::<IpAddr>() {
        return Ok(ipnet::IpNet::from(addr));
    }

    let (address, mask) = value.split_once('/').ok_or_else(|| {
        invalid_native_address(key, value, "address has no prefix or subnet mask")
    })?;
    let address = address.parse::<IpAddr>().map_err(|source| {
        invalid_native_address(key, value, "invalid IP address").with_source(source)
    })?;
    let mask = mask.parse::<IpAddr>().map_err(|source| {
        invalid_native_address(key, value, "invalid subnet mask").with_source(source)
    })?;
    let prefix = match (address, mask) {
        (IpAddr::V4(_), IpAddr::V4(mask)) => prefix_from_mask(u32::from(mask), 32),
        (IpAddr::V6(_), IpAddr::V6(mask)) => prefix_from_mask(u128::from(mask), 128),
        _ => None,
    }
    .ok_or_else(|| {
        invalid_native_address(
            key,
            value,
            "subnet mask is non-contiguous or from another address family",
        )
    })?;
    ipnet::IpNet::new(address, prefix)
        .map(|net| net.trunc())
        .map_err(|source| {
            invalid_native_address(key, value, "invalid address prefix").with_source(source)
        })
}

fn prefix_from_mask(mask: impl Into<u128>, width: u8) -> Option<u8> {
    let aligned = mask.into() << (128 - width);
    let prefix = u8::try_from(aligned.leading_ones()).ok()?;
    let expected = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (aligned == expected && prefix <= width).then_some(prefix)
}

fn invalid_native_address(key: &RuleKey, value: &str, detail: &str) -> Error {
    Error::new(
        ErrorKind::CorruptNativeState,
        format!("invalid INetFw address {value}: {detail}"),
    )
    .with_logical_key(key)
}

fn parse_ports(value: &str, key: &RuleKey) -> Result<Vec<PortRange>, Error> {
    if value.is_empty() || value == "*" {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|item| {
            let item = item.trim();
            let range = if let Some((start, end)) = item.split_once('-') {
                PortRange::range(parse_port(start, key)?, parse_port(end, key)?)
            } else {
                PortRange::single(parse_port(item, key)?)
            };
            range.map_err(|error| {
                Error::new(
                    ErrorKind::CorruptNativeState,
                    format!("invalid INetFw port matcher: {error}"),
                )
                .with_logical_key(key)
            })
        })
        .collect()
}

fn parse_port(value: &str, key: &RuleKey) -> Result<u16, Error> {
    value.parse().map_err(|source| {
        Error::new(
            ErrorKind::CorruptNativeState,
            format!("invalid INetFw port {value}"),
        )
        .with_logical_key(key)
        .with_source(source)
    })
}

fn corrupt<T>(key: &RuleKey, message: &str) -> Result<T, Error> {
    Err(Error::new(ErrorKind::CorruptNativeState, message).with_logical_key(key))
}
