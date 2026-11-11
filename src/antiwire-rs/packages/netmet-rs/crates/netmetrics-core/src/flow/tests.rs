use super::*;
use crate::{ByteDelta, CookieSource, ProcessIdentity, Protocol, SocketCookie};
use std::net::{IpAddr, Ipv4Addr};

mod accounting;
mod attribution;
mod cookies;
mod interface;

fn key(port: u16) -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: port,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 443,
    }
}

fn cookie(value: u64) -> SocketCookie {
    SocketCookie {
        value,
        source: CookieSource::LinuxSockCookie,
    }
}
