//! smol-native asynchronous facade.

use crate::async_facade::async_facade;

async_facade! {
    /// Firewall owner whose blocking native work runs on smol's blocking executor.
    pub struct SmolFirewall;
    runtime = "smol",
    into = into_smol,
    run = smol::unblock,
}
