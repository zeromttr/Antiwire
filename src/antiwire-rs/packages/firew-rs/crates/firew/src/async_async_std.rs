//! async-std-native asynchronous facade.

use crate::async_facade::async_facade;

async_facade! {
    /// Firewall owner whose blocking native work runs on async-std's blocking pool.
    pub struct AsyncStdFirewall;
    runtime = "async-std",
    into = into_async_std,
    run = async_std::task::spawn_blocking,
}
