//! Blocking waits on native event descriptors.

use std::os::fd::RawFd;
use std::time::{Duration, Instant};

/// Blocks until `fd` is readable or `deadline` arrives, waiting at most `max_wait`.
///
/// The wait is at least one millisecond, so a deadline already past still
/// yields briefly instead of spinning. A failed `poll` returns early; the
/// caller's next read reports whatever went wrong.
pub fn wait_readable(fd: RawFd, deadline: Instant, max_wait: Duration) {
    let wait = deadline
        .saturating_duration_since(Instant::now())
        .clamp(Duration::from_millis(1), max_wait);
    let timeout_ms = libc::c_int::try_from(wait.as_millis()).unwrap_or(libc::c_int::MAX);
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid `pollfd` for the duration of the call; the caller keeps
    // `fd` open until it returns.
    unsafe {
        libc::poll(&raw mut pollfd, 1, timeout_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_once_the_deadline_passes_on_an_idle_descriptor() {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors `pipe` writes.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let started = Instant::now();
        wait_readable(
            fds[0],
            started + Duration::from_millis(20),
            Duration::from_secs(1),
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        // SAFETY: both descriptors came from `pipe` above and are closed once.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
