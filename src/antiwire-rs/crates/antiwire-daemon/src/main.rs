//! The `antiwire-daemon` executable. Everything it does is in the library.

fn main() -> anyhow::Result<()> {
    antiwire_daemon::run()
}
