-- `windivert_enabled`: whether the daemon may use WinDivert, a third-party
-- Windows kernel driver, for connect-time flow owners and the port 53 divert.
-- It is off unless the user turns it on: anti-cheat software can treat the
-- driver as an integrity violation. While it is off the driver is neither
-- downloaded nor loaded. Windows only; ignored elsewhere.
ALTER TABLE daemon_settings ADD COLUMN windivert_enabled INTEGER NOT NULL DEFAULT 0;

-- `dns_bypass_blocking_enabled`: on Windows without WinDivert, whether DNS that an
-- application sends past the resolver, straight to a server of its own choosing, is
-- blocked. Windows cannot redirect it without a kernel driver, and a block can leave
-- such an application without name resolution, so it is off unless the user turns
-- it on. Other platforms redirect that DNS and do not read this.
ALTER TABLE daemon_settings ADD COLUMN dns_bypass_blocking_enabled INTEGER NOT NULL DEFAULT 0;
