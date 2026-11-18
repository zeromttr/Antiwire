-- `windivert_enabled`: whether the daemon may use WinDivert, a third-party
-- Windows kernel driver, for connect-time flow owners and the port 53 divert.
-- It is off unless the user turns it on: anti-cheat software can treat the
-- driver as an integrity violation. While it is off the driver is neither
-- downloaded nor loaded. Windows only; ignored elsewhere.
ALTER TABLE daemon_settings ADD COLUMN windivert_enabled INTEGER NOT NULL DEFAULT 0;
