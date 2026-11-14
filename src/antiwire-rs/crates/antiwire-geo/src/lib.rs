//! `GeoIP` and MAC vendor (OUI) resolution.

mod geo;
mod oui;

pub use geo::{GeoError, GeoIpLookup, GeoResult};
pub use oui::OuiResolver;
