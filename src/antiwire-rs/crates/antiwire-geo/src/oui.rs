#[cfg(feature = "embedded-oui")]
use std::collections::HashMap;
#[cfg(feature = "embedded-oui")]
use std::io::Read;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OuiError {
    #[error("failed to load embedded OUI database: {0}")]
    Load(String),
    #[error("embedded OUI support not enabled (build with `embedded-oui` feature)")]
    Disabled,
}

/// MAC vendor resolution from an embedded IEEE OUI database when enabled.
#[derive(Clone, Debug)]
pub struct OuiResolver {
    #[cfg(feature = "embedded-oui")]
    vendors: HashMap<[u8; 3], String>,
}

impl OuiResolver {
    /// Loads the vendor table built into the binary.
    ///
    /// # Errors
    ///
    /// [`OuiError::Disabled`] without the `embedded-oui` feature, and [`OuiError::Load`]
    /// when the table cannot be decompressed.
    pub fn from_embedded() -> Result<Self, OuiError> {
        #[cfg(feature = "embedded-oui")]
        {
            const OUI_DATA_GZ: &[u8] = include_bytes!("../assets/oui.gz");

            let mut decoder = flate2::read::GzDecoder::new(OUI_DATA_GZ);
            let mut oui_text = String::new();
            decoder
                .read_to_string(&mut oui_text)
                .map_err(|e| OuiError::Load(e.to_string()))?;

            let vendors = parse_oui_text(&oui_text);

            if vendors.is_empty() {
                return Err(OuiError::Load(
                    "no OUI entries found in embedded data".to_owned(),
                ));
            }

            Ok(Self { vendors })
        }

        #[cfg(not(feature = "embedded-oui"))]
        {
            Err(OuiError::Disabled)
        }
    }

    pub fn vendor(&self, mac: &str) -> Option<&str> {
        #[cfg(feature = "embedded-oui")]
        {
            let prefix = parse_mac_prefix(mac)?;
            // Locally administered addresses are randomized or assigned by the
            // local administrator, so their first three bytes are not an IEEE
            // manufacturer identity even if they happen to match one.
            if prefix[0] & 0x02 != 0 {
                return None;
            }
            self.vendors.get(&prefix).map(String::as_str)
        }

        #[cfg(not(feature = "embedded-oui"))]
        {
            let _ = mac;
            None
        }
    }
}

#[cfg(feature = "embedded-oui")]
fn parse_oui_text(oui_text: &str) -> HashMap<[u8; 3], String> {
    let mut vendors = HashMap::new();
    for line in oui_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let Some((prefix_str, vendor)) = line.split_once('\t') else {
            continue;
        };
        if prefix_str.len() != 6 {
            continue;
        }

        let Ok(bytes) = (0..3)
            .map(|index| u8::from_str_radix(&prefix_str[index * 2..index * 2 + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
        else {
            continue;
        };
        vendors
            .entry([bytes[0], bytes[1], bytes[2]])
            .or_insert_with(|| vendor.to_owned());
    }
    vendors
}

#[cfg(feature = "embedded-oui")]
fn parse_mac_prefix(mac: &str) -> Option<[u8; 3]> {
    let mac = mac.trim();

    let parts: Vec<&str> = if mac.contains(':') {
        mac.split(':').collect()
    } else if mac.contains('-') {
        mac.split('-').collect()
    } else if mac.len() >= 6 {
        let a = u8::from_str_radix(&mac[0..2], 16).ok()?;
        let b = u8::from_str_radix(&mac[2..4], 16).ok()?;
        let c = u8::from_str_radix(&mac[4..6], 16).ok()?;
        return Some([a, b, c]);
    } else {
        return None;
    };

    if parts.len() < 3 {
        return None;
    }

    let a = u8::from_str_radix(parts[0], 16).ok()?;
    let b = u8::from_str_radix(parts[1], 16).ok()?;
    let c = u8::from_str_radix(parts[2], 16).ok()?;
    Some([a, b, c])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "embedded-oui")]
    #[test]
    fn embedded_oui_resolves_known_prefix() {
        let resolver = OuiResolver::from_embedded().expect("oui db");
        let vendor = resolver.vendor("00:1B:63:AA:BB:CC");
        assert!(vendor.is_some());
    }

    #[cfg(feature = "embedded-oui")]
    #[test]
    fn oui_parser_and_common_mac_formats_resolve_exact_vendor() {
        let resolver = OuiResolver {
            vendors: parse_oui_text("001B63\tApple, Inc.\ninvalid\n"),
        };

        assert_eq!(resolver.vendor("00:1b:63:aa:bb:cc"), Some("Apple, Inc."));
        assert_eq!(resolver.vendor("00-1B-63-AA-BB-CC"), Some("Apple, Inc."));
        assert_eq!(resolver.vendor("001B63AABBCC"), Some("Apple, Inc."));
        assert_eq!(resolver.vendor("not-a-mac"), None);
    }

    #[cfg(feature = "embedded-oui")]
    #[test]
    fn randomized_mac_does_not_claim_an_ieee_vendor() {
        let resolver = OuiResolver {
            vendors: parse_oui_text("021B63\tWrong Vendor\n"),
        };
        assert_eq!(resolver.vendor("02:1B:63:AA:BB:CC"), None);
    }

    #[cfg(not(feature = "embedded-oui"))]
    #[test]
    fn disabled_feature_returns_error() {
        assert!(OuiResolver::from_embedded().is_err());
    }
}
