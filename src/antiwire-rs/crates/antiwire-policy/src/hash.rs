/// FNV-1a / DJB2 domain hashing (right-to-left), matching the C# blocklist engine.
pub(crate) fn reverse_hash_pair(domain: &str) -> u64 {
    let mut h1 = 2_166_136_261_u32;
    let mut h2 = 5_381_u32;

    for byte in domain.as_bytes().iter().rev() {
        let c = if byte.is_ascii_uppercase() {
            byte.to_ascii_lowercase()
        } else {
            *byte
        };
        h1 = h1.wrapping_mul(16_777_619) ^ u32::from(c);
        h2 = h2
            .wrapping_shl(5)
            .wrapping_add(h2)
            .wrapping_add(u32::from(c));
    }

    (u64::from(h1) << 32) | u64::from(h2)
}

/// Incremental suffix hash at a label boundary while scanning right-to-left.
pub(crate) fn suffix_hash_at_boundary(h1: u32, h2: u32) -> u64 {
    (u64::from(h1) << 32) | u64::from(h2)
}

/// Lowercase ASCII domain into `out`, returning the slice of written bytes.
pub(crate) fn ascii_lower_into<'a>(domain: &str, out: &'a mut [u8; 256]) -> Option<&'a str> {
    if domain.len() > out.len() {
        return None;
    }
    for (idx, byte) in domain.as_bytes().iter().enumerate() {
        out[idx] = if byte.is_ascii_uppercase() {
            byte.to_ascii_lowercase()
        } else {
            *byte
        };
    }
    std::str::from_utf8(&out[..domain.len()]).ok()
}

#[cfg(test)]
mod tests {
    use super::reverse_hash_pair;

    #[test]
    fn reverse_hash_pair_is_case_insensitive() {
        assert_eq!(
            reverse_hash_pair("TRACKER.CO.UK"),
            reverse_hash_pair("tracker.co.uk")
        );
    }
}
