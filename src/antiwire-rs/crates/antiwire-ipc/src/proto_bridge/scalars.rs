//! Checked and saturating integer conversions for proto fields.

pub(super) fn clamp_confidence(value: i32) -> i32 {
    antiwire_store::clamp_ai_confidence(value)
}

pub(super) fn u32_to_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// A row id from a request. Ids on the wire are unsigned and rows are
/// signed, so one past `i32::MAX` names no row and is refused, not clamped.
pub(super) fn id_from_proto(id: u32) -> Result<i32, String> {
    i32::try_from(id).map_err(|_| format!("id {id} is out of range"))
}

/// A row id for a reply. Database ids are positive; one that is not would be
/// a store bug, and is sent as 0, which no request accepts as an id.
pub(super) fn id_to_proto(id: i32) -> u32 {
    debug_assert!(id > 0, "row ids are positive, got {id}");
    u32::try_from(id).unwrap_or(0)
}

pub(super) fn i32_to_u32(value: i32) -> u32 {
    u32::try_from(value.max(0)).unwrap_or(0)
}

pub(super) fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value.max(0)).unwrap_or(0)
}
