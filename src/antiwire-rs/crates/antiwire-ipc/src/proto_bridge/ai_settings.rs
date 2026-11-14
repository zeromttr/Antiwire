//! AI decision settings: the confidence floor and per-category actions.

use antiwire_proto::SettingsRequest;
use antiwire_store::DaemonSetting;

/// Whether the request carries confidence scores to apply.
///
/// A legacy client omits the scores, which decode as zero. It also omits the
/// decision mode, which the current client always sends, so a request without
/// a recognized mode leaves the stored scores unchanged. Scores that are
/// applied are raised to the floor of 60.
pub(super) fn request_specifies_ai_confidence(request: &SettingsRequest) -> bool {
    matches!(
        request.ai_decision_mode.as_str(),
        "proactive" | "retroactive"
    )
}

/// Coerces an action string to `block` or `record`, defaulting to `record`.
pub(super) fn ai_action_or_default(value: &str) -> String {
    if value == "block" {
        "block".to_owned()
    } else {
        "record".to_owned()
    }
}

/// A recognized action is the signal that the client owns that category's
/// controls. A legacy client sends empty action strings, so an old save cannot
/// silently disable categories or wipe their actions.
pub(super) fn is_ai_action(value: &str) -> bool {
    matches!(value, "block" | "record")
}

/// Applies the per-category controls a client actually sent. Each category is
/// gated on its own action, so a legacy or partial client cannot disable
/// categories it does not know about.
pub(super) fn apply_ai_decision_types(settings: &mut DaemonSetting, request: &SettingsRequest) {
    if is_ai_action(&request.ai_advertising_action) {
        settings.ai_advertising_enabled = request.ai_advertising_enabled;
        settings.ai_advertising_action = ai_action_or_default(&request.ai_advertising_action);
    }
    if is_ai_action(&request.ai_tracking_action) {
        settings.ai_tracking_enabled = request.ai_tracking_enabled;
        settings.ai_tracking_action = ai_action_or_default(&request.ai_tracking_action);
    }
    if is_ai_action(&request.ai_telemetry_action) {
        settings.ai_telemetry_enabled = request.ai_telemetry_enabled;
        settings.ai_telemetry_action = ai_action_or_default(&request.ai_telemetry_action);
    }
    if is_ai_action(&request.ai_analytics_action) {
        settings.ai_analytics_enabled = request.ai_analytics_enabled;
        settings.ai_analytics_action = ai_action_or_default(&request.ai_analytics_action);
    }
    if is_ai_action(&request.ai_malicious_action) {
        settings.ai_malicious_enabled = request.ai_malicious_enabled;
        settings.ai_malicious_action = ai_action_or_default(&request.ai_malicious_action);
    }
    if is_ai_action(&request.ai_fraud_action) {
        settings.ai_fraud_enabled = request.ai_fraud_enabled;
        settings.ai_fraud_action = ai_action_or_default(&request.ai_fraud_action);
    }
    if is_ai_action(&request.ai_cryptomining_action) {
        settings.ai_cryptomining_enabled = request.ai_cryptomining_enabled;
        settings.ai_cryptomining_action = ai_action_or_default(&request.ai_cryptomining_action);
    }
    if is_ai_action(&request.ai_tunnel_action) {
        settings.ai_tunnel_enabled = request.ai_tunnel_enabled;
        settings.ai_tunnel_action = ai_action_or_default(&request.ai_tunnel_action);
    }
}
