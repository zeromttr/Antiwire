//! Moves an application's rules to its new executable when the flow layer
//! sees it move to a new version.

use std::sync::Arc;

use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use antiwire_flow::AppRuleRetargeter;
use antiwire_services::RuleService;
use tracing::{info, warn};

/// Version moves waiting for the retarget worker. A move that does not fit is
/// dropped with a warning; the next move of the same application catches its
/// rules again by family.
const RETARGET_QUEUE_CAPACITY: usize = 256;

/// Re-points rules through the rule service when the flow layer sees a move.
///
/// Work happens on a thread of its own, one move at a time and in the order
/// they were seen: checking signatures reads both executables from disk, and
/// the flow layer reports moves from its hot path.
pub(crate) struct RuleRetargeter {
    moves: std::sync::mpsc::SyncSender<(String, String)>,
}

impl RuleRetargeter {
    pub(crate) fn spawn(service: Arc<RuleService>, alerts: AlertPublisher) -> Self {
        let (moves, pending) =
            std::sync::mpsc::sync_channel::<(String, String)>(RETARGET_QUEUE_CAPACITY);
        let spawned = std::thread::Builder::new()
            .name("antiwire-retarget".to_owned())
            .spawn(move || {
                for (previous_path, new_path) in pending {
                    retarget_after_move(&service, &alerts, &previous_path, &new_path);
                }
            });
        if let Err(error) = spawned {
            warn!(%error, "could not start the rule retarget worker; rules will not follow version moves");
        }
        Self { moves }
    }
}

impl AppRuleRetargeter for RuleRetargeter {
    fn retarget_app_rules(&self, previous_path: &str, new_path: &str) {
        if self
            .moves
            .try_send((previous_path.to_owned(), new_path.to_owned()))
            .is_err()
        {
            warn!(
                previous_path,
                new_path, "rule retarget worker unavailable; this version move was not applied"
            );
        }
    }
}

/// Moves an application's rules after a version move, telling the user when
/// allow rules stay behind because the new executable's publisher is unverified.
fn retarget_after_move(
    service: &RuleService,
    alerts: &AlertPublisher,
    previous_path: &str,
    new_path: &str,
) {
    let same_publisher = antiwire_platform::code_signing::same_verified_publisher(
        std::path::Path::new(previous_path),
        std::path::Path::new(new_path),
    );
    let outcome = match service.retarget_app_rules(previous_path, new_path, same_publisher) {
        Ok(outcome) => outcome,
        Err(error) => {
            warn!(
                %error,
                previous_path,
                new_path,
                "failed to re-point application rules after a version move"
            );
            return;
        }
    };
    if outcome.moved > 0 {
        info!(
            count = outcome.moved,
            same_publisher,
            previous_path,
            new_path,
            "re-pointed application rules after a version move"
        );
    }
    if outcome.held_allows > 0 {
        warn!(
            count = outcome.held_allows,
            previous_path,
            new_path,
            "allow rules not moved: the new executable's publisher could not be verified"
        );
        alerts.publish(Alert::new(
            AlertKind::ApplicationRulesNotMoved,
            Severity::Warning,
            "Allow Rules Not Applied to a New Version",
            format!(
                "'{new_path}' could not be verified as signed by the same publisher as \
                 '{previous_path}', so its allow rules were not moved to it. Review the \
                 application's rules if you trust the new version."
            ),
        ));
    }
}
