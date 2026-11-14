//! Update status conversion to protobuf IPC types.

use antiwire_update::status::UpdateState;

pub(crate) fn update_status_to_proto(
    status: &antiwire_update::UpdateStatus,
) -> antiwire_proto::UpdateStatus {
    let state = match status.state {
        UpdateState::Unknown => antiwire_proto::update_status::State::UpdateStateUnknown,
        UpdateState::UpToDate => antiwire_proto::update_status::State::UpdateStateUpToDate,
        UpdateState::Available => antiwire_proto::update_status::State::UpdateStateAvailable,
        UpdateState::Installing => antiwire_proto::update_status::State::UpdateStateInstalling,
        UpdateState::Failed => antiwire_proto::update_status::State::UpdateStateFailed,
        UpdateState::Unsupported => antiwire_proto::update_status::State::UpdateStateUnsupported,
    };
    let (available_version, notes) = status
        .available
        .as_ref()
        .map(|release| (release.version.to_string(), release.notes.clone()))
        .unwrap_or_default();
    let last_checked_at = status
        .last_checked
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .unwrap_or_default();
    antiwire_proto::UpdateStatus {
        state: state as i32,
        current_version: status.current_version.to_string(),
        available_version,
        notes,
        detail: status.detail.clone(),
        channel: status.channel.name().to_owned(),
        last_checked_at,
        check_error: status.check_error.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_update::status::AvailableRelease;

    fn status(
        state: UpdateState,
        available: Option<AvailableRelease>,
    ) -> antiwire_update::UpdateStatus {
        antiwire_update::UpdateStatus {
            state,
            current_version: "0.2.0".parse().expect("version"),
            available,
            detail: "reason".to_owned(),
            channel: antiwire_update::Channel::Beta,
            last_checked: Some(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            ),
            check_error: "the beta feed could not be read".to_owned(),
        }
    }

    #[test]
    fn carries_the_channel_and_the_last_check() {
        let proto = update_status_to_proto(&status(UpdateState::UpToDate, None));
        assert_eq!(proto.channel, "beta");
        assert_eq!(proto.last_checked_at, 1_700_000_000);
        assert_eq!(proto.check_error, "the beta feed could not be read");

        let never = antiwire_update::UpdateStatus {
            last_checked: None,
            ..status(UpdateState::Unknown, None)
        };
        assert_eq!(update_status_to_proto(&never).last_checked_at, 0);
    }

    fn release() -> AvailableRelease {
        AvailableRelease {
            version: "0.3.0".parse().expect("version"),
            notes: "Faster DNS.".to_owned(),
        }
    }

    #[test]
    fn every_state_maps_to_its_proto_variant() {
        let cases = [
            (
                UpdateState::Unknown,
                antiwire_proto::update_status::State::UpdateStateUnknown,
            ),
            (
                UpdateState::UpToDate,
                antiwire_proto::update_status::State::UpdateStateUpToDate,
            ),
            (
                UpdateState::Available,
                antiwire_proto::update_status::State::UpdateStateAvailable,
            ),
            (
                UpdateState::Installing,
                antiwire_proto::update_status::State::UpdateStateInstalling,
            ),
            (
                UpdateState::Failed,
                antiwire_proto::update_status::State::UpdateStateFailed,
            ),
            (
                UpdateState::Unsupported,
                antiwire_proto::update_status::State::UpdateStateUnsupported,
            ),
        ];
        for (state, expected) in cases {
            let proto = update_status_to_proto(&status(state, None));
            assert_eq!(proto.state, expected as i32, "state {state:?}");
        }
    }

    #[test]
    fn available_release_is_copied_for_every_state() {
        for state in [
            UpdateState::Unknown,
            UpdateState::UpToDate,
            UpdateState::Available,
            UpdateState::Installing,
            UpdateState::Failed,
            UpdateState::Unsupported,
        ] {
            let proto = update_status_to_proto(&status(state, Some(release())));
            assert_eq!(proto.available_version, "0.3.0", "state {state:?}");
            assert_eq!(proto.notes, "Faster DNS.", "state {state:?}");
        }
    }

    #[test]
    fn no_available_release_leaves_version_and_notes_empty() {
        let proto = update_status_to_proto(&status(UpdateState::UpToDate, None));
        assert_eq!(proto.current_version, "0.2.0");
        assert_eq!(proto.available_version, "");
        assert_eq!(proto.notes, "");
        assert_eq!(proto.detail, "reason");
    }
}
