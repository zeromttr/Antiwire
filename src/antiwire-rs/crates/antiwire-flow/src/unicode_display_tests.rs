use std::path::Path;
use std::time::{Duration, Instant};

use antiwire_events::AlertKind;

use crate::test_support;

fn assert_neutralized(text: &str, raw_name: &str) {
    assert!(
        text.contains(r"\u{202E}"),
        "bidi override should be visibly escaped: {text:?}"
    );
    assert!(
        text.contains(r"\u{200B}"),
        "zero-width character should be visibly escaped: {text:?}"
    );
    assert!(!text.contains('\u{202E}'));
    assert!(!text.contains('\u{200B}'));
    assert!(
        !text.contains(raw_name),
        "raw executable name must not cross a display boundary: {text:?}"
    );
}

async fn wait_for_siem(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if contents.contains(r"\\u{202E}") && contents.contains(r"\\u{200B}") {
                return contents;
            }
        }
        assert!(Instant::now() < deadline, "SIEM event was never written");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn unicode_executable_identity_stays_raw_while_displays_are_neutralized() {
    let fixture = test_support::fixture();
    let raw_name = "report\u{202E}\u{200B}.exe".to_owned();
    let executable = fixture.dir.path().join(&raw_name);
    std::fs::write(&executable, b"MZ").expect("create temporary executable-named file");
    assert!(
        executable.is_file(),
        "temporary executable path must remain reachable"
    );
    assert_eq!(
        std::fs::read(&executable).expect("read temporary executable"),
        b"MZ"
    );
    let raw_path = executable
        .to_str()
        .expect("temporary path should be valid UTF-8")
        .to_owned();

    let mut notifications = fixture.publisher.subscribe();
    let app_id = fixture.resolver.get_or_create_app_id(&raw_path, &raw_name);
    assert!(app_id > 0);

    let application = fixture
        .store
        .list_applications()
        .expect("list applications")
        .into_iter()
        .find(|application| application.id == app_id)
        .expect("raw executable application row");
    assert_eq!(application.app_path, raw_path);
    assert_eq!(application.app_name, raw_name);
    assert!(Path::new(&application.app_path).is_file());

    let streamed = notifications
        .recv()
        .await
        .expect("new application notification");
    assert_eq!(streamed.kind, AlertKind::NewApplication);
    assert_neutralized(&streamed.message, &raw_name);

    let alert = fixture
        .store
        .list_alerts()
        .expect("list persisted alerts")
        .into_iter()
        .find(|alert| alert.alert_type == "NEW_APP")
        .expect("persisted new-application alert");
    assert_neutralized(&alert.message, &raw_name);

    let siem = wait_for_siem(&fixture.dir.path().join("siem.json")).await;
    assert_neutralized(&siem, &raw_name);
}
