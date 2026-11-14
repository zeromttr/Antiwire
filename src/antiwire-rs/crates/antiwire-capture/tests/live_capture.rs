use antiwire_capture::{
    AppFilter, AppFlowSource, CaptureOptions, CaptureSession, CaptureStatus, FlowTuple, Transport,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires an installed packet-capture provider and elevated capture permissions"]
fn opens_interface_and_produces_a_valid_pcap() {
    let session = CaptureSession::new();
    let device = session
        .discover_devices()
        .into_iter()
        .next()
        .expect("no Npcap/libpcap capture interface is available");

    session
        .start(CaptureOptions {
            device_name: device.name,
            capture_filter: String::new(),
            snap_length: 96,
            promiscuous: false,
            read_timeout_ms: 100,
            max_seconds: 1,
            max_bytes: 1024 * 1024,
            app_filter: None,
        })
        .and_then(antiwire_capture::CaptureStartup::wait)
        .expect("capture should start");

    let deadline = Instant::now() + Duration::from_secs(5);
    while session.status().is_active() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(session.status(), CaptureStatus::Stopped);

    let mut pcap = Vec::new();
    session
        .capture_reader()
        .expect("completed capture should be readable")
        .read_to_end(&mut pcap)
        .expect("capture file should be readable");
    assert!(pcap.len() >= 24);
    assert_eq!(&pcap[..4], &0xa1b2_c3d4_u32.to_le_bytes());
}

/// Flows reported by hand, standing in for the daemon's connection tracker.
#[derive(Default)]
struct ReportedFlows(parking_lot::Mutex<Vec<FlowTuple>>);

impl AppFlowSource for ReportedFlows {
    fn flows(&self) -> Option<Vec<FlowTuple>> {
        Some(self.0.lock().clone())
    }
}

/// Exchanges a few bytes over `stream` and its accepted peer.
fn exchange(stream: &mut TcpStream, peer: &mut TcpStream) {
    let mut buffer = [0_u8; 5];
    stream.write_all(b"hello").expect("write");
    peer.read_exact(&mut buffer).expect("read");
    peer.write_all(b"world").expect("write back");
    stream.read_exact(&mut buffer).expect("read back");
}

#[test]
#[ignore = "requires an installed packet-capture provider, a loopback capture interface, and elevated capture permissions"]
fn an_application_capture_keeps_only_that_applications_loopback_flow() {
    let session = CaptureSession::new();
    let device = session
        .discover_devices()
        .into_iter()
        .find(|device| device.loopback)
        .expect("no loopback capture interface is available");

    let reported = Arc::new(ReportedFlows::default());
    session
        .start(CaptureOptions {
            device_name: device.name,
            capture_filter: "tcp".to_owned(),
            snap_length: 256,
            promiscuous: false,
            read_timeout_ms: 50,
            max_seconds: 0,
            max_bytes: 4 * 1024 * 1024,
            app_filter: Some(AppFilter {
                app_name: "test-app".to_owned(),
                source: Arc::clone(&reported) as Arc<dyn AppFlowSource>,
                hold: Duration::from_secs(1),
                refresh: Duration::from_millis(50),
                hold_budget_bytes: 1024 * 1024,
            }),
        })
        .and_then(antiwire_capture::CaptureStartup::wait)
        .expect("capture should start");

    let app_listener = TcpListener::bind("127.0.0.1:0").expect("bind app listener");
    let other_listener = TcpListener::bind("127.0.0.1:0").expect("bind other listener");
    let mut app = TcpStream::connect(app_listener.local_addr().unwrap()).expect("connect app");
    let (mut app_peer, _) = app_listener.accept().expect("accept app");
    let mut other = TcpStream::connect(other_listener.local_addr().unwrap()).expect("connect");
    let (mut other_peer, _) = other_listener.accept().expect("accept other");
    exchange(&mut app, &mut app_peer);
    exchange(&mut other, &mut other_peer);

    // The tracker learns of a flow after its handshake; the hold covers that.
    thread::sleep(Duration::from_millis(300));
    reported.0.lock().push(FlowTuple {
        transport: Transport::Tcp,
        local: app.local_addr().unwrap(),
        remote: app.peer_addr().unwrap(),
    });
    exchange(&mut app, &mut app_peer);
    exchange(&mut other, &mut other_peer);
    // Past the hold, so the handshake was settled while capturing, not at stop.
    thread::sleep(Duration::from_millis(1_500));
    session.stop().expect("stop");

    let deadline = Instant::now() + Duration::from_secs(5);
    while session.status().is_active() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(session.status(), CaptureStatus::Stopped);

    let app_ports = [
        u32::from(app.local_addr().unwrap().port()),
        u32::from(app.peer_addr().unwrap().port()),
    ];
    let frames = session.frame_reader().take_frames().unwrap_or_default();
    let snapshot = session.snapshot();
    println!(
        "kept {} frames, filtered {} packets",
        frames.len(),
        snapshot.filtered_packets
    );
    assert!(
        frames.iter().all(|frame| {
            app_ports.contains(&frame.source_port) && app_ports.contains(&frame.destination_port)
        }),
        "only the application's flow is kept"
    );
    assert!(
        frames.iter().any(|frame| frame.info.contains("SYN")),
        "the handshake captured before the flow was reported is kept"
    );
    assert!(frames.len() >= 6, "kept {} frames", frames.len());
    assert!(snapshot.filtered_packets > 0, "the other flow is filtered");
    assert_eq!(snapshot.app_name, "test-app");
}
