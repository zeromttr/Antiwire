//! Exercise the real Hickory pool against a slow, multiplexed TCP server.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinSet;

use crate::upstream::{AdmissionClass, UpstreamAdmission};

/// Holds replies until released, while continuing to read requests. A serial
/// request/reply server would test head-of-line blocking instead of the client's
/// multiplexer capacity.
struct HeldTcp {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    received: Arc<AtomicUsize>,
    answering: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl HeldTcp {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TCP listener");
        let addr = listener.local_addr().expect("listen address");
        let connections = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(AtomicUsize::new(0));
        let (answering, answers) = watch::channel(true);
        let task = {
            let connections = Arc::clone(&connections);
            let received = Arc::clone(&received);
            tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.expect("accept");
                            stream.set_nodelay(true).expect("no delayed replies");
                            connections.fetch_add(1, Ordering::SeqCst);
                            let received = Arc::clone(&received);
                            let answers = answers.clone();
                            tasks.spawn(async move {
                                let (mut reader, writer) = stream.into_split();
                                let writer = Arc::new(Mutex::new(writer));
                                let mut replies = JoinSet::new();
                                while let Ok(len) = reader.read_u16().await {
                                    let mut wire = vec![0; usize::from(len)];
                                    reader.read_exact(&mut wire).await.expect("query body");
                                    let request = Message::from_vec(&wire).expect("query");
                                    received.fetch_add(1, Ordering::SeqCst);
                                    let writer = Arc::clone(&writer);
                                    let mut answers = answers.clone();
                                    replies.spawn(async move {
                                        answers.wait_for(|ready| *ready).await.expect("release");
                                        let mut response = Message::response(request.id, OpCode::Query);
                                        response.add_query(request.queries[0].clone());
                                        response.add_answer(hickory_proto::rr::Record::from_rdata(
                                            request.queries[0].name().clone(),
                                            30,
                                            hickory_proto::rr::RData::A(
                                                hickory_proto::rr::rdata::A::new(192, 0, 2, 5),
                                            ),
                                        ));
                                        let wire = response.to_vec().expect("answer wire");
                                        let mut writer = writer.lock().await;
                                        writer.write_u16(u16::try_from(wire.len()).expect("length"))
                                            .await.expect("answer length");
                                        writer.write_all(&wire).await.expect("answer body");
                                    });
                                }
                            });
                        }
                        Some(result) = tasks.join_next() => { result.expect("connection task"); }
                    }
                }
            })
        };
        Self {
            addr,
            connections,
            received,
            answering,
            task,
        }
    }
}

impl Drop for HeldTcp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn saturated_tier_rejects_locally_without_reconnecting_or_going_down() {
    let server = HeldTcp::start().await;
    let upstream = Arc::new(
        build_upstream_dns(DnsProtocol::Tcp, &[server.addr.to_string()]).expect("upstream"),
    );
    let admission = Arc::new(UpstreamAdmission::new(Arc::clone(&upstream)));
    admission
        .exchange(&query(0, "warm.example."), AdmissionClass::Foreground, None)
        .await
        .expect("warm the connection");
    server.answering.send(false).expect("hold replies");

    let capacity = usize::try_from(antiwire_tuning::DNS_MAX_CONCURRENT_UPSTREAM).expect("capacity");
    let mut requests = JoinSet::new();
    for id in 0..capacity {
        let admission = Arc::clone(&admission);
        requests.spawn(async move {
            admission
                .exchange(
                    &query(
                        u16::try_from(id).expect("id"),
                        &format!("burst{id}.example."),
                    ),
                    AdmissionClass::Foreground,
                    None,
                )
                .await
        });
    }

    // Keep every response outstanding past Hickory's entire Busy retry window
    // (20 + 40 + 80 + 160 ms), but within the transport's 800 ms timeout.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let received = server.received.load(Ordering::SeqCst) - 1;
    let connections = server.connections.load(Ordering::SeqCst);
    let degraded = upstream.endpoints_degraded();
    server.answering.send(true).expect("release replies");
    let failures = upstream.tiers[0].health.consecutive_failures();
    let mut rejected = 0;
    let mut answered = 0;
    while let Some(result) = requests.join_next().await {
        match result.expect("exchange task") {
            Ok(_) => answered += 1,
            Err(error) => {
                assert!(crate::upstream::query_never_sent(&error), "{error}");
                rejected += 1;
            }
        }
    }
    assert_eq!(
        received, MAX_IN_FLIGHT_PER_TIER,
        "only work that fits is sent to Hickory"
    );
    assert_eq!(answered, MAX_IN_FLIGHT_PER_TIER);
    assert_eq!(rejected, capacity - MAX_IN_FLIGHT_PER_TIER);
    assert_eq!(
        connections, 1,
        "local saturation must not discard a healthy connection"
    );
    assert!(!degraded, "local saturation must not mark the tier down");
    assert_eq!(failures, 0, "rejections do not count as transport failures");
    assert_eq!(upstream.tiers[0].health.consecutive_failures(), 0);

    // The same admission wrapper and pool remain usable as soon as replies
    // release the permits; neither tier recovery nor a new connection is needed.
    admission
        .exchange(
            &query(0, "after.example."),
            AdmissionClass::Foreground,
            None,
        )
        .await
        .expect("capacity returns after the burst");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

/// The regression this guards: an attempt waited a fixed 150 ms for a tier
/// slot, so the tail of a burst was answered SERVFAIL while most of its
/// deadline was still left and the slots were about to free.
#[tokio::test]
async fn a_burst_past_the_tier_slots_queues_within_its_deadline() {
    let server = HeldTcp::start().await;
    let upstream = Arc::new(
        build_upstream_dns(DnsProtocol::Tcp, &[server.addr.to_string()]).expect("upstream"),
    );
    let admission = Arc::new(UpstreamAdmission::new(Arc::clone(&upstream)));
    admission
        .exchange(&query(0, "warm.example."), AdmissionClass::Foreground, None)
        .await
        .expect("warm the connection");
    server.answering.send(false).expect("hold replies");

    let burst = MAX_IN_FLIGHT_PER_TIER + 8;
    let mut requests = JoinSet::new();
    for id in 0..burst {
        let admission = Arc::clone(&admission);
        requests.spawn(async move {
            admission
                .exchange(
                    &query(
                        u16::try_from(id).expect("id"),
                        &format!("burst{id}.example."),
                    ),
                    AdmissionClass::Foreground,
                    Some(antiwire_tuning::DNS_QUERY_DEADLINE),
                )
                .await
        });
    }

    // Hold every reply past the short wait that work with no deadline gets,
    // but within the transport's 800 ms timeout.
    tokio::time::sleep(antiwire_tuning::DNS_UPSTREAM_ADMISSION_TIMEOUT * 2).await;
    assert_eq!(
        server.received.load(Ordering::SeqCst) - 1,
        MAX_IN_FLIGHT_PER_TIER,
        "the rest of the burst is queued here, not sent to Hickory"
    );
    server.answering.send(true).expect("release replies");

    while let Some(result) = requests.join_next().await {
        result
            .expect("exchange task")
            .expect("a queued query is answered once a slot frees");
    }
    assert_eq!(server.received.load(Ordering::SeqCst) - 1, burst);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.tiers[0].health.consecutive_failures(), 0);
}

#[tokio::test]
async fn saturated_tier_does_not_failure_hold_names() {
    use crate::integration_tests::support::{allow_policy, forward};
    use crate::service::testing::respond;
    use crate::{CacheKey, DnsConfig, QueryEngine};

    let server = HeldTcp::start().await;
    let engine = Arc::new(QueryEngine::new(
        allow_policy(),
        DnsConfig {
            protocol: DnsProtocol::Tcp,
            upstreams: vec![server.addr.to_string()],
            ..DnsConfig::default()
        },
    ));
    forward(&engine, &query(0, "warm.example."))
        .await
        .expect("warm");
    server.answering.send(false).expect("hold replies");
    let mut requests = JoinSet::new();
    for id in 0..MAX_IN_FLIGHT_PER_TIER {
        let engine = Arc::clone(&engine);
        requests.spawn(async move {
            forward(
                &engine,
                &query(
                    u16::try_from(id).expect("id"),
                    &format!("held{id}.example."),
                ),
            )
            .await
            .expect("reply")
        });
    }
    assert!(
        wait_until(Duration::from_millis(200), || {
            server.received.load(Ordering::SeqCst) == MAX_IN_FLIGHT_PER_TIER + 1
        })
        .await,
        "all tier slots filled"
    );

    // These arrive with little more than one transport attempt left of their
    // deadline, so they cannot queue for a slot and are refused.
    let nearly_spent = antiwire_tuning::DNS_QUERY_DEADLINE
        .saturating_sub(antiwire_tuning::DNS_TRANSPORT_TIMEOUT)
        .saturating_sub(antiwire_tuning::DNS_UPSTREAM_ADMISSION_TIMEOUT / 2);
    let mut rejected = JoinSet::new();
    for id in 0..3 {
        let engine = Arc::clone(&engine);
        rejected.spawn(async move {
            let name = format!("rejected{id}.example");
            let received_at = std::time::Instant::now()
                .checked_sub(nearly_spent)
                .expect("instant supports subtraction");
            let bytes = respond(&engine, &query(id, &format!("{name}.")), received_at).await;
            let response = Message::from_vec(&bytes).expect("local reply");
            assert_eq!(
                response.response_code,
                hickory_proto::op::ResponseCode::ServFail
            );
            assert!(
                !engine.response_cache().failure_held(&CacheKey::from_query(
                    &name,
                    RecordType::A,
                    1
                )),
                "local overload must not failure-hold {name}"
            );
        });
    }
    while let Some(result) = rejected.join_next().await {
        result.expect("rejected query");
    }
    server.answering.send(true).expect("release replies");
    while let Some(result) = requests.join_next().await {
        assert_eq!(
            result.expect("held query").response_code,
            hickory_proto::op::ResponseCode::NoError
        );
    }
    for id in 0..3 {
        let response = forward(&engine, &query(id, &format!("rejected{id}.example.")))
            .await
            .expect("immediate retry");
        assert_eq!(
            response.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(response.answers.len(), 1);
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        server.received.load(Ordering::SeqCst),
        MAX_IN_FLIGHT_PER_TIER + 4
    );
}
