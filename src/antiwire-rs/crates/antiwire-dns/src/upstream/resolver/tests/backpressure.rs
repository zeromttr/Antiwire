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

/// A primary that takes connections and never answers, as a blocked port 853
/// does, with a fallback that answers, behind one admission limit.
fn blocked_primary_with_fallback(
    primary: &HeldTcp,
    fallback: &SwitchableUdp,
) -> Arc<UpstreamAdmission> {
    let upstream = tiers_of(&[
        (DnsProtocol::Tcp, &[primary.addr]),
        (DnsProtocol::Udp, &[fallback.addr]),
    ]);
    Arc::new(UpstreamAdmission::new(Arc::new(upstream)))
}

/// Sends `count` queries at once with the whole client deadline, and returns
/// their results once every caller has its answer.
async fn burst(
    admission: &Arc<UpstreamAdmission>,
    label: &str,
    count: usize,
) -> Vec<std::result::Result<UpstreamAnswer, NetError>> {
    let mut requests = JoinSet::new();
    for id in 0..count {
        let admission = Arc::clone(admission);
        let name = format!("{label}{id}.example.");
        requests.spawn(async move {
            admission
                .exchange(
                    &query(u16::try_from(id).expect("id"), &name),
                    AdmissionClass::Foreground,
                    Some(antiwire_tuning::DNS_QUERY_DEADLINE),
                )
                .await
        });
    }
    let mut results = Vec::with_capacity(count);
    while let Some(result) = requests.join_next().await {
        results.push(result.expect("exchange task"));
    }
    results
}

fn foreground_capacity() -> usize {
    usize::try_from(antiwire_tuning::DNS_MAX_CONCURRENT_UPSTREAM).expect("capacity")
}

/// The regression this guards: with port 853 blocked, each query's attempt on
/// the primary waited two seconds behind the one opening its connection. It
/// held the query's admission all that time, though the fallback had answered
/// long before, so a few hundred misses used up the limit and the rest were
/// refused with a working fallback.
#[tokio::test]
async fn an_attempt_behind_a_connecting_tier_gives_up_its_admission_once_answered() {
    let primary = HeldTcp::start().await;
    primary.answering.send(false).expect("hold replies");
    let fallback = SwitchableUdp::start(true).await;
    let admission = blocked_primary_with_fallback(&primary, &fallback);

    let waiting = 64;
    for result in burst(&admission, "blocked", waiting + 1).await {
        result.expect("the fallback answers");
    }

    // One attempt was sent to the primary and is still waiting on it. The
    // others never reached it, and their queries are answered.
    let released = wait_until(Duration::from_secs(1), || {
        admission.foreground_available() >= foreground_capacity() - 1
    })
    .await;
    assert!(
        released,
        "{} admissions still held by queries that were answered",
        foreground_capacity() - admission.foreground_available()
    );
}

/// The regression this guards: while a blocked primary was still on its first
/// connection, every query gave it the hedge delay, though its attempt only
/// queued behind that connection and was never sent.
#[tokio::test]
async fn a_query_behind_a_connecting_tier_is_not_delayed_for_it() {
    let primary = HeldTcp::start().await;
    primary.answering.send(false).expect("hold replies");
    let fallback = SwitchableUdp::start(true).await;
    let admission = blocked_primary_with_fallback(&primary, &fallback);

    // The first query's attempt opens the connection and stays on it.
    burst(&admission, "first", 1).await;
    assert_eq!(primary.connections.load(Ordering::SeqCst), 1);

    // The fastest of a few, so a busy runner cannot fail this by stalling one.
    let mut fastest = Duration::MAX;
    for id in 0..5 {
        let started = Instant::now();
        burst(&admission, &format!("later{id}-"), 1)
            .await
            .pop()
            .expect("one result")
            .expect("the fallback answers");
        fastest = fastest.min(started.elapsed());
    }
    assert!(
        fastest < antiwire_tuning::DOH_HEDGE_DELAY,
        "the fastest later query took {fastest:?}"
    );
}

/// The regression this guards: with a working primary gone quiet, attempts
/// queued for one of its slots held their queries' admission until the slot
/// wait ran out, long after the fallback had answered.
#[tokio::test]
async fn an_attempt_queued_for_a_slot_gives_up_its_admission_once_answered() {
    let primary = HeldTcp::start().await;
    let fallback = SwitchableUdp::start(true).await;
    let admission = blocked_primary_with_fallback(&primary, &fallback);
    burst(&admission, "warm", 1)
        .await
        .pop()
        .expect("one result")
        .expect("warm the connection");
    primary.answering.send(false).expect("hold replies");

    let queued = 64;
    for result in burst(&admission, "quiet", MAX_IN_FLIGHT_PER_TIER + queued).await {
        result.expect("the fallback answers");
    }

    // The attempts that were sent are still upstream work. The queued ones
    // are not.
    let released = wait_until(Duration::from_millis(600), || {
        admission.foreground_available() >= foreground_capacity() - MAX_IN_FLIGHT_PER_TIER
    })
    .await;
    assert!(
        released,
        "{} admissions still held, {} of them by attempts that were sent",
        foreground_capacity() - admission.foreground_available(),
        MAX_IN_FLIGHT_PER_TIER
    );
    assert_eq!(
        primary.received.load(Ordering::SeqCst) - 1,
        MAX_IN_FLIGHT_PER_TIER,
        "a queued attempt whose query is answered is not sent"
    );
}

/// The regression this guards: attempts queued for a slot were sent as the
/// slots freed, though the failures that freed them had just taken the tier
/// down. A down tier is asked by its one recovery attempt and nothing else.
#[tokio::test]
async fn an_attempt_queued_while_its_tier_goes_down_is_not_sent() {
    let server = HeldTcp::start().await;
    let upstream = Arc::new(
        build_upstream_dns(DnsProtocol::Tcp, &[server.addr.to_string()]).expect("upstream"),
    );
    let admission = Arc::new(UpstreamAdmission::new(Arc::clone(&upstream)));
    burst(&admission, "warm", 1)
        .await
        .pop()
        .expect("one result")
        .expect("warm the connection");
    server.answering.send(false).expect("hold replies");

    // The first burst fills the tier's slots and fails at the transport's
    // timeout. The second arrives late enough to still be queued then.
    let first = {
        let admission = Arc::clone(&admission);
        tokio::spawn(async move { burst(&admission, "sent", MAX_IN_FLIGHT_PER_TIER).await })
    };
    tokio::time::sleep(DNS_TRANSPORT_TIMEOUT * 3 / 4).await;
    let second = {
        let admission = Arc::clone(&admission);
        tokio::spawn(async move { burst(&admission, "queued", MAX_IN_FLIGHT_PER_TIER).await })
    };
    tokio::time::sleep(DNS_TRANSPORT_TIMEOUT / 2).await;
    let sent_by_the_first = server.received.load(Ordering::SeqCst);

    first.await.expect("first burst");
    let refused = second
        .await
        .expect("second burst")
        .into_iter()
        .filter(|result| {
            result
                .as_ref()
                .is_err_and(crate::upstream::query_never_sent)
        })
        .count();
    assert!(
        upstream.endpoints_degraded(),
        "the first burst took it down"
    );
    // A slot can free before the failure that takes the tier down is counted,
    // so a few of the second burst may be sent first.
    let sent_after = server.received.load(Ordering::SeqCst) - sent_by_the_first;
    assert!(
        sent_after < MAX_IN_FLIGHT_PER_TIER / 2 && refused > MAX_IN_FLIGHT_PER_TIER / 2,
        "{sent_after} queries sent after the first burst, {refused} refused unsent"
    );
}
