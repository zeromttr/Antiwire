//! Integration tests for the hickory-server backed DNS listener (UDP and TCP).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::support;
use super::support::{
    encode_query, stub_config_with_upstream, BlockOnePolicy, MockUpstream, MockUpstreamConfig,
};
use crate::{BlockResponseMode, DnsConfig, DnsListener, QueryEngine};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Answer count that pushes a response well past the 512-byte non-EDNS UDP limit.
const OVERSIZED_ANSWER_COUNT: u32 = 60;

fn start_listener<P>(policy: P, config: DnsConfig) -> DnsListener
where
    P: antiwire_policy::PolicyEngine + Send + Sync + Unpin + 'static,
{
    let stub = Arc::new(QueryEngine::new(policy, config));
    DnsListener::start_on(stub, "127.0.0.1:0".parse().expect("addr")).expect("start listener")
}

async fn udp_exchange(addr: SocketAddr, wire: &[u8]) -> Vec<u8> {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    // Connected, so the kernel drops anything not from this listener. These
    // tests run in parallel and their client ports are recycled between them,
    // and an unconnected socket will happily accept another test's late reply —
    // which then fails the txid assertion in whichever test caught it.
    client.connect(addr).await.expect("client connect");
    client.send(wire).await.expect("send query");
    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
        .await
        .expect("udp response timeout")
        .expect("recv udp response");
    buf.truncate(len);
    buf
}

/// DNS over TCP frames each message with a two-byte big-endian length prefix.
async fn tcp_exchange(addr: SocketAddr, wire: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("tcp connect");
    let len = u16::try_from(wire.len()).expect("query fits a tcp frame");
    stream
        .write_all(&len.to_be_bytes())
        .await
        .expect("write length prefix");
    stream.write_all(wire).await.expect("write query");
    stream.flush().await.expect("flush query");

    let read = async {
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut body).await?;
        Ok::<_, std::io::Error>(body)
    };

    tokio::time::timeout(Duration::from_secs(3), read)
        .await
        .expect("tcp response timeout")
        .expect("read tcp response")
}

#[tokio::test]
async fn listener_returns_blocked_response_over_udp() {
    let mut listener = start_listener(
        BlockOnePolicy {
            domain: "blocked.example",
        },
        DnsConfig {
            block_mode: BlockResponseMode::Sinkhole,
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    );

    let wire = encode_query("blocked.example", RecordType::A, 0xBEEF);
    let bytes = udp_exchange(listener.udp_addr(), &wire).await;

    let response = Message::from_vec(&bytes).expect("parse response");
    assert_eq!(response.metadata.id, 0xBEEF);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);

    listener.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn listener_forwards_misses_to_mock_upstream_over_udp() {
    let upstream = MockUpstream::start().await;
    let mut listener = start_listener(
        support::allow_policy(),
        stub_config_with_upstream(&upstream),
    );

    let wire = encode_query("forward.example", RecordType::A, 0x1234);
    let bytes = udp_exchange(listener.udp_addr(), &wire).await;

    let response = Message::from_vec(&bytes).expect("parse response");
    assert_eq!(response.metadata.id, 0x1234);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(upstream.calls(), 1);

    listener.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn listener_answers_queries_over_tcp() {
    let upstream = MockUpstream::start().await;
    let mut listener = start_listener(
        support::allow_policy(),
        stub_config_with_upstream(&upstream),
    );
    let tcp_addr = listener.tcp_addr().expect("tcp listener bound");

    let wire = encode_query("tcp.example", RecordType::A, 0x5678);
    let bytes = tcp_exchange(tcp_addr, &wire).await;

    let response = Message::from_vec(&bytes).expect("parse tcp response");
    assert_eq!(response.metadata.id, 0x5678);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);

    listener.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn oversized_udp_answer_truncates_and_tcp_retry_returns_it_whole() {
    // A stream upstream, standing in for the DoH default: unlike UDP it is not
    // capped at the 512 bytes a non-EDNS query advertises, so it can hand us an
    // answer that will not fit in the client's datagram.
    let upstream = MockUpstream::start_tcp_with(MockUpstreamConfig {
        answer_count: OVERSIZED_ANSWER_COUNT,
        ..MockUpstreamConfig::default()
    })
    .await;
    let mut listener = start_listener(
        support::allow_policy(),
        stub_config_with_upstream(&upstream),
    );
    let tcp_addr = listener.tcp_addr().expect("tcp listener bound");

    // A non-EDNS client may only assume 512 bytes over UDP.
    let wire = encode_query("big.example", RecordType::A, 0x0A0A);
    let udp_bytes = udp_exchange(listener.udp_addr(), &wire).await;
    assert!(
        udp_bytes.len() <= 512,
        "non-EDNS UDP answer must fit 512 bytes, got {}",
        udp_bytes.len()
    );

    let udp_response = Message::from_vec(&udp_bytes).expect("parse udp response");
    assert!(
        udp_response.metadata.truncation,
        "oversized answer must set the TC bit so the client retries over TCP"
    );
    assert_eq!(udp_response.metadata.id, 0x0A0A);

    // The retry carries the whole answer, served from cache.
    let tcp_bytes = tcp_exchange(tcp_addr, &wire).await;
    let tcp_response = Message::from_vec(&tcp_bytes).expect("parse tcp response");
    assert!(!tcp_response.metadata.truncation);
    assert_eq!(
        tcp_response.answers.len(),
        OVERSIZED_ANSWER_COUNT as usize,
        "TCP retry must return every answer record"
    );

    listener.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn concurrent_udp_clients_receive_distinct_txids() {
    let upstream = MockUpstream::start().await;
    let mut listener = start_listener(
        support::allow_policy(),
        stub_config_with_upstream(&upstream),
    );
    let addr = listener.udp_addr();

    let mut handles = Vec::new();
    for id in 0..16_u16 {
        handles.push(tokio::spawn(async move {
            let wire = encode_query("concurrent.example", RecordType::A, 0x1000 + id);
            (id, udp_exchange(addr, &wire).await)
        }));
    }

    for handle in handles {
        let (id, bytes) = handle.await.expect("join");
        let response = Message::from_vec(&bytes).expect("parse response");
        assert_eq!(response.metadata.id, 0x1000 + id);
    }

    listener.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn shutdown_stops_the_listener() {
    let upstream = MockUpstream::start().await;
    let mut listener = start_listener(
        support::allow_policy(),
        stub_config_with_upstream(&upstream),
    );
    let addr = listener.udp_addr();

    let wire = encode_query("before-shutdown.example", RecordType::A, 0x4321);
    let bytes = udp_exchange(addr, &wire).await;
    assert_eq!(
        Message::from_vec(&bytes).expect("parse").metadata.id,
        0x4321
    );

    assert!(listener.is_running());
    listener.shutdown().await.expect("shutdown");
    assert!(!listener.is_running());
}
