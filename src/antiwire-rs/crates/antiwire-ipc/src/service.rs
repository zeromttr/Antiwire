//! The gRPC service: the daemon's services, routed to by RPC.

use std::sync::Arc;

use antiwire_capture::CaptureSession;
use antiwire_events::{
    ActiveConnectionCounter, AlertPublisher, CollectorHealth, TrafficStreamingHub,
};
use antiwire_services::DomainServices;
use antiwire_store::Store;
use antiwire_update::UpdateService;
use tokio_util::sync::CancellationToken;

use crate::handlers::{
    AiDecisionsApi, AlertsApi, CaptureApi, DomainLookupApi, NetworkMappingApi, RulesApi,
    SettingsApi, TrafficApi, UpdatesApi,
};

/// What a [`ServiceImpl`] serves.
pub struct ServiceParts {
    pub services: DomainServices,
    /// Read directly by the history and alert RPCs.
    pub store: Arc<Store>,
    pub traffic_hub: TrafficStreamingHub,
    pub alerts: AlertPublisher,
    pub active_connections: Arc<dyn ActiveConnectionCounter>,
    pub collector_health: Arc<CollectorHealth>,
    pub capture: Arc<CaptureSession>,
    pub updates: Arc<UpdateService>,
    /// Cancelled when the server stops; every stream ends then.
    pub shutdown: CancellationToken,
}

/// The gRPC service: one facade per domain, each holding only what its
/// RPCs use. The handlers live in [`crate::handlers`].
pub struct ServiceImpl {
    pub(crate) ai_decisions: AiDecisionsApi,
    pub(crate) capture: CaptureApi,
    pub(crate) domain_lookup: DomainLookupApi,
    pub(crate) network_mapping: NetworkMappingApi,
    pub(crate) alerts: AlertsApi,
    pub(crate) rules: RulesApi,
    pub(crate) settings: SettingsApi,
    pub(crate) traffic: TrafficApi,
    pub(crate) updates: UpdatesApi,
}

impl ServiceImpl {
    pub(crate) fn new(parts: ServiceParts) -> Self {
        let ServiceParts {
            services,
            store,
            traffic_hub,
            alerts,
            active_connections,
            collector_health,
            capture,
            updates,
            shutdown,
        } = parts;
        Self {
            ai_decisions: AiDecisionsApi {
                decisions: services.ai_decisions,
            },
            capture: CaptureApi {
                capture,
                active_connections: Arc::clone(&active_connections),
                shutdown: shutdown.clone(),
            },
            domain_lookup: DomainLookupApi {
                lookups: services.domain_lookup,
            },
            network_mapping: NetworkMappingApi {
                worker: services.network_mapping,
            },
            alerts: AlertsApi {
                store: Arc::clone(&store),
                alerts,
                shutdown: shutdown.clone(),
            },
            rules: RulesApi {
                rules: services.rules,
            },
            settings: SettingsApi {
                settings: services.settings,
                hosts_blocklist: services.hosts_blocklist,
                geo_database: services.geo_database,
            },
            traffic: TrafficApi {
                store,
                traffic_hub,
                active_connections,
                collector_health,
                shutdown,
            },
            updates: UpdatesApi { updates },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::TestService;
    use antiwire_events::{Alert, AlertKind, Severity};
    use tonic::Request;
    // The handler impl lives in `crate::handlers`; tests here still call its
    // methods, so the trait must be in scope.
    use antiwire_proto::antiwire_service_server::AntiwireService as _;

    #[tokio::test]
    async fn alerts_round_trip_via_service() {
        let service = TestService::new();
        service.alerts.publish(
            Alert::new(
                AlertKind::MaliciousFlow,
                Severity::Warning,
                "Blocked connection",
                "example.com was blocked",
            )
            .at(1),
        );
        service.alerts.flush();

        let response = service
            .get_alerts(Request::new(antiwire_proto::Empty {}))
            .await
            .expect("get alerts")
            .into_inner();
        assert_eq!(response.alerts.len(), 1);
        let id = response.alerts[0].id;
        assert!(id > 0);

        let dismissed = service
            .dismiss_alert(Request::new(antiwire_proto::AlertRequest { id }))
            .await
            .expect("dismiss alert")
            .into_inner();
        assert!(dismissed.success);
        assert_eq!(
            service
                .get_alerts(Request::new(antiwire_proto::Empty {}))
                .await
                .expect("get alerts after dismiss")
                .into_inner()
                .alerts,
            []
        );
        let again = service
            .dismiss_alert(Request::new(antiwire_proto::AlertRequest { id }))
            .await
            .expect("dismiss the alert again")
            .into_inner();
        assert!(again.success, "dismissing is idempotent");
        assert_eq!(again.message, "Alert was already dismissed");

        service.alerts.publish(Alert::new(
            AlertKind::MaliciousFlow,
            Severity::Warning,
            "Another alert",
            "",
        ));
        service.alerts.flush();
        let cleared = service
            .clear_alerts(Request::new(antiwire_proto::Empty {}))
            .await
            .expect("clear alerts")
            .into_inner();
        assert!(cleared.success);
        assert_eq!(
            service
                .get_alerts(Request::new(antiwire_proto::Empty {}))
                .await
                .expect("get alerts after clear")
                .into_inner()
                .alerts,
            []
        );
    }

    #[tokio::test]
    async fn history_is_deleted_via_service() {
        let service = TestService::new();
        let alerts = || async {
            service
                .get_alerts(Request::new(antiwire_proto::Empty {}))
                .await
                .expect("get alerts")
                .into_inner()
                .alerts
                .len()
        };
        service.alerts.publish(Alert::new(
            AlertKind::MaliciousFlow,
            Severity::Warning,
            "Recent alert",
            "",
        ));
        service.alerts.flush();
        assert_eq!(alerts().await, 1);

        // A start in the future keeps the alert just raised.
        let future = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        let kept = service
            .delete_history(Request::new(antiwire_proto::DeleteHistoryRequest {
                all: false,
                since: u64::try_from(future.unix_timestamp()).unwrap(),
            }))
            .await
            .expect("delete future history")
            .into_inner();
        assert_eq!(kept.deleted_count, 0);
        assert_eq!(alerts().await, 1);

        let unset = service
            .delete_history(Request::new(antiwire_proto::DeleteHistoryRequest::default()))
            .await
            .expect_err("an unset start is rejected");
        assert_eq!(unset.code(), tonic::Code::InvalidArgument);
        assert_eq!(alerts().await, 1);

        let all = service
            .delete_history(Request::new(antiwire_proto::DeleteHistoryRequest {
                all: true,
                since: 0,
            }))
            .await
            .expect("delete all history")
            .into_inner();
        assert!(all.success);
        assert_eq!(all.deleted_count, 1);
        assert_eq!(alerts().await, 0);
    }

    #[tokio::test]
    async fn ai_decisions_are_listed_via_service() {
        let service = TestService::new();
        let updated_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        for (domain, verdict) in [("ads.example", "block"), ("fine.example", "")] {
            service
                .store
                .upsert_domain_decision(&antiwire_store::DomainDecision {
                    domain: domain.to_owned(),
                    model: "test".to_owned(),
                    rating_advertising: 0.97,
                    rating_tracking: 0.1,
                    rating_telemetry: 0.0,
                    rating_analytics: 0.0,
                    rating_malicious: 0.0,
                    rating_fraud: 0.0,
                    rating_cryptomining: 0.0,
                    rating_tunnel: 0.0,
                    verdict: verdict.to_owned(),
                    top_category: "advertising".to_owned(),
                    top_score: 0.97,
                    rating_newly_registered: 0.0,
                    rating_registry_hold: 0.0,
                    rating_hidden_registrant: 0.0,
                    rating_abusive_registrar: 0.0,
                    scan_tier: "basic".to_owned(),
                    first_seen: updated_at,
                    updated_at,
                })
                .expect("save decision");
        }

        let blocked = service
            .get_ai_decisions(Request::new(antiwire_proto::AiDecisionsRequest {
                verdict_filter: "block".to_owned(),
                ..Default::default()
            }))
            .await
            .expect("get AI decisions")
            .into_inner();
        assert_eq!(blocked.total_count, 1);
        assert_eq!((blocked.block_count, blocked.clean_count), (1, 1));
        let row = &blocked.decisions[0];
        assert_eq!(row.domain, "ads.example");
        assert_eq!(row.verdict, "block");
        assert_eq!(row.updated_at, 1_700_000_000);
        assert!((row.rating_advertising - 0.97).abs() < f64::EPSILON);

        let invalid = service
            .get_ai_decisions(Request::new(antiwire_proto::AiDecisionsRequest {
                verdict_filter: "maybe".to_owned(),
                ..Default::default()
            }))
            .await
            .expect_err("unknown verdict filter");
        assert_eq!(invalid.code(), tonic::Code::InvalidArgument);

        let deleted = service
            .delete_ai_decision(Request::new(antiwire_proto::DeleteAiDecisionRequest {
                domain: "ADS.EXAMPLE.".to_owned(),
            }))
            .await
            .expect("delete AI decision")
            .into_inner();
        assert!(deleted.success);
        assert!(service
            .store
            .get_domain_decision("ads.example")
            .expect("lookup")
            .is_none());
        assert!(service
            .store
            .cached_domain_decision("ads.example")
            .is_none());
        let missing = service
            .delete_ai_decision(Request::new(antiwire_proto::DeleteAiDecisionRequest {
                domain: "ads.example".to_owned(),
            }))
            .await
            .expect("delete missing decision")
            .into_inner();
        assert!(!missing.success);
        let empty = service
            .delete_ai_decision(Request::new(antiwire_proto::DeleteAiDecisionRequest {
                domain: "  ".to_owned(),
            }))
            .await
            .expect("empty domain is refused, not an error")
            .into_inner();
        assert!(!empty.success);
        assert_eq!(empty.message, "domain is empty");
    }

    #[tokio::test]
    async fn refreshing_a_decision_requires_a_saved_row_and_an_api_key() {
        let service = TestService::new();
        let missing = service
            .refresh_ai_decision(Request::new(antiwire_proto::RefreshAiDecisionRequest {
                domain: "missing.example".to_owned(),
            }))
            .await
            .expect_err("missing decision");
        assert_eq!(missing.code(), tonic::Code::NotFound);

        let updated_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        service
            .store
            .upsert_domain_decision(&antiwire_store::DomainDecision {
                domain: "ads.example".to_owned(),
                model: "test".to_owned(),
                rating_advertising: 0.1,
                rating_tracking: 0.1,
                rating_telemetry: 0.1,
                rating_analytics: 0.1,
                rating_malicious: 0.1,
                rating_fraud: 0.1,
                rating_cryptomining: 0.1,
                rating_tunnel: 0.1,
                verdict: String::new(),
                top_category: String::new(),
                top_score: 0.1,
                rating_newly_registered: 0.0,
                rating_registry_hold: 0.0,
                rating_hidden_registrant: 0.0,
                rating_abusive_registrar: 0.0,
                scan_tier: "basic".to_owned(),
                first_seen: updated_at,
                updated_at,
            })
            .expect("save decision");
        let unconfigured = service
            .refresh_ai_decision(Request::new(antiwire_proto::RefreshAiDecisionRequest {
                domain: "ads.example".to_owned(),
            }))
            .await
            .expect_err("no api key");
        assert_eq!(unconfigured.code(), tonic::Code::FailedPrecondition);
        assert!(service
            .store
            .get_domain_decision("ads.example")
            .expect("lookup")
            .is_some());
    }

    #[tokio::test]
    async fn advanced_check_requires_a_saved_row_and_an_api_key() {
        let service = TestService::new();
        let missing = service
            .advanced_ai_decision(Request::new(antiwire_proto::AdvancedAiDecisionRequest {
                domain: "missing.example".to_owned(),
            }))
            .await
            .expect_err("missing decision");
        assert_eq!(missing.code(), tonic::Code::NotFound);

        let updated_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        service
            .store
            .upsert_domain_decision(&antiwire_store::DomainDecision {
                domain: "ads.example".to_owned(),
                model: "test".to_owned(),
                rating_advertising: 0.1,
                rating_tracking: 0.1,
                rating_telemetry: 0.1,
                rating_analytics: 0.1,
                rating_malicious: 0.1,
                rating_fraud: 0.1,
                rating_cryptomining: 0.1,
                rating_tunnel: 0.1,
                verdict: String::new(),
                top_category: String::new(),
                top_score: 0.1,
                rating_newly_registered: 0.0,
                rating_registry_hold: 0.0,
                rating_hidden_registrant: 0.0,
                rating_abusive_registrar: 0.0,
                scan_tier: "basic".to_owned(),
                first_seen: updated_at,
                updated_at,
            })
            .expect("save decision");
        let unconfigured = service
            .advanced_ai_decision(Request::new(antiwire_proto::AdvancedAiDecisionRequest {
                domain: "ads.example".to_owned(),
            }))
            .await
            .expect_err("no api key");
        assert_eq!(unconfigured.code(), tonic::Code::FailedPrecondition);
        let saved = service
            .store
            .get_domain_decision("ads.example")
            .expect("lookup")
            .expect("row");
        assert_eq!(saved.scan_tier, "basic");
    }

    #[tokio::test]
    async fn explain_domain_block_reports_named_blocklists() {
        let service = TestService::new();
        let mut builder = antiwire_policy::BlocklistBuilder::new(1);
        builder.add_from_list("hagezi_light", "ads.example");
        service
            .services
            .dns
            .engine
            .write()
            .publish_blocklist(builder.prepare().expect("prepare"));

        let blocked = service
            .explain_domain_block(Request::new(antiwire_proto::ExplainDomainBlockRequest {
                domain: "SUB.ADS.EXAMPLE".to_owned(),
            }))
            .await
            .expect("explain")
            .into_inner();
        assert!(blocked.blocked);
        assert_eq!(blocked.source, "blocklist");
        assert_eq!(blocked.blocklist_names, vec!["hagezi_light".to_owned()]);

        let allowed = service
            .explain_domain_block(Request::new(antiwire_proto::ExplainDomainBlockRequest {
                domain: "ok.example".to_owned(),
            }))
            .await
            .expect("explain allowed")
            .into_inner();
        assert!(!allowed.blocked);
        assert_eq!(allowed.source, "");
        assert_eq!(allowed.blocklist_names, [] as [String; 0]);
    }

    #[tokio::test]
    async fn explain_domain_block_reports_firewall_rule_for_dns_rules() {
        let service = TestService::new();
        let added = service
            .add_rule(Request::new(antiwire_proto::Rule {
                id: 0,
                target_type: "DNS".to_owned(),
                target_value: "ads.example".to_owned(),
                action: "BLOCK".to_owned(),
                direction: "OUTBOUND".to_owned(),
            }))
            .await
            .expect("add dns rule")
            .into_inner();
        assert!(added.success, "{}", added.message);

        let blocked = service
            .explain_domain_block(Request::new(antiwire_proto::ExplainDomainBlockRequest {
                domain: "ads.example".to_owned(),
            }))
            .await
            .expect("explain")
            .into_inner();
        assert!(blocked.blocked);
        assert_eq!(blocked.source, "dns_rule");
        assert_eq!(
            blocked.blocklist_names,
            vec![antiwire_policy::FIREWALL_RULE_LABEL.to_owned()]
        );
    }

    #[tokio::test]
    async fn realtime_traffic_stream_ends_at_shutdown() {
        use tokio_stream::StreamExt;

        let service = TestService::new();
        let mut stream = service
            .stream_realtime_traffic(Request::new(antiwire_proto::Empty {}))
            .await
            .expect("stream")
            .into_inner();

        service.begin_shutdown();

        let next = tokio::time::timeout(std::time::Duration::from_millis(500), stream.next()).await;
        assert!(
            matches!(next, Ok(None)),
            "shutdown must end the stream, not spin; got {next:?}"
        );
    }

    #[tokio::test]
    async fn country_statistics_return_all_saved_country_counts() {
        let service = TestService::new();
        let now = time::OffsetDateTime::now_utc();
        let mut log = antiwire_store::NewConnectionLog {
            timestamp: now,
            app_id: 1,
            app_path: String::new(),
            protocol: "TCP".to_owned(),
            src_ip: "10.0.0.1".to_owned(),
            src_port: 12_345,
            dst_ip: "203.0.113.1".to_owned(),
            dst_port: 443,
            dst_domain: String::new(),
            bytes_sent: 0,
            bytes_received: 0,
            action_taken: "ALLOWED".to_owned(),
            last_seen: now,
            country_code: "IN".to_owned(),
            isp: String::new(),
            blocklist_names: String::new(),
            conn_id: 0,
            conn_pid: 0,
            is_close: false,
            replace_domain: false,
        };
        service
            .store
            .insert_connection_logs(&[log.clone()])
            .expect("India record");
        log.country_code.clear();
        service
            .store
            .insert_connection_logs(&[log])
            .expect("unknown record");
        let statistics = service
            .get_country_statistics(Request::new(antiwire_proto::Empty {}))
            .await
            .expect("country statistics")
            .into_inner();
        assert_eq!(statistics.total_count, 2);
        assert_eq!(statistics.unknown_count, 1);
        assert_eq!(statistics.country_counts.len(), 1);
        assert_eq!(statistics.country_counts["IN"], 1);
    }

    #[tokio::test]
    async fn remove_rule_refuses_an_id_that_does_not_fit_i32() {
        // Truncating it would name some other rule.
        let service = TestService::new();
        let reply = service
            .remove_rule(Request::new(antiwire_proto::Rule {
                id: u32::try_from(i32::MAX).expect("i32::MAX fits u32") + 1,
                target_type: "DNS".to_owned(),
                target_value: "example.test".to_owned(),
                action: "BLOCK".to_owned(),
                direction: "BOTH".to_owned(),
            }))
            .await
            .expect("an action reply")
            .into_inner();
        assert!(!reply.success);
        assert!(reply.message.contains("out of range"), "{}", reply.message);

        let reply = service
            .remove_country_rule(Request::new(antiwire_proto::CountryRule {
                id: u32::try_from(i32::MAX).expect("i32::MAX fits u32") + 1,
                country_code: "US".to_owned(),
                action: "BLOCK".to_owned(),
                direction: "BOTH".to_owned(),
                cidrs: Vec::new(),
            }))
            .await
            .expect("an action reply")
            .into_inner();
        assert!(!reply.success);
        assert!(reply.message.contains("out of range"), "{}", reply.message);
    }

    #[tokio::test]
    async fn stopping_an_idle_or_unknown_capture_is_refused() {
        let service = TestService::new();
        for capture_id in ["default", "other"] {
            let reply = service
                .stop_capture(Request::new(antiwire_proto::CaptureControl {
                    capture_id: capture_id.to_owned(),
                }))
                .await
                .expect("an action reply")
                .into_inner();
            assert!(!reply.success, "{capture_id}");
        }

        let status = service
            .get_capture_status(Request::new(antiwire_proto::CaptureControl {
                capture_id: "default".to_owned(),
            }))
            .await
            .expect("status")
            .into_inner();
        assert_eq!(status.state, "idle");
        assert_eq!(
            service
                .get_capture_status(Request::new(antiwire_proto::CaptureControl {
                    capture_id: "other".to_owned(),
                }))
                .await
                .expect_err("unknown session")
                .code(),
            tonic::Code::NotFound
        );
    }
}
