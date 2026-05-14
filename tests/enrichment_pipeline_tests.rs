use netascan::enrichment::{EnrichmentConfig, enrich_devices};
use netascan::scanner::{DiscoveredHost, DiscoveryMethod};
use std::net::IpAddr;

fn host_fixture() -> DiscoveredHost {
    DiscoveredHost {
        ip: "192.168.1.50".parse::<IpAddr>().unwrap(),
        mac: Some("AA:BB:CC:DD:EE:50".parse().unwrap()),
        hostname: Some("printer.local".into()),
        method: DiscoveryMethod::Tcp,
        open_ports: vec![],
        rtt_ms: Some(4),
        vendor: Some("Existing Vendor".into()),
        device_model: Some("LaserJet".into()),
        os_hint: Some("Linux".into()),
        security_findings: vec![],
    }
}

#[tokio::test(flavor = "current_thread")]
async fn enrich_devices_with_all_sources_disabled_returns_hosts_unchanged() {
    let mut hosts = vec![host_fixture()];
    let original = hosts.clone();
    let config = EnrichmentConfig {
        snmp_enabled: false,
        mdns_enabled: false,
        mac_api_enabled: false,
        snmp_timeout_ms: 1000,
        mdns_timeout_ms: 2000,
        snmp_community: "public".into(),
    };

    enrich_devices(&mut hosts, &config).await;

    assert_eq!(hosts.len(), original.len());
    assert_eq!(hosts[0].ip, original[0].ip);
    assert_eq!(hosts[0].mac, original[0].mac);
    assert_eq!(hosts[0].hostname, original[0].hostname);
    assert_eq!(hosts[0].vendor, original[0].vendor);
    assert_eq!(hosts[0].device_model, original[0].device_model);
    assert_eq!(hosts[0].os_hint, original[0].os_hint);
}
