use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use mdns_sd::{Receiver, ServiceDaemon, ServiceEvent};

const MDNS_META_QUERY: &str = "_services._dns-sd._udp.local.";
const MDNS_MAX_TIMEOUT_MS: u64 = 2_000;
const POLL_INTERVAL_MS: u64 = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsResult {
    pub hostname: Option<String>,
    pub device_model: Option<String>,
}

pub async fn probe_mdns(ip: IpAddr, timeout_ms: u64) -> Option<MdnsResult> {
    let effective_timeout_ms = timeout_ms.min(MDNS_MAX_TIMEOUT_MS);

    match tokio::task::spawn_blocking(move || probe_mdns_blocking(ip, effective_timeout_ms)).await {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(%ip, %error, "mDNS task join failed");
            None
        }
    }
}

fn probe_mdns_blocking(ip: IpAddr, timeout_ms: u64) -> Option<MdnsResult> {
    let daemon = ServiceDaemon::new()
        .map_err(|error| {
            tracing::debug!(%ip, %error, "mDNS daemon creation failed");
        })
        .ok()?;

    let meta_receiver = daemon
        .browse(MDNS_META_QUERY)
        .map_err(|error| {
            tracing::debug!(%ip, %error, "mDNS meta-query browse failed");
        })
        .ok()?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut service_receivers: Vec<Receiver<ServiceEvent>> = Vec::new();
    let mut discovered_service_types = HashSet::new();
    let mut result = MdnsResult {
        hostname: None,
        device_model: None,
    };

    while Instant::now() < deadline {
        while let Ok(event) = meta_receiver.try_recv() {
            if let ServiceEvent::ServiceFound(_, service_type) = event {
                if discovered_service_types.insert(service_type.clone()) {
                    match daemon.browse(&service_type) {
                        Ok(receiver) => service_receivers.push(receiver),
                        Err(error) => {
                            tracing::debug!(%ip, %error, service_type, "mDNS service browse failed");
                        }
                    }
                }
            }
        }

        for receiver in &service_receivers {
            while let Ok(event) = receiver.try_recv() {
                apply_service_event(ip, event, &mut result);
            }
        }

        if result.hostname.is_some() && result.device_model.is_some() {
            break;
        }

        std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }

    let _ = daemon.shutdown();

    if result.hostname.is_some() || result.device_model.is_some() {
        Some(result)
    } else {
        tracing::debug!(%ip, %timeout_ms, "mDNS probe completed without matching records");
        None
    }
}

fn apply_service_event(target_ip: IpAddr, event: ServiceEvent, result: &mut MdnsResult) {
    if let ServiceEvent::ServiceResolved(info) = event {
        if !info.get_addresses().contains(&target_ip) {
            return;
        }

        if result.hostname.is_none() {
            result.hostname = normalize_mdns_value(Some(info.get_hostname().trim_end_matches('.').to_string()));
        }

        if result.device_model.is_none() {
            result.device_model = normalize_mdns_value(info.get_property_val_str("model").map(ToString::to_string));
        }
    }
}

fn normalize_mdns_value(value: Option<String>) -> Option<String> {
    let trimmed = value?.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
