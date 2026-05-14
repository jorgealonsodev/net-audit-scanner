use std::sync::OnceLock;

#[cfg(test)]
use std::sync::Mutex;

use reqwest::header::AUTHORIZATION;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{Duration, Instant, sleep};

const MAC_VENDORS_API_BASE: &str = "https://api.macvendors.com";

pub async fn lookup_mac_vendor(mac: &str, api_key: Option<&str>) -> Option<String> {
    wait_for_rate_limit().await;

    let url = format!("{}/{}", api_base_url().trim_end_matches('/'), mac);
    let mut request = http_client().get(url);

    if let Some(key) = api_key.filter(|value| !value.trim().is_empty()) {
        request = request.header(AUTHORIZATION, format!("Bearer {key}"));
    }

    match request.send().await {
        Ok(response) if response.status().is_success() => {
            let body = response
                .text()
                .await
                .map_err(|error| {
                    tracing::debug!(%mac, %error, "MacVendors body read failed");
                })
                .ok()?;

            let vendor = body.trim();
            if vendor.is_empty() {
                None
            } else {
                Some(vendor.to_string())
            }
        }
        Ok(response) if response.status().as_u16() == 404 => None,
        Ok(response) => {
            tracing::debug!(%mac, status = %response.status(), "MacVendors lookup failed");
            None
        }
        Err(error) => {
            tracing::debug!(%mac, %error, "MacVendors request failed");
            None
        }
    }
}

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("mac vendor client should build")
    })
}

fn api_base_url() -> String {
    #[cfg(test)]
    {
        if let Some(base_url) = test_api_base_url()
            .lock()
            .expect("test api base url mutex should not poison")
            .clone()
        {
            return base_url;
        }
    }

    MAC_VENDORS_API_BASE.to_string()
}

async fn wait_for_rate_limit() {
    let mut last_request = rate_limit_state().lock().await;

    if let Some(previous) = *last_request {
        let elapsed = previous.elapsed();
        if elapsed < Duration::from_secs(1) {
            sleep(Duration::from_secs(1) - elapsed).await;
        }
    }

    *last_request = Some(Instant::now());
}

fn rate_limit_state() -> &'static AsyncMutex<Option<Instant>> {
    static RATE_LIMIT: OnceLock<AsyncMutex<Option<Instant>>> = OnceLock::new();

    RATE_LIMIT.get_or_init(|| AsyncMutex::new(None))
}

#[cfg(test)]
fn test_api_base_url() -> &'static Mutex<Option<String>> {
    static TEST_BASE_URL: OnceLock<Mutex<Option<String>>> = OnceLock::new();

    TEST_BASE_URL.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
pub(crate) fn set_test_api_base_url(base_url: Option<String>) {
    *test_api_base_url()
        .lock()
        .expect("test api base url mutex should not poison") = base_url;
}

#[cfg(test)]
pub(crate) async fn reset_rate_limit_for_tests() {
    *rate_limit_state().lock().await = None;
}

#[cfg(test)]
mod tests {
    use super::{lookup_mac_vendor, reset_rate_limit_for_tests, set_test_api_base_url};
    use std::sync::{Mutex, OnceLock};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        static TEST_GUARD: OnceLock<Mutex<()>> = OnceLock::new();

        TEST_GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test guard should not poison")
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "current_thread")]
    async fn lookup_mac_vendor_returns_vendor_name_from_api() {
        let _guard = test_guard();
        let server = MockServer::start().await;
        set_test_api_base_url(Some(server.uri()));
        reset_rate_limit_for_tests().await;

        Mock::given(method("GET"))
            .and(path("/AA:BB:CC:DD:EE:FF"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Acme Devices Inc"))
            .mount(&server)
            .await;

        let vendor = lookup_mac_vendor("AA:BB:CC:DD:EE:FF", Some("secret-token")).await;

        assert_eq!(vendor, Some("Acme Devices Inc".to_string()));
        let requests = server.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let auth = requests[0]
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .expect("authorization header");
        assert_eq!(auth, "Bearer secret-token");
        set_test_api_base_url(None);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "current_thread")]
    async fn lookup_mac_vendor_returns_none_on_not_found() {
        let _guard = test_guard();
        let server = MockServer::start().await;
        set_test_api_base_url(Some(server.uri()));
        reset_rate_limit_for_tests().await;

        Mock::given(method("GET"))
            .and(path("/11:22:33:44:55:66"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let vendor = lookup_mac_vendor("11:22:33:44:55:66", None).await;

        assert_eq!(vendor, None);
        set_test_api_base_url(None);
    }
}
