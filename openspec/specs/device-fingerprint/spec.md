# Spec: Device Fingerprint

## Requirements

### REQ-FP-1: OS Hint Field on DiscoveredHost

The system SHALL expose an `os_hint: Option<String>` field on the `DiscoveredHost` struct.

**Scenarios:**

- **Given** a `DiscoveredHost` with no OS signals
  **When** the host is serialized to JSON
  **Then** the `os_hint` field is present and null

- **Given** a `DiscoveredHost` with an OS hint of "Linux"
  **When** the host is deserialized from JSON
  **Then** `os_hint` is `Some("Linux")`

### REQ-FP-2: TTL-Based OS Inference

The system SHALL infer the operating system from the TTL value in ICMP echo reply packets.

**Scenarios:**

- **Given** an ICMP reply with TTL in range 60–64
  **When** TTL is analyzed
  **Then** the OS hint is "Linux/macOS"

- **Given** an ICMP reply with TTL in range 120–128
  **When** TTL is analyzed
  **Then** the OS hint is "Windows"

- **Given** an ICMP reply with TTL in range 250–254
  **When** TTL is analyzed
  **Then** the OS hint is "FreeBSD"

- **Given** an ICMP reply with TTL below 32
  **When** TTL is analyzed
  **Then** the OS hint is `None` (too many hops for reliable inference)

### REQ-FP-3: Banner-Based OS Inference

The system SHALL infer the operating system from service banner text using pattern matching.

**Scenarios:**

- **Given** an SSH banner containing "Ubuntu" (e.g., `SSH-2.0-OpenSSH_8.9p1 Ubuntu-4ubuntu0.5`)
  **When** `infer_os_from_banner()` is called
  **Then** it returns `Some("Ubuntu Linux")`

- **Given** an SSH banner containing "Debian"
  **When** `infer_os_from_banner()` is called
  **Then** it returns `Some("Debian Linux")`

- **Given** a banner containing "Microsoft" or "Windows"
  **When** `infer_os_from_banner()` is called
  **Then** it returns `Some("Windows")`

- **Given** a banner with no recognizable OS pattern
  **When** `infer_os_from_banner()` is called
  **Then** it returns `None`

### REQ-FP-4: Signal Priority

The system SHALL prefer banner-based OS hints over TTL-based hints when both are available.

**Scenarios:**

- **Given** a host with TTL hint "Linux/macOS" and banner hint "Ubuntu Linux"
  **When** the host's `os_hint` is resolved
  **Then** the final `os_hint` is "Ubuntu Linux"

- **Given** a host with only a TTL hint
  **When** the host's `os_hint` is resolved
  **Then** the final `os_hint` is the TTL-derived value

- **Given** a host with neither TTL nor banner hints
  **When** the host's `os_hint` is resolved
  **Then** `os_hint` is `None`

### REQ-FP-5: No New Dependencies

The implementation SHALL NOT introduce new external crate dependencies.

**Scenarios:**

- **Given** the current `Cargo.toml` dependency list
  **When** the device-fingerprint change is applied
  **Then** `Cargo.toml` dependency count is unchanged
