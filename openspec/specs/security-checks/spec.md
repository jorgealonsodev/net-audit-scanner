# Spec: security-checks

## Requirements

### REQ-SEC-1: Default Credential Testing — HTTP

The system SHALL attempt default credential authentication against open HTTP ports (port 80 or service classified as Http). For each target, it SHALL send an HTTP GET request with a Basic Authorization header encoding each credential pair from the default list. A finding SHALL be recorded when the response status is 2xx (success) instead of 401/403 (rejected).

**Scenarios:**

- **Given** an HTTP server on port 80 that accepts `admin:admin` via Basic Auth
  **When** `check_default_credentials()` is called
  **Then** a SecurityFinding with `check_type="default_credential"` and `severity=High` is recorded

- **Given** an HTTP server that rejects all default credentials (returns 401)
  **When** `check_default_credentials()` is called
  **Then** no SecurityFinding is recorded for that port

- **Given** `CredentialsCheckConfig.enabled = false`
  **When** `check_default_credentials()` is called
  **Then** no HTTP requests are made and no findings are recorded

### REQ-SEC-2: Default Credential Testing — FTP

The system SHALL attempt default credential authentication against open FTP ports (port 21 or service classified as Ftp). For each target, it SHALL establish a raw TCP connection, send `USER <username>` and `PASS <password>` commands, and parse the server response. A finding SHALL be recorded when the response code is `230` (Login successful) instead of `530` (Authentication failed).

**Scenarios:**

- **Given** an FTP server on port 21 that accepts `admin:admin`
  **When** `check_default_credentials()` is called
  **Then** a SecurityFinding with `check_type="default_credential"` and `severity=High` is recorded

- **Given** an FTP server that rejects all default credentials (returns 530)
  **When** `check_default_credentials()` is called
  **Then** no SecurityFinding is recorded for that port

### REQ-SEC-3: Default Credential Testing — Telnet

The system SHALL attempt default credential authentication against open Telnet ports (port 23 or service classified as Telnet). For each target, it SHALL establish a raw TCP connection, wait for a login prompt, send the username, wait for a password prompt, send the password, and check for a successful shell prompt. A finding SHALL be recorded when the connection does not close and returns a prompt-like response after credentials are sent.

**Scenarios:**

- **Given** a Telnet server on port 23 that accepts `admin:admin`
  **When** `check_default_credentials()` is called
  **Then** a SecurityFinding with `check_type="default_credential"` and `severity=High` is recorded

- **Given** a Telnet server that rejects all default credentials
  **When** `check_default_credentials()` is called
  **Then** no SecurityFinding is recorded for that port

### REQ-SEC-4: SecurityFinding Model

The system SHALL provide a `SecurityFinding` struct with the following fields: `check_type` (string identifying the check performed), `severity` (enum: Critical, High, Medium, Low), `port` (u16), `service` (string identifying the target service), `description` (string with human-readable details), and `target_ip` (string with the affected host IP). The struct SHALL implement Serialize, Deserialize, Clone, and Debug.

**Scenarios:**

- **Given** a SecurityFinding is created
  **When** serialized to JSON
  **Then** all fields are present and correctly formatted

### REQ-SEC-5: Post-Scan Integration

The system SHALL execute credential checks as a post-scan step, after port scanning and CVE enrichment are complete. The findings SHALL be attached to the corresponding `DiscoveredHost` as a new `security_findings: Vec<SecurityFinding>` field. Execution SHALL be gated by `CredentialsCheckConfig.enabled`.

**Scenarios:**

- **Given** a scan completes with hosts having open HTTP/FTP/Telnet ports
  **When** the post-scan step runs with `enabled = true`
  **Then** each host's `security_findings` field contains results for applicable services

- **Given** a scan completes with `enabled = false`
  **When** the post-scan step runs
  **Then** `security_findings` is an empty Vec for all hosts

### REQ-SEC-6: Default Credential List

The system SHALL use a hardcoded default credential list for the MVP: `(admin, admin)`, `(admin, password)`, `(root, root)`, `(root, admin)`, `(root, password)`, `(guest, guest)`. The `custom_list` config field SHALL be reserved for future use and ignored in this MVP.

**Scenarios:**

- **Given** a service accepts `root:root`
  **When** `check_default_credentials()` is called
  **Then** a finding is recorded after trying `admin:admin` and `admin:password`, then `root:root`
