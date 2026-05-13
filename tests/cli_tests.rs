use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;

#[test]
fn version_flag_prints_correct_version() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("netascan 0.1.0"));
}

#[test]
fn help_flag_shows_subcommands() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.arg("--help");
    let binding = cmd.assert().success();
    let output = binding.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scan"), "help should mention 'scan'");
    assert!(stdout.contains("report"), "help should mention 'report'");
    assert!(stdout.contains("serve"), "help should mention 'serve'");
    assert!(stdout.contains("update"), "help should mention 'update'");
}

// ─── Scan CLI tests (fast — no network probes) ───

#[test]
fn scan_help_shows_all_flags() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--help"]);
    let output = cmd.assert().success().get_output().stdout.clone();
    let stdout = String::from_utf8_lossy(&output);
    assert!(stdout.contains("--network"), "scan help should show --network flag");
    assert!(
        stdout.contains("--concurrency"),
        "scan help should show --concurrency flag"
    );
    assert!(
        stdout.contains("--timeout-ms"),
        "scan help should show --timeout-ms flag"
    );
    assert!(stdout.contains("--json"), "scan help should show --json flag");
}

#[test]
fn scan_network_invalid_cidr_shows_error() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--network", "not-a-cidr"]);
    cmd.assert().failure().stderr(
        predicates::str::contains("invalid")
            .or(predicates::str::contains("error").or(predicates::str::contains("failed"))),
    );
}

// ─── Scan integration tests (slow — run actual probes) ───

#[test]
#[ignore = "runs actual TCP probes (~3s)"]
fn scan_network_auto_accepted() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--network", "auto"]);
    // Should not fail to parse; actual scan may find no hosts
    cmd.assert().code(predicates::ord::eq(0).or(predicates::ord::eq(1)));
}

#[test]
#[ignore = "runs actual TCP probes (~3s)"]
fn scan_network_loopback_exits_success() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--network", "127.0.0.1/32"]);
    cmd.assert().success();
}

#[test]
#[ignore = "runs actual TCP probes (~3s)"]
fn scan_json_flag_accepted() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--network", "127.0.0.1/32", "--json"]);
    cmd.assert().success();
}

#[test]
#[ignore = "runs actual TCP probes (~3s)"]
fn scan_concurrency_flag_accepted() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--network", "127.0.0.1/32", "--concurrency", "64"]);
    cmd.assert().success();
}

#[test]
#[ignore = "runs actual TCP probes (~3s)"]
fn scan_timeout_ms_flag_accepted() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--network", "127.0.0.1/32", "--timeout-ms", "500"]);
    cmd.assert().success();
}

#[test]
#[ignore = "runs actual TCP probes (~3s)"]
fn scan_network_loopback_integration() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--network", "127.0.0.1/32", "--timeout-ms", "500"]);
    let assert = cmd.assert().success();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show table header or "No hosts discovered"
    assert!(
        stdout.contains("IP") || stdout.contains("No hosts"),
        "expected table or empty message, got: {stdout}"
    );
}

#[test]
#[ignore = "runs actual TCP probes (~3s)"]
fn scan_json_output_format() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--network", "127.0.0.1/32", "--json", "--timeout-ms", "500"]);
    let assert = cmd.assert().success();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // JSON output should be valid JSON array
    assert!(stdout.trim().starts_with('['), "expected JSON array, got: {stdout}");
}

// ─── Update CLI tests ───

#[test]
fn update_help_shows_source_flag() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["update", "--help"]);
    let output = cmd.assert().success().get_output().stdout.clone();
    let stdout = String::from_utf8_lossy(&output);
    assert!(stdout.contains("--source"), "update help should show --source flag");
}

#[test]
fn scan_help_shows_no_update_flag() {
    let mut cmd = Command::cargo_bin("netascan").unwrap();
    cmd.args(["scan", "--help"]);
    let output = cmd.assert().success().get_output().stdout.clone();
    let stdout = String::from_utf8_lossy(&output);
    assert!(stdout.contains("--no-update"), "scan help should show --no-update flag");
}
