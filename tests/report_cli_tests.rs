use assert_cmd::Command;
use predicates::prelude::*;

fn cli() -> Command {
    Command::cargo_bin("netascan").unwrap()
}

#[test]
fn report_html_to_stdout_from_file() {
    let assert = cli()
        .arg("report")
        .arg("--format")
        .arg("html")
        .arg("--input")
        .arg("tests/fixtures/scan_result.json")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<!DOCTYPE html>"), "HTML should contain DOCTYPE");
    assert!(stdout.contains("192.168.1.10"), "HTML should contain host IP");
    // Template renders CVE count (1), not individual CVE IDs
    assert!(stdout.contains("<td>1</td>"), "HTML should show 1 CVE for the host");
}

#[test]
fn report_html_to_file() {
    let output_path = "/tmp/netascan_test_report.html";
    let _ = std::fs::remove_file(output_path);

    cli()
        .arg("report")
        .arg("--format")
        .arg("html")
        .arg("--input")
        .arg("tests/fixtures/scan_result.json")
        .arg("--output")
        .arg(output_path)
        .assert()
        .success();

    let content = std::fs::read_to_string(output_path).expect("Output file should exist");
    assert!(content.contains("<!DOCTYPE html>"), "File should contain DOCTYPE");
    assert!(content.contains("192.168.1.10"), "File should contain host IP");

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn report_json_to_stdout_from_file() {
    let assert = cli()
        .arg("report")
        .arg("--format")
        .arg("json")
        .arg("--input")
        .arg("tests/fixtures/scan_result.json")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Pretty-printed JSON should have newlines
    assert!(stdout.contains('\n'), "JSON should be pretty-printed");
    assert!(stdout.contains("192.168.1.10"), "JSON should contain host IP");
    assert!(stdout.contains("generated_at"), "JSON should have generated_at");
    assert!(stdout.contains("host_count"), "JSON should have host_count");
    assert!(stdout.contains("CVE-2021-41617"), "JSON should contain CVE ID");
}

#[test]
fn report_json_to_file() {
    let output_path = "/tmp/netascan_test_report.json";
    let _ = std::fs::remove_file(output_path);

    cli()
        .arg("report")
        .arg("--format")
        .arg("json")
        .arg("--input")
        .arg("tests/fixtures/scan_result.json")
        .arg("--output")
        .arg(output_path)
        .assert()
        .success();

    let content = std::fs::read_to_string(output_path).expect("Output file should exist");
    let value: serde_json::Value = serde_json::from_str(&content).expect("Should be valid JSON");
    assert_eq!(value["host_count"], 1);
    assert_eq!(value["hosts"][0]["ip"], "192.168.1.10");

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn report_html_from_stdin() {
    let input = std::fs::read_to_string("tests/fixtures/scan_result.json").unwrap();

    let assert = cli()
        .arg("report")
        .arg("--format")
        .arg("html")
        .arg("--input")
        .arg("-")
        .write_stdin(input)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<!DOCTYPE html>"), "HTML should contain DOCTYPE");
    assert!(stdout.contains("192.168.1.10"), "HTML should contain host IP");
}

#[test]
fn report_json_from_stdin() {
    let input = std::fs::read_to_string("tests/fixtures/scan_result.json").unwrap();

    let assert = cli()
        .arg("report")
        .arg("--format")
        .arg("json")
        .arg("--input")
        .arg("-")
        .write_stdin(input)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("192.168.1.10"), "JSON should contain host IP");
    assert!(stdout.contains("host_count"), "JSON should have host_count");
}

#[test]
fn report_missing_input_file_exits_with_error() {
    cli()
        .arg("report")
        .arg("--format")
        .arg("html")
        .arg("--input")
        .arg("tests/fixtures/nonexistent.json")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Report error").or(predicate::str::contains("IO error")));
}

#[test]
fn report_last_prints_not_yet_implemented() {
    cli()
        .arg("report")
        .arg("--last")
        .arg("--input")
        .arg("tests/fixtures/scan_result.json")
        .assert()
        .success()
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn report_default_format_is_html() {
    let assert = cli()
        .arg("report")
        .arg("--input")
        .arg("tests/fixtures/scan_result.json")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<!DOCTYPE html>"), "Default format should be HTML");
}

#[test]
fn report_html_contains_full_report_structure() {
    let assert = cli()
        .arg("report")
        .arg("--format")
        .arg("html")
        .arg("--input")
        .arg("tests/fixtures/scan_result.json")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // HTML5 structure
    assert!(stdout.contains("<!DOCTYPE html>"), "Should have DOCTYPE");
    assert!(stdout.contains("</html>"), "Should have closing html tag");

    // Summary section
    assert!(stdout.contains("Hosts Scanned"), "Should have hosts label");
    assert!(stdout.contains("CVEs Found"), "Should have CVEs label");
    assert!(stdout.contains("Insecure Ports"), "Should have insecure ports label");

    // Host data from fixture
    assert!(stdout.contains("192.168.1.10"), "Should contain host IP");
    assert!(stdout.contains("server.local"), "Should contain hostname");
    assert!(stdout.contains("OpenBSD"), "Should contain vendor");

    // CVE details
    assert!(stdout.contains("CVE-2021-41617"), "Should contain CVE ID");
    assert!(stdout.contains("HIGH"), "Should show severity in uppercase");
    assert!(stdout.contains("7.8"), "Should show CVSS score");
    assert!(stdout.contains("OpenSSH sshd vulnerability"), "Should show CVE description");

    // Port details
    assert!(stdout.contains(">22<"), "Should show SSH port");
    assert!(stdout.contains(">80<"), "Should show HTTP port");
    assert!(stdout.contains("ssh"), "Should show ssh service");
    assert!(stdout.contains("http"), "Should show http service");
}

#[test]
fn report_html_to_file_contains_complete_output() {
    let output_path = "/tmp/netascan_full_report.html";
    let _ = std::fs::remove_file(output_path);

    cli()
        .arg("report")
        .arg("--format")
        .arg("html")
        .arg("--input")
        .arg("tests/fixtures/scan_result.json")
        .arg("--output")
        .arg(output_path)
        .assert()
        .success();

    let content = std::fs::read_to_string(output_path).expect("Output file should exist");

    // Full pipeline: JSON input → HTML file with all sections
    assert!(content.contains("<!DOCTYPE html>"));
    assert!(content.contains("Security Audit Report"));
    assert!(content.contains("192.168.1.10"));
    assert!(content.contains("CVE-2021-41617"));
    assert!(content.contains("server.local"));
    assert!(content.contains("OpenBSD"));
    assert!(content.contains("Devices"));
    assert!(content.contains("CVE Details"));

    let _ = std::fs::remove_file(output_path);
}
