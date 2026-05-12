use assert_cmd::Command;

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
