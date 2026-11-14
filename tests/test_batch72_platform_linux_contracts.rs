#[cfg(target_os = "linux")]
#[test]
fn test_platform002_flatpak_loginctl_argv_decomposition() {
    use camellia_remote_protocol::platform::linux::{build_loginctl_command, CMD_LOGINCTL};
    use std::ffi::OsStr;

    let expected_bin = CMD_LOGINCTL.as_str();

    // Test 1: Native non-flatpak environment
    std::env::remove_var("FLATPAK_ID");
    let cmd = build_loginctl_command(Some(&["show-session", "-p", "Type", "seat0"]));
    let program = cmd.get_program().to_string_lossy();
    assert_eq!(program, expected_bin);
    let args: Vec<&OsStr> = cmd.get_args().collect();
    assert_eq!(args, vec!["show-session", "-p", "Type", "seat0"]);

    // Test 2: Flatpak environment with FLATPAK_ID set
    std::env::set_var("FLATPAK_ID", "org.camellia_remote.CamelliaRemote");
    let cmd = build_loginctl_command(Some(&["show-session", "-p", "Type", "seat0"]));
    let program = cmd.get_program().to_string_lossy();
    assert_eq!(program, "flatpak-spawn");

    let args: Vec<&OsStr> = cmd.get_args().collect();
    // Must be distinct argv elements: --host, <loginctl-path>, show-session, -p, Type, seat0
    // Crucially, loginctl and its arguments must NEVER be joined into a single string with spaces
    assert_eq!(
        args,
        vec![
            OsStr::new("--host"),
            OsStr::new(expected_bin),
            OsStr::new("show-session"),
            OsStr::new("-p"),
            OsStr::new("Type"),
            OsStr::new("seat0")
        ]
    );

    // Test 3: Flatpak with empty args (e.g. loginctl availability check)
    let cmd = build_loginctl_command(None);
    assert_eq!(cmd.get_program().to_string_lossy(), "flatpak-spawn");
    let args: Vec<&OsStr> = cmd.get_args().collect();
    assert_eq!(args, vec![OsStr::new("--host"), OsStr::new(expected_bin)]);

    // Clean up environment
    std::env::remove_var("FLATPAK_ID");
}
