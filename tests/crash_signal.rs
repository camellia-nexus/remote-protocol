#![cfg(all(target_os = "linux", not(debug_assertions)))]

use camellia_remote_protocol::config::{Config, APP_NAME};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

const CHILD_ENV: &str = "CAMELLIA_CRASH_SIGNAL_TEST_CHILD";
const CHILD_CONFIG_HOME: &str = "/proc/self/cwd/config";

#[inline(never)]
fn nvidia_release_sigsegv_probe() -> ! {
    unsafe {
        libc::raise(libc::SIGSEGV);
    }
    std::process::abort();
}

#[test]
fn release_sigsegv_uses_default_os_disposition() {
    if std::env::var_os(CHILD_ENV).is_some() {
        std::env::set_var("XDG_CONFIG_HOME", CHILD_CONFIG_HOME);
        *APP_NAME.write().expect("app name lock must be available") =
            format!("CamelliaCrashSignalTest{}", std::process::id());
        let _ = Config::get_option("enable-hwcodec");

        unsafe {
            libc::signal(libc::SIGSEGV, libc::SIG_DFL);
        }
        nvidia_release_sigsegv_probe();
    }

    let root = tempfile::tempdir().expect("isolated child root must be created");

    let status = Command::new(std::env::current_exe().expect("test executable must be available"))
        .arg("--exact")
        .arg("release_sigsegv_uses_default_os_disposition")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .current_dir(root.path())
        .status()
        .expect("child test process must start");

    let config_written = root.path().join("config").exists();
    let signal = status.signal();
    let exit_code = status.code();

    assert!(
        signal == Some(libc::SIGSEGV) && !config_written,
        "signal={signal:?}, exit_code={exit_code:?}, config_written={config_written}"
    );
}
