use camellia_remote_protocol::config::{
    self, is_custom_client, is_disable_ab, is_disable_account, is_disable_group,
    is_disable_installation, is_disable_settings, store_binary_durable, Ab, AbEntry, DeviceGroup,
    Group, GroupPeer, GroupUser, HARD_SETTINGS,
};
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

static TEST_SERIAL_LOCK: Mutex<()> = Mutex::new(());

struct HardSettingsGuard {
    saved: HashMap<String, String>,
}

impl HardSettingsGuard {
    fn new() -> Self {
        let saved = HARD_SETTINGS.read().unwrap().clone();
        HARD_SETTINGS.write().unwrap().clear();
        Self { saved }
    }
}

impl Drop for HardSettingsGuard {
    fn drop(&mut self) {
        *HARD_SETTINGS.write().unwrap() = self.saved.clone();
    }
}

#[test]
fn test_config002_custom_policy_and_custom_client_semantics() {
    let _serial_lock = TEST_SERIAL_LOCK.lock().unwrap();
    let _guard = HardSettingsGuard::new();

    // 1. Default empty state: all disable policies must be false, custom client must be false
    assert!(!is_custom_client());
    assert!(!is_disable_ab());
    assert!(!is_disable_account());
    assert!(!is_disable_group());
    assert!(!is_disable_settings());
    assert!(!is_disable_installation());

    // 2. Setting disable-ab to "Y"
    HARD_SETTINGS
        .write()
        .unwrap()
        .insert("disable-ab".to_string(), "Y".to_string());
    assert!(is_custom_client());
    assert!(is_disable_ab());
    assert!(!is_disable_account());
    assert!(!is_disable_group());

    // 3. Setting disable-ab to "N"
    HARD_SETTINGS
        .write()
        .unwrap()
        .insert("disable-ab".to_string(), "N".to_string());
    assert!(is_custom_client());
    assert!(!is_disable_ab());

    // 4. Setting disable-account to "Y"
    HARD_SETTINGS
        .write()
        .unwrap()
        .insert("disable-account".to_string(), "Y".to_string());
    assert!(is_disable_account());

    // 5. Setting disable-group to "Y"
    HARD_SETTINGS
        .write()
        .unwrap()
        .insert("disable-group".to_string(), "Y".to_string());
    assert!(is_disable_group());

    // 6. Setting disable-settings and disable-installation
    HARD_SETTINGS
        .write()
        .unwrap()
        .insert("disable-settings".to_string(), "Y".to_string());
    HARD_SETTINGS
        .write()
        .unwrap()
        .insert("disable-installation".to_string(), "Y".to_string());
    assert!(is_disable_settings());
    assert!(is_disable_installation());

    // 7. Clearing hard settings restores default non-custom state
    HARD_SETTINGS.write().unwrap().clear();
    assert!(!is_custom_client());
    assert!(!is_disable_ab());
    assert!(!is_disable_account());
    assert!(!is_disable_group());
}

#[test]
fn test_config003_address_book_and_group_atomic_storage_and_roundtrip() {
    let _serial_lock = TEST_SERIAL_LOCK.lock().unwrap();
    // 1. Test Ab roundtrip
    Ab::remove();
    let initial_ab = Ab::load();
    assert!(initial_ab.access_token.is_empty());
    assert!(initial_ab.ab_entries.is_empty());

    let entry1 = AbEntry {
        guid: "personal-test-entry-1".to_string(),
        name: "Test Entry 1".to_string(),
        ..Default::default()
    };
    let test_ab = Ab {
        access_token: "test-token-12345".to_string(),
        ab_entries: vec![entry1],
    };
    let ab_json = serde_json::to_string(&test_ab).expect("serialize ab");
    Ab::try_store(&ab_json).expect("try_store ab must succeed");

    let loaded_ab = Ab::load();
    assert_eq!(loaded_ab.access_token, "test-token-12345");
    assert_eq!(loaded_ab.ab_entries.len(), 1);
    assert_eq!(loaded_ab.ab_entries[0].guid, "personal-test-entry-1");
    assert_eq!(loaded_ab.ab_entries[0].name, "Test Entry 1");

    // Clean up
    Ab::remove();
    let after_remove = Ab::load();
    assert!(after_remove.access_token.is_empty());
    assert!(after_remove.ab_entries.is_empty());

    // 2. Test Group roundtrip
    Group::remove();
    let initial_group = Group::load();
    assert!(initial_group.users.is_empty());
    assert!(initial_group.peers.is_empty());
    assert!(initial_group.device_groups.is_empty());

    let user = GroupUser {
        name: "admin".to_string(),
        display_name: "Admin User".to_string(),
    };
    let peer = GroupPeer {
        id: "peer-200".to_string(),
        username: "desktop-host".to_string(),
        ..Default::default()
    };
    let device_group = DeviceGroup {
        name: "Production Servers".to_string(),
    };
    let test_group = Group {
        access_token: "group-token-abc".to_string(),
        users: vec![user],
        peers: vec![peer],
        device_groups: vec![device_group],
    };
    let group_json = serde_json::to_string(&test_group).expect("serialize group");
    Group::try_store(&group_json).expect("try_store group must succeed");

    let loaded_group = Group::load();
    assert_eq!(loaded_group.access_token, "group-token-abc");
    assert_eq!(loaded_group.users.len(), 1);
    assert_eq!(loaded_group.users[0].name, "admin");
    assert_eq!(loaded_group.users[0].display_name, "Admin User");
    assert_eq!(loaded_group.peers.len(), 1);
    assert_eq!(loaded_group.peers[0].id, "peer-200");
    assert_eq!(loaded_group.device_groups.len(), 1);
    assert_eq!(loaded_group.device_groups[0].name, "Production Servers");

    // Clean up
    Group::remove();
    let group_after_remove = Group::load();
    assert!(group_after_remove.users.is_empty());
    assert!(group_after_remove.peers.is_empty());
    assert!(group_after_remove.device_groups.is_empty());
}

#[test]
fn test_config003_transient_failure_preserves_file_without_deletion() {
    let _serial_lock = TEST_SERIAL_LOCK.lock().unwrap();
    // 1. Address Book: write corrupted data to storage file
    Ab::remove();
    let ab_path = config::Config::path(format!("{}_ab", config::APP_NAME.read().unwrap().clone()));
    fs::write(&ab_path, b"corrupted-non-encrypted-payload").expect("write corrupted ab payload");
    assert!(ab_path.exists());

    // Calling Ab::load() encounters decryption error.
    // CONFIG-003 guarantees it returns default WITHOUT deleting the file.
    let loaded = Ab::load();
    assert!(loaded.access_token.is_empty());
    assert!(loaded.ab_entries.is_empty());
    assert!(
        ab_path.exists(),
        "Corrupted file must NOT be deleted upon load error (CONFIG-003)"
    );

    // Explicit remove MUST delete the file
    Ab::remove();
    assert!(
        !ab_path.exists(),
        "Ab::remove() must delete the file when requested"
    );

    // 2. Group: write corrupted data to storage file
    Group::remove();
    let group_path = config::Config::path(format!(
        "{}_group",
        config::APP_NAME.read().unwrap().clone()
    ));
    fs::write(&group_path, b"corrupted-non-encrypted-group-payload")
        .expect("write corrupted group payload");
    assert!(group_path.exists());

    let loaded_group = Group::load();
    assert!(loaded_group.users.is_empty());
    assert!(
        group_path.exists(),
        "Corrupted group file must NOT be deleted upon load error (CONFIG-003)"
    );

    // Explicit remove MUST delete the file
    Group::remove();
    assert!(
        !group_path.exists(),
        "Group::remove() must delete the file when requested"
    );
}

#[test]
fn test_config003_store_binary_durable_atomic_and_permissions() {
    let _serial_lock = TEST_SERIAL_LOCK.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "camellia_test_config003_{}_{:x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    let target_file = temp_dir.join("subfolder").join("durable_data.bin");

    let payload = b"Hello, durable and atomic world!";
    store_binary_durable(&target_file, payload).expect("store_binary_durable must succeed");

    assert!(target_file.exists());
    let read_back = fs::read(&target_file).expect("read back file");
    assert_eq!(read_back, payload);

    // Ensure no lingering temporary files in parent directory
    let parent = target_file.parent().unwrap();
    let mut temp_files_count = 0;
    for entry in fs::read_dir(parent).expect("read parent dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".tmp") {
            temp_files_count += 1;
        }
    }
    assert_eq!(
        temp_files_count, 0,
        "No temporary files should linger after successful durable write"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&target_file).expect("metadata").permissions();
        let mode = perms.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Target file must have restrictive 0600 permissions on Unix, got {:o}",
            mode
        );
    }

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}
