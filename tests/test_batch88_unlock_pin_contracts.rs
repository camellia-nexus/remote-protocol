//! Contract and unit tests for Protocol Batch 88: CRED-005 Unlock PIN Security.

use camellia_remote_protocol::config::Config;

#[test]
fn test_unlock_pin_lifecycle_and_constant_time_verification() {
    // 1. Initial state: clear any PIN
    Config::clear_unlock_pin();
    assert!(
        !Config::has_unlock_pin(),
        "Initially should not have an unlock PIN"
    );
    assert!(
        !Config::verify_unlock_pin("123456"),
        "Verification with candidate should fail when empty"
    );
    assert!(
        !Config::verify_unlock_pin(""),
        "Verification with empty string should fail when empty"
    );

    // 2. Set an unlock PIN
    Config::set_unlock_pin("SecretPin88");
    assert!(
        Config::has_unlock_pin(),
        "Should have unlock PIN after setting"
    );

    // 3. Constant-time verification
    assert!(
        Config::verify_unlock_pin("SecretPin88"),
        "Exact PIN must verify true"
    );
    assert!(
        !Config::verify_unlock_pin("SecretPin87"),
        "Different last char must verify false"
    );
    assert!(
        !Config::verify_unlock_pin("secretpin88"),
        "Different case must verify false"
    );
    assert!(
        !Config::verify_unlock_pin("SecretPin"),
        "Shorter PIN must verify false"
    );
    assert!(
        !Config::verify_unlock_pin("SecretPin88Longer"),
        "Longer PIN must verify false"
    );
    assert!(
        !Config::verify_unlock_pin(""),
        "Empty candidate must verify false"
    );

    // 4. Overwrite PIN
    Config::set_unlock_pin("NewPin99");
    assert!(Config::has_unlock_pin());
    assert!(
        !Config::verify_unlock_pin("SecretPin88"),
        "Old PIN must no longer verify"
    );
    assert!(Config::verify_unlock_pin("NewPin99"), "New PIN must verify");

    // 5. Clear PIN
    Config::clear_unlock_pin();
    assert!(
        !Config::has_unlock_pin(),
        "Must report false after clearing PIN"
    );
    assert!(
        !Config::verify_unlock_pin("NewPin99"),
        "Cleared PIN must not verify"
    );
}
