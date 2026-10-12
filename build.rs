fn main() {
    println!("cargo:rerun-if-changed=migrations");
    for name in [
        "SANDBOX_PRODUCTION_NATIVE",
        "LIBSQLITE3_SYS_USE_PKG_CONFIG",
        "SQLITE3_NO_PKG_CONFIG",
        "SQLITE3_STATIC",
        "SQLITE3_LIB_DIR",
        "SQLITE3_INCLUDE_DIR",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if std::env::var_os("SANDBOX_PRODUCTION_NATIVE").is_none() {
        return;
    }
    assert_eq!(
        std::env::var("SANDBOX_PRODUCTION_NATIVE").ok().as_deref(),
        Some("1"),
        "invalid production native contract"
    );
    assert_eq!(
        std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref(),
        Some("linux"),
        "production native target must be Linux"
    );
    assert_eq!(
        std::env::var("CARGO_CFG_TARGET_ARCH").ok().as_deref(),
        Some("x86_64"),
        "production native target must be AMD64"
    );
    for (name, expected) in [
        ("LIBSQLITE3_SYS_USE_PKG_CONFIG", "1"),
        ("SQLITE3_NO_PKG_CONFIG", "1"),
        ("SQLITE3_STATIC", "1"),
        ("SQLITE3_LIB_DIR", "/opt/sandbox-sqlite/lib"),
        ("SQLITE3_INCLUDE_DIR", "/opt/sandbox-sqlite/include"),
    ] {
        assert_eq!(
            std::env::var(name).ok().as_deref(),
            Some(expected),
            "production SQLite override must be fixed"
        );
    }
    let archive = std::path::Path::new("/opt/sandbox-sqlite/lib/libsqlite3.a");
    assert!(
        archive.is_file() && !archive.is_symlink(),
        "production SQLite static archive missing"
    );
    let header = std::fs::read_to_string("/opt/sandbox-sqlite/include/sqlite3.h")
        .unwrap_or_else(|_| panic!("production SQLite header missing"));
    assert!(
        header.len() < 2 * 1024 * 1024,
        "production SQLite header bounds"
    );
    let versions: Vec<_> = header
        .lines()
        .filter(|line| line.starts_with("#define SQLITE_VERSION "))
        .collect();
    assert_eq!(
        versions,
        ["#define SQLITE_VERSION        \"3.53.4\""],
        "production SQLite version mismatch"
    );
    println!("cargo:rustc-env=SANDBOX_BUILT_SQLITE_VERSION=3.53.4");
}
