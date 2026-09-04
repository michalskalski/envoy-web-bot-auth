use std::{fs, path::PathBuf};

fn repository_file(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(name);
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {name}: {error}"))
}

fn record_value(record: &str, key: &str) -> String {
    record
        .lines()
        .map(str::trim)
        .find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name.trim() == key).then(|| value.trim().trim_matches('"').to_owned())
        })
        .unwrap_or_else(|| panic!("compatibility record has no {key}"))
}

#[test]
fn envoy_runtime_and_sdk_pins_are_consistent() {
    let record = repository_file("compatibility.toml");
    let gateway = record_value(&record, "envoy_gateway");
    let runtime = record_value(&record, "envoy_runtime");
    let digest = record_value(&record, "envoy_runtime_digest");
    let sdk = record_value(&record, "envoy_sdk_revision");

    let makefile = repository_file("Makefile");
    assert!(makefile.contains(&format!("EG_VERSION ?= {gateway}")));
    let dockerfile = repository_file("Dockerfile");
    assert!(dockerfile.contains(&format!("envoy:{runtime}@{digest}")));
    let resources = repository_file("examples/kind/resources.yaml");
    assert!(resources.contains(&format!("envoy:{runtime}@{digest}")));
    let cargo = repository_file("crates/module/Cargo.toml");
    assert!(cargo.contains(&format!("rev = \"{sdk}\"")));
}

#[test]
fn compatibility_record_documents_both_module_loading_paths() {
    let record = repository_file("compatibility.toml");
    assert_eq!(
        record_value(&record, "kubernetes_image_volume_minimum"),
        "1.35"
    );
    assert_eq!(
        record_value(&record, "kubernetes_init_container_fallback"),
        "1.34"
    );
    let base = repository_file("examples/kind/resources.yaml");
    assert!(base.contains("name: web-bot-auth-module\n              image:"));
    let fallback = repository_file("examples/kind/overlays/init-container/kustomization.yaml");
    assert!(fallback.contains("initContainers"));
    assert!(fallback.contains("emptyDir: {}"));
}

#[test]
fn workspace_packages_keep_protocol_and_artifact_boundaries_explicit() {
    let record = repository_file("compatibility.toml");
    assert_eq!(
        record_value(&record, "protocol_revision"),
        "draft-ietf-webbotauth-httpsig-protocol-00"
    );
    assert_eq!(record_value(&record, "protocol_published"), "2026-09-01");
    assert_eq!(record_value(&record, "rust_toolchain"), "1.97.1");
    assert_eq!(
        record_value(&record, "module_target"),
        "x86_64-unknown-linux-gnu"
    );
    assert_eq!(
        record_value(&record, "resolver_target"),
        "x86_64-unknown-linux-musl"
    );

    let workspace = repository_file("Cargo.toml");
    for member in [
        "crates/protocol",
        "crates/module",
        "crates/resolver",
        "tests/harness",
    ] {
        assert!(workspace.contains(member), "workspace member {member}");
    }
    let module = repository_file("crates/module/Cargo.toml");
    assert!(module.contains("crate-type = [\"cdylib\", \"rlib\"]"));
    assert!(!module.contains("axum"));
    assert!(!module.contains("reqwest"));
    let resolver = repository_file("crates/resolver/Cargo.toml");
    assert!(resolver.contains("name = \"web-bot-auth-resolver\""));
}
