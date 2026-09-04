use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize, Serialize)]
struct Compatibility {
    envoy_gateway: String,
    envoy_runtime: String,
    envoy_runtime_digest: String,
    envoy_sdk_revision: String,
    protocol_revision: String,
    protocol_published: String,
    rust_toolchain: String,
    module_target: String,
    resolver_target: String,
    kubernetes_image_volume_minimum: String,
    kubernetes_init_container_fallback: String,
}

#[derive(Debug, Parser)]
struct Arguments {
    #[arg(long)]
    tag: String,
    #[arg(long)]
    repository: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value = "compatibility.toml")]
    record: PathBuf,
}

fn load_compatibility(path: &Path) -> Result<Compatibility, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let compatibility: Compatibility =
        toml::from_str(&text).map_err(|error| format!("invalid compatibility.toml: {error}"))?;

    let digest_hex = compatibility.envoy_runtime_digest.strip_prefix("sha256:");
    if compatibility.envoy_runtime_digest.len() != 71
        || digest_hex.is_none_or(|value| {
            value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(
            "invalid compatibility.toml: envoy_runtime_digest must be sha256 plus 64 hex characters"
                .to_owned(),
        );
    }
    Ok(compatibility)
}

fn generate(arguments: &Arguments) -> Result<(), String> {
    let compatibility = load_compatibility(&arguments.record)?;
    let metadata = json!({
        "tag": arguments.tag,
        "repository": arguments.repository,
        "artifacts": {
            "module": "envoy-web-bot-auth-module",
            "resolver": "web-bot-auth-resolver",
            "module_installer": "envoy-web-bot-auth-module-installer",
        },
        "compatibility": compatibility,
    });
    let mut output = serde_json::to_vec_pretty(&metadata)
        .map_err(|error| format!("cannot serialize compatibility metadata: {error}"))?;
    output.push(b'\n');
    if let Some(parent) = arguments
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    fs::write(&arguments.output, output)
        .map_err(|error| format!("cannot write {}: {error}", arguments.output.display()))
}

fn main() {
    if let Err(error) = generate(&Arguments::parse()) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_record(content: &str) -> PathBuf {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("wba-compat-{}-{id}.toml", std::process::id()));
        fs::write(&path, content).expect("temporary record can be written");
        path
    }

    const VALID: &str = include_str!("../../../../compatibility.toml");

    #[test]
    fn valid_record_is_loaded() {
        let path = temp_record(VALID);
        let compatibility = load_compatibility(&path).expect("record is valid");
        fs::remove_file(path).expect("temporary record can be removed");
        assert_eq!(compatibility.envoy_gateway, "v1.9.1");
        assert_eq!(compatibility.protocol_published, "2026-09-01");
    }

    #[test]
    fn missing_field_is_rejected() {
        let path = temp_record(&VALID.replace("envoy_gateway = \"v1.9.1\"\n", ""));
        let error = load_compatibility(&path).expect_err("missing field must fail");
        fs::remove_file(path).expect("temporary record can be removed");
        assert!(error.contains("envoy_gateway"));
    }

    #[test]
    fn non_string_field_is_rejected() {
        let path = temp_record(&VALID.replace("envoy_gateway = \"v1.9.1\"", "envoy_gateway = 1"));
        let error = load_compatibility(&path).expect_err("wrong type must fail");
        fs::remove_file(path).expect("temporary record can be removed");
        assert!(error.contains("envoy_gateway"));
    }

    #[test]
    fn malformed_digest_is_rejected() {
        let path = temp_record(&VALID.replace(
            "sha256:eb2c01c13125d1629637cb4e4cce7207009fb7cc2c8027f9742758549d15b6f4",
            "sha256:not-a-digest",
        ));
        let error = load_compatibility(&path).expect_err("malformed digest must fail");
        fs::remove_file(path).expect("temporary record can be removed");
        assert!(error.contains("envoy_runtime_digest"));
    }
}
