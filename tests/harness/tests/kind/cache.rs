//! Rotation and resolver restart cases.

use super::{
    Mode, apply_mode, reset_fixture, resolver_pod, resolver_pod_identity, resolver_restart_count,
    restart_gateway, restart_resolver_container, signed_status, start_forward,
    wait_for_resolver_restart,
};

const PRIVATE_KEY_A: &str = "tests/harness/tests/kind/keys/agent-a.private.json";
const PRIVATE_KEY_B: &str = "tests/harness/tests/kind/keys/agent-b.private.json";

struct GatewayCleanup;

impl Drop for GatewayCleanup {
    fn drop(&mut self) {
        let _ = restart_gateway(Some(1));
    }
}

#[tokio::test]
#[ignore = "requires a prepared kind cluster"]
async fn rotation_replaces_removed_keys() -> Result<(), String> {
    apply_mode(Mode::Required)?;
    let forward = start_forward().await?;
    let port = forward.port();
    reset_fixture("healthy-v1")?;
    signed_status(port, 200, PRIVATE_KEY_A, &[])?;
    reset_fixture("rotated-v2")?;
    signed_status(port, 200, PRIVATE_KEY_B, &[])?;
    signed_status(port, 403, PRIVATE_KEY_A, &[])?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a prepared kind cluster"]
async fn resolver_sidecar_restart_recovers() -> Result<(), String> {
    apply_mode(Mode::Required)?;
    let _cleanup = GatewayCleanup;
    let forward = start_forward().await?;
    let port = forward.port();
    reset_fixture("healthy-v1")?;
    signed_status(port, 200, PRIVATE_KEY_A, &[])?;

    let (gateway_pod, gateway_uid) = resolver_pod_identity()?;
    let pod = resolver_pod()?;
    let previous_count = resolver_restart_count(&pod)?;
    restart_resolver_container(&pod)?;
    wait_for_resolver_restart(&pod, previous_count)?;
    let (restarted_gateway_pod, restarted_gateway_uid) = resolver_pod_identity()?;
    if restarted_gateway_pod != gateway_pod || restarted_gateway_uid != gateway_uid {
        return Err("gateway_pod_changed_during_resolver_restart".into());
    }
    reset_fixture("healthy-v1")?;
    signed_status(port, 200, PRIVATE_KEY_A, &[])?;
    Ok(())
}
