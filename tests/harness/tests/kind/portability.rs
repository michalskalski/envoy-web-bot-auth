//! Module loading portability cases.

use super::{EG_NAMESPACE, gateway_pods, kubectl, reset_fixture, signed_status_at, start_forward};

const PRIVATE_KEY_A: &str = "tests/harness/tests/kind/keys/agent-a.private.json";

#[tokio::test]
#[ignore = "requires a prepared kind cluster with the init-container overlay"]
async fn init_container_module_loading() -> Result<(), String> {
    let forward = start_forward().await?;
    let port = forward.port();
    reset_fixture("healthy-v1")?;
    let pods = gateway_pods()?;
    let mut checked = 0;
    for pod in pods {
        let exit_code = kubectl(&[
            "get",
            "pod",
            "--namespace",
            EG_NAMESPACE,
            &pod,
            "--output",
            "jsonpath={.status.initContainerStatuses[?(@.name==\"web-bot-auth-module-installer\")].state.terminated.exitCode}",
        ])?;
        if exit_code.is_empty() {
            continue;
        }
        checked += 1;
        if exit_code != "0" {
            return Err("module_installer_did_not_complete".into());
        }
    }
    if checked == 0 {
        return Err("module_installer_status_missing".into());
    }
    signed_status_at(
        port,
        "/",
        PRIVATE_KEY_A,
        "https://fixture.web-bot-auth.test",
        200,
        &[],
    )?;
    Ok(())
}
