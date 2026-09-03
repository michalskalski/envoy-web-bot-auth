//! Resolver Service topology check.

use super::{EG_NAMESPACE, gateway_pods, kubectl, signed_status, start_forward, wait_until};
use std::time::Duration;

const PRIVATE_KEY: &str = "tests/harness/tests/kind/keys/agent-a.private.json";

#[tokio::test]
#[ignore = "requires a prepared kind cluster with the external resolver fixture overlay"]
async fn external_resolver_service_verifies_request() -> Result<(), String> {
    wait_until(
        Duration::from_secs(180),
        "external_resolver_still_runs_as_sidecar",
        || {
            for pod in gateway_pods()? {
                let containers = kubectl(&[
                    "get",
                    "pod",
                    "--namespace",
                    EG_NAMESPACE,
                    &pod,
                    "--output",
                    "jsonpath={.spec.containers[*].name}",
                ])?;
                if containers
                    .split_whitespace()
                    .any(|container| container == "web-bot-auth-resolver")
                {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )?;

    let forward = start_forward().await?;
    signed_status(forward.port(), 200, PRIVATE_KEY, &[])
}
