//! SecurityPolicy and rate-limit composition cases.

use super::{
    AGENT_B, EG_NAMESPACE, Mode, apply_composition, apply_mode, apply_rate_policy,
    composition_cleanup, flush_redis, gateway_pods, kubectl, rate_limit_deployment, reset_fixture,
    restart_gateway, signed_status_at, start_forward, start_pod_forward, status_at,
    wait_for_deployment_replicas, wait_for_gateway_pods,
};

const PRIVATE_KEY_A: &str = "tests/harness/tests/kind/keys/agent-a.private.json";
const PRIVATE_KEY_B: &str = "tests/harness/tests/kind/keys/agent-b.private.json";

#[tokio::test]
#[ignore = "requires a prepared kind cluster with the composition overlay"]
async fn envoy_security_policy_consumes_verified_identity() -> Result<(), String> {
    let _cleanup = composition_cleanup();
    apply_mode(Mode::Observe)?;
    apply_composition()?;
    let forward = start_forward().await?;
    let port = forward.port();
    reset_fixture("healthy-v1")?;

    let unsigned = status_at(port, "/composition/auth", &[]).await?;
    if unsigned.status().as_u16() != 403 {
        return Err("composition_unsigned_was_allowed".into());
    }
    let forged = status_at(
        port,
        "/composition/auth",
        &[
            ("x-web-bot-auth-status", "verified"),
            (
                "x-web-bot-auth-identity",
                "https://fixture.web-bot-auth.test/.well-known/http-message-signatures-directory",
            ),
            ("x-web-bot-auth-keyid", "attacker-key"),
        ],
    )
    .await?;
    if forged.status().as_u16() != 403 {
        return Err("composition_forged_identity_was_allowed".into());
    }

    signed_status_at(
        port,
        "/composition/auth",
        PRIVATE_KEY_A,
        "https://fixture.web-bot-auth.test",
        200,
        &[],
    )?;
    signed_status_at(port, "/composition/auth", PRIVATE_KEY_B, AGENT_B, 403, &[])?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a prepared kind cluster with the composition overlay"]
async fn local_rate_limit_is_per_proxy_and_not_identity_keyed() -> Result<(), String> {
    let _cleanup = composition_cleanup();
    apply_mode(Mode::Observe)?;
    apply_composition()?;
    apply_rate_policy("examples/kind/composition/local-catchall.yaml", 2)?;

    let pods = gateway_pods()?;
    if pods.len() < 2 {
        return Err("two_gateway_pods_required".into());
    }
    let first = start_pod_forward(&pods[0]).await?;
    let second = start_pod_forward(&pods[1]).await?;
    for port in [first.port(), second.port()] {
        for expected in [200, 200, 429] {
            let response = status_at(port, "/composition/quota", &[]).await?;
            if response.status().as_u16() != expected {
                return Err("local_per_proxy_limit_mismatch".into());
            }
        }
    }
    drop(second);
    drop(first);
    restart_gateway(Some(1))?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a prepared kind cluster with Redis-backed global rate limiting"]
async fn global_rate_limit_shares_identity_across_proxies() -> Result<(), String> {
    let _cleanup = composition_cleanup();
    apply_mode(Mode::Observe)?;
    apply_composition()?;
    let rate_limit = rate_limit_deployment()?;
    kubectl(&[
        "scale",
        "deployment",
        &rate_limit,
        "--namespace",
        EG_NAMESPACE,
        "--replicas=1",
    ])?;
    wait_for_deployment_replicas(EG_NAMESPACE, &rate_limit, 1)?;
    apply_rate_policy("examples/kind/composition/global-identity.yaml", 2)?;
    reset_fixture("healthy-v1")?;
    flush_redis()?;
    wait_for_gateway_pods(2)?;

    let pods = gateway_pods()?;
    if pods.len() < 2 {
        return Err("two_gateway_pods_required".into());
    }
    let first = start_pod_forward(&pods[0]).await?;
    let second = start_pod_forward(&pods[1]).await?;
    signed_status_at(
        first.port(),
        "/composition/quota",
        PRIVATE_KEY_A,
        "https://fixture.web-bot-auth.test",
        200,
        &[],
    )?;
    signed_status_at(
        second.port(),
        "/composition/quota",
        PRIVATE_KEY_A,
        "https://fixture.web-bot-auth.test",
        200,
        &[],
    )?;
    signed_status_at(
        first.port(),
        "/composition/quota",
        PRIVATE_KEY_A,
        "https://fixture.web-bot-auth.test",
        429,
        &[],
    )?;
    signed_status_at(
        second.port(),
        "/composition/quota",
        PRIVATE_KEY_B,
        AGENT_B,
        200,
        &[],
    )?;

    kubectl(&[
        "scale",
        "deployment",
        &rate_limit,
        "--namespace",
        EG_NAMESPACE,
        "--replicas=0",
    ])?;
    wait_for_deployment_replicas(EG_NAMESPACE, &rate_limit, 0)?;
    signed_status_at(
        first.port(),
        "/composition/quota",
        PRIVATE_KEY_B,
        AGENT_B,
        200,
        &[],
    )?;
    kubectl(&[
        "scale",
        "deployment",
        &rate_limit,
        "--namespace",
        EG_NAMESPACE,
        "--replicas=1",
    ])?;
    wait_for_deployment_replicas(EG_NAMESPACE, &rate_limit, 1)?;
    drop(second);
    drop(first);
    restart_gateway(Some(1))?;
    Ok(())
}
