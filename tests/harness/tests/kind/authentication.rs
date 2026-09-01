//! Admission and resolver failure matrix cases.

use super::context::Context;
use super::scenario::{ADMISSION_CASES, Mode, RequestCase, Scenario};
use super::{
    apply_mode, assert_client_assertions_are_removed, restart_gateway, signed_status_checked,
    start_forward,
};

const PRIVATE_KEY: &str = "tests/harness/tests/kind/keys/agent-a.private.json";

pub(super) async fn run_mode(mode: Mode) -> Result<(), String> {
    apply_mode(mode)?;
    restart_gateway(Some(1))?;
    let forward = start_forward().await?;
    let context = Context::new(mode, forward.port());
    for request in ADMISSION_CASES {
        let scenario = Scenario::new(mode, *request);
        eprintln!("kind scenario={}", scenario.name);
        context.set_fixture(scenario.request.fixture().name())?;
        execute(scenario, &context).await?;
    }
    Ok(())
}

async fn execute(scenario: Scenario, context: &Context) -> Result<(), String> {
    let expected = scenario.expected();
    match scenario.request {
        RequestCase::Unsigned => {
            let response = context.status(&[]).await?;
            context.assert_response(response, expected).await?;
            assert_client_assertions_are_removed(context.port, context.mode).await
        }
        RequestCase::MalformedHeaders => {
            let response = context.status(&[("signature", "malformed")]).await?;
            context.assert_response(response, expected).await
        }
        RequestCase::Verified => signed_status_checked(context.port, expected, PRIVATE_KEY, &[]),
        RequestCase::MissingKey => signed_status_checked(
            context.port,
            expected,
            PRIVATE_KEY,
            &["--key-id", "kind-missing-key"],
        ),
        RequestCase::Tampered => {
            signed_status_checked(context.port, expected, PRIVATE_KEY, &["--tamper"])
        }
        RequestCase::Expired => {
            signed_status_checked(context.port, expected, PRIVATE_KEY, &["--expired"])
        }
        RequestCase::ResolverMalformed
        | RequestCase::ResolverUnavailable
        | RequestCase::ResolverDelayed => {
            signed_status_checked(context.port, expected, PRIVATE_KEY, &[])
        }
    }
}

#[tokio::test]
#[ignore = "requires a prepared kind cluster"]
async fn admission_and_resolver_failure_matrix() -> Result<(), String> {
    for mode in [Mode::Observe, Mode::Optional, Mode::Required] {
        run_mode(mode).await?;
    }
    Ok(())
}
