//! Shared state for one Kind scenario.

use super::scenario::ExpectedResponse;
use super::{Mode, reset_fixture, status};

pub(super) struct Context {
    pub(super) mode: Mode,
    pub(super) port: u16,
}

impl Context {
    pub(super) const fn new(mode: Mode, port: u16) -> Self {
        Self { mode, port }
    }

    pub(super) fn set_fixture(&self, fixture: &'static str) -> Result<(), String> {
        reset_fixture(fixture)
    }

    pub(super) async fn status(
        &self,
        headers: &[(&str, &str)],
    ) -> Result<reqwest::Response, String> {
        status(self.port, headers).await
    }

    pub(super) async fn assert_response(
        &self,
        response: reqwest::Response,
        expected: ExpectedResponse,
    ) -> Result<(), String> {
        if response.status().as_u16() != expected.status {
            return Err("kind_status_mismatch".into());
        }
        if expected.challenge != response.headers().get("accept-signature").is_some() {
            return Err("kind_challenge_mismatch".into());
        }
        if expected.status != 200 {
            return Ok(());
        }
        let body = response
            .text()
            .await
            .map_err(|_| "kind_backend_body_failed".to_owned())?;
        let body: serde_json::Value =
            serde_json::from_str(&body).map_err(|_| "kind_backend_body_invalid".to_owned())?;
        if body.get("status").and_then(serde_json::Value::as_str) != Some(expected.trusted_status) {
            return Err("kind_trusted_status_mismatch".into());
        }
        let identity = body
            .get("identity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let key_id = body
            .get("key_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if identity != expected.identity.unwrap_or_default()
            || key_id != expected.key_id.unwrap_or_default()
        {
            return Err("kind_trusted_identity_mismatch".into());
        }
        if expected.client_assertion_absent
            && expected.identity.is_none()
            && (!identity.is_empty() || !key_id.is_empty())
        {
            return Err("kind_client_assertion_forwarded".into());
        }
        Ok(())
    }
}
