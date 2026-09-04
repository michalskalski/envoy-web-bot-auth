//! Envoy request state and callback pipeline.

use crate::candidate::VerificationCandidate;
use crate::config::Settings;
use crate::policy::{
    Admission, InvalidKind, Reason, UnverifiedKind, VerificationResult, admission,
};
use crate::request::{RequestComponents, SignatureHeaderState, classify_signature_headers};
use crate::verify::{join_response_body, response_status, verify_resolver_response};
use envoy_proxy_dynamic_modules_rust_sdk::{
    CatchUnwind, EnvoyBuffer, EnvoyCounterVecId, EnvoyHttpFilter, HttpFilter, abi, envoy_log_error,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use web_bot_auth_protocol::{
    MAX_RESOLVE_BODY_BYTES, ResolveRequest, ResolveResponse, ResolverApiVersion,
};

pub(crate) struct WebBotAuthFilter {
    settings: Arc<Settings>,
    pending: Option<PendingVerification>,
    outcome_counter: Option<EnvoyCounterVecId>,
}

impl WebBotAuthFilter {
    pub(crate) fn new(settings: Arc<Settings>, outcome_counter: Option<EnvoyCounterVecId>) -> Self {
        Self {
            settings,
            pending: None,
            outcome_counter,
        }
    }

    fn finish<EHF: EnvoyHttpFilter>(
        &self,
        envoy_filter: &mut EHF,
        result: VerificationResult,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_headers_status {
        match self.apply_result(envoy_filter, &result) {
            Admission::Allow => {
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
            }
            Admission::Reject { .. } => {
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration
            }
        }
    }

    pub(crate) fn apply_result<EHF: EnvoyHttpFilter>(
        &self,
        envoy_filter: &mut EHF,
        result: &VerificationResult,
    ) -> Admission {
        let status = result.status();
        let reason = result.reason().as_str();
        envoy_filter.set_dynamic_metadata_string_batch(
            crate::METADATA_NAMESPACE,
            &[("status", status), ("reason", reason)],
        );
        if let Some(counter) = self.outcome_counter {
            let _ = envoy_filter.increment_counter_vec(counter, &[status, reason], 1);
        }
        envoy_filter.set_dynamic_metadata_bool(
            crate::METADATA_NAMESPACE,
            "verified",
            matches!(result, VerificationResult::Verified(_)),
        );
        if let Some(identity) = result.identity() {
            envoy_filter.set_dynamic_metadata_string_batch(
                crate::METADATA_NAMESPACE,
                &[
                    ("identity", &identity.identifier),
                    ("keyid", &identity.key_id),
                ],
            );
        }

        if self.settings.forward_identity_headers {
            envoy_filter.set_request_header(crate::HEADER_STATUS, status.as_bytes());
            if let Some(identity) = result.identity() {
                envoy_filter
                    .set_request_header(crate::HEADER_IDENTITY, identity.identifier.as_bytes());
                envoy_filter.set_request_header(crate::HEADER_KEY_ID, identity.key_id.as_bytes());
            }
        }

        let decision = admission(self.settings.mode, result);
        if let Admission::Reject { status, challenge } = decision {
            let challenge_headers: [(&str, &[u8]); 2] = [
                ("content-type", b"text/plain; charset=utf-8"),
                ("accept-signature", b"sig=(\"@method\" \"@authority\" \"@path\" \"signature-agent\";key=\"sig\");alg=\"ed25519\";tag=\"web-bot-auth\""),
            ];
            let plain_headers: [(&str, &[u8]); 1] =
                [("content-type", b"text/plain; charset=utf-8")];
            let headers = if challenge {
                &challenge_headers[..]
            } else {
                &plain_headers[..]
            };
            let body = match status {
                400 => b"malformed Web Bot Auth request\n".as_slice(),
                503 => b"Web Bot Auth verification unavailable\n".as_slice(),
                _ => b"Web Bot Auth required or invalid\n".as_slice(),
            };
            envoy_filter.send_response(status, headers, Some(body), Some("web_bot_auth_denied"));
        }
        decision
    }
}

struct PendingVerification {
    callout_id: u64,
    candidate: VerificationCandidate,
}

impl<EHF> HttpFilter<EHF> for WebBotAuthFilter
where
    EHF: EnvoyHttpFilter,
{
    fn on_request_headers(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_headers_status {
        sanitize_assertion_headers(envoy_filter);

        let has_signature = envoy_filter
            .get_request_header_value(crate::HEADER_SIGNATURE)
            .is_some();
        let has_signature_input = envoy_filter
            .get_request_header_value(crate::HEADER_SIGNATURE_INPUT)
            .is_some();
        let has_signature_agent = envoy_filter
            .get_request_header_value(crate::HEADER_SIGNATURE_AGENT)
            .is_some();

        match classify_signature_headers(has_signature, has_signature_input, has_signature_agent) {
            SignatureHeaderState::Unsigned => self.finish(
                envoy_filter,
                VerificationResult::NotPresent {
                    reason: Reason::Unsigned,
                },
            ),
            SignatureHeaderState::Incomplete => self.finish(
                envoy_filter,
                VerificationResult::Invalid {
                    kind: InvalidKind::Malformed,
                    reason: Reason::IncompleteFields,
                },
            ),
            SignatureHeaderState::Candidate => {
                if !end_of_stream {
                    return self.finish(
                        envoy_filter,
                        VerificationResult::Unverified {
                            kind: UnverifiedKind::Unsupported,
                            reason: Reason::RequestBodyUnsupported,
                        },
                    );
                }
                let request = match RequestComponents::try_from_envoy(envoy_filter) {
                    Ok(request) => request,
                    Err(_) => {
                        return self.finish(
                            envoy_filter,
                            VerificationResult::Invalid {
                                kind: InvalidKind::Malformed,
                                reason: Reason::RequestCapture,
                            },
                        );
                    }
                };
                let candidate = match VerificationCandidate::parse(
                    &request,
                    self.settings.accept_legacy_signature_agent,
                    &self.settings.required_components,
                    unix_time(),
                    self.settings.max_signature_lifetime_seconds,
                    self.settings.clock_skew_seconds,
                ) {
                    Ok(candidate) => candidate,
                    Err(error) => return self.finish(envoy_filter, error.result()),
                };
                let resolver_request = ResolveRequest {
                    api_version: ResolverApiVersion::V1,
                    discovery: candidate.discovery,
                    agent_url: candidate.signed_url.clone(),
                    key_id: candidate.key_id.clone(),
                };
                let body = match serde_json::to_vec(&resolver_request) {
                    Ok(body) => body,
                    Err(_) => {
                        return self.finish(
                            envoy_filter,
                            VerificationResult::Unverified {
                                kind: UnverifiedKind::Unavailable,
                                reason: Reason::ResolverEncoding,
                            },
                        );
                    }
                };
                if body.len() > MAX_RESOLVE_BODY_BYTES {
                    return self.finish(
                        envoy_filter,
                        VerificationResult::Invalid {
                            kind: InvalidKind::Malformed,
                            reason: Reason::ProfileFieldTooLarge,
                        },
                    );
                }
                let headers: [(&str, &[u8]); 5] = [
                    (":method", b"POST"),
                    (":path", b"/v1/resolve"),
                    ("host", b"web-bot-auth-resolver"),
                    ("content-type", b"application/json"),
                    ("accept", b"application/json"),
                ];
                let (result, callout_id) = envoy_filter.send_http_callout(
                    &self.settings.resolver.cluster,
                    &headers,
                    Some(&body),
                    self.settings.resolver.timeout_ms,
                );
                if !matches!(
                    result,
                    abi::envoy_dynamic_module_type_http_callout_init_result::Success
                ) {
                    return self.finish(
                        envoy_filter,
                        VerificationResult::Unverified {
                            kind: UnverifiedKind::Unavailable,
                            reason: Reason::ResolverUnavailable,
                        },
                    );
                }
                self.pending = Some(PendingVerification {
                    callout_id,
                    candidate,
                });
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopAllIterationAndWatermark
            }
        }
    }

    fn on_http_callout_done(
        &mut self,
        envoy_filter: &mut EHF,
        callout_id: u64,
        result: abi::envoy_dynamic_module_type_http_callout_result,
        response_headers: Option<&[(EnvoyBuffer, EnvoyBuffer)]>,
        response_body: Option<&[EnvoyBuffer]>,
    ) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if pending.callout_id != callout_id {
            envoy_log_error!("web-bot-auth reason=resolver_callout_mismatch");
            let result = VerificationResult::Unverified {
                kind: UnverifiedKind::Unavailable,
                reason: Reason::ResolverCalloutMismatch,
            };
            if matches!(self.apply_result(envoy_filter, &result), Admission::Allow) {
                envoy_filter.continue_decoding();
            }
            return;
        }
        let resolver_response = if !matches!(
            result,
            abi::envoy_dynamic_module_type_http_callout_result::Success
        ) || response_status(response_headers) != Some(200)
        {
            Err(Reason::ResolverUnavailable)
        } else {
            response_body
                .and_then(join_response_body)
                .and_then(|body| serde_json::from_slice::<ResolveResponse>(&body).ok())
                .ok_or(Reason::ResolverResponse)
        };

        let result = verify_resolver_response(pending.candidate, resolver_response);
        match self.apply_result(envoy_filter, &result) {
            Admission::Allow => envoy_filter.continue_decoding(),
            Admission::Reject { .. } => {}
        }
    }
}

pub(crate) fn sanitize_assertion_headers(envoy_filter: &mut impl EnvoyHttpFilter) {
    for header in [
        crate::HEADER_STATUS,
        crate::HEADER_IDENTITY,
        crate::HEADER_KEY_ID,
    ] {
        envoy_filter.remove_request_header(header);
    }
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

pub(crate) fn wrap<EHF>(filter: WebBotAuthFilter) -> Box<dyn HttpFilter<EHF>>
where
    EHF: EnvoyHttpFilter,
{
    Box::new(CatchUnwind::new(filter))
}
