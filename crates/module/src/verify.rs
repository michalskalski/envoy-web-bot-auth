//! Resolver response validation and result construction.

use crate::{
    candidate::VerificationCandidate,
    policy::{InvalidKind, Reason, UnverifiedKind, VerificationResult, VerifiedIdentity},
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyBuffer;
use web_bot_auth::keyring::{KeyRing, Thumbprintable};
use web_bot_auth_protocol::{MAX_RESOLVE_BODY_BYTES, ResolveResponse};

pub(super) fn response_status(headers: Option<&[(EnvoyBuffer, EnvoyBuffer)]>) -> Option<u32> {
    headers?.iter().find_map(|(name, value)| {
        (name.as_slice() == b":status")
            .then(|| std::str::from_utf8(value.as_slice()).ok()?.parse().ok())
            .flatten()
    })
}

pub(super) fn join_response_body(chunks: &[EnvoyBuffer]) -> Option<Vec<u8>> {
    let length = chunks.iter().try_fold(0usize, |length, chunk| {
        length.checked_add(chunk.as_slice().len())
    })?;
    if length > MAX_RESOLVE_BODY_BYTES {
        return None;
    }
    let mut body = Vec::with_capacity(length);
    for chunk in chunks {
        body.extend_from_slice(chunk.as_slice());
    }
    Some(body)
}

pub(super) fn verify_resolver_response(
    candidate: VerificationCandidate,
    response: Result<ResolveResponse, Reason>,
) -> VerificationResult {
    let response = match response {
        Ok(response) => response,
        Err(reason) => {
            return VerificationResult::Unverified {
                kind: UnverifiedKind::Unavailable,
                reason,
            };
        }
    };
    match response {
        ResolveResponse::KeyNotFound {
            normalized_identifier,
            ..
        } => {
            if normalized_identifier == candidate.normalized_identifier {
                VerificationResult::Unverified {
                    kind: UnverifiedKind::KeyNotFound,
                    reason: Reason::KeyNotFound,
                }
            } else {
                VerificationResult::Unverified {
                    kind: UnverifiedKind::Unavailable,
                    reason: Reason::ResolverIdentifier,
                }
            }
        }
        ResolveResponse::Resolved {
            normalized_identifier,
            jwk: wire_jwk,
            ..
        } => {
            if normalized_identifier != candidate.normalized_identifier {
                return VerificationResult::Unverified {
                    kind: UnverifiedKind::Unavailable,
                    reason: Reason::ResolverIdentifier,
                };
            }
            let jwk = Thumbprintable::OKP {
                crv: "Ed25519".into(),
                x: wire_jwk.x,
            };
            if jwk.b64_thumbprint() != candidate.key_id {
                return VerificationResult::Unverified {
                    kind: UnverifiedKind::Unavailable,
                    reason: Reason::KeyThumbprint,
                };
            }
            let mut keyring = KeyRing::default();
            if keyring.try_import_jwk(&jwk).is_err() {
                return VerificationResult::Unverified {
                    kind: UnverifiedKind::Unavailable,
                    reason: Reason::KeyAlgorithm,
                };
            }
            if candidate.verifier.verify(&keyring, None).is_err() {
                return VerificationResult::Invalid {
                    kind: InvalidKind::Rejected,
                    reason: Reason::SignatureVerification,
                };
            }
            VerificationResult::Verified(VerifiedIdentity {
                identifier: normalized_identifier,
                key_id: candidate.key_id,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestComponents;
    use serde::Deserialize;
    use web_bot_auth_protocol::Ed25519Jwk;

    #[derive(Deserialize)]
    struct Vector {
        request: VectorRequest,
        signature_agent: String,
        signature_input: String,
        signature: String,
    }

    #[derive(Deserialize)]
    struct VectorRequest {
        method: String,
        authority: String,
        path: String,
    }

    fn candidate() -> VerificationCandidate {
        let vector: Vector =
            serde_json::from_str(include_str!("../../../tests/vectors/draft-02-ed25519.json"))
                .expect("the official vector is valid JSON");
        let request = RequestComponents {
            method: vector.request.method,
            authority: vector.request.authority,
            path: vector.request.path,
            signature: vec![vector.signature],
            signature_input: vec![vector.signature_input],
            signature_agent: vec![vector.signature_agent],
            ..RequestComponents::from_pseudo_headers("GET", "unused", "/unused")
        };
        VerificationCandidate::parse(&request, false, &[], 1_735_690_000, u64::MAX, 0)
            .expect("the official vector is a valid candidate")
    }

    fn response(identifier: &str, x: String) -> ResolveResponse {
        ResolveResponse::Resolved {
            normalized_identifier: identifier.into(),
            jwk: Ed25519Jwk::new(x),
        }
    }

    #[test]
    fn rejects_a_resolver_identifier_mismatch_as_unavailable() {
        let candidate = candidate();
        let result = verify_resolver_response(
            candidate,
            Ok(response(
                "https://other.example/keys",
                "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".into(),
            )),
        );

        assert_eq!(
            result,
            VerificationResult::Unverified {
                kind: UnverifiedKind::Unavailable,
                reason: Reason::ResolverIdentifier,
            }
        );
        assert!(result.identity().is_none());
    }

    #[test]
    fn rejects_a_resolver_thumbprint_mismatch_as_unavailable() {
        let candidate = candidate();
        let result = verify_resolver_response(
            candidate,
            Ok(response(
                "https://signature-agent.test/.well-known/http-message-signatures-directory",
                "ArQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".into(),
            )),
        );

        assert_eq!(
            result,
            VerificationResult::Unverified {
                kind: UnverifiedKind::Unavailable,
                reason: Reason::KeyThumbprint,
            }
        );
        assert!(result.identity().is_none());
    }

    #[test]
    fn rejects_an_unusable_resolver_jwk_as_unavailable() {
        let mut candidate = candidate();
        let jwk = Ed25519Jwk::new("not-a-base64-key".into());
        candidate.key_id = jwk.b64_thumbprint();
        let result = verify_resolver_response(
            candidate,
            Ok(ResolveResponse::Resolved {
                normalized_identifier:
                    "https://signature-agent.test/.well-known/http-message-signatures-directory"
                        .into(),
                jwk,
            }),
        );

        assert_eq!(
            result,
            VerificationResult::Unverified {
                kind: UnverifiedKind::Unavailable,
                reason: Reason::KeyAlgorithm,
            }
        );
        assert!(result.identity().is_none());
    }

    #[test]
    fn accepts_a_key_not_found_response_only_for_the_expected_identifier() {
        let candidate = candidate();
        let result = verify_resolver_response(
            candidate,
            Ok(ResolveResponse::KeyNotFound {
                normalized_identifier:
                    "https://signature-agent.test/.well-known/http-message-signatures-directory"
                        .into(),
            }),
        );

        assert_eq!(
            result,
            VerificationResult::Unverified {
                kind: UnverifiedKind::KeyNotFound,
                reason: Reason::KeyNotFound,
            }
        );
    }
}
