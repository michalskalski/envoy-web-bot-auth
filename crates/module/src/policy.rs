use crate::config::Mode;

/// A syntactically uninterpretable credential differs from one that was
/// understood and conclusively rejected. Enforcing modes expose that
/// distinction as HTTP 400 versus HTTP 403.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvalidKind {
    Malformed,
    Rejected,
}

/// Why verification could not reach a cryptographic conclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnverifiedKind {
    Unsupported,
    KeyNotFound,
    Unavailable,
}

/// Bounded operational reason codes. No client controlled text is admitted
/// into metadata, metric labels, or logs through this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    Unsigned,
    IncompleteFields,
    RequestBodyUnsupported,
    RequestCapture,
    MalformedProfile,
    UnsupportedMultipleSignatures,
    MissingSignatureAgent,
    SignatureAgentNotBound,
    UnsupportedDiscoveryType,
    InvalidDiscoveryUrl,
    ProfileFieldTooLarge,
    MissingRequiredComponent,
    InvalidFreshness,
    UnsupportedAlgorithm,
    ResolverEncoding,
    ResolverUnavailable,
    ResolverResponse,
    ResolverCalloutMismatch,
    KeyNotFound,
    ResolverIdentifier,
    KeyThumbprint,
    KeyAlgorithm,
    SignatureVerification,
    Verified,
}

impl Reason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::IncompleteFields => "incomplete_fields",
            Self::RequestBodyUnsupported => "request_body_unsupported",
            Self::RequestCapture => "request_capture",
            Self::MalformedProfile => "malformed_profile",
            Self::UnsupportedMultipleSignatures => "unsupported_multiple_signatures",
            Self::MissingSignatureAgent => "missing_signature_agent",
            Self::SignatureAgentNotBound => "signature_agent_not_bound",
            Self::UnsupportedDiscoveryType => "unsupported_discovery_type",
            Self::InvalidDiscoveryUrl => "invalid_discovery_url",
            Self::ProfileFieldTooLarge => "profile_field_too_large",
            Self::MissingRequiredComponent => "missing_required_component",
            Self::InvalidFreshness => "invalid_freshness",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::ResolverEncoding => "resolver_encoding",
            Self::ResolverUnavailable => "resolver_unavailable",
            Self::ResolverResponse => "resolver_response",
            Self::ResolverCalloutMismatch => "resolver_callout_mismatch",
            Self::KeyNotFound => "key_not_found",
            Self::ResolverIdentifier => "resolver_identifier",
            Self::KeyThumbprint => "key_thumbprint",
            Self::KeyAlgorithm => "key_algorithm",
            Self::SignatureVerification => "signature_verification",
            Self::Verified => "verified",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedIdentity {
    pub(crate) identifier: String,
    pub(crate) key_id: String,
}

/// Complete authentication result for one request.
///
/// Identity fields exist only in `Verified`, making it impossible to
/// accidentally forward a resolver provided identity after any failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VerificationResult {
    NotPresent {
        reason: Reason,
    },
    Invalid {
        kind: InvalidKind,
        reason: Reason,
    },
    Unverified {
        kind: UnverifiedKind,
        reason: Reason,
    },
    Verified(VerifiedIdentity),
}

impl VerificationResult {
    pub(crate) const fn status(&self) -> &'static str {
        match self {
            Self::NotPresent { .. } => "not-present",
            Self::Invalid { .. } => "invalid",
            Self::Unverified { .. } => "unverified",
            Self::Verified(_) => "verified",
        }
    }

    pub(crate) const fn reason(&self) -> Reason {
        match self {
            Self::NotPresent { reason }
            | Self::Invalid { reason, .. }
            | Self::Unverified { reason, .. } => *reason,
            Self::Verified(_) => Reason::Verified,
        }
    }

    pub(crate) const fn identity(&self) -> Option<&VerifiedIdentity> {
        match self {
            Self::Verified(identity) => Some(identity),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Allow,
    Reject { status: u32, challenge: bool },
}

pub(crate) const fn admission(mode: Mode, result: &VerificationResult) -> Admission {
    if matches!(mode, Mode::Observe) {
        return Admission::Allow;
    }

    match result {
        VerificationResult::NotPresent { .. } => match mode {
            Mode::Observe | Mode::Optional => Admission::Allow,
            Mode::Required => Admission::Reject {
                status: 403,
                challenge: true,
            },
        },
        VerificationResult::Invalid {
            kind: InvalidKind::Malformed,
            ..
        } => Admission::Reject {
            status: 400,
            challenge: false,
        },
        VerificationResult::Invalid {
            kind: InvalidKind::Rejected,
            ..
        }
        | VerificationResult::Unverified {
            kind: UnverifiedKind::Unsupported | UnverifiedKind::KeyNotFound,
            ..
        } => Admission::Reject {
            status: 403,
            challenge: false,
        },
        VerificationResult::Unverified {
            kind: UnverifiedKind::Unavailable,
            ..
        } => Admission::Reject {
            status: 503,
            challenge: false,
        },
        VerificationResult::Verified(_) => Admission::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> VerificationResult {
        VerificationResult::Verified(VerifiedIdentity {
            identifier: "https://agent.example/keys".into(),
            key_id: "thumbprint".into(),
        })
    }

    #[test]
    fn admission_matrix_covers_every_result_subtype() {
        let cases = [
            (
                VerificationResult::NotPresent {
                    reason: Reason::Unsigned,
                },
                Admission::Allow,
                Admission::Reject {
                    status: 403,
                    challenge: true,
                },
            ),
            (
                VerificationResult::Invalid {
                    kind: InvalidKind::Malformed,
                    reason: Reason::MalformedProfile,
                },
                Admission::Reject {
                    status: 400,
                    challenge: false,
                },
                Admission::Reject {
                    status: 400,
                    challenge: false,
                },
            ),
            (
                VerificationResult::Invalid {
                    kind: InvalidKind::Rejected,
                    reason: Reason::SignatureVerification,
                },
                Admission::Reject {
                    status: 403,
                    challenge: false,
                },
                Admission::Reject {
                    status: 403,
                    challenge: false,
                },
            ),
            (
                VerificationResult::Unverified {
                    kind: UnverifiedKind::Unsupported,
                    reason: Reason::UnsupportedAlgorithm,
                },
                Admission::Reject {
                    status: 403,
                    challenge: false,
                },
                Admission::Reject {
                    status: 403,
                    challenge: false,
                },
            ),
            (
                VerificationResult::Unverified {
                    kind: UnverifiedKind::KeyNotFound,
                    reason: Reason::KeyNotFound,
                },
                Admission::Reject {
                    status: 403,
                    challenge: false,
                },
                Admission::Reject {
                    status: 403,
                    challenge: false,
                },
            ),
            (
                VerificationResult::Unverified {
                    kind: UnverifiedKind::Unavailable,
                    reason: Reason::ResolverUnavailable,
                },
                Admission::Reject {
                    status: 503,
                    challenge: false,
                },
                Admission::Reject {
                    status: 503,
                    challenge: false,
                },
            ),
            (identity(), Admission::Allow, Admission::Allow),
        ];

        for (result, optional, required) in cases {
            assert_eq!(admission(Mode::Observe, &result), Admission::Allow);
            assert_eq!(admission(Mode::Optional, &result), optional);
            assert_eq!(admission(Mode::Required, &result), required);
        }
    }

    #[test]
    fn only_verified_results_expose_identity() {
        let verified = identity();
        assert_eq!(verified.status(), "verified");
        assert_eq!(verified.reason().as_str(), "verified");
        assert!(verified.identity().is_some());

        let failed = VerificationResult::Invalid {
            kind: InvalidKind::Rejected,
            reason: Reason::InvalidFreshness,
        };
        assert_eq!(failed.status(), "invalid");
        assert!(failed.identity().is_none());
    }
}
