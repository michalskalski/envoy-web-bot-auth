//! Typed descriptions for the executable Kind scenarios.

const FIXTURE_AGENT_A_KEY_ID: &str = "j1Khjsy1_ooXOFJ3X3NzQmqVhrkYHOXt4_Y8vZKEQ5g";

#[derive(Clone, Copy, Debug)]
pub(super) enum Mode {
    Observe,
    Optional,
    Required,
}

impl Mode {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }

    pub(super) const fn malformed_status(self) -> u16 {
        match self {
            Self::Observe => 200,
            Self::Optional | Self::Required => 400,
        }
    }

    pub(super) const fn rejected_status(self) -> u16 {
        match self {
            Self::Observe => 200,
            Self::Optional | Self::Required => 403,
        }
    }

    pub(super) const fn unavailable_status(self) -> u16 {
        match self {
            Self::Observe => 200,
            Self::Optional | Self::Required => 503,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum FixtureState {
    Healthy,
    Malformed,
    Unavailable,
    Delayed,
}

impl FixtureState {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Healthy => "healthy-v1",
            Self::Malformed => "malformed",
            Self::Unavailable => "unavailable",
            Self::Delayed => "delayed",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum RequestCase {
    Unsigned,
    MalformedHeaders,
    Verified,
    MissingKey,
    Tampered,
    Expired,
    ResolverMalformed,
    ResolverUnavailable,
    ResolverDelayed,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ExpectedResponse {
    pub(super) status: u16,
    pub(super) challenge: bool,
    pub(super) trusted_status: &'static str,
    pub(super) identity: Option<&'static str>,
    pub(super) key_id: Option<&'static str>,
    pub(super) client_assertion_absent: bool,
}

impl RequestCase {
    pub(super) const fn fixture(self) -> FixtureState {
        match self {
            Self::ResolverMalformed => FixtureState::Malformed,
            Self::ResolverUnavailable => FixtureState::Unavailable,
            Self::ResolverDelayed => FixtureState::Delayed,
            Self::Unsigned
            | Self::MalformedHeaders
            | Self::Verified
            | Self::MissingKey
            | Self::Tampered
            | Self::Expired => FixtureState::Healthy,
        }
    }

    pub(super) const fn expected(self, mode: Mode) -> ExpectedResponse {
        let status = match self {
            Self::Unsigned => {
                if matches!(mode, Mode::Required) {
                    403
                } else {
                    200
                }
            }
            Self::Verified => 200,
            Self::MalformedHeaders => mode.malformed_status(),
            Self::MissingKey | Self::Tampered | Self::Expired => mode.rejected_status(),
            Self::ResolverMalformed | Self::ResolverUnavailable | Self::ResolverDelayed => {
                mode.unavailable_status()
            }
        };
        let challenge = matches!(self, Self::Unsigned) && matches!(mode, Mode::Required);
        let (trusted_status, identity, key_id) = match self {
            Self::Unsigned => ("not-present", None, None),
            Self::MalformedHeaders | Self::Tampered | Self::Expired => ("invalid", None, None),
            Self::Verified => (
                "verified",
                Some(
                    "https://fixture.web-bot-auth.test/.well-known/http-message-signatures-directory",
                ),
                Some(FIXTURE_AGENT_A_KEY_ID),
            ),
            Self::MissingKey
            | Self::ResolverMalformed
            | Self::ResolverUnavailable
            | Self::ResolverDelayed => ("unverified", None, None),
        };
        ExpectedResponse {
            status,
            challenge,
            trusted_status,
            identity,
            key_id,
            client_assertion_absent: true,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Scenario {
    pub(super) name: &'static str,
    pub(super) mode: Mode,
    pub(super) request: RequestCase,
}

impl Scenario {
    pub(super) const fn new(mode: Mode, request: RequestCase) -> Self {
        Self {
            name: request.name(),
            mode,
            request,
        }
    }

    pub(super) const fn expected(self) -> ExpectedResponse {
        self.request.expected(self.mode)
    }
}

impl RequestCase {
    const fn name(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::MalformedHeaders => "malformed_headers",
            Self::Verified => "verified",
            Self::MissingKey => "missing_key",
            Self::Tampered => "tampered",
            Self::Expired => "expired",
            Self::ResolverMalformed => "resolver_malformed",
            Self::ResolverUnavailable => "resolver_unavailable",
            Self::ResolverDelayed => "resolver_delayed",
        }
    }
}

pub(super) const ADMISSION_CASES: &[RequestCase] = &[
    RequestCase::Unsigned,
    RequestCase::MalformedHeaders,
    RequestCase::Verified,
    RequestCase::MissingKey,
    RequestCase::Tampered,
    RequestCase::Expired,
    RequestCase::ResolverMalformed,
    RequestCase::ResolverUnavailable,
    RequestCase::ResolverDelayed,
];
