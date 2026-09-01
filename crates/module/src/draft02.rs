use crate::RequestComponents;
use crate::policy::{InvalidKind, Reason, UnverifiedKind, VerificationResult};
use web_bot_auth::WebBotAuthVerifier;
use web_bot_auth::components::{CoveredComponent, DerivedComponent, HTTPFieldParameters};
use web_bot_auth_protocol::{DiscoveryMechanism, MAX_KEY_ID_BYTES, parse_discovery_target};

#[derive(Clone, Debug)]
pub(crate) struct Draft02Candidate {
    pub(crate) verifier: WebBotAuthVerifier,
    pub(crate) discovery: DiscoveryMechanism,
    pub(crate) signed_url: String,
    pub(crate) normalized_identifier: String,
    pub(crate) key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CandidateError {
    Malformed,
    /// Draft 02 permits multiple Web Bot Auth signatures. Version 1 supports
    /// one because the dependency selects one label, the filter tracks one
    /// resolver call, and the trusted output represents one identity.
    MultipleSignatures,
    MissingSignatureAgent,
    SignatureAgentNotBound,
    UnsupportedDiscoveryType,
    InvalidDiscoveryUrl,
    ProfileFieldTooLarge,
    MissingRequiredComponent,
    InvalidFreshness,
    UnsupportedAlgorithm,
}

impl CandidateError {
    pub(crate) fn result(&self) -> VerificationResult {
        match self {
            Self::Malformed => VerificationResult::Invalid {
                kind: InvalidKind::Malformed,
                reason: Reason::MalformedProfile,
            },
            Self::MultipleSignatures => VerificationResult::Unverified {
                kind: UnverifiedKind::Unsupported,
                reason: Reason::UnsupportedMultipleSignatures,
            },
            Self::MissingSignatureAgent => VerificationResult::Invalid {
                // A readable dictionary without our label fails binding.
                kind: InvalidKind::Rejected,
                reason: Reason::MissingSignatureAgent,
            },
            Self::SignatureAgentNotBound => VerificationResult::Invalid {
                kind: InvalidKind::Rejected,
                reason: Reason::SignatureAgentNotBound,
            },
            Self::UnsupportedDiscoveryType => VerificationResult::Unverified {
                kind: UnverifiedKind::Unsupported,
                reason: Reason::UnsupportedDiscoveryType,
            },
            Self::InvalidDiscoveryUrl => VerificationResult::Invalid {
                kind: InvalidKind::Rejected,
                reason: Reason::InvalidDiscoveryUrl,
            },
            Self::ProfileFieldTooLarge => VerificationResult::Invalid {
                kind: InvalidKind::Malformed,
                reason: Reason::ProfileFieldTooLarge,
            },
            Self::MissingRequiredComponent => VerificationResult::Invalid {
                kind: InvalidKind::Rejected,
                reason: Reason::MissingRequiredComponent,
            },
            Self::InvalidFreshness => VerificationResult::Invalid {
                kind: InvalidKind::Rejected,
                reason: Reason::InvalidFreshness,
            },
            Self::UnsupportedAlgorithm => VerificationResult::Unverified {
                kind: UnverifiedKind::Unsupported,
                reason: Reason::UnsupportedAlgorithm,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignatureAgentForm {
    Dictionary,
    LegacyItem,
}

struct SelectedAgent {
    item: sfv::Item,
    form: SignatureAgentForm,
}

impl Draft02Candidate {
    pub(crate) fn parse(
        request: &RequestComponents,
        accept_legacy: bool,
        required_components: &[String],
        now: i64,
        max_lifetime: u64,
        clock_skew: u64,
    ) -> Result<Self, CandidateError> {
        let profile_label = profile_signature_label(&request.signature_input)?;
        let expected_agent_key =
            signature_agent_key_from_input(&request.signature_input, &profile_label)?;
        let agent = select_agent(
            &request.signature_agent,
            expected_agent_key.as_deref(),
            accept_legacy,
        )?;
        let verifier = WebBotAuthVerifier::parse(request).map_err(|_| CandidateError::Malformed)?;
        let parsed = verifier.get_parsed_label();
        let label = parsed.label.as_str();
        if label != profile_label {
            return Err(CandidateError::Malformed);
        }
        let agent_key = signed_agent_member_key(&parsed.base.components)?;
        if agent_key != expected_agent_key {
            return Err(CandidateError::Malformed);
        }
        let details = &parsed.base.parameters.details;

        if !supported_algorithm(&parsed.base.parameters.raw) {
            return Err(CandidateError::UnsupportedAlgorithm);
        }
        validate_freshness(
            details.created,
            details.expires,
            now,
            max_lifetime,
            clock_skew,
        )?;
        validate_coverage(
            &parsed.base.components,
            agent_key.as_deref(),
            agent.form,
            required_components,
        )?;

        let key_id = details.keyid.clone().ok_or(CandidateError::Malformed)?;
        if key_id.is_empty() {
            return Err(CandidateError::Malformed);
        }
        let (signed_url, discovery) = parse_agent(agent.item)?;
        if key_id.len() > MAX_KEY_ID_BYTES {
            return Err(CandidateError::ProfileFieldTooLarge);
        }
        let target =
            parse_discovery_target(&signed_url, discovery).map_err(|error| match error {
                web_bot_auth_protocol::DiscoveryUrlError::TooLong => {
                    CandidateError::ProfileFieldTooLarge
                }
                _ => CandidateError::InvalidDiscoveryUrl,
            })?;
        let normalized_identifier = target.normalized_identifier;

        Ok(Self {
            verifier,
            discovery,
            signed_url,
            normalized_identifier,
            key_id,
        })
    }
}

fn profile_signature_label(values: &[String]) -> Result<String, CandidateError> {
    let mut profile_labels = Vec::new();
    for value in values {
        let dictionary = sfv::Parser::new(value)
            .parse_dictionary()
            .map_err(|_| CandidateError::Malformed)?;
        for (label, entry) in dictionary {
            if let sfv::ListEntry::InnerList(list) = entry
                && list
                    .params
                    .get("tag")
                    .and_then(|value| value.as_string())
                    .is_some_and(|tag| tag.as_str() == "web-bot-auth")
            {
                profile_labels.push(label.as_str().to_owned());
            }
        }
    }
    match profile_labels.len() {
        0 => Err(CandidateError::Malformed),
        1 => Ok(profile_labels.remove(0)),
        _ => Err(CandidateError::MultipleSignatures),
    }
}

fn validate_freshness(
    created: Option<i64>,
    expires: Option<i64>,
    now: i64,
    max_lifetime: u64,
    clock_skew: u64,
) -> Result<(), CandidateError> {
    let created = created.ok_or(CandidateError::InvalidFreshness)?;
    let expires = expires.ok_or(CandidateError::InvalidFreshness)?;
    let skew = i64::try_from(clock_skew).map_err(|_| CandidateError::InvalidFreshness)?;
    let lifetime = expires
        .checked_sub(created)
        .ok_or(CandidateError::InvalidFreshness)?;
    if lifetime < 0
        || u64::try_from(lifetime)
            .ok()
            .is_none_or(|value| value > max_lifetime)
        || created > now.saturating_add(skew)
        || expires < now.saturating_sub(skew)
    {
        return Err(CandidateError::InvalidFreshness);
    }
    Ok(())
}

fn validate_coverage(
    components: &indexmap::IndexMap<CoveredComponent, String>,
    agent_key: Option<&str>,
    agent_form: SignatureAgentForm,
    required_components: &[String],
) -> Result<(), CandidateError> {
    let mut authority_or_target = false;
    let mut bound_agent = false;
    let mut legacy_agent = false;
    let mut names = Vec::new();

    for component in components.keys() {
        match component {
            CoveredComponent::Derived(DerivedComponent::Method { req: false }) => {
                names.push("@method");
            }
            CoveredComponent::Derived(DerivedComponent::Path { req: false }) => {
                names.push("@path");
            }
            CoveredComponent::Derived(DerivedComponent::TargetUri { req: false }) => {
                authority_or_target = true;
                names.push("@target-uri");
            }
            CoveredComponent::Derived(DerivedComponent::Authority { req: false }) => {
                authority_or_target = true;
                names.push("@authority");
            }
            CoveredComponent::HTTP(field) => {
                names.push(field.name.as_str());
                if field.name == "signature-agent" {
                    match field.parameters.0.as_slice() {
                        [HTTPFieldParameters::Key(key)]
                            if agent_key.is_some_and(|expected| expected == key) =>
                        {
                            bound_agent = true;
                        }
                        [] => legacy_agent = true,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if !authority_or_target {
        return Err(CandidateError::MissingRequiredComponent);
    }
    let agent_is_bound = match agent_form {
        SignatureAgentForm::Dictionary => bound_agent,
        SignatureAgentForm::LegacyItem => legacy_agent,
    };
    if !agent_is_bound {
        return Err(CandidateError::SignatureAgentNotBound);
    }
    for required in required_components {
        if !names.contains(&required.as_str()) {
            return Err(CandidateError::MissingRequiredComponent);
        }
    }
    Ok(())
}

fn signed_agent_member_key(
    components: &indexmap::IndexMap<CoveredComponent, String>,
) -> Result<Option<String>, CandidateError> {
    components
        .keys()
        .find_map(|component| match component {
            CoveredComponent::HTTP(field) if field.name == "signature-agent" => {
                Some(match field.parameters.0.as_slice() {
                    [] => Ok(None),
                    [HTTPFieldParameters::Key(key)] => Ok(Some(key.clone())),
                    _ => Err(CandidateError::Malformed),
                })
            }
            _ => None,
        })
        .unwrap_or(Err(CandidateError::SignatureAgentNotBound))
}

fn signature_agent_key_from_input(
    values: &[String],
    label: &str,
) -> Result<Option<String>, CandidateError> {
    for value in values {
        let dictionary = sfv::Parser::new(value)
            .parse_dictionary()
            .map_err(|_| CandidateError::Malformed)?;
        let Some(sfv::ListEntry::InnerList(list)) = dictionary.get(label) else {
            continue;
        };
        for item in &list.items {
            let component: CoveredComponent = (*item)
                .clone()
                .try_into()
                .map_err(|_| CandidateError::Malformed)?;
            if let CoveredComponent::HTTP(field) = component
                && field.name == "signature-agent"
            {
                return match field.parameters.0.as_slice() {
                    [] => Ok(None),
                    [HTTPFieldParameters::Key(key)] => Ok(Some(key.clone())),
                    _ => Err(CandidateError::Malformed),
                };
            }
        }
        return Err(CandidateError::SignatureAgentNotBound);
    }
    Err(CandidateError::Malformed)
}

fn supported_algorithm(parameters: &sfv::Parameters) -> bool {
    match parameters.get("alg") {
        None => true,
        Some(value) => value
            .as_string()
            .is_some_and(|algorithm| algorithm.as_str() == "ed25519"),
    }
}

fn select_agent(
    values: &[String],
    agent_key: Option<&str>,
    accept_legacy: bool,
) -> Result<SelectedAgent, CandidateError> {
    let mut dictionary = sfv::Dictionary::new();
    let mut dictionary_valid = true;
    for value in values {
        match sfv::Parser::new(value).parse_dictionary() {
            Ok(parsed) => dictionary.extend(parsed),
            Err(_) => {
                dictionary_valid = false;
                break;
            }
        }
    }
    if dictionary_valid {
        return match agent_key.and_then(|key| dictionary.get(key)) {
            Some(sfv::ListEntry::Item(item)) => Ok(SelectedAgent {
                item: item.clone(),
                form: SignatureAgentForm::Dictionary,
            }),
            Some(sfv::ListEntry::InnerList(_)) => Err(CandidateError::Malformed),
            None => Err(CandidateError::MissingSignatureAgent),
        };
    }
    if accept_legacy && agent_key.is_none() && values.len() == 1 {
        return sfv::Parser::new(&values[0])
            .parse_item()
            .map(|item| SelectedAgent {
                item,
                form: SignatureAgentForm::LegacyItem,
            })
            .map_err(|_| CandidateError::Malformed);
    }
    Err(CandidateError::Malformed)
}

fn parse_agent(item: sfv::Item) -> Result<(String, DiscoveryMechanism), CandidateError> {
    let signed_url = item
        .bare_item
        .as_string()
        .ok_or(CandidateError::Malformed)?
        .as_str()
        .to_owned();
    let discovery_type = match item.params.get("type") {
        None => DiscoveryMechanism::Directory,
        Some(value) => match value.as_token().map(|token| token.as_str()) {
            Some("directory") => DiscoveryMechanism::Directory,
            Some("jwks_uri") => DiscoveryMechanism::JwksUri,
            Some("cimd") => DiscoveryMechanism::Cimd,
            _ => return Err(CandidateError::UnsupportedDiscoveryType),
        },
    };
    Ok((signed_url, discovery_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use web_bot_auth::keyring::{Algorithm, KeyRing, Thumbprintable};

    fn request(agent: &str, signature_input: &str) -> RequestComponents {
        RequestComponents {
            signature: vec!["sig1=:AA==:".into()],
            signature_input: vec![signature_input.into()],
            signature_agent: vec![agent.into()],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/robots.txt")
        }
    }

    fn valid_input() -> &'static str {
        r#"sig1=("@method" "@authority" "@path" "signature-agent";key="sig1");created=1735689600;expires=1735693200;keyid="test-key";alg="ed25519";tag="web-bot-auth""#
    }

    fn minimum_input(component: &str) -> String {
        format!(
            r#"sig1=("{component}" "signature-agent";key="sig1");created=1735689600;expires=1735693200;keyid="test-key";tag="web-bot-auth""#
        )
    }

    #[test]
    fn every_candidate_error_owns_its_security_classification() {
        let cases = [
            (
                CandidateError::Malformed,
                InvalidKind::Malformed,
                Reason::MalformedProfile,
            ),
            (
                CandidateError::MissingSignatureAgent,
                InvalidKind::Rejected,
                Reason::MissingSignatureAgent,
            ),
            (
                CandidateError::SignatureAgentNotBound,
                InvalidKind::Rejected,
                Reason::SignatureAgentNotBound,
            ),
            (
                CandidateError::InvalidDiscoveryUrl,
                InvalidKind::Rejected,
                Reason::InvalidDiscoveryUrl,
            ),
            (
                CandidateError::ProfileFieldTooLarge,
                InvalidKind::Malformed,
                Reason::ProfileFieldTooLarge,
            ),
            (
                CandidateError::MissingRequiredComponent,
                InvalidKind::Rejected,
                Reason::MissingRequiredComponent,
            ),
            (
                CandidateError::InvalidFreshness,
                InvalidKind::Rejected,
                Reason::InvalidFreshness,
            ),
        ];
        for (error, expected_kind, expected_reason) in cases {
            assert_eq!(
                error.result(),
                VerificationResult::Invalid {
                    kind: expected_kind,
                    reason: expected_reason,
                }
            );
        }

        for (error, expected_reason) in [
            (
                CandidateError::MultipleSignatures,
                Reason::UnsupportedMultipleSignatures,
            ),
            (
                CandidateError::UnsupportedDiscoveryType,
                Reason::UnsupportedDiscoveryType,
            ),
            (
                CandidateError::UnsupportedAlgorithm,
                Reason::UnsupportedAlgorithm,
            ),
        ] {
            assert_eq!(
                error.result(),
                VerificationResult::Unverified {
                    kind: UnverifiedKind::Unsupported,
                    reason: expected_reason,
                }
            );
        }
    }

    #[test]
    fn legacy_mode_does_not_weaken_dictionary_binding() {
        use web_bot_auth::components::{HTTPField, HTTPFieldParametersSet};

        let mut components = indexmap::IndexMap::new();
        components.insert(
            CoveredComponent::Derived(DerivedComponent::Method { req: false }),
            String::new(),
        );
        components.insert(
            CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
            String::new(),
        );
        components.insert(
            CoveredComponent::Derived(DerivedComponent::Path { req: false }),
            String::new(),
        );
        components.insert(
            CoveredComponent::HTTP(HTTPField {
                name: "signature-agent".into(),
                parameters: HTTPFieldParametersSet(vec![]),
            }),
            String::new(),
        );

        assert_eq!(
            validate_coverage(
                &components,
                Some("sig1"),
                SignatureAgentForm::Dictionary,
                &[]
            ),
            Err(CandidateError::SignatureAgentNotBound),
        );
        assert_eq!(
            validate_coverage(&components, None, SignatureAgentForm::LegacyItem, &[]),
            Ok(()),
        );

        assert_eq!(
            select_agent(
                &[r#"sig1="https://agent.example""#.into()],
                Some("sig1"),
                true,
            )
            .expect("dictionary parses")
            .form,
            SignatureAgentForm::Dictionary,
        );
        assert_eq!(
            select_agent(&[r#""https://agent.example""#.into()], None, true)
                .expect("legacy item parses")
                .form,
            SignatureAgentForm::LegacyItem,
        );
    }

    #[test]
    fn accepts_the_protocol_minimum_coverage() {
        for component in ["@authority", "@target-uri"] {
            let candidate = Draft02Candidate::parse(
                &request(r#"sig1="https://agent.example""#, &minimum_input(component)),
                false,
                &[],
                1735690000,
                86_400,
                5,
            )
            .expect("authority or target URI plus the agent member is sufficient");
            assert_eq!(candidate.key_id, "test-key");
        }
    }

    #[test]
    fn accepts_absent_algorithm_for_the_ed25519_profile() {
        let input = valid_input().replace(";alg=\"ed25519\"", "");
        Draft02Candidate::parse(
            &request(r#"sig1="https://agent.example""#, &input),
            false,
            &[],
            1735690000,
            86_400,
            5,
        )
        .expect("an absent algorithm uses the profile's Ed25519 key type");
    }

    #[test]
    fn rejects_an_incompatible_stated_algorithm() {
        let input = valid_input().replace(";alg=\"ed25519\"", ";alg=\"rsa-pss-sha512\"");
        assert_eq!(
            Draft02Candidate::parse(
                &request(r#"sig1="https://agent.example""#, &input),
                false,
                &[],
                1735690000,
                86_400,
                5,
            )
            .expect_err("the Ed25519 profile rejects another stated algorithm"),
            CandidateError::UnsupportedAlgorithm,
        );
    }

    #[test]
    fn parses_typed_discovery_and_normalizes_identifiers() {
        let candidate = Draft02Candidate::parse(
            &request(
                r#"sig1="https://Agent.Example:443/keys?roll=2#ignored";type=jwks_uri"#,
                valid_input(),
            ),
            false,
            &[],
            1735690000,
            86_400,
            5,
        )
        .expect("candidate parses");
        assert_eq!(candidate.discovery, DiscoveryMechanism::JwksUri);
        assert_eq!(
            candidate.normalized_identifier,
            "https://agent.example/keys"
        );
        assert_eq!(
            candidate.signed_url,
            "https://Agent.Example:443/keys?roll=2#ignored"
        );
    }

    #[test]
    fn directory_requires_an_origin_and_resolves_the_well_known_uri() {
        let candidate = Draft02Candidate::parse(
            &request(r#"sig1="https://agent.example/""#, valid_input()),
            false,
            &[],
            1735690000,
            86_400,
            5,
        )
        .expect("origin parses");
        assert_eq!(
            candidate.normalized_identifier,
            "https://agent.example/.well-known/http-message-signatures-directory"
        );

        let error = Draft02Candidate::parse(
            &request(r#"sig1="https://agent.example/keys""#, valid_input()),
            false,
            &[],
            1735690000,
            86_400,
            5,
        )
        .expect_err("directory path is not an origin");
        assert_eq!(error, CandidateError::InvalidDiscoveryUrl);
    }

    #[test]
    fn rejects_wrong_label_and_multiple_profile_signatures() {
        let error = Draft02Candidate::parse(
            &request(r#"other="https://agent.example""#, valid_input()),
            false,
            &[],
            1735690000,
            86_400,
            5,
        )
        .expect_err("the signed Signature-Agent member is mandatory");
        assert_eq!(error, CandidateError::MissingSignatureAgent);

        let input = format!("{}, sig2={}", valid_input(), &valid_input()[5..]);
        let error = Draft02Candidate::parse(
            &request(r#"sig1="https://agent.example""#, &input),
            false,
            &[],
            1735690000,
            86_400,
            5,
        )
        .expect_err("multiple profile signatures are out of scope");
        assert_eq!(error, CandidateError::MultipleSignatures);
    }

    #[test]
    fn rejects_insecure_urls_and_stale_or_overlong_signatures() {
        let error = Draft02Candidate::parse(
            &request(r#"sig1="http://agent.example""#, valid_input()),
            false,
            &[],
            1735690000,
            86_400,
            5,
        )
        .expect_err("https is mandatory");
        assert_eq!(error, CandidateError::InvalidDiscoveryUrl);

        let error = Draft02Candidate::parse(
            &request(r#"sig1="https://agent.example""#, valid_input()),
            false,
            &[],
            1735700000,
            60,
            0,
        )
        .expect_err("expired and overlong");
        assert_eq!(error, CandidateError::InvalidFreshness);
    }

    #[test]
    fn rejects_an_empty_key_id_before_resolver_lookup() {
        let error = Draft02Candidate::parse(
            &request(
                r#"sig1="https://agent.example""#,
                r#"sig1=("@method" "@authority" "@path" "signature-agent";key="sig1");created=1735689600;expires=1735693200;keyid="";alg="ed25519";tag="web-bot-auth""#,
            ),
            false,
            &[],
            1735690000,
            86_400,
            5,
        )
        .expect_err("an empty key ID is malformed");
        assert_eq!(error, CandidateError::Malformed);
    }

    #[derive(Deserialize)]
    struct Vector {
        public_jwk: VectorJwk,
        thumbprint: String,
        request: VectorRequest,
        signature_agent: String,
        signature_input: String,
        signature: String,
    }

    #[derive(Deserialize)]
    struct VectorJwk {
        x: String,
    }

    #[derive(Deserialize)]
    struct VectorRequest {
        method: String,
        authority: String,
        path: String,
    }

    #[test]
    fn verifies_the_official_minimum_ed25519_vector() {
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
        let candidate = Draft02Candidate::parse(&request, false, &[], 1735690000, u64::MAX, 0)
            .expect("the official minimum coverage is accepted");
        let jwk = Thumbprintable::OKP {
            crv: "Ed25519".into(),
            x: vector.public_jwk.x,
        };
        let mut keyring = KeyRing::default();
        assert!(keyring.import_raw(
            vector.thumbprint,
            Algorithm::Ed25519,
            jwk.public_key().expect("the vector key is valid"),
        ));
        candidate
            .verifier
            .verify(&keyring, None)
            .expect("the official Ed25519 signature verifies");
    }
}
