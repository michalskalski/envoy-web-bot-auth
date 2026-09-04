//! Generate a current Web Bot Auth request for kind scenarios.
//!
//! The committed JWKs are deliberately test only. This binary uses the same
//! signing crate as the module, so its output remains a useful integration
//! fixture when the profile's serialization changes.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use indexmap::IndexMap;
use serde::Deserialize;
use sfv::SerializeValue;
use std::{fs, time::Duration};
use url::Url;
use web_bot_auth::{
    components::{
        CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParameters, HTTPFieldParametersSet,
    },
    keyring::{Algorithm, Thumbprintable},
    message_signatures::{MessageSigner, UnsignedMessage},
};

const SIGNATURE_LABEL: &str = "sig";

#[derive(Debug, Parser)]
#[command(name = "wba-kind-request")]
struct Args {
    /// Gateway URL whose request components will be signed.
    #[arg(long)]
    url: Url,
    /// Test only private JWK containing Ed25519 key material.
    #[arg(long)]
    key: std::path::PathBuf,
    /// Signature Agent identifier. It must match one of the fixture resolver hosts.
    #[arg(long, default_value = "https://fixture.web-bot-auth.test")]
    agent: String,
    #[arg(long, value_enum, default_value_t = DiscoveryArg::Directory)]
    discovery: DiscoveryArg,
    /// Use a distinct key ID to exercise the authoritative missing key path.
    #[arg(long)]
    key_id: Option<String>,
    /// Send the generated request and fail unless the response has this status.
    #[arg(long)]
    expect_status: Option<u16>,
    /// Expected trusted status in the backend echo response.
    #[arg(long)]
    expect_trusted_status: Option<String>,
    /// Expected trusted identity in the backend echo response.
    #[arg(long)]
    expect_identity: Option<String>,
    /// Expected trusted key ID in the backend echo response.
    #[arg(long)]
    expect_key_id: Option<String>,
    /// Require the backend echo to contain no identity or key ID.
    #[arg(long)]
    expect_client_assertions_absent: bool,
    /// Mutate one signature byte after signing.
    #[arg(long)]
    tamper: bool,
    /// Create a signature whose expiration is already reached.
    #[arg(long)]
    expired: bool,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum DiscoveryArg {
    Directory,
    JwksUri,
    Cimd,
}

impl DiscoveryArg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::JwksUri => "jwks_uri",
            Self::Cimd => "cimd",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateJwk {
    kty: String,
    crv: String,
    x: String,
    d: String,
    #[serde(rename = "use")]
    _use: Option<String>,
    #[serde(rename = "comment")]
    _comment: Option<String>,
}

struct SigningRequest {
    method: String,
    authority: String,
    path: String,
    signature_agent: String,
    signature_input: String,
    signature: String,
}

impl UnsignedMessage for SigningRequest {
    fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String> {
        IndexMap::from([
            (
                CoveredComponent::Derived(DerivedComponent::Method { req: false }),
                self.method.clone(),
            ),
            (
                CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
                self.authority.clone(),
            ),
            (
                CoveredComponent::Derived(DerivedComponent::Path { req: false }),
                self.path.clone(),
            ),
            (
                CoveredComponent::HTTP(HTTPField {
                    name: "signature-agent".into(),
                    parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key(
                        SIGNATURE_LABEL.into(),
                    )]),
                }),
                signature_agent_member(&self.signature_agent, SIGNATURE_LABEL)
                    .expect("fixture Signature-Agent must contain its label"),
            ),
        ])
    }

    fn register_header_contents(&mut self, signature_input: String, signature: String) {
        self.signature_input = format!("{SIGNATURE_LABEL}={signature_input}");
        self.signature = format!("{SIGNATURE_LABEL}={signature}");
    }
}

fn signature_agent_member(value: &str, label: &str) -> Option<String> {
    let dictionary = sfv::Parser::new(value).parse_dictionary().ok()?;
    match dictionary.get(label)? {
        sfv::ListEntry::Item(item) => Some(item.serialize_value()),
        sfv::ListEntry::InnerList(_) => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();
    let jwk: PrivateJwk =
        serde_json::from_slice(&fs::read(&args.key).map_err(|_| "cannot read test private JWK")?)
            .map_err(|_| "invalid test private JWK")?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err("test private JWK must be an Ed25519 OKP key".into());
    }
    let private_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(jwk.d)
        .map_err(|_| "test private JWK has invalid base64url d")?
        .try_into()
        .map_err(|_| "test private JWK d must be 32 bytes")?;
    let key_id = args.key_id.unwrap_or_else(|| {
        Thumbprintable::OKP {
            crv: "Ed25519".into(),
            x: jwk.x,
        }
        .b64_thumbprint()
    });
    let authority = authority(&args.url)?;
    let signature_agent = format!(
        r#"{SIGNATURE_LABEL}="{}";type={}"#,
        args.agent,
        args.discovery.as_str()
    );
    let mut request = SigningRequest {
        method: "GET".into(),
        authority,
        path: args.url.path().to_owned(),
        signature_agent,
        signature_input: String::new(),
        signature: String::new(),
    };
    MessageSigner {
        keyid: key_id,
        // The integration environment has no replay cache. A constant makes
        // failures reproducible without weakening production behavior.
        nonce: "kind-fixture".into(),
        tag: "web-bot-auth".into(),
    }
    .generate_signature_headers_content(
        &mut request,
        if args.expired {
            Duration::ZERO
        } else {
            Duration::from_secs(30)
        },
        Algorithm::Ed25519,
        &private_key,
    )
    .map_err(|_| "could not generate Web Bot Auth signature")?;
    if args.tamper {
        tamper_signature(&mut request.signature)?;
    }

    let dictionary = sfv::Parser::new(&request.signature_agent)
        .parse_dictionary()
        .map_err(|_| "generated Signature-Agent is not a dictionary")?;
    let item = match dictionary
        .get(SIGNATURE_LABEL)
        .ok_or("generated Signature-Agent has no signature label")?
    {
        sfv::ListEntry::Item(item) => item,
        sfv::ListEntry::InnerList(_) => {
            return Err("generated Signature-Agent label is not an item".into());
        }
    };
    if item
        .params
        .get("type")
        .and_then(|value| value.as_token())
        .is_none()
    {
        return Err("generated discovery type is not a token".into());
    }

    if let Some(expected) = args.expect_status {
        if args.expired {
            std::thread::sleep(Duration::from_secs(6));
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "could not build local kind client")?;
        let response = client
            .get(args.url)
            .header("signature", &request.signature)
            .header("signature-input", &request.signature_input)
            .header("signature-agent", &request.signature_agent)
            .send()
            .await
            .map_err(|_| "could not send signed kind request")?;
        let actual = response.status().as_u16();
        if actual != expected {
            return Err(format!("expected HTTP {expected}, got HTTP {actual}"));
        }
        if actual == 200 {
            let body = response
                .text()
                .await
                .map_err(|_| "could not read backend echo response")?;
            assert_backend_echo(
                &body,
                args.expect_trusted_status.as_deref(),
                args.expect_identity.as_deref(),
                args.expect_key_id.as_deref(),
                args.expect_client_assertions_absent,
            )?;
        }
        println!("status={actual}");
    } else {
        println!("Signature: {}", request.signature);
        println!("Signature-Input: {}", request.signature_input);
        println!("Signature-Agent: {}", request.signature_agent);
    }
    Ok(())
}

fn tamper_signature(signature: &mut String) -> Result<(), String> {
    let start = signature
        .find("=:")
        .map(|index| index + 2)
        .ok_or("generated signature has no byte sequence")?;
    let byte = signature
        .as_bytes()
        .get(start)
        .copied()
        .ok_or("generated signature has an empty byte sequence")?;
    signature.replace_range(start..start + 1, if byte == b'A' { "B" } else { "A" });
    Ok(())
}

fn assert_backend_echo(
    body: &str,
    expected_status: Option<&str>,
    expected_identity: Option<&str>,
    expected_key_id: Option<&str>,
    assertions_absent: bool,
) -> Result<(), String> {
    let body: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "backend echo response is not JSON")?;
    if let Some(expected) = expected_status
        && body.get("status").and_then(serde_json::Value::as_str) != Some(expected)
    {
        let actual = body
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<missing>");
        return Err(format!(
            "backend trusted status mismatch: expected {expected}, got {actual}"
        ));
    }
    let identity = body
        .get("identity")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let key_id = body
        .get("key_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if let Some(expected) = expected_identity
        && identity != expected
    {
        return Err("backend trusted identity mismatch".into());
    }
    if let Some(expected) = expected_key_id
        && key_id != expected
    {
        return Err(format!(
            "backend trusted key ID mismatch: expected {expected}, got {key_id}"
        ));
    }
    if assertions_absent
        && (!identity.is_empty() || !key_id.is_empty())
        && expected_identity.is_none()
    {
        return Err("client assertion reached backend".into());
    }
    Ok(())
}

fn authority(url: &Url) -> Result<String, String> {
    let host = url.host_str().ok_or("request URL has no host")?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use web_bot_auth::{WebBotAuthVerifier, keyring::KeyRing, message_signatures::SignedMessage};

    impl SignedMessage for SigningRequest {
        fn lookup_component(&self, component: &CoveredComponent) -> Vec<String> {
            match component {
                CoveredComponent::Derived(DerivedComponent::Method { req: false }) => {
                    vec![self.method.clone()]
                }
                CoveredComponent::Derived(DerivedComponent::Authority { req: false }) => {
                    vec![self.authority.clone()]
                }
                CoveredComponent::Derived(DerivedComponent::Path { req: false }) => {
                    vec![self.path.clone()]
                }
                CoveredComponent::HTTP(field) if field.name == "signature-agent" => {
                    match field.parameters.0.as_slice() {
                        [HTTPFieldParameters::Key(key)] => {
                            signature_agent_member(&self.signature_agent, key)
                                .into_iter()
                                .collect()
                        }
                        [] => vec![self.signature_agent.clone()],
                        _ => vec![],
                    }
                }
                CoveredComponent::HTTP(field) if field.name == "signature-input" => {
                    vec![self.signature_input.clone()]
                }
                CoveredComponent::HTTP(field) if field.name == "signature" => {
                    vec![self.signature.clone()]
                }
                _ => Vec::new(),
            }
        }
    }

    #[test]
    fn fixture_a_key_generates_a_verifiable_dictionary_bound_signature() {
        let private: PrivateJwk =
            serde_json::from_str(include_str!("keys/agent-a.private.json")).unwrap();
        let key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(private.d)
            .unwrap()
            .try_into()
            .unwrap();
        let public = URL_SAFE_NO_PAD.decode(&private.x).unwrap();
        let key_id = Thumbprintable::OKP {
            crv: private.crv,
            x: private.x,
        }
        .b64_thumbprint();
        let mut request = SigningRequest {
            method: "GET".into(),
            authority: "gateway.test".into(),
            path: "/robots.txt".into(),
            signature_agent: r#"sig="https://fixture.web-bot-auth.test";type=directory"#.into(),
            signature_input: String::new(),
            signature: String::new(),
        };
        MessageSigner {
            keyid: key_id.clone(),
            nonce: "test".into(),
            tag: "web-bot-auth".into(),
        }
        .generate_signature_headers_content(
            &mut request,
            Duration::from_secs(30),
            Algorithm::Ed25519,
            &key,
        )
        .unwrap();
        let dictionary = sfv::Parser::new(&request.signature_agent)
            .parse_dictionary()
            .unwrap();
        let item = match dictionary.get("sig").unwrap() {
            sfv::ListEntry::Item(item) => item,
            sfv::ListEntry::InnerList(_) => panic!("fixture label must be an item"),
        };
        assert_eq!(
            item.params
                .get("type")
                .and_then(|value| value.as_token())
                .map(|value| value.as_str()),
            Some("directory")
        );
        let verifier = WebBotAuthVerifier::parse(&request).unwrap();
        let mut keyring = KeyRing::default();
        keyring.import_raw(key_id, Algorithm::Ed25519, public);
        verifier.verify(&keyring, None).unwrap();
        assert!(
            request
                .signature_input
                .contains(r#""signature-agent";key="sig""#)
        );
    }

    #[test]
    fn authority_retains_a_non_default_port() {
        assert_eq!(
            authority(&Url::parse("http://127.0.0.1:8888/").unwrap()).unwrap(),
            "127.0.0.1:8888"
        );
    }
}
