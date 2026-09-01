//! Cryptographic checks over immutable protocol vectors.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sfv::SerializeValue;
use web_bot_auth::{
    WebBotAuthVerifier,
    components::{CoveredComponent, DerivedComponent, HTTPField},
    keyring::{Algorithm, KeyRing},
    message_signatures::SignedMessage,
};

#[derive(Deserialize)]
struct Vector {
    public_jwk: PublicJwk,
    thumbprint: String,
    request: Request,
    signature_agent: String,
    signature_input: String,
    signature: String,
}

#[derive(Deserialize)]
struct PublicJwk {
    x: String,
}

#[derive(Deserialize)]
struct Request {
    authority: String,
}

struct SignedVector {
    authority: String,
    signature_agent: String,
    signature_input: String,
    signature: String,
}

impl SignedMessage for SignedVector {
    fn lookup_component(&self, component: &CoveredComponent) -> Vec<String> {
        match component {
            CoveredComponent::Derived(DerivedComponent::Authority { req: false }) => {
                vec![self.authority.clone()]
            }
            CoveredComponent::HTTP(field) if field.name == "signature-agent" => {
                match field.parameters.0.as_slice() {
                    [] => vec![self.signature_agent.clone()],
                    [web_bot_auth::components::HTTPFieldParameters::Key(key)] => {
                        let dictionary = sfv::Parser::new(&self.signature_agent)
                            .parse_dictionary()
                            .expect("the immutable vector has valid Signature-Agent syntax");
                        match dictionary.get(key.as_str()) {
                            Some(sfv::ListEntry::Item(item)) => vec![item.serialize_value()],
                            _ => Vec::new(),
                        }
                    }
                    _ => Vec::new(),
                }
            }
            CoveredComponent::HTTP(field) if field.name == "signature-input" => {
                vec![self.signature_input.clone()]
            }
            CoveredComponent::HTTP(field) if field.name == "signature" => {
                vec![self.signature.clone()]
            }
            CoveredComponent::HTTP(HTTPField { .. }) => Vec::new(),
            _ => Vec::new(),
        }
    }
}

#[test]
fn draft_02_ed25519_appendix_vector_verifies_without_generation() {
    let vector: Vector = serde_json::from_str(include_str!("../../vectors/draft-02-ed25519.json"))
        .expect("immutable vector JSON is valid");
    let public = URL_SAFE_NO_PAD
        .decode(vector.public_jwk.x)
        .expect("immutable vector public key is base64url");
    let verifier = WebBotAuthVerifier::parse(&SignedVector {
        authority: vector.request.authority,
        signature_agent: vector.signature_agent,
        signature_input: vector.signature_input,
        signature: vector.signature,
    })
    .expect("draft-02 vector parses");
    let mut keyring = KeyRing::default();
    keyring.import_raw(vector.thumbprint, Algorithm::Ed25519, public);
    verifier
        .verify(&keyring, None)
        .expect("draft-02 Appendix E.2.1 signature verifies");
}
