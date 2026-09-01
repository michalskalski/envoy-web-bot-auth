//! Resource wire representations and bounded JWKS or CIMD parsing.

use super::fetch::{FetchError, FetchErrorKind, ResourceKind, is_directory_url};
use serde::Deserialize;
use url::Url;
use web_bot_auth_protocol::{Ed25519Jwk, MAX_AGENT_URL_BYTES};

#[derive(Clone, Debug)]
pub(super) enum ParsedResource {
    Jwks(Vec<ResourceKeyEntry>),
    Cimd(CimdResource),
}

#[derive(Clone, Debug)]
pub(super) struct ResourceKeyEntry {
    pub(super) jwk: Ed25519Jwk,
    pub(super) kid: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct CimdResource {
    pub(super) inline_jwks: Option<Vec<ResourceKeyEntry>>,
    pub(super) jwks_uri: Option<Url>,
}

#[derive(Deserialize)]
struct FetchedJwks {
    keys: Vec<FetchedJwk>,
}

#[derive(Deserialize)]
struct FetchedJwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    x: Option<String>,
}

#[derive(Deserialize)]
struct FetchedCimd {
    client_id: String,
    #[serde(default)]
    jwks: Option<FetchedJwks>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

pub(super) fn parse_resource(
    kind: ResourceKind,
    fetched_url: &Url,
    body: &[u8],
    max_keys: usize,
) -> Result<ParsedResource, FetchError> {
    match kind {
        ResourceKind::Jwks => {
            let jwks: FetchedJwks = serde_json::from_slice(body)
                .map_err(|_| FetchError::new(FetchErrorKind::InvalidResource))?;
            let directory = is_directory_url(fetched_url);
            Ok(ParsedResource::Jwks(parse_keys(jwks, max_keys, directory)?))
        }
        ResourceKind::Cimd => {
            let metadata: FetchedCimd = serde_json::from_slice(body)
                .map_err(|_| FetchError::new(FetchErrorKind::InvalidResource))?;
            if metadata.client_id != fetched_url.as_str() {
                return Err(FetchError::new(FetchErrorKind::InvalidResource));
            }
            let (inline_jwks, jwks_uri) = match (metadata.jwks, metadata.jwks_uri) {
                (Some(jwks), None) => (Some(parse_keys(jwks, max_keys, false)?), None),
                (None, Some(uri)) => {
                    if uri.len() > MAX_AGENT_URL_BYTES {
                        return Err(FetchError::new(FetchErrorKind::InvalidResource));
                    }
                    let mut url = Url::parse(&uri)
                        .map_err(|_| FetchError::new(FetchErrorKind::InvalidResource))?;
                    url.set_fragment(None);
                    (None, Some(url))
                }
                _ => return Err(FetchError::new(FetchErrorKind::InvalidResource)),
            };
            Ok(ParsedResource::Cimd(CimdResource {
                inline_jwks,
                jwks_uri,
            }))
        }
    }
}

fn parse_keys(
    jwks: FetchedJwks,
    max_keys: usize,
    directory: bool,
) -> Result<Vec<ResourceKeyEntry>, FetchError> {
    if jwks.keys.len() > max_keys {
        return Err(FetchError::new(FetchErrorKind::InvalidResource));
    }
    jwks.keys
        .into_iter()
        .filter(|key| key.kty == "OKP" && key.crv.as_deref() == Some("Ed25519"))
        .map(|key| {
            let kid = key.kid;
            let jwk = Ed25519Jwk::new(
                key.x
                    .ok_or_else(|| FetchError::new(FetchErrorKind::InvalidResource))?,
            );
            if !jwk.is_valid_public_key() {
                return Err(FetchError::new(FetchErrorKind::InvalidResource));
            }
            if directory
                && kid
                    .as_deref()
                    .is_some_and(|kid| kid != jwk.b64_thumbprint())
            {
                return Err(FetchError::new(FetchErrorKind::InvalidResource));
            }
            Ok(ResourceKeyEntry { jwk, kid })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
    const THUMBPRINT: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

    fn parse(kind: ResourceKind, url: &str, body: &str) -> Result<ParsedResource, FetchError> {
        parse_resource(
            kind,
            &Url::parse(url).expect("test URL is valid"),
            body.as_bytes(),
            8,
        )
    }

    #[test]
    fn cimd_requires_an_exact_client_id() {
        let url = "https://agent.example/card?generation=2";
        let valid = format!(r#"{{"client_id":"{url}","jwks_uri":"https://agent.example/jwks"}}"#);
        assert!(matches!(
            parse(ResourceKind::Cimd, url, &valid),
            Ok(ParsedResource::Cimd(_))
        ));

        let missing = r#"{"jwks_uri":"https://agent.example/jwks"}"#;
        assert_eq!(
            parse(ResourceKind::Cimd, url, missing)
                .expect_err("missing client_id must be rejected")
                .kind,
            FetchErrorKind::InvalidResource
        );

        let different =
            r#"{"client_id":"https://agent.example/card","jwks_uri":"https://agent.example/jwks"}"#;
        assert_eq!(
            parse(ResourceKind::Cimd, url, different)
                .expect_err("client_id comparison must be byte exact")
                .kind,
            FetchErrorKind::InvalidResource
        );
    }

    #[test]
    fn directory_kid_is_retained_and_must_be_the_thumbprint() {
        let url = "https://agent.example/.well-known/http-message-signatures-directory";
        let body = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"{THUMBPRINT}","x":"{X}"}}]}}"#
        );
        let ParsedResource::Jwks(keys) = parse(ResourceKind::Jwks, url, &body).unwrap() else {
            panic!("expected a JWK set");
        };
        assert_eq!(keys[0].kid.as_deref(), Some(THUMBPRINT));

        let invalid = body.replace(THUMBPRINT, "operator-label");
        assert_eq!(
            parse(ResourceKind::Jwks, url, &invalid)
                .expect_err("directory kid must match the key thumbprint")
                .kind,
            FetchErrorKind::InvalidResource
        );
    }
}
