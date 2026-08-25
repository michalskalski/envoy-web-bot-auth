// Required by the factory-registration macro in the Envoy SDK.
#![allow(unpredictable_function_pointer_comparisons)]

mod config;

use config::Settings;
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyBuffer;
use envoy_proxy_dynamic_modules_rust_sdk::{
    abi, declare_init_functions, envoy_log_error, envoy_log_info, EnvoyHttpFilter,
    EnvoyHttpFilterConfig, HttpFilter, HttpFilterConfig,
};
use sfv::SerializeValue;
use std::sync::Arc;
use web_bot_auth::components::{CoveredComponent, DerivedComponent, HTTPFieldParameters};
use web_bot_auth::message_signatures::SignedMessage;

const PSEUDO_HEADER_METHOD: &str = ":method";
const PSEUDO_HEADER_AUTHORITY: &str = ":authority";
const PSEUDO_HEADER_PATH: &str = ":path";
const HEADER_SIGNATURE: &str = "signature";
const HEADER_SIGNATURE_INPUT: &str = "signature-input";
const HEADER_SIGNATURE_AGENT: &str = "signature-agent";

declare_init_functions!(program_init, new_http_filter_config);

fn program_init() -> bool {
    true
}

fn new_http_filter_config<EC, EHF>(
    _envoy_config: &mut EC,
    name: &str,
    config: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>>
where
    EC: EnvoyHttpFilterConfig,
    EHF: EnvoyHttpFilter,
{
    if name != "web-bot-auth" {
        return None;
    }

    let settings = match Settings::parse(config) {
        Ok(settings) => settings,
        Err(error) => {
            envoy_log_error!("invalid web-bot-auth configuration: {error}");
            return None;
        }
    };

    envoy_log_info!("web-bot-auth configuration accepted");

    Some(Box::new(WebBotAuthConfig {
        settings: Arc::new(settings),
    }))
}

struct WebBotAuthConfig {
    settings: Arc<Settings>,
}

struct WebBotAuthFilter {
    settings: Arc<Settings>,
}

impl<EHF> HttpFilterConfig<EHF> for WebBotAuthConfig
where
    EHF: EnvoyHttpFilter,
{
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(WebBotAuthFilter {
            settings: Arc::clone(&self.settings),
        })
    }
}

impl<EHF> HttpFilter<EHF> for WebBotAuthFilter
where
    EHF: EnvoyHttpFilter,
{
    fn on_request_headers(
        &mut self,
        envoy_filter: &mut EHF,
        _end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_headers_status {
        let has_signature = envoy_filter
            .get_request_header_value(HEADER_SIGNATURE)
            .is_some();
        let has_signature_input = envoy_filter
            .get_request_header_value(HEADER_SIGNATURE_INPUT)
            .is_some();
        let has_signature_agent = envoy_filter
            .get_request_header_value(HEADER_SIGNATURE_AGENT)
            .is_some();

        match classify_signature_headers(has_signature, has_signature_input, has_signature_agent) {
            SignatureHeaderState::Unsigned => {
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
            }
            SignatureHeaderState::Incomplete => {
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
            }
            SignatureHeaderState::Candidate => {
                let _request = match RequestComponents::try_from_envoy(envoy_filter) {
                    Ok(request) => request,
                    Err(_error) => {
                        return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue;
                    }
                };

                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
            }
        }
    }

    fn on_response_headers(
        &mut self,
        envoy_filter: &mut EHF,
        _end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_response_headers_status {
        envoy_filter.set_response_header(
            "x-envoy-web-bot-auth",
            self.settings.response_header_value.as_bytes(),
        );

        abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RequestCaptureError {
    MissingHeader(&'static str),
    InvalidUtf8(&'static str),
    NonAsciiHeader(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
enum SignatureHeaderState {
    Unsigned,
    Incomplete,
    Candidate,
}

struct RequestComponents {
    method: String,
    authority: String,
    path: String,
    query: String,
    signature: Vec<String>,
    signature_input: Vec<String>,
    signature_agent: Vec<String>,
}

impl RequestComponents {
    fn from_pseudo_headers(method: &str, authority: &str, raw_path: &str) -> Self {
        let (path, query) = match raw_path.split_once('?') {
            Some((path, query_without_question_mark)) => {
                (path.to_owned(), format!("?{query_without_question_mark}"))
            }
            None => (raw_path.to_owned(), String::new()),
        };

        Self {
            method: method.to_ascii_uppercase(),
            authority: authority.trim_ascii().to_owned(),
            path,
            query,
            signature: Vec::new(),
            signature_input: Vec::new(),
            signature_agent: Vec::new(),
        }
    }

    fn try_from_envoy(envoy_filter: &impl EnvoyHttpFilter) -> Result<Self, RequestCaptureError> {
        let method_buffer = envoy_filter
            .get_request_header_value(PSEUDO_HEADER_METHOD)
            .ok_or(RequestCaptureError::MissingHeader(PSEUDO_HEADER_METHOD))?;
        let method = decode_ascii_header(&method_buffer, PSEUDO_HEADER_METHOD)?;

        let authority_buffer = envoy_filter
            .get_request_header_value(PSEUDO_HEADER_AUTHORITY)
            .ok_or(RequestCaptureError::MissingHeader(PSEUDO_HEADER_AUTHORITY))?;
        let authority = decode_ascii_header(&authority_buffer, PSEUDO_HEADER_AUTHORITY)?;

        let raw_path_buffer = envoy_filter
            .get_request_header_value(PSEUDO_HEADER_PATH)
            .ok_or(RequestCaptureError::MissingHeader(PSEUDO_HEADER_PATH))?;
        let raw_path = decode_ascii_header(&raw_path_buffer, PSEUDO_HEADER_PATH)?;

        let signature_buffers = envoy_filter.get_request_header_values(HEADER_SIGNATURE);
        if signature_buffers.is_empty() {
            return Err(RequestCaptureError::MissingHeader(HEADER_SIGNATURE));
        }
        let signatures = copy_ascii_header_values(&signature_buffers, HEADER_SIGNATURE)?;

        let signature_input_buffers =
            envoy_filter.get_request_header_values(HEADER_SIGNATURE_INPUT);
        if signature_input_buffers.is_empty() {
            return Err(RequestCaptureError::MissingHeader(HEADER_SIGNATURE_INPUT));
        }
        let signature_inputs =
            copy_ascii_header_values(&signature_input_buffers, HEADER_SIGNATURE_INPUT)?;

        let signature_agent_buffers =
            envoy_filter.get_request_header_values(HEADER_SIGNATURE_AGENT);
        if signature_agent_buffers.is_empty() {
            return Err(RequestCaptureError::MissingHeader(HEADER_SIGNATURE_AGENT));
        }
        let signature_agent =
            copy_ascii_header_values(&signature_agent_buffers, HEADER_SIGNATURE_AGENT)?;

        Ok(Self {
            signature: signatures,
            signature_input: signature_inputs,
            signature_agent,
            ..Self::from_pseudo_headers(method, authority, raw_path)
        })
    }
}

impl SignedMessage for RequestComponents {
    fn lookup_component(&self, name: &web_bot_auth::components::CoveredComponent) -> Vec<String> {
        match name {
            CoveredComponent::Derived(DerivedComponent::Method { req: false }) => {
                vec![self.method.clone()]
            }
            CoveredComponent::Derived(DerivedComponent::Authority { req: false }) => {
                vec![self.authority.clone()]
            }
            CoveredComponent::Derived(DerivedComponent::Path { req: false }) => {
                vec![self.path.clone()]
            }
            CoveredComponent::Derived(DerivedComponent::Query { req: false }) => {
                vec![self.query.clone()]
            }
            CoveredComponent::HTTP(field) if field.name == HEADER_SIGNATURE_AGENT => {
                match field.parameters.0.as_slice() {
                    [] => self.signature_agent.clone(),
                    [HTTPFieldParameters::Key(key)] => {
                        select_dictionary_member(&self.signature_agent, key)
                            .into_iter()
                            .collect()
                    }
                    _ => vec![],
                }
            }
            CoveredComponent::HTTP(field) if field.parameters.0.is_empty() => {
                match field.name.as_str() {
                    HEADER_SIGNATURE => self.signature.clone(),
                    HEADER_SIGNATURE_INPUT => self.signature_input.clone(),
                    _ => vec![],
                }
            }

            _ => vec![],
        }
    }
}

fn select_dictionary_member(field_values: &[String], key: &str) -> Option<String> {
    let mut dictionary = sfv::Dictionary::new();

    for field_value in field_values {
        sfv::Parser::new(field_value)
            .parse_dictionary_with_visitor(&mut dictionary)
            .ok()?;
    }

    match dictionary.get(key)? {
        sfv::ListEntry::Item(item) => Some(item.serialize_value()),
        sfv::ListEntry::InnerList(_) => None,
    }
}

fn decode_ascii_header<'a>(
    buffer: &'a EnvoyBuffer<'_>,
    name: &'static str,
) -> Result<&'a str, RequestCaptureError> {
    let value = std::str::from_utf8(buffer.as_slice())
        .map_err(|_| RequestCaptureError::InvalidUtf8(name))?;

    if !value.is_ascii() {
        return Err(RequestCaptureError::NonAsciiHeader(name));
    }

    Ok(value)
}

fn copy_ascii_header_values(
    buffers: &[EnvoyBuffer<'_>],
    name: &'static str,
) -> Result<Vec<String>, RequestCaptureError> {
    buffers
        .iter()
        .map(|buffer| {
            let value = decode_ascii_header(buffer, name)?;
            Ok(value.to_owned())
        })
        .collect()
}

fn classify_signature_headers(
    has_signature: bool,
    has_signature_input: bool,
    has_signature_agent: bool,
) -> SignatureHeaderState {
    if !has_signature && !has_signature_input && !has_signature_agent {
        SignatureHeaderState::Unsigned
    } else if has_signature && has_signature_input && has_signature_agent {
        SignatureHeaderState::Candidate
    } else {
        SignatureHeaderState::Incomplete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use web_bot_auth::components::{HTTPField, HTTPFieldParametersSet};

    #[test]
    fn classifies_signature_header_presence() {
        let cases = [
            (false, false, false, SignatureHeaderState::Unsigned),
            (false, false, true, SignatureHeaderState::Incomplete),
            (false, true, false, SignatureHeaderState::Incomplete),
            (false, true, true, SignatureHeaderState::Incomplete),
            (true, false, false, SignatureHeaderState::Incomplete),
            (true, false, true, SignatureHeaderState::Incomplete),
            (true, true, false, SignatureHeaderState::Incomplete),
            (true, true, true, SignatureHeaderState::Candidate),
        ];

        for (has_signature, has_signature_input, has_signature_agent, expected) in cases {
            assert_eq!(
                classify_signature_headers(has_signature, has_signature_input, has_signature_agent,),
                expected,
            );
        }
    }

    #[test]
    fn retrieves_raw_signature_fields() {
        let request = RequestComponents {
            signature: vec!["sig1=:first:".into(), "sig2=:second:".into()],
            signature_input: vec![r#"sig1=("@method")"#.into()],
            signature_agent: vec![
                r#"sig1="https://one.example""#.into(),
                r#"sig2="https://two.example""#.into(),
            ],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let raw_component = |name: &str| {
            CoveredComponent::HTTP(HTTPField {
                name: name.into(),
                parameters: HTTPFieldParametersSet(vec![]),
            })
        };

        assert_eq!(
            request.lookup_component(&raw_component(HEADER_SIGNATURE)),
            vec!["sig1=:first:", "sig2=:second:"],
        );
        assert_eq!(
            request.lookup_component(&raw_component(HEADER_SIGNATURE_INPUT)),
            vec![r#"sig1=("@method")"#],
        );
        assert_eq!(
            request.lookup_component(&raw_component(HEADER_SIGNATURE_AGENT)),
            vec![
                r#"sig1="https://one.example""#,
                r#"sig2="https://two.example""#,
            ],
        );
    }

    #[test]
    fn retrieves_a_selected_signature_agent_dictionary_member() {
        let request = RequestComponents {
            signature_agent: vec![
                r#"sig1="https://one.example", sig2="https://two.example""#.into()
            ],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let component = CoveredComponent::HTTP(HTTPField {
            name: HEADER_SIGNATURE_AGENT.into(),
            parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key("sig1".into())]),
        });

        assert_eq!(
            request.lookup_component(&component),
            vec![r#""https://one.example""#],
        );
    }

    #[test]
    fn returns_empty_when_signature_agent_key_is_missing() {
        let request = RequestComponents {
            signature_agent: vec![r#"sig1="https://one.example""#.into()],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let component = CoveredComponent::HTTP(HTTPField {
            name: HEADER_SIGNATURE_AGENT.into(),
            parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key("sig2".into())]),
        });

        assert_eq!(request.lookup_component(&component), Vec::<String>::new(),);
    }

    #[test]
    fn returns_empty_when_signature_agent_dictionary_is_malformed() {
        let request = RequestComponents {
            signature_agent: vec![r#"sig1="https://one.example", broken="#.into()],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let component = CoveredComponent::HTTP(HTTPField {
            name: HEADER_SIGNATURE_AGENT.into(),
            parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key("sig1".into())]),
        });

        assert_eq!(request.lookup_component(&component), Vec::<String>::new(),);
    }

    #[test]
    fn returns_empty_for_unsupported_signature_agent_parameters() {
        let request = RequestComponents {
            signature_agent: vec![r#"sig1="https://one.example""#.into()],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let component = CoveredComponent::HTTP(HTTPField {
            name: HEADER_SIGNATURE_AGENT.into(),
            parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Sf]),
        });

        assert_eq!(request.lookup_component(&component), Vec::<String>::new(),);
    }

    #[test]
    fn decodes_an_ascii_pseudo_header() {
        let buffer = EnvoyBuffer::new(b"/caf%C3%A9");

        assert_eq!(
            decode_ascii_header(&buffer, PSEUDO_HEADER_PATH),
            Ok("/caf%C3%A9"),
        );
    }

    #[test]
    fn rejects_a_non_ascii_pseudo_header() {
        let buffer = EnvoyBuffer::new("/café".as_bytes());

        assert_eq!(
            decode_ascii_header(&buffer, PSEUDO_HEADER_PATH),
            Err(RequestCaptureError::NonAsciiHeader(PSEUDO_HEADER_PATH,)),
        );
    }

    #[test]
    fn rejects_invalid_utf8_in_a_pseudo_header() {
        let buffer = EnvoyBuffer::new(b"/caf\xff");

        assert_eq!(
            decode_ascii_header(&buffer, PSEUDO_HEADER_PATH),
            Err(RequestCaptureError::InvalidUtf8(PSEUDO_HEADER_PATH)),
        );
    }

    #[test]
    fn lookup_returns_empty_for_unsupported_components() {
        let request =
            RequestComponents::from_pseudo_headers("GET", "example.test:8443", "/ask?q=bears");

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Scheme {
                req: false
            },)),
            Vec::<String>::new(),
        );

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Method {
                req: true
            },)),
            Vec::<String>::new(),
        );
    }

    #[test]
    fn reconstructs_method_authority_path_and_query() {
        let request =
            RequestComponents::from_pseudo_headers("get", " example.test:8443 ", "/ask?q=bears");

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Method {
                req: false
            })),
            vec!["GET"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Authority {
                req: false
            })),
            vec!["example.test:8443"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Path {
                req: false
            })),
            vec!["/ask"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Query {
                req: false
            })),
            vec!["?q=bears"]
        );
    }

    #[test]
    fn reconstructs_an_absent_query_as_an_empty_component() {
        let request = RequestComponents::from_pseudo_headers("GET", "example.test", "/health");

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Path {
                req: false
            })),
            vec!["/health"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Query {
                req: false
            })),
            vec![""]
        );
    }

    #[test]
    fn reconstructs_an_empty_query_with_its_delimiter() {
        let request = RequestComponents::from_pseudo_headers("GET", "example.test", "/health?");

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Path {
                req: false
            })),
            vec!["/health"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Query {
                req: false
            })),
            vec!["?"]
        );
    }
}
