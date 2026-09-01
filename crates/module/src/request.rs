//! Capture Envoy pseudo headers and expose the signed message view.

use crate::{
    HEADER_SIGNATURE, HEADER_SIGNATURE_AGENT, HEADER_SIGNATURE_INPUT, PSEUDO_HEADER_AUTHORITY,
    PSEUDO_HEADER_METHOD, PSEUDO_HEADER_PATH, PSEUDO_HEADER_SCHEME,
};
use envoy_proxy_dynamic_modules_rust_sdk::{EnvoyBuffer, EnvoyHttpFilter};
use sfv::SerializeValue;
use web_bot_auth::components::{CoveredComponent, DerivedComponent, HTTPFieldParameters};
use web_bot_auth::message_signatures::SignedMessage;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RequestCaptureError {
    MissingHeader(&'static str),
    InvalidUtf8(&'static str),
    NonAsciiHeader(&'static str),
    HeaderTooLarge(&'static str),
}

// These limits leave room for normal repeated signature fields while bounding
// the data copied into the verifier.
const MAX_SIGNATURE_HEADER_VALUES: usize = 16;
const MAX_SIGNATURE_HEADER_VALUE_BYTES: usize = 4 * 1024;
const MAX_SIGNATURE_FIELD_BYTES: usize = 8 * 1024;
const MAX_SIGNATURE_HEADERS_BYTES: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignatureHeaderState {
    Unsigned,
    Incomplete,
    Candidate,
}

pub(crate) struct RequestComponents {
    pub(crate) method: String,
    pub(crate) scheme: String,
    pub(crate) authority: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) signature: Vec<String>,
    pub(crate) signature_input: Vec<String>,
    pub(crate) signature_agent: Vec<String>,
}

impl RequestComponents {
    pub(crate) fn from_pseudo_headers(method: &str, authority: &str, raw_path: &str) -> Self {
        let (path, query) = match raw_path.split_once('?') {
            Some((path, query_without_question_mark)) => {
                (path.to_owned(), format!("?{query_without_question_mark}"))
            }
            None => (raw_path.to_owned(), String::new()),
        };

        Self {
            // HTTP Message Signatures cover the method bytes as received.
            method: method.to_owned(),
            scheme: "https".into(),
            authority: authority.trim_ascii().to_owned(),
            path,
            query,
            signature: Vec::new(),
            signature_input: Vec::new(),
            signature_agent: Vec::new(),
        }
    }

    pub(crate) fn try_from_envoy(
        envoy_filter: &impl EnvoyHttpFilter,
    ) -> Result<Self, RequestCaptureError> {
        let method_buffer = envoy_filter
            .get_request_header_value(PSEUDO_HEADER_METHOD)
            .ok_or(RequestCaptureError::MissingHeader(PSEUDO_HEADER_METHOD))?;
        let method = decode_ascii_header(&method_buffer, PSEUDO_HEADER_METHOD)?;
        let authority_buffer = envoy_filter
            .get_request_header_value(PSEUDO_HEADER_AUTHORITY)
            .ok_or(RequestCaptureError::MissingHeader(PSEUDO_HEADER_AUTHORITY))?;
        let authority = decode_ascii_header(&authority_buffer, PSEUDO_HEADER_AUTHORITY)?;
        let scheme_buffer = envoy_filter
            .get_request_header_value(PSEUDO_HEADER_SCHEME)
            .ok_or(RequestCaptureError::MissingHeader(PSEUDO_HEADER_SCHEME))?;
        let scheme = decode_ascii_header(&scheme_buffer, PSEUDO_HEADER_SCHEME)?;
        let raw_path_buffer = envoy_filter
            .get_request_header_value(PSEUDO_HEADER_PATH)
            .ok_or(RequestCaptureError::MissingHeader(PSEUDO_HEADER_PATH))?;
        let raw_path = decode_ascii_header(&raw_path_buffer, PSEUDO_HEADER_PATH)?;

        let signature_buffers = envoy_filter.get_request_header_values(HEADER_SIGNATURE);
        if signature_buffers.is_empty() {
            return Err(RequestCaptureError::MissingHeader(HEADER_SIGNATURE));
        }
        let mut total_signature_bytes = 0;
        let signatures = copy_ascii_header_values(
            &signature_buffers,
            HEADER_SIGNATURE,
            &mut total_signature_bytes,
        )?;
        let signature_input_buffers =
            envoy_filter.get_request_header_values(HEADER_SIGNATURE_INPUT);
        if signature_input_buffers.is_empty() {
            return Err(RequestCaptureError::MissingHeader(HEADER_SIGNATURE_INPUT));
        }
        let signature_inputs = copy_ascii_header_values(
            &signature_input_buffers,
            HEADER_SIGNATURE_INPUT,
            &mut total_signature_bytes,
        )?;
        let signature_agent_buffers =
            envoy_filter.get_request_header_values(HEADER_SIGNATURE_AGENT);
        if signature_agent_buffers.is_empty() {
            return Err(RequestCaptureError::MissingHeader(HEADER_SIGNATURE_AGENT));
        }
        let signature_agent = copy_ascii_header_values(
            &signature_agent_buffers,
            HEADER_SIGNATURE_AGENT,
            &mut total_signature_bytes,
        )?;

        let mut request = Self {
            signature: signatures,
            signature_input: signature_inputs,
            signature_agent,
            ..Self::from_pseudo_headers(method, authority, raw_path)
        };
        request.scheme = scheme.to_ascii_lowercase();
        Ok(request)
    }
}

impl SignedMessage for RequestComponents {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        match name {
            CoveredComponent::Derived(DerivedComponent::Method { req: false }) => {
                vec![self.method.clone()]
            }
            CoveredComponent::Derived(DerivedComponent::Authority { req: false }) => {
                vec![self.authority.clone()]
            }
            CoveredComponent::Derived(DerivedComponent::Scheme { req: false }) => {
                vec![self.scheme.clone()]
            }
            CoveredComponent::Derived(DerivedComponent::TargetUri { req: false }) => {
                vec![format!(
                    "{}://{}{}{}",
                    self.scheme, self.authority, self.path, self.query
                )]
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

pub(crate) fn decode_ascii_header<'a>(
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
    total_bytes: &mut usize,
) -> Result<Vec<String>, RequestCaptureError> {
    if buffers.len() > MAX_SIGNATURE_HEADER_VALUES {
        return Err(RequestCaptureError::HeaderTooLarge(name));
    }
    let mut field_bytes: usize = 0;
    buffers
        .iter()
        .map(|buffer| {
            let value_bytes = buffer.as_slice().len();
            field_bytes = field_bytes
                .checked_add(value_bytes)
                .filter(|bytes| *bytes <= MAX_SIGNATURE_FIELD_BYTES)
                .ok_or(RequestCaptureError::HeaderTooLarge(name))?;
            *total_bytes = total_bytes
                .checked_add(value_bytes)
                .filter(|bytes| *bytes <= MAX_SIGNATURE_HEADERS_BYTES)
                .ok_or(RequestCaptureError::HeaderTooLarge(name))?;
            if value_bytes > MAX_SIGNATURE_HEADER_VALUE_BYTES {
                return Err(RequestCaptureError::HeaderTooLarge(name));
            }
            let value = decode_ascii_header(buffer, name)?;
            Ok(value.to_owned())
        })
        .collect()
}

pub(crate) fn classify_signature_headers(
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

    fn buffers<'a>(values: &'a [&'a [u8]]) -> Vec<EnvoyBuffer<'a>> {
        values.iter().map(|value| EnvoyBuffer::new(value)).collect()
    }

    #[test]
    fn preserves_method_case_for_signature_lookup() {
        let request =
            RequestComponents::from_pseudo_headers("customMethod", "example.test", "/robots.txt");

        assert_eq!(request.method, "customMethod");
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Method {
                req: false,
            })),
            vec!["customMethod"],
        );
    }

    #[test]
    fn bounds_each_signature_field_and_the_combined_capture() {
        let too_many = (0..=MAX_SIGNATURE_HEADER_VALUES)
            .map(|_| b"x".as_slice())
            .collect::<Vec<_>>();
        assert_eq!(
            copy_ascii_header_values(&buffers(&too_many), HEADER_SIGNATURE, &mut 0),
            Err(RequestCaptureError::HeaderTooLarge(HEADER_SIGNATURE)),
        );

        let oversized = [vec![b'x'; MAX_SIGNATURE_HEADER_VALUE_BYTES + 1]];
        let oversized = oversized.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            copy_ascii_header_values(&buffers(&oversized), HEADER_SIGNATURE, &mut 0),
            Err(RequestCaptureError::HeaderTooLarge(HEADER_SIGNATURE)),
        );

        let field = vec![b'x'; MAX_SIGNATURE_FIELD_BYTES / 2];
        let field_values = [field.as_slice(), field.as_slice()];
        assert_eq!(
            copy_ascii_header_values(&buffers(&field_values), HEADER_SIGNATURE, &mut 0),
            Ok(vec!["x".repeat(MAX_SIGNATURE_FIELD_BYTES / 2); 2]),
        );

        let mut total = MAX_SIGNATURE_HEADERS_BYTES;
        assert_eq!(
            copy_ascii_header_values(&buffers(&[b"x"]), HEADER_SIGNATURE_INPUT, &mut total),
            Err(RequestCaptureError::HeaderTooLarge(HEADER_SIGNATURE_INPUT)),
        );
    }
}
