// Required by the factory-registration macro in the Envoy 1.38.3 SDK.
#![allow(unpredictable_function_pointer_comparisons)]

mod config;

use config::Settings;
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilter, HttpFilterConfig, abi,
    declare_init_functions, envoy_log_error, envoy_log_info,
};
use std::sync::Arc;
use web_bot_auth::components::{CoveredComponent, DerivedComponent};
use web_bot_auth::message_signatures::SignedMessage;

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

struct RequestComponents {
    method: String,
    authority: String,
    path: String,
    query: String,
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
        }
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
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
