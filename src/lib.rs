// Required by the factory-registration macro in the Envoy 1.38.3 SDK.
#![allow(unpredictable_function_pointer_comparisons)]

mod config;

use config::Settings;
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilter, HttpFilterConfig, abi,
    declare_init_functions, envoy_log_error, envoy_log_info,
};
use std::sync::Arc;

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
