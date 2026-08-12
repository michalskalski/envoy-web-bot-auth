// Required by the factory-registration macro in the Envoy 1.38.3 SDK.
#![allow(unpredictable_function_pointer_comparisons)]

use envoy_proxy_dynamic_modules_rust_sdk::{
    abi, declare_init_functions, EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilter,
    HttpFilterConfig,
};

declare_init_functions!(program_init, new_http_filter_config);

fn program_init() -> bool {
    true
}

fn new_http_filter_config<EC, EHF>(
    _envoy_config: &mut EC,
    name: &str,
    _config: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>>
where
    EC: EnvoyHttpFilterConfig,
    EHF: EnvoyHttpFilter,
{
    if name != "web-bot-auth" {
        return None;
    }

    Some(Box::new(WebBotAuthConfig))
}

struct WebBotAuthConfig;

impl<EHF> HttpFilterConfig<EHF> for WebBotAuthConfig
where
    EHF: EnvoyHttpFilter,
{
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(WebBotAuthFilter)
    }
}

struct WebBotAuthFilter;

impl<EHF> HttpFilter<EHF> for WebBotAuthFilter
where
    EHF: EnvoyHttpFilter,
{
    fn on_response_headers(
        &mut self,
        envoy_filter: &mut EHF,
        _end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_response_headers_status {
        envoy_filter.set_response_header("x-envoy-web-bot-auth", b"hello-world");

        abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue
    }
}
