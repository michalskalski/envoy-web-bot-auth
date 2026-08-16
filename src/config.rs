use serde::Deserialize;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub(crate) enum ConfigError {
    Json(serde_json::Error),
    EmptyResponseHeaderValue,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "{error}"),
            Self::EmptyResponseHeaderValue => {
                write!(formatter, "response_header_value must not be empty")
            }
        }
    }
}

impl Error for ConfigError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) response_header_value: String,
}

impl Settings {
    pub(crate) fn parse(config: &[u8]) -> Result<Self, ConfigError> {
        let settings: Settings = serde_json::from_slice(config).map_err(ConfigError::Json)?;

        if settings.response_header_value.is_empty() {
            return Err(ConfigError::EmptyResponseHeaderValue);
        }
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_settings() {
        let settings = Settings::parse(br#"{"response_header_value":"hello-from-config"}"#)
            .expect("valid settings should parse");

        assert_eq!(settings.response_header_value, "hello-from-config");
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = Settings::parse(
            br#"{
                  "response_header_value":"hello",
                  "response_heder_typo":"ignored"
              }"#,
        )
        .expect_err("unknown fields must be rejected");

        assert!(matches!(error, ConfigError::Json(_)));
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_an_empty_response_header_value() {
        let error = Settings::parse(br#"{"response_header_value":""}"#)
            .expect_err("an empty value must be rejected");

        assert!(matches!(error, ConfigError::EmptyResponseHeaderValue));
    }
}
