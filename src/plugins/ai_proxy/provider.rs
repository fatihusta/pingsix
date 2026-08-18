//! ai-proxy provider registry.
//!
//! Each provider contributes the static wiring the generic pipeline needs:
//! the default endpoint, the default chat path used when an endpoint URL
//! carries no path of its own, which request-body field
//! `override.llm_options.max_tokens` maps onto, and the outbound content
//! type. Endpoints mirror APISIX (`apisix/plugins/ai-providers/*.lua`):
//!
//! * `openai` — `api.openai.com` `/v1/chat/completions`; `max_tokens` maps
//!   to `max_completion_tokens` and the legacy `max_tokens` is removed
//!   (OpenAI rejects requests carrying both).
//! * `deepseek` — `api.deepseek.com` `/chat/completions` (no `/v1`
//!   prefix); `max_tokens`.
//! * `openai-compatible` — no default host (`override.endpoint` required);
//!   OpenAI-compatible chat path `/v1/chat/completions`; `max_tokens`.
//! * `anthropic` — `api.anthropic.com` `/v1/messages`; `max_tokens`; the
//!   client's OpenAI-format body is converted to Anthropic Messages format
//!   (system role extraction) and `anthropic-version` is injected.

use serde::{Deserialize, Serialize};

/// The LLM providers supported by ai-proxy v1.
///
/// Wire values are kebab-case to match APISIX's provider enum verbatim;
/// serde's unknown-variant error lists every legal value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Provider {
    Openai,
    OpenaiCompatible,
    Deepseek,
    Anthropic,
}

impl Provider {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Provider::Openai => "openai",
            Provider::OpenaiCompatible => "openai-compatible",
            Provider::Deepseek => "deepseek",
            Provider::Anthropic => "anthropic",
        }
    }
}

/// Which request-body field `override.llm_options.max_tokens` writes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaxTokensField {
    /// OpenAI Chat Completions: write `max_completion_tokens` and delete the
    /// legacy `max_tokens` field (carrying both is rejected upstream).
    MaxCompletionTokens,
    /// Every other v1 provider keeps the classic `max_tokens` field.
    MaxTokens,
}

/// Static per-provider wiring for the generic ai-proxy pipeline.
pub(crate) struct ProviderSpec {
    /// Full default endpoint URL, or `None` when the provider requires
    /// `override.endpoint` (openai-compatible).
    pub(crate) default_endpoint: Option<&'static str>,
    /// Default chat-completions path applied when the effective endpoint URL
    /// carries no path of its own (APISIX: "endpoint path wins over the
    /// capability path; a scheme+host endpoint keeps the default path").
    pub(crate) chat_path: &'static str,
    /// Target field for `override.llm_options.max_tokens`.
    pub(crate) max_tokens_field: MaxTokensField,
    /// Outbound `Content-Type` (JSON for every v1 provider).
    pub(crate) content_type: &'static str,
}

static OPENAI: ProviderSpec = ProviderSpec {
    default_endpoint: Some("https://api.openai.com/v1/chat/completions"),
    chat_path: "/v1/chat/completions",
    max_tokens_field: MaxTokensField::MaxCompletionTokens,
    content_type: "application/json",
};

static OPENAI_COMPATIBLE: ProviderSpec = ProviderSpec {
    default_endpoint: None,
    chat_path: "/v1/chat/completions",
    max_tokens_field: MaxTokensField::MaxTokens,
    content_type: "application/json",
};

static DEEPSEEK: ProviderSpec = ProviderSpec {
    // NOTE: DeepSeek's chat path has no `/v1` prefix.
    default_endpoint: Some("https://api.deepseek.com/chat/completions"),
    chat_path: "/chat/completions",
    max_tokens_field: MaxTokensField::MaxTokens,
    content_type: "application/json",
};

static ANTHROPIC: ProviderSpec = ProviderSpec {
    default_endpoint: Some("https://api.anthropic.com/v1/messages"),
    chat_path: "/v1/messages",
    max_tokens_field: MaxTokensField::MaxTokens,
    content_type: "application/json",
};

/// Static wiring for one provider.
pub(crate) fn provider_spec(provider: Provider) -> &'static ProviderSpec {
    match provider {
        Provider::Openai => &OPENAI,
        Provider::OpenaiCompatible => &OPENAI_COMPATIBLE,
        Provider::Deepseek => &DEEPSEEK,
        Provider::Anthropic => &ANTHROPIC,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_match_apisix_provider_enum() {
        for (value, expected) in [
            ("openai", Provider::Openai),
            ("openai-compatible", Provider::OpenaiCompatible),
            ("deepseek", Provider::Deepseek),
            ("anthropic", Provider::Anthropic),
        ] {
            let parsed: Provider = serde_json::from_value(serde_json::json!(value))
                .unwrap_or_else(|e| panic!("{value}: {e}"));
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), value);
        }
    }

    #[test]
    fn unknown_provider_error_lists_legal_values() {
        let err = serde_json::from_value::<Provider>(serde_json::json!("cohere")).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("openai-compatible"), "{text}");
        assert!(text.contains("anthropic"), "{text}");
    }

    #[test]
    fn endpoints_and_max_tokens_fields_match_apisix() {
        assert_eq!(
            provider_spec(Provider::Openai).default_endpoint,
            Some("https://api.openai.com/v1/chat/completions")
        );
        assert_eq!(
            provider_spec(Provider::Openai).max_tokens_field,
            MaxTokensField::MaxCompletionTokens
        );

        let compatible = provider_spec(Provider::OpenaiCompatible);
        assert_eq!(compatible.default_endpoint, None);
        assert_eq!(compatible.chat_path, "/v1/chat/completions");
        assert_eq!(compatible.max_tokens_field, MaxTokensField::MaxTokens);

        let deepseek = provider_spec(Provider::Deepseek);
        assert_eq!(
            deepseek.default_endpoint,
            Some("https://api.deepseek.com/chat/completions")
        );
        assert_eq!(deepseek.max_tokens_field, MaxTokensField::MaxTokens);

        let anthropic = provider_spec(Provider::Anthropic);
        assert_eq!(
            anthropic.default_endpoint,
            Some("https://api.anthropic.com/v1/messages")
        );
        assert_eq!(anthropic.max_tokens_field, MaxTokensField::MaxTokens);

        for provider in [
            Provider::Openai,
            Provider::OpenaiCompatible,
            Provider::Deepseek,
            Provider::Anthropic,
        ] {
            assert_eq!(provider_spec(provider).content_type, "application/json");
        }
    }
}
