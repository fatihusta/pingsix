use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    config::UpstreamHashOn,
    core::{PluginPhases, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::config::parse_and_validate_plugin_config,
    utils::{apisix_vars::match_apisix_vars, request::request_selector_key},
};

pub const PLUGIN_NAME: &str = "response-rewrite";
const PRIORITY: i32 = 899;

pub fn create_response_rewrite_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginResponseRewrite { config }))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum HeadersConfig {
    /// Simple mode: {"Header": "Value"}
    Simple(HashMap<String, String>),
    /// Structured mode: {"set": {}, "add": [], "remove": []}
    Structured {
        #[serde(default)]
        add: Vec<String>,
        #[serde(default)]
        set: HashMap<String, String>,
        #[serde(default)]
        remove: Vec<String>,
    },
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    status_code: Option<u16>,
    headers: Option<HeadersConfig>,
    /// Format like [["arg_name", "==", "val"], ["http_x", "!=", "reg"]]
    vars: Option<Vec<Vec<String>>>,
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Failed to parse response-rewrite config")?;
        Ok(config)
    }
}

pub struct PluginResponseRewrite {
    config: PluginConfig,
}

impl PluginResponseRewrite {
    /// Expand the documented response-rewrite variables. Unknown `$name`
    /// sequences are deliberately preserved rather than silently erased.
    fn expand_vars(&self, session: &mut Session, ctx: &ProxyContext, val: &str) -> String {
        let remote_addr = request_selector_key(session, &UpstreamHashOn::VARS, "remote_addr");
        Self::expand_template(
            val,
            &remote_addr,
            ctx.selected.as_ref().map(|selected| selected.node.as_str()),
            ctx.request_id(),
        )
    }

    fn expand_template(
        val: &str,
        remote_addr: &str,
        upstream_addr: Option<&str>,
        request_id: Option<&str>,
    ) -> String {
        if !val.contains('$') {
            return val.to_string();
        }
        // Replace only the three supported `$name` tokens by identifier
        // boundary, so a variable like `$request_id_suffix` or
        // `$remote_address` is preserved verbatim instead of being silently
        // rewritten by a prefix match.
        let mut out = String::with_capacity(val.len());
        let mut rest = val;
        while let Some(dollar) = rest.find('$') {
            out.push_str(&rest[..dollar]);
            let after = &rest[dollar + 1..];
            let name_len = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            if name_len == 0 {
                // Lone '$' or '$' followed by a non-identifier char: keep '$'.
                out.push('$');
                rest = after;
                continue;
            }
            let name = &after[..name_len];
            // Known variable names expand even when the value is unavailable
            // (empty string). Unknown names are preserved verbatim. The
            // token boundary above ensures `$remote_address` is treated as an
            // unknown name, not a `$remote_addr` prefix match.
            match name {
                "remote_addr" => out.push_str(remote_addr),
                "upstream_addr" => out.push_str(upstream_addr.unwrap_or("")),
                "request_id" => out.push_str(request_id.unwrap_or("")),
                _ => {
                    out.push('$');
                    out.push_str(name);
                }
            }
            rest = &after[name_len..];
        }
        out.push_str(rest);
        out
    }
}

#[async_trait]
impl ProxyPlugin for PluginResponseRewrite {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }
    fn priority(&self) -> i32 {
        PRIORITY
    }
    fn phases(&self) -> PluginPhases {
        PluginPhases::RESPONSE
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // 1. Check matching conditions
        let vars = self.config.vars.as_deref().unwrap_or(&[]);
        if !match_apisix_vars(session, vars) {
            return Ok(());
        }

        // 2. Override the status code when configured
        if let Some(code) = self.config.status_code {
            if let Ok(status) = StatusCode::from_u16(code) {
                let _ = upstream_response.set_status(status);
            }
        }

        // 3. Apply header mutations
        if let Some(ref h_cfg) = self.config.headers {
            match h_cfg {
                HeadersConfig::Simple(headers) => {
                    for (k, v) in headers {
                        let val = self.expand_vars(session, ctx, v);
                        upstream_response.insert_header(k.clone(), val)?;
                    }
                }
                HeadersConfig::Structured { add, set, remove } => {
                    // Remove
                    for k in remove {
                        upstream_response.remove_header(k);
                    }
                    // Set
                    for (k, v) in set {
                        let val = self.expand_vars(session, ctx, v);
                        upstream_response.insert_header(k.clone(), val)?;
                    }
                    // Add
                    for entry in add {
                        if let Some((k, v)) = entry.split_once(':') {
                            let val = self.expand_vars(session, ctx, v.trim());
                            upstream_response.append_header(k.trim().to_string(), val)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PluginResponseRewrite;

    #[test]
    fn expands_context_variables_and_preserves_unknown_variables() {
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "client=$remote_addr upstream=$upstream_addr id=$request_id unknown=$unknown",
                "192.0.2.1",
                Some("10.0.0.1:8080"),
                Some("request-123"),
            ),
            "client=192.0.2.1 upstream=10.0.0.1:8080 id=request-123 unknown=$unknown"
        );
    }

    #[test]
    fn missing_context_variables_expand_to_empty_strings() {
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "$upstream_addr/$request_id/$unknown",
                "192.0.2.1",
                None,
                None,
            ),
            "//$unknown"
        );
    }

    #[test]
    fn prefix_overlapping_variables_are_not_partially_rewritten() {
        // `$remote_address` must not be rewritten by the `$remote_addr` prefix,
        // and `$request_id_suffix` must not be rewritten by `$request_id`.
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "$remote_address-$request_id_suffix",
                "192.0.2.1",
                Some("10.0.0.1:8080"),
                Some("req-1"),
            ),
            "$remote_address-$request_id_suffix"
        );
    }

    #[test]
    fn adjacent_known_variables_are_all_replaced() {
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "$remote_addr$upstream_addr$request_id",
                "192.0.2.1",
                Some("10.0.0.1:8080"),
                Some("req-1"),
            ),
            "192.0.2.110.0.0.1:8080req-1"
        );
    }

    #[test]
    fn lone_dollar_sign_and_non_identifier_dollar_are_preserved() {
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "price=$5 and trailing=$",
                "192.0.2.1",
                None,
                None,
            ),
            "price=$5 and trailing=$"
        );
    }
}
