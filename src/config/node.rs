//! Upstream node configuration: address parsing, validation and wire forms.

use std::{
    collections::HashMap,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

use super::UpstreamScheme;

/// `host` / `host:port` / `[ipv6]:port`.
static HOST_PORT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:\[(.+?)\]|([^:]+))(?::(\d+))?$").expect("Invalid HOST_PORT_REGEX pattern")
});

/// Hostname / FQDN only (no port, no IP literals).
static HOST_FQDN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
        .expect("Invalid regex pattern for node host FQDN validation")
});

fn validate_node_host(host: &str) -> Result<(), ValidationError> {
    if host.is_empty() {
        return Err(ValidationError::new("invalid_host"));
    }
    let bare = if host.starts_with('[') {
        if !(host.ends_with(']') && host.len() > 2) {
            return Err(ValidationError::new("invalid_host"));
        }
        &host[1..host.len() - 1]
    } else {
        host
    };

    if bare.parse::<Ipv4Addr>().is_ok() || bare.parse::<Ipv6Addr>().is_ok() {
        return Ok(());
    }

    // Dotted-quad lookalikes (e.g. 999.999.999.999) would otherwise match the
    // FQDN regex because digit labels are valid hostnames.
    if is_ipv4_shaped(bare) {
        return Err(ValidationError::new("invalid_host"));
    }

    if HOST_FQDN_REGEX.is_match(host) {
        return Ok(());
    }

    Err(ValidationError::new("invalid_host"))
}

fn is_ipv4_shaped(s: &str) -> bool {
    let mut parts = 0;
    for part in s.split('.') {
        parts += 1;
        if parts > 4 || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    parts == 4
}

fn strip_ipv6_brackets(host: &str) -> &str {
    if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

/// Split `host` / `host:port` / `[ipv6]:port`. A missing port yields `None`,
/// meaning "use the upstream scheme default". An explicit `0` is rejected: the
/// pre-PR validation treated it as invalid, and silently remapping it to the
/// default would accept configurations that used to fail.
fn split_host_port(addr: &str) -> Result<(&str, Option<u16>), ValidationError> {
    let caps = HOST_PORT_REGEX
        .captures(addr)
        .ok_or_else(|| ValidationError::new("invalid_address_format"))?;
    let host = caps
        .get(1)
        .or_else(|| caps.get(2))
        .ok_or_else(|| ValidationError::new("invalid_host"))?
        .as_str();

    validate_node_host(host)?;

    let port = match caps.get(3) {
        Some(p) => {
            let port = p
                .as_str()
                .parse::<u16>()
                .map_err(|_| ValidationError::new("invalid_port"))?;
            if port == 0 {
                return Err(ValidationError::new("invalid_port"));
            }
            Some(port)
        }
        None => None,
    };

    Ok((host, port))
}

/// Reject an explicit `0` on the list wire form: a port is either omitted
/// (scheme default) or explicitly `1..=65535`. This keeps list-form semantics
/// identical to the map form, where `"host:0"` is rejected by
/// [`split_host_port`].
fn deserialize_port<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let port = Option::<u16>::deserialize(deserializer)?;
    if port == Some(0) {
        return Err(serde::de::Error::custom(
            "node port must be 1..=65535, or omitted to use the scheme default",
        ));
    }
    Ok(port)
}

fn priority_is_default(priority: &i8) -> bool {
    *priority == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct Node {
    #[validate(custom(function = "validate_node_host"))]
    pub host: String,
    /// Explicit port (`1..=65535`), or `None` to use the upstream scheme
    /// default (80 for http/grpc, 443 for https/grpcs).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_port"
    )]
    pub port: Option<u16>,
    /// Relative load-balancing weight. `0` keeps the node in the configuration
    /// but excludes it from backend selection.
    #[serde(default = "Node::default_weight")]
    pub weight: u32,
    /// Selection priority among nodes (`i8`: -128..=127). Higher wins.
    #[serde(default, skip_serializing_if = "priority_is_default")]
    pub priority: i8,
}

impl Node {
    fn default_weight() -> u32 {
        1
    }

    /// Whether this node participates in load balancing.
    pub fn is_enabled(&self) -> bool {
        self.weight > 0
    }

    /// Host without surrounding IPv6 brackets, for comparisons and sorting.
    pub fn bare_host(&self) -> &str {
        strip_ipv6_brackets(&self.host)
    }

    /// Sort / fingerprint key. Includes weight and priority so two nodes that
    /// share a `(host, port)` pair (only possible when at least one is disabled)
    /// still sort deterministically instead of depending on insertion order.
    pub fn sort_key(&self) -> (&str, u16, u32, i8) {
        (
            self.bare_host(),
            self.port.unwrap_or(0),
            self.weight,
            self.priority,
        )
    }

    /// Canonical `host:port` / `[ipv6]:port` key used for lookups and display.
    ///
    /// Callers that only need to write the address somewhere should use the
    /// [`fmt::Display`] impl instead and skip the allocation.
    pub fn addr_key(&self) -> String {
        self.to_string()
    }

    /// Port actually dialed: the configured one, or the scheme default when the
    /// node omits it. Must stay in sync with backend construction in discovery.
    pub fn effective_port(&self, scheme: &UpstreamScheme) -> u16 {
        self.port.unwrap_or(match scheme {
            UpstreamScheme::HTTPS | UpstreamScheme::GRPCS => 443,
            UpstreamScheme::HTTP | UpstreamScheme::GRPC => 80,
        })
    }

    /// Address key after applying the scheme default port, so `example.com` and
    /// `example.com:80` over HTTP compare equal.
    pub fn effective_addr_key(&self, scheme: &UpstreamScheme) -> String {
        let mut key = String::new();
        let _ = write_addr(
            &mut key,
            self.bare_host(),
            Some(self.effective_port(scheme)),
        );
        key
    }

    /// Match a wire address (`host`, `host:port`, `[ipv6]:port`) without building
    /// an owned `addr_key` for this node.
    pub fn matches_addr(&self, addr: &str) -> bool {
        match split_host_port(addr) {
            Ok((host, port)) => self.bare_host() == host && self.port == port,
            Err(_) => false,
        }
    }
}

/// IPv6 hosts are re-bracketed so the result parses back as `host:port`.
/// A `None` port is omitted entirely (the scheme default applies).
fn write_addr(out: &mut impl fmt::Write, host: &str, port: Option<u16>) -> fmt::Result {
    if host.contains(':') {
        write!(out, "[{host}]")?;
    } else {
        write!(out, "{host}")?;
    }
    if let Some(port) = port {
        write!(out, ":{port}")?;
    }
    Ok(())
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_addr(f, self.bare_host(), self.port)
    }
}

/// Parses the legacy address form (`host`, `host:port`, `[ipv6]:port`) into a
/// node with default weight and priority.
impl FromStr for Node {
    type Err = ValidationError;

    fn from_str(addr: &str) -> Result<Self, Self::Err> {
        let (host, port) = split_host_port(addr)?;
        Ok(Node {
            host: host.to_string(),
            port,
            weight: Node::default_weight(),
            priority: 0,
        })
    }
}

/// Upstream node set.
///
/// Wire format accepts both the legacy map (`{"host:port": weight}`) and the
/// list (`[{host, port, weight, priority}, ...]`) forms. After
/// deserialization the canonical in-memory representation is always a list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Nodes(pub Vec<Node>);

impl Nodes {
    pub fn as_slice(&self) -> &[Node] {
        &self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Node> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Linear scan for a wire address; the node set is small by construction.
    pub fn contains_addr(&self, addr: &str) -> bool {
        self.0.iter().any(|n| n.matches_addr(addr))
    }

    pub fn push(&mut self, node: Node) {
        self.0.push(node);
    }

    #[cfg(test)]
    pub fn from_map(map: HashMap<String, u32>) -> Self {
        Self::try_from(map).unwrap_or_else(|e| panic!("invalid upstream nodes map: {e}"))
    }
}

impl TryFrom<HashMap<String, u32>> for Nodes {
    type Error = ValidationErrors;

    fn try_from(map: HashMap<String, u32>) -> Result<Self, Self::Error> {
        let mut errors = ValidationErrors::new();
        let mut nodes = Vec::with_capacity(map.len());
        for (addr, weight) in map {
            match addr.parse::<Node>() {
                Ok(node) => nodes.push(Node { weight, ..node }),
                Err(mut err) => {
                    err.add_param("key".into(), &addr);
                    errors.add("nodes", err);
                }
            }
        }

        if errors.is_empty() {
            // Canonicalize order: `HashMap` iteration order is random across
            // runs, and node order decides discovery/insert order (e.g. which
            // backend survives an equal-priority address collision). Sorting
            // makes restarts and re-submissions deterministic.
            nodes.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
            Ok(Nodes(nodes))
        } else {
            Err(errors)
        }
    }
}

impl Validate for Nodes {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if self.is_empty() {
            errors.add("nodes", ValidationError::new("nodes_empty"));
            return Err(errors);
        }

        if !self.iter().any(Node::is_enabled) {
            errors.add("nodes", ValidationError::new("nodes_all_disabled"));
        }

        // Report per-node failures as errors of this field rather than nesting
        // them: `ValidationErrors` panics when the same field is filled twice,
        // which two invalid nodes (or one plus a field error above) would do.
        for (index, node) in self.0.iter().enumerate() {
            if let Err(mut err) = validate_node_host(&node.host) {
                err.add_param("index".into(), &index);
                err.add_param("host".into(), &node.host);
                errors.add("nodes", err);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl<'de> Deserialize<'de> for Nodes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Dispatched on the wire shape (map vs. list) instead of an untagged
        // enum so that a bad entry reports its real error (e.g. `priority` out
        // of range or a non-integer weight) rather than the generic "did not
        // match any variant of untagged enum" message.
        struct NodesVisitor;

        impl<'de> serde::de::Visitor<'de> for NodesVisitor {
            type Value = Nodes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of \"address:port\" to weight, or an array of node objects")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut nodes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(node) = seq.next_element::<Node>()? {
                    nodes.push(node);
                }
                Ok(Nodes(nodes))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let map = HashMap::<String, u32>::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )?;
                Nodes::try_from(map).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(NodesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(host: &str, port: u16, weight: u32, priority: i8) -> Node {
        Node {
            host: host.into(),
            // Test convenience: 0 means "port omitted" (scheme default). An
            // explicit 0 is rejected by deserialization and must never be
            // constructed.
            port: (port != 0).then_some(port),
            weight,
            priority,
        }
    }

    #[test]
    fn split_host_port_parses_supported_forms() {
        let test_cases = [
            ("127.0.0.1", ("127.0.0.1", None)),
            // IPv6 without brackets; brackets are re-added for SocketAddr / addr keys.
            ("[::1]", ("::1", None)),
            ("example.com", ("example.com", None)),
            ("example.com:80", ("example.com", Some(80))),
            ("192.168.1.1:8080", ("192.168.1.1", Some(8080))),
            (
                "[2001:db8:85a3::8a2e:370:7334]:8080",
                ("2001:db8:85a3::8a2e:370:7334", Some(8080)),
            ),
            // Maximum valid socket port parses; one past it must be rejected
            // instead of wrapping around to zero.
            ("127.0.0.1:65535", ("127.0.0.1", Some(65535))),
        ];

        for (input, expected) in test_cases {
            let result = split_host_port(input).unwrap();
            assert_eq!(result, expected, "Failed for input: {input}");
        }

        assert!(split_host_port("").is_err());
        assert!(split_host_port("invalid:port").is_err());
        assert!(split_host_port("127.0.0.1:invalid").is_err());
        assert!(
            split_host_port("127.0.0.1:65536").is_err(),
            "port above u16::MAX must be rejected, not wrapped"
        );
        assert!(
            split_host_port("[::1]:65536").is_err(),
            "IPv6 port above u16::MAX must be rejected, not wrapped"
        );
        assert!(
            split_host_port("127.0.0.1:0").is_err(),
            "explicit port 0 must be rejected, not remapped to the scheme default"
        );
    }

    #[test]
    fn node_display_formats_ipv4_and_ipv6() {
        assert_eq!(node("10.0.0.1", 80, 1, 0).addr_key(), "10.0.0.1:80");
        assert_eq!(node("::1", 8080, 1, 0).to_string(), "[::1]:8080");
        // Already-bracketed hosts must not be double-wrapped.
        assert_eq!(node("[::1]", 8080, 1, 0).to_string(), "[::1]:8080");
    }

    #[test]
    fn node_parses_from_addr_and_round_trips_through_display() {
        for addr in [
            "127.0.0.1:18080",
            "[2001:db8::1]:443",
            "example.com:80",
            // A portless address round-trips without a port.
            "example.com",
        ] {
            let node: Node = addr.parse().unwrap();
            assert_eq!(node.to_string(), addr);
            assert_eq!(node.weight, 1);
            assert_eq!(node.priority, 0);
        }

        assert!("not a host".parse::<Node>().is_err());
        assert!("127.0.0.1:0".parse::<Node>().is_err());
    }

    #[test]
    fn nodes_deserializes_map_into_list() {
        let nodes: Nodes = serde_json::from_value(serde_json::json!({
            "127.0.0.1:18080": 1,
            "10.0.0.2:80": 2
        }))
        .unwrap();

        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains_addr("127.0.0.1:18080"));
        assert!(nodes.contains_addr("10.0.0.2:80"));
        let weights: HashMap<_, _> = nodes.iter().map(|n| (n.addr_key(), n.weight)).collect();
        assert_eq!(weights["127.0.0.1:18080"], 1);
        assert_eq!(weights["10.0.0.2:80"], 2);
        // Map-derived nodes are canonically sorted, so the order is stable
        // across restarts regardless of HashMap iteration order.
        assert_eq!(nodes.as_slice()[0].addr_key(), "10.0.0.2:80");
        assert_eq!(nodes.as_slice()[1].addr_key(), "127.0.0.1:18080");
    }

    #[test]
    fn nodes_deserializes_list_form() {
        let nodes: Nodes = serde_json::from_value(serde_json::json!([
            {"host": "127.0.0.1", "port": 18080, "weight": 1, "priority": 0},
            {"host": "10.0.0.2", "port": 80, "weight": 2}
        ]))
        .unwrap();

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes.as_slice()[0].host, "127.0.0.1");
        assert_eq!(nodes.as_slice()[0].port, Some(18080));
        assert_eq!(nodes.as_slice()[1].weight, 2);
        assert_eq!(nodes.as_slice()[1].priority, 0); // serde default
    }

    #[test]
    fn nodes_list_defaults_weight_and_omitted_port() {
        let nodes: Nodes =
            serde_json::from_value(serde_json::json!([{"host": "example.com"}])).unwrap();
        let node = &nodes.as_slice()[0];
        assert!(node.port.is_none());
        assert_eq!(node.weight, 1);
        assert_eq!(node.priority, 0);
    }

    #[test]
    fn nodes_serialize_omits_default_port_and_priority() {
        let nodes = Nodes(vec![node("example.com", 0, 1, 0)]);
        let value = serde_json::to_value(&nodes).unwrap();
        let obj = &value.as_array().unwrap()[0];
        assert!(
            obj.get("port").is_none(),
            "omitted port must not serialize as 0"
        );
        assert!(
            obj.get("priority").is_none(),
            "default priority must not serialize as 0"
        );
        assert_eq!(obj["host"], "example.com");
        assert_eq!(obj["weight"], 1);
    }

    #[test]
    fn explicit_zero_port_is_rejected_on_every_wire_form() {
        // List form.
        let list_err = serde_json::from_value::<Nodes>(serde_json::json!([{
            "host": "127.0.0.1",
            "port": 0
        }]))
        .unwrap_err();
        assert!(
            list_err.to_string().contains("1..=65535"),
            "explicit 0 must fail with a specific message: {list_err}"
        );

        // Map form ("host:0" key) and FromStr share the same parser.
        assert!(Nodes::try_from(HashMap::from([("127.0.0.1:0".to_string(), 1)])).is_err());
        assert!("127.0.0.1:0".parse::<Node>().is_err());
    }

    #[test]
    fn list_form_errors_keep_their_specific_message() {
        // `priority: 128` overflows i8. The error must name the real cause
        // instead of the generic untagged-enum fallback message.
        let err = serde_json::from_value::<Nodes>(serde_json::json!([{
            "host": "127.0.0.1",
            "port": 80,
            "priority": 128
        }]))
        .unwrap_err();
        assert!(
            err.to_string().contains("expected i8"),
            "priority overflow must surface its own error: {err}"
        );

        // Same for a non-integer weight in the map form.
        let err = serde_json::from_value::<Nodes>(serde_json::json!({
            "127.0.0.1:80": "one"
        }))
        .unwrap_err();
        assert!(
            err.to_string().contains("expected u32"),
            "bad map weight must surface its own error: {err}"
        );
    }

    #[test]
    fn nodes_serializes_as_list() {
        let nodes = Nodes::from_map(HashMap::from([("127.0.0.1:80".to_string(), 1)]));
        let value = serde_json::to_value(&nodes).unwrap();
        assert!(
            value.is_array(),
            "canonical wire output must be a list: {value}"
        );
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(value[0]["host"], "127.0.0.1");
        assert_eq!(value[0]["port"], 80);
        assert_eq!(value[0]["weight"], 1);
    }

    #[test]
    fn nodes_rejects_empty_and_invalid_map_entries() {
        assert!(Nodes::default().validate().is_err());

        let bad_key = HashMap::from([("not a host".to_string(), 1)]);
        assert!(Nodes::try_from(bad_key).is_err());
    }

    #[test]
    fn nodes_push_and_contains_addr() {
        let mut nodes = Nodes::default();
        nodes.push("127.0.0.1:18080".parse().unwrap());
        nodes.push("[2001:db8::1]:443".parse().unwrap());

        assert!(nodes.contains_addr("127.0.0.1:18080"));
        assert!(nodes.contains_addr("[2001:db8::1]:443"));
        assert!(!nodes.contains_addr("10.0.0.9:80"));
        assert_eq!(nodes.len(), 2);
        assert!(nodes.validate().is_ok());
    }

    #[test]
    fn nodes_weight_zero_is_disabled_but_valid_with_enabled_peer() {
        let nodes = Nodes::from_map(HashMap::from([
            ("127.0.0.1:80".to_string(), 0),
            ("10.0.0.2:80".to_string(), 1),
        ]));
        assert!(nodes.validate().is_ok());
        assert_eq!(nodes.iter().filter(|n| n.is_enabled()).count(), 1);
        assert_eq!(nodes.iter().filter(|n| !n.is_enabled()).count(), 1);
    }

    #[test]
    fn validate_node_host_accepts_ipv4_ipv6_and_fqdn() {
        for host in [
            "127.0.0.1",
            "192.168.1.1",
            "::1",
            "[::1]",
            "2001:db8::1",
            "[2001:db8::1]",
            "localhost",
            "example.com",
            "api.example.com",
            "my-service.default.svc.cluster.local",
        ] {
            assert!(
                validate_node_host(host).is_ok(),
                "expected valid host: {host}"
            );
        }

        for host in [
            "",
            "   ",
            "not a host",
            "127.0.0.1:80",
            "999.999.999.999",
            "[::1",
            "example.com.",
            "-bad.example",
            "example..com",
            // Validation must not trim: a whitespace-padded host would validate
            // but then fail DNS resolution at runtime with a confusing error.
            " example.com",
            "example.com ",
        ] {
            assert!(
                validate_node_host(host).is_err(),
                "expected invalid host: {host}"
            );
        }
    }

    #[test]
    fn node_validate_rejects_invalid_host() {
        assert!(node("not a host", 80, 1, 0).validate().is_err());
        assert!(node("example.com", 80, 1, 0).validate().is_ok());
    }

    #[test]
    fn nodes_validate_rejects_all_disabled() {
        let all_disabled = Nodes(vec![node("127.0.0.1", 80, 0, 0)]);
        assert!(all_disabled.validate().is_err());
    }

    #[test]
    fn nodes_validate_reports_every_invalid_node_without_panicking() {
        let nodes = Nodes(vec![
            node("not a host", 80, 1, 0),
            node("also bad", 80, 1, 0),
            node("example.com", 80, 1, 0),
            node("999.999.999.999", 80, 1, 0),
        ]);

        let err = nodes
            .validate()
            .expect_err("invalid hosts must be rejected");
        let field_errors = err.field_errors();
        let reported = field_errors
            .get("nodes")
            .expect("errors must be attached to the nodes field");
        assert_eq!(
            reported.len(),
            3,
            "every invalid node must be reported: {reported:?}"
        );
    }

    #[test]
    fn nodes_validate_combines_field_error_with_invalid_node() {
        // `nodes_all_disabled` plus a per-node error previously filled the same
        // field twice, which panics inside `ValidationErrors`.
        let nodes = Nodes(vec![node("not a host", 80, 0, 0)]);
        assert!(nodes.validate().is_err());
    }

    #[test]
    fn effective_port_applies_scheme_default_only_when_omitted() {
        let omitted = node("example.com", 0, 1, 0);
        assert_eq!(omitted.effective_port(&UpstreamScheme::HTTP), 80);
        assert_eq!(omitted.effective_port(&UpstreamScheme::GRPC), 80);
        assert_eq!(omitted.effective_port(&UpstreamScheme::HTTPS), 443);
        assert_eq!(omitted.effective_port(&UpstreamScheme::GRPCS), 443);

        let explicit = node("example.com", 8080, 1, 0);
        assert_eq!(explicit.effective_port(&UpstreamScheme::HTTPS), 8080);

        let v6 = node("::1", 0, 1, 0);
        assert_eq!(
            v6.effective_addr_key(&UpstreamScheme::HTTPS),
            "[::1]:443",
            "effective key must stay parseable for IPv6"
        );
    }

    #[test]
    fn node_priority_is_i8() {
        let ok: Node = serde_json::from_value(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "priority": -1
        }))
        .unwrap();
        assert_eq!(ok.priority, -1);

        let edges: Node = serde_json::from_value(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "priority": 127
        }))
        .unwrap();
        assert_eq!(edges.priority, 127);

        assert!(serde_json::from_value::<Node>(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "priority": 128
        }))
        .is_err());
        assert!(serde_json::from_value::<Node>(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "priority": -129
        }))
        .is_err());
    }

    #[test]
    fn nodes_rejects_mixed_map_and_list_wire_forms() {
        // JSON: a bare Node object is neither a weight map (values must be u32)
        // nor a list (must be an array).
        assert!(serde_json::from_value::<Nodes>(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "weight": 1
        }))
        .is_err());

        // JSON: array of weight-map entries is not a valid list of Node objects.
        assert!(serde_json::from_value::<Nodes>(serde_json::json!(["127.0.0.1:80", 1])).is_err());
    }
}
