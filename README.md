# PingSIX

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.98%2B-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://img.shields.io/github/actions/workflow/status/zhu327/pingsix/rust.yml)](https://github.com/zhu327/pingsix/actions)

> A high-performance, cloud-native API gateway built with Rust

PingSIX is a modern API gateway designed for cloud-native environments, offering exceptional performance, flexibility, and reliability. Inspired by industry leaders like [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [Apache APISIX](https://apisix.apache.org/), PingSIX leverages Rust's safety and performance characteristics to deliver enterprise-grade reverse proxying and API management capabilities.

## ✨ Features

- 🚀 **High Performance**: Built with Rust and Tokio for exceptional throughput and low latency
- 🔄 **Dynamic Configuration**: Real-time configuration updates via etcd integration
- 🛣️ **Advanced Routing**: Flexible request matching based on host, path, methods, and priorities
- 🔌 **Rich Plugin Ecosystem**: 29 built-in plugins with easy extensibility
- 📊 **Observability**: Built-in Prometheus metrics and Sentry integration
- 🔒 **Security**: JWT/API key authentication, IP restrictions, CORS support, circuit breaking
- ⚡ **Load Balancing**: Multiple algorithms with active and passive health checking
- 🌐 **SSL/TLS**: Dynamic certificate loading with SNI support
- 📝 **Admin API**: RESTful API compatible with Apache APISIX specification

## 📚 Documentation

- **[User Guide](USER_GUIDE.md)** - Comprehensive documentation with examples and best practices
- **[Configuration Reference](USER_GUIDE.md#configuration)** - Detailed configuration options
- **[Plugin Documentation](USER_GUIDE.md#plugins)** - Complete plugin reference and usage
- **[Admin API](USER_GUIDE.md#admin-api)** - RESTful API for dynamic configuration
- **[Examples](USER_GUIDE.md#examples)** - Real-world usage scenarios

## 🚀 Quick Start

### Prerequisites

- Rust stable (MSRV 1.98); local toolchain via `rust-toolchain.toml` (`channel = "1.98.0"`)
- (Optional) etcd for dynamic configuration

### Installation

```bash
# Clone the repository
git clone https://github.com/zhu327/pingsix.git
cd pingsix

# Build the project
cargo build --release

# Run with configuration
./target/release/pingsix -c config.yaml
```

### Basic Configuration

Create a `config.yaml` file:

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:8080

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "httpbin.org:80": 1
      type: roundrobin
```

Start PingSIX:

```bash
./target/release/pingsix -c config.yaml
```

Test the gateway:

```bash
curl http://localhost:8080/get
```

## 🔌 Plugin Ecosystem

PingSIX includes 29 built-in plugins organized by category:

> **Upgrading from an earlier build:** the `cache` plugin was renamed to
> `proxy-cache` (breaking, no alias). Rewrite every `cache:` plugin key in
> static configs and etcd route/global-rule data to `proxy-cache:` **before**
> deploying — a single stale key fails the whole config snapshot build.

### 🔐 Authentication & Security
- **`jwt-auth`** - JWT token validation with multiple algorithms
- **`key-auth`** - API key authentication with rotation support
- **`basic-auth`** - HTTP Basic Authentication with constant-time comparison
- **`csrf`** - CSRF protection using double-submit cookie pattern
- **`ip-restriction`** - IP allowlist/blocklist with CIDR support
- **`uri-blocker`** - URI regex blocklist (APISIX compatible)
- **`request-validation`** - JSON Schema validation of request headers and bodies (APISIX compatible)
- **`cors`** - Cross-Origin Resource Sharing with regex patterns
- **`exit-transformer`** - Declarative rewriting of gateway-generated error responses

### 🚦 Traffic Management
- **`limit-count`** - Request rate limiting with flexible keys
- **`limit-req`** - Leaky bucket rate limiting with burst queueing
- **`limit-conn`** - Concurrent request limiting with burst delay
- **`traffic-split`** - A/B testing and canary deployments with weighted traffic distribution
- **`proxy-mirror`** - Asynchronous request mirroring to shadow upstreams
- **`api-breaker`** - Circuit breaking with exponential backoff recovery
- **`proxy-rewrite`** - Request modification
- **`response-rewrite`** - Response headers modification
- **`redirect`** - HTTP redirects with regex support
- **`proxy-cache`** - Response caching with TTL, opt-in PURGE, and conditions
- **`client-control`** - Request body size limiting (413 enforcement)

### 🤖 AI / LLM
- **`ai-proxy`** - OpenAI-format LLM proxy to openai / deepseek / anthropic /
  any OpenAI-compatible endpoint: auth injection, request-body transforms,
  per-provider upstreams, SSE passthrough (APISIX compatible)

### 📊 Observability
- **`prometheus`** - Metrics collection and exposition
- **`file-logger`** - Structured access logging
- **`request-id`** - Request tracing with unique IDs

### 🗜️ Performance
- **`gzip`** / **`brotli`** - Response compression
- **`grpc-web`** - gRPC-Web protocol support

### 🛠️ Utilities & Testing
- **`echo`** - Wrap or replace upstream response bodies for testing
- **`fault-injection`** - Chaos engineering with delay and abort injection

> 📖 For detailed plugin configuration, see the [Plugin Documentation](USER_GUIDE.md#plugins)

## 🏗️ Architecture

PingSIX is built on a modular architecture with the following key components:

- **Core Engine**: Built on Cloudflare's Pingora framework for high-performance HTTP handling
- **Plugin System**: Extensible plugin architecture with 29 built-in plugins
- **Configuration Management**: Support for both static YAML and dynamic etcd-based configuration
- **Admin API**: RESTful API for runtime configuration management
- **Observability**: Built-in metrics, logging, and error tracking

## 🔧 Configuration

PingSIX supports both static and dynamic configuration:

### Static Configuration (YAML)
```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:8080
  prometheus:
    address: 0.0.0.0:9091

routes:
  - id: "api-gateway"
    uri: /api/*
    upstream:
      nodes:
        "backend1.example.com:8080": 1
        "backend2.example.com:8080": 1
      type: roundrobin
    plugins:
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100
```

### Dynamic Configuration (etcd + Admin API)
```bash
# Create a route via Admin API
curl -X PUT http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/api/*",
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend1.example.com:8080": 1
      }
    }
  }'
```

> 📖 For complete configuration reference, see the [Configuration Guide](USER_GUIDE.md#configuration)

## 🚀 Performance

PingSIX is designed for high performance:

- **Zero-copy**: Efficient request/response handling with minimal memory allocation
- **Async I/O**: Built on Tokio for excellent concurrency
- **Connection Pooling**: Efficient upstream connection management
- **Health Checking**: Automatic failover for unhealthy backends
- **Caching**: Built-in response caching with configurable TTL

### Benchmarks

| Metric | Performance |
|--------|-------------|
| Requests/sec | 100K+ RPS |
| Latency (P99) | < 10ms |
| Memory Usage | < 50MB |
| CPU Usage | < 30% (4 cores) |

> 📊 The table above lists **design targets** from an AWS c5.xlarge (4 vCPU, 8GB RAM)
> baseline. The repository does not yet ship a reproducible end-to-end load-test
> harness that produces these numbers; treat them as goals, not guarantees.
> Micro-benchmarks (`cargo bench --bench plugin_pipeline`, `--bench
> route_matching`) cover plugin dispatch and route matching only.

## 🌐 Use Cases

PingSIX is ideal for:

- **API Gateway**: Centralized API management and routing
- **Reverse Proxy**: High-performance load balancing and proxying
- **Microservices**: Service mesh and inter-service communication
- **CDN Edge**: Content delivery and caching at the edge
- **Security Gateway**: Authentication, authorization, and traffic filtering

## 🤝 Community & Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/zhu327/pingsix/issues)
- **Discussions**: [Community discussions and Q&A](https://github.com/zhu327/pingsix/discussions)
- **Documentation**: [Comprehensive user guide](USER_GUIDE.md)

## 🛠️ Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/zhu327/pingsix.git
cd pingsix

# Install dependencies
cargo build

# Run tests
cargo test

# Run with development config
cargo run -- -c config.yaml
```

### Creating Custom Plugins

```rust
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use pingsix::core::{
    FilterVerdict, PluginEntry, PluginPhases, ProxyContext, ProxyPlugin,
    ProxyPluginExecutor, Rejection,
};

pub struct MyCustomPlugin {
    config: MyPluginConfig,
}

#[async_trait]
impl ProxyPlugin for MyCustomPlugin {
    fn name(&self) -> &str {
        "my-custom-plugin"
    }

    fn priority(&self) -> i32 {
        1000
    }

    // There is no `phases()` method: phases are construction data (see the
    // `PluginEntry::new` call below). A hook whose phase is not declared is
    // never executed.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> pingora_error::Result<FilterVerdict> {
        if should_reject(&self.config, session) {
            // Return the rejection; the pipeline writes it through the shared
            // exit-response path (so exit-transformer rules apply). A plugin
            // never writes a rejection response itself.
            return Ok(FilterVerdict::Reject(
                Rejection::new(StatusCode::FORBIDDEN).with_body("request denied"),
            ));
        }
        Ok(FilterVerdict::Continue)
    }
}

// Embedders pair each plugin with its declared lifecycle phases when
// building the executor; builtin plugins get theirs from `PLUGIN_META`.
let executor = ProxyPluginExecutor::new(vec![PluginEntry::new(
    Arc::new(MyCustomPlugin { config }),
    PluginPhases::REQUEST,
)]);
```

> **Breaking plugin contract:** `ProxyPlugin::request_filter` now returns
> `FilterVerdict` — `Continue` to proceed, or `Reject(Rejection)` to
> short-circuit. Rejection responses are no longer written by the plugin (the
> former `ResponseBuilder::send_proxy_error` is gone): the plugin returns a
> `Rejection` value (`Rejection::new(status).with_body(..)` plus optional
> `with_content_type`, `with_header(s)`, `with_close_connection`) and the
> pipeline writes it once through `utils::response::send_rejection`, so
> `exit-transformer` rules apply uniformly to every gateway rejection. The
> `phases()` method is gone too: hook phases are declared as construction
> data — builtin plugins declare them once in `PLUGIN_META`, and embedders pass
> them to `PluginEntry::new(plugin, PHASES)` when building a
> `ProxyPluginExecutor`. A hook whose phase is not declared is never executed.
> `ProxyContext::selected` is now `Option<SelectedUpstream>` after Pingora takes
> ownership of the peer; use its `upstream`, `backend`, `sni`, and `node` fields
> rather than accessing `HttpPeer`.
>
> 📖 For plugin development guide, see [Plugin Development](USER_GUIDE.md#plugin-development)

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**: Follow our coding standards and add tests
4. **Commit your changes**: `git commit -m 'Add amazing feature'`
5. **Push to the branch**: `git push origin feature/amazing-feature`
6. **Open a Pull Request**

### Development Guidelines

- Follow Rust best practices and idioms
- Add tests for new functionality
- Update documentation for API changes
- Ensure all tests pass: `cargo test`
- Format code: `cargo fmt`
- Run clippy: `cargo clippy`

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Provide detailed reproduction steps for bugs
- Include system information and PingSIX version

## 🙏 Acknowledgments

PingSIX is built on the shoulders of giants:

- **[Cloudflare Pingora](https://github.com/cloudflare/pingora)** - High-performance HTTP proxy framework
- **[Apache APISIX](https://apisix.apache.org/)** - API gateway design patterns and Admin API compatibility
- **[Tokio](https://tokio.rs/)** - Asynchronous runtime for Rust
- **[etcd](https://etcd.io/)** - Distributed configuration storage

Special thanks to all contributors and the Rust community for making this project possible.

---

<div align="center">

**[Documentation](USER_GUIDE.md)** • **[Examples](USER_GUIDE.md#examples)** • **[Contributing](#-contributing)** • **[License](#-license)**

Made with ❤️ by the PingSIX team

</div>
