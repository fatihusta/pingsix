# PingSIX API Gateway - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Core Concepts](#core-concepts)
4. [Configuration](#configuration)
5. [Docker Deployment](#docker-deployment)
6. [Kubernetes Deployment](#kubernetes-deployment)
7. [Routing](#routing)
8. [Upstreams](#upstreams)
9. [Services](#services)
10. [Global Rules](#global-rules)
11. [Plugins](#plugins)
12. [Plugin Development](#plugin-development)
13. [Admin API](#admin-api)
14. [SSL/TLS Configuration](#ssltls-configuration)
15. [Monitoring and Observability](#monitoring-and-observability)
16. [Examples](#examples)
17. [Troubleshooting](#troubleshooting)

## Introduction

PingSIX is a high-performance API gateway built with Rust, designed for modern cloud-native environments. It provides advanced routing, load balancing, security, and observability features with excellent performance and reliability.

### Key Features

- **High Performance**: Built with Rust and Tokio for exceptional throughput and low latency
- **Dynamic Configuration**: Real-time configuration updates via etcd integration
- **Flexible Routing**: Advanced request matching based on host, path, methods, and priorities
- **Rich Plugin Ecosystem**: 28 built-in plugins for authentication, rate limiting, compression, and more
- **Health Checking**: Active health checks for upstream services
- **Observability**: Built-in Prometheus metrics and Sentry integration
- **Admin API**: RESTful API for dynamic configuration management

## Getting Started

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/zhu327/pingsix.git
   cd pingsix
   ```

2. **Build the project**:
   ```bash
   cargo build --release
   ```

3. **Run PingSIX**:
   ```bash
   ./target/release/pingsix -c config.yaml
   ```

### Basic Configuration

Create a `config.yaml` file with the following minimal configuration:

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

This configuration creates a simple proxy that forwards all requests to httpbin.org.

## Core Concepts

### Routes

Routes define how incoming requests are matched and processed. Each route specifies:
- **Matching criteria**: URI patterns, hosts, HTTP methods
- **Destination**: Where to forward the request (upstream or service)
- **Plugins**: Additional processing to apply
- **Name** (optional): Human-readable name

> **Upstream requirement:** PingSIX currently requires every route to bind an
> upstream, `upstream_id`, or `service_id` — even when a locally short-circuiting
> plugin such as `redirect` or `fault-injection(abort)` would respond
> without a backend. Use a placeholder upstream for such route-scoped plugins,
> or configure the plugin on a **global rule** to avoid a dummy upstream.
> This differs from APISIX, which allows upstream-less routes; the constraint is
> enforced at config validation time with this error.

### Upstreams

Upstreams define backend server pools with:
- **Nodes**: Backend servers with weight and optional priority (map or list form)
- **Load balancing**: Algorithm for distributing requests within a priority group
- **Health checks**: Monitoring backend server health; selection prefers the highest ready priority
- **Name** (optional): Human-readable name

### Services

Services group upstreams and plugins for reusability:
- **Upstream reference**: Link to an upstream configuration
- **Plugin configuration**: Shared plugins across multiple routes
- **Host matching**: Optional host-based routing
- **Name** (optional): Human-readable name

### Global Rules

Global rules apply plugins to all requests matching certain criteria:
- **Universal plugins**: Applied to all traffic
- **Monitoring**: Prometheus metrics, logging
- **Security**: Global authentication, rate limiting

## Configuration

### Configuration Structure

PingSIX uses YAML configuration with the following main sections:

```yaml
# Pingora framework settings
pingora:
  version: 1
  threads: 4
  pid_file: /var/run/pingsix.pid
  daemon: false

# PingSIX specific settings
pingsix:
  listeners: []       # Network listeners
  etcd: {}            # etcd configuration (optional)
  data_encryption: {} # Encrypt secrets in etcd (optional; see Data Encryption)
  admin: {}           # Admin API (optional)
  prometheus: {}      # Metrics endpoint (optional)
  sentry: {}          # Error tracking (optional)
  log: {}             # File logging (optional)

# Resource definitions
routes: []          # Route configurations
upstreams: []       # Upstream server pools
services: []        # Service definitions
global_rules: []    # Global plugin rules
ssls: []            # SSL certificates
```

### Listeners

Listeners define where PingSIX accepts connections:

```yaml
pingsix:
  listeners:
    # HTTP listener
    - address: 0.0.0.0:80
      offer_h2c: true  # HTTP/2 Cleartext support
    
    # HTTPS listener
    - address: 0.0.0.0:443
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true   # HTTP/2 over TLS
```

### etcd Integration

Enable dynamic configuration with etcd:

```yaml
pingsix:
  etcd:
    host:
      - "http://127.0.0.1:2379"
      - "http://127.0.0.1:2380"
    prefix: /pingsix
    timeout: 30
    connect_timeout: 10
    user: username      # Optional authentication
    password: password  # Optional authentication
```

#### Hot Reload & Atomic Resource Swaps

List, watch, and reconnect all share one control-plane path:

1. Build a candidate `ResourceConfigSet` (full list, or watch events coalesced per key in etcd order).
2. Validate and compile a `CandidateSnapshot` in dependency order
   (upstreams → services → global rules → routes → SSL matchers).
3. Publish a single immutable `RuntimeSnapshot` to the data plane.
4. Incrementally reconcile health checks (unchanged upstream fingerprints are not restarted).

Formal control-plane state and the published runtime snapshot are updated only after every step
succeeds. On failure the previous snapshot keeps serving traffic (last-known-good). Watch apply
failures interrupt the watch stream and force a full relist so rejected revisions are not skipped.
Empty watch batches do not publish.

### Data Encryption

When configuration is stored in etcd, sensitive fields can be encrypted at rest.
Enable this under `pingsix.data_encryption`:

```yaml
pingsix:
  etcd:
    host: ["http://127.0.0.1:2379"]
    prefix: /pingsix

  data_encryption:
    enable: true
    keyring:
      - "new-primary-key"   # used to encrypt new values
      - "previous-key"      # kept so older ciphertext still decrypts
```

**Behavior:**

- Admin API writes encrypt marked fields before they are stored in etcd.
- etcd load/watch decrypts them into memory; the data plane always sees plaintext.
- Admin **read** API (GET/LIST) decrypts to the logical resource first, then
  masks secret fields with `***`. Responses never contain ciphertext, and the
  output is identical whether or not encryption is enabled.
- **Resaving a redacted response is safe.** The `***` mask is a reserved
  sentinel: on PUT, any secret field still set to `***` is restored from the
  currently stored value, so a GET → edit → PUT round-trip keeps untouched
  secrets instead of persisting the mask (which would also fail validation, e.g.
  an SSL key). To rotate a secret, send its new value instead of `***`.
  (Consequently `***` cannot be used as a literal secret value.)
- Static YAML config is not encrypted (only the etcd store path).
- The first keyring entry encrypts. On decrypt, every entry is tried in order
  (newest first) so keys can be rotated without rewriting all resources.

**Ciphertext format:** values are stored as a versioned envelope
`$pingsix-enc:<version>$<payload>`. The current version `v1` is
`base64(nonce || ciphertext)` of AES-256-GCM with an Argon2id-derived key. The
scheme marker makes ciphertext detectable (plaintext passes through unchanged),
and the version tag lets the format evolve safely; an unknown version is a clear
error rather than a silent bad decrypt.

**What is encrypted today:**

| Resource / plugin | Field(s) |
|-------------------|----------|
| `ssls` | `key` (TLS private key) |
| `upstreams` / inline `upstream` | `tls.client_key` |
| `basic-auth` | `password` |
| `jwt-auth` | `secret` |
| `key-auth` | `key`, `keys[]` |
| `csrf` | `key` |

**Adding a new secret field:** the `#[encrypt]` markers are the single source of
truth — encrypt-on-write, decrypt-on-read *and* Admin GET/LIST redaction all walk
the same fields (redaction is just `SecretOp::Redact` over that walk). So:

1. Mark the field with `#[encrypt]` (or `#[encrypt(nested)]` / `#[encrypt(plugins)]`)
   on the config struct. This alone wires up encrypt, decrypt and redaction.
2. For a plugin, add its `SECRETS_TRANSFORM` to that plugin's `PluginMeta`
   entry in the `PLUGIN_META` inventory (`src/plugins/mod.rs`) so the resource's
   `plugins` walk can reach it.

There is no separate redaction list to maintain — masking follows the schema.

**Enabling encryption on an existing store (lazy migration):** turning
`data_encryption` on does *not* rewrite resources already in etcd — they stay
plaintext and continue to load normally (decrypt is a no-op on plaintext). Each
resource migrates to ciphertext the next time it is written through the Admin
API. Notably, **resaving a redacted GET body is enough**: on GET the secret is
returned masked as `***`; on the resave PUT that sentinel is restored from the
in-memory stored value and the write path encrypts it, so the operator does not
need to re-enter the secret. Untouched resources remain plaintext until they are
re-`PUT`, so plan a rewrite pass (re-`PUT` each `ssls`/`upstreams` and any
route/service/global_rule carrying plugin secrets) if you want the whole store
encrypted at rest.

> Because `***` is a reserved sentinel, a resave restores the previously stored
> secret; to actually change a secret, send its new value instead of `***`.

**Key rotation:** add the new key at the top of `keyring`, keep old keys below
until all stored values have been rewritten (or you no longer need them).

> Do not remove an old keyring entry while etcd still holds ciphertext produced
> with that key — decryption will fail and the resource will not load.

**Disabling encryption (`enable: false`):** decryption is fail-closed. Once
`data_encryption` is turned off (or a keyring entry that produced existing
ciphertext is removed/changed), any affected value in etcd can no longer be read
and the **affected resource fails to load** on startup/watch (the last-known-good
snapshot keeps serving traffic in the meantime).

> ℹ️ Admin writes to *other* resources are not blocked by an undecryptable
> resource: the write path validates only structure and cross-resource
> references, which never read secret values. This means you can recover by
> overwriting (re-`PUT`) the affected resource with a value the current keyring
> can handle.

> ⚠️ **Disabling encryption is a manual migration.** The Admin write path always
> encrypts while `enable: true`, so you cannot rewrite values to plaintext by
> re-`PUT`ting them with encryption still on. And once `enable: false`, any
> ciphertext left in etcd can no longer be read (fail-closed). Because the read
> API only ever returns secrets masked as `***`, **you must already hold the
> plaintext secret values** (SSL keys, plugin secrets) out of band. To disable:
>
> 1. Set `enable: false` (and drop the keyring). Affected resources whose etcd
>    value is still ciphertext will fail to load until rewritten; a running
>    instance keeps serving its last-known-good snapshot in the meantime.
> 2. Re-`PUT` each affected `ssls`, `upstreams`, and any
>    route/service/global_rule carrying plugin secrets, **supplying the real
>    plaintext values** (not the `***` mask — a masked resave cannot be restored
>    once decryption is off). With encryption disabled these are stored as
>    plaintext, overwriting the ciphertext.
>
> For throwaway/test data you can instead clear and recreate the affected keys
> (e.g. `etcdctl del --prefix <prefix>`).

> ⚠️ **Do not change the key derivation or the value of an in-use keyring entry**
> while its ciphertext remains in etcd — the derived key would change and old
> values become undecryptable. If you hit
> `Failed to decrypt value with any configured keyring key`, it means etcd holds
> ciphertext that the current configuration cannot decrypt; restore the correct
> keyring, or clear/rewrite the affected keys.

**Interoperability (writers other than the Admin API):** encryption happens on
the Admin write path. Any component that writes resources **directly to etcd**
(for example the
[pingsix-ingress-controller](https://github.com/zhu327/pingsix-ingress-controller))
bypasses that path and would store secrets in plaintext, producing a mixed
plaintext/ciphertext store. If you enable `data_encryption`, ensure every writer
is encryption-aware, or keep such writers on a deployment where encryption is
off. Note also that APISIX-style `consumers` (which carry per-consumer plugin
credentials) are a further place secrets live; they are **not** encrypted yet and
should be considered when planning ingress-controller compatibility.

## Docker Deployment

PingSIX provides a multi-stage Docker build for efficient containerized deployment. The Docker image is optimized for production use with minimal attack surface and resource consumption.

### Building the Docker Image

Build the PingSIX Docker image from the project root:

```bash
# Build the Docker image for the host architecture
docker build -t pingsix:latest .
```

The published Dockerfile targets a single architecture (the builder host). Multi-arch
`buildx` images are not claimed or verified by default.

### Docker Image Features

The PingSIX Docker image includes:

- **Multi-stage build**: Optimized build process with dependency caching
- **Minimal runtime**: Based on Debian Bookworm Slim for security and size
- **Non-root user**: Runs as `pingsix` user for enhanced security
- **Pre-configured directories**: Logging and runtime directories with proper permissions
- **Exposed ports**: 8080 (HTTP proxy), 7085 (status/readiness), 9091 (Prometheus).
  The image binds status to `0.0.0.0:7085` so Kubernetes `httpGet` probes work.
  Override back to loopback only if probes use `exec`. Admin is not enabled in the
  default image config.

### Running PingSIX with Docker

#### Basic Usage

```bash
# Run with default configuration
docker run -d --name pingsix \
  -p 8080:8080 \
  -p 9091:9091 \
  pingsix:latest

# Run with custom configuration
docker run -d --name pingsix \
  -p 8080:8080 \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  pingsix:latest

# Run with custom configuration and log persistence
docker run -d --name pingsix \
  -p 8080:8080 \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  -v /path/to/logs:/var/log/pingsix \
  pingsix:latest
```

#### Docker Compose Deployment

Create a `docker-compose.yml` file for easy deployment:

```yaml
version: '3.8'

services:
  pingsix:
    image: pingsix:latest
    container_name: pingsix
    restart: unless-stopped
    ports:
      - "80:8080"      # HTTP traffic
      - "443:8443"     # HTTPS traffic (if configured)
      - "9091:9091"    # Prometheus metrics
      # Admin is opt-in via config (etcd + admin); default bind should be loopback.
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./ssl:/etc/ssl:ro                    # SSL certificates
      - pingsix-logs:/var/log/pingsix        # Log persistence
    environment:
      - RUST_LOG=info
    networks:
      - pingsix-network

  # Optional: etcd for dynamic configuration
  etcd:
    image: quay.io/coreos/etcd:v3.5.9
    container_name: pingsix-etcd
    restart: unless-stopped
    ports:
      - "2379:2379"
      - "2380:2380"
    environment:
      - ETCD_NAME=etcd1
      - ETCD_DATA_DIR=/etcd-data
      - ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379
      - ETCD_ADVERTISE_CLIENT_URLS=http://etcd:2379
      - ETCD_LISTEN_PEER_URLS=http://0.0.0.0:2380
      - ETCD_INITIAL_ADVERTISE_PEER_URLS=http://etcd:2380
      - ETCD_INITIAL_CLUSTER=etcd1=http://etcd:2380
      - ETCD_INITIAL_CLUSTER_TOKEN=etcd-cluster-1
      - ETCD_INITIAL_CLUSTER_STATE=new
    volumes:
      - etcd-data:/etcd-data
    networks:
      - pingsix-network

volumes:
  pingsix-logs:
  etcd-data:

networks:
  pingsix-network:
    driver: bridge
```

Run the stack:

```bash
# Start the services
docker-compose up -d

# View logs
docker-compose logs -f pingsix

# Stop the services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### Configuration Best Practices

#### Volume Mounts

```yaml
volumes:
  # Configuration (read-only)
  - ./config.yaml:/app/config.yaml:ro
  
  # SSL certificates (read-only)
  - ./ssl:/etc/ssl:ro
  
  # Logs (read-write)
  - ./logs:/var/log/pingsix
```

#### Environment Variables

```bash
# Logging level
RUST_LOG=info
```

## Kubernetes Deployment

PingSIX provides Helm charts for easy deployment in Kubernetes environments. The Helm chart supports three deployment modes to fit different use cases:

1. **Ingress Controller Mode**: Full Kubernetes Ingress controller with dynamic configuration
2. **etcd Mode**: Standalone gateway with etcd for dynamic configuration management
3. **Static Configuration Mode**: Standalone gateway with static YAML configuration

### Prerequisites

- Kubernetes cluster (v1.19+)
- Helm 3.x installed
- kubectl configured to access your cluster

### Installation

First, clone the PingSIX Helm chart repository:

```bash
git clone https://github.com/zhu327/pingsix-helm-chart.git
cd pingsix-helm-chart/charts
```

### Deployment Mode 1: Ingress Controller Mode

This mode enables PingSIX to work as a Kubernetes Ingress controller, automatically synchronizing Ingress, Gateway API, and custom resources (ApisixRoute, ApisixUpstream, etc.) to configure routes dynamically.

**Features:**
- Full Kubernetes Ingress controller functionality
- Support for Gateway API, Ingress, and APISIX custom resources
- Automatic configuration synchronization from Kubernetes resources
- No etcd required (uses in-memory configuration)

**Installation:**

```bash
helm install apisix \
  --namespace ingress-apisix \
  --create-namespace \
  --set etcd.enabled=false \
  --set ingress-controller.enabled=true \
  --set ingress-controller.gatewayProxy.createDefault=true \
  ./apisix
```

**Configuration:**

When using Ingress controller mode, you manage routes through Kubernetes resources instead of YAML configuration files.

#### Using Gateway API

First, configure the GatewayClass and Gateway resources:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  namespace: ingress-apisix
  name: apisix
spec:
  controllerName: apisix.apache.org/apisix-ingress-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  namespace: ingress-apisix
  name: apisix
spec:
  gatewayClassName: apisix
  listeners:
  - name: http
    protocol: HTTP
    port: 80
  infrastructure:
    parametersRef:
      group: apisix.apache.org
      kind: GatewayProxy
      name: apisix-config
```

Then create an HTTPRoute to configure routing:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  namespace: ingress-apisix
  name: httpbin-route
spec:
  parentRefs:
  - name: apisix
  rules:
  - matches:
    - path:
        type: Exact
        value: /ip
    backendRefs:
    - name: httpbin
      port: 80
```

#### Using Kubernetes Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  namespace: ingress-apisix
  name: httpbin-ingress
spec:
  ingressClassName: apisix
  rules:
    - http:
        paths:
          - backend:
              service:
                name: httpbin
                port:
                  number: 80
            path: /ip
            pathType: Exact
```

#### Using APISIX Custom Resources

```yaml
apiVersion: apisix.apache.org/v2
kind: ApisixRoute
metadata:
  namespace: ingress-apisix
  name: httpbin-route
spec:
  ingressClassName: apisix
  http:
    - name: getting-started-ip
      match:
        paths:
          - /ip
      backends:
        - serviceName: httpbin
          servicePort: 80
      plugins:
        - name: limit-count
          enable: true
          config:
            key_type: vars
            key: remote_addr
            time_window: 60
            count: 100
```

**More Examples:**

For detailed Ingress controller examples and configuration, refer to the official Apache APISIX Ingress Controller documentation:
- [Configure Routes](https://apisix.apache.org/zh/docs/ingress-controller/getting-started/configure-routes/)
- [Load Balancing](https://apisix.apache.org/docs/ingress-controller/tutorials/load-balancing)
- [Authentication](https://apisix.apache.org/docs/ingress-controller/tutorials/authentication)

### Deployment Mode 2: etcd Mode

This mode deploys PingSIX with etcd for dynamic configuration management via the Admin API.

**Features:**
- Dynamic configuration updates via Admin API
- etcd-based configuration persistence
- Suitable for traditional API gateway deployments

**Installation:**

```bash
helm install apisix \
  --namespace pingsix \
  --create-namespace \
  --set etcd.enabled=true \
  --set ingress-controller.enabled=false \
  --set pingsix.admin.enabled=true \
  --set pingsix.admin.apiKey="your-secure-api-key" \
  ./apisix
```

**Configuration via Admin API:**

After installation, you can manage routes dynamically using the Admin API:

```bash
# Port forward to access Admin API
kubectl port-forward -n pingsix svc/apisix-admin 9181:9181

# Create a route
curl -X PUT http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-secure-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/api/*",
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend-service.default.svc.cluster.local:8080": 1
      }
    }
  }'
```

**Custom Values:**

Create a `values-etcd.yaml` file:

```yaml
etcd:
  enabled: true
  auth:
    rbac:
      create: true
      rootPassword: "your-etcd-password"

pingsix:
  admin:
    enabled: true
    apiKey: "your-secure-api-key"
    address: "127.0.0.1:9181"
  
  prometheus:
    enabled: true
    address: "0.0.0.0:9091"

  listeners:
    - address: "0.0.0.0:8080"
      offerH2c: false
```

Install with custom values:

```bash
helm install apisix \
  --namespace pingsix \
  --create-namespace \
  -f values-etcd.yaml \
  ./apisix
```

### Deployment Mode 3: Static Configuration Mode

This mode deploys PingSIX with static YAML configuration, suitable for simple deployments or when etcd is managed externally.

**Features:**
- Simple deployment with static configuration
- No etcd dependency (use external etcd or static config)
- Configuration updates require pod restart

**Installation with Static Configuration:**

Create a `values-static.yaml` file:

```yaml
etcd:
  enabled: false

ingress-controller:
  enabled: false

pingsix:
  listeners:
    - address: "0.0.0.0:8080"
      offerH2c: false

routes:
  - id: "1"
    uri: /api/{*path}
    upstream:
      nodes:
        "backend-service.default.svc.cluster.local:8080": 1
      type: roundrobin
    plugins:
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100

globalRules:
  - id: "1"
    plugins:
      prometheus: {}
```

Install with static configuration:

```bash
helm install apisix \
  --namespace pingsix \
  --create-namespace \
  -f values-static.yaml \
  ./apisix
```

**Installation with External etcd:**

If you have an external etcd cluster:

```yaml
etcd:
  enabled: false

externalEtcd:
  host:
    - "http://etcd-cluster.etcd.svc.cluster.local:2379"
  user: "root"
  password: "your-password"

pingsix:
  admin:
    enabled: true
    apiKey: "your-secure-api-key"
```

### Common Helm Configuration Options

#### Scaling and Resources

```yaml
# Use DaemonSet for node-level deployment
useDaemonSet: true

# Or use Deployment with replicas
useDaemonSet: false
replicaCount: 3

# Enable autoscaling
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

# Resource requests and limits
resources:
  limits:
    cpu: 1000m
    memory: 512Mi
  requests:
    cpu: 200m
    memory: 256Mi
```

#### Service Configuration

```yaml
service:
  type: LoadBalancer  # Options: ClusterIP, NodePort, LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
  externalTrafficPolicy: Local  # Preserve client source IP
```

#### TLS/SSL Configuration

```yaml
pingsix:
  listeners:
    - address: "0.0.0.0:8080"
    - address: "0.0.0.0:8443"
      tls:
        # Use Kubernetes Secret for certificates
        secretName: pingsix-tls
        # Or use custom filenames in secret
        certFilename: tls.crt
        keyFilename: tls.key
      offerH2: true
```

Create the TLS secret:

```bash
kubectl create secret tls pingsix-tls \
  --cert=server.crt \
  --key=server.key \
  -n pingsix
```

#### Monitoring and Observability

```yaml
pingsix:
  prometheus:
    enabled: true
    address: "0.0.0.0:9091"

metrics:
  serviceMonitor:
    enabled: true
    interval: 15s
    labels:
      release: prometheus

pingsix:
  sentry:
    enabled: true
    dsn: "https://your-dsn@sentry.io/project-id"
```

### Accessing PingSIX

#### Port Forward

```bash
# Access gateway
kubectl port-forward -n pingsix svc/apisix-gateway 8080:80

# Access Admin API (if enabled)
kubectl port-forward -n pingsix svc/apisix-admin 9181:9181

# Access Prometheus metrics (if enabled)
kubectl port-forward -n pingsix svc/apisix-gateway 9091:9091
```

#### Using Ingress

```yaml
ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class: nginx
  hosts:
    - host: pingsix.example.com
      paths:
        - /
  tls:
    - secretName: pingsix-ingress-tls
      hosts:
        - pingsix.example.com
```

### Upgrading

```bash
# Update chart repository
cd pingsix-helm-chart
git pull

# Upgrade with new configuration
helm upgrade apisix \
  --namespace pingsix \
  -f values.yaml \
  ./charts/apisix

# Check upgrade status
helm history apisix -n pingsix
```

### Uninstalling

```bash
# Uninstall PingSIX
helm uninstall apisix -n pingsix

# Delete namespace (optional)
kubectl delete namespace pingsix
```

### Troubleshooting Kubernetes Deployment

#### Check Pod Status

```bash
kubectl get pods -n pingsix
kubectl describe pod <pod-name> -n pingsix
kubectl logs <pod-name> -n pingsix
```

#### Check Configuration

```bash
# View ConfigMap
kubectl get configmap -n pingsix
kubectl describe configmap apisix -n pingsix

# View generated config
kubectl get configmap apisix -n pingsix -o yaml
```

#### Debug Connection Issues

```bash
# Test internal connectivity
kubectl run -n pingsix test-pod --image=curlimages/curl --rm -it -- sh

# Inside the pod
curl http://apisix-gateway:80/health
```

#### Check Service Endpoints

```bash
kubectl get endpoints -n pingsix
kubectl get svc -n pingsix
```

## Routing

### Basic Route Configuration

```yaml
routes:
  - id: "api-v1"
    uri: /api/v1/{*path}        # Catch-all for /api/v1/* requests
    host: api.example.com
    methods: ["GET", "POST"]
    upstream:
      nodes:
        "backend1.example.com:8080": 1
        "backend2.example.com:8080": 1
      type: roundrobin
```

### Route Matching

Routes support multiple matching criteria based on the `matchit` routing library:

#### URI Matching

PingSIX uses `matchit` for route matching, which supports the following patterns:

```yaml
# Static/exact match
uri: /api/users

# Named parameters (capture path segments)
uri: /api/users/{id}          # Matches /api/users/123, captures id=123
uri: /api/users/{id}/posts    # Matches /api/users/123/posts

# Catch-all parameters (capture remaining path)
uri: /static/{*filepath}      # Matches /static/css/style.css, captures filepath=css/style.css
uri: /{*path}                 # Matches any path

# Parameter with suffix
uri: /images/img{id}.png      # Matches /images/img123.png, captures id=123

# Multiple URIs with different patterns
uris: ["/api/v1/users/{id}", "/api/v2/users/{user_id}"]
```

**Important Notes:**
- A route must have at least one URI pattern defined, using either the `uri` field for a single pattern or the `uris` field for multiple patterns.
- Use `{parameter_name}` for named parameters that capture a single path segment.
- Use `{*parameter_name}` for catch-all parameters that capture the remaining path.
- Catch-all parameters must be at the end of the path.
- Only one parameter is allowed per path segment.
- Static routes have higher priority than dynamic routes.

**Route Parameter Examples:**
```yaml
# Named parameter examples
uri: /users/{id}                    # Matches: /users/123
uri: /users/{id}/posts/{post_id}    # Matches: /users/123/posts/456
uri: /files/{filename}.{ext}        # Matches: /files/document.pdf

# Catch-all parameter examples  
uri: /static/{*filepath}            # Matches: /static/css/main.css
uri: /api/v1/{*path}               # Matches: /api/v1/users/123/posts
uri: /{*path}                      # Matches: any path

# Mixed examples
uri: /api/{version}/users/{*path}   # Matches: /api/v1/users/123/posts
```

**Parameter Access:**
Route parameters are captured and can be accessed by plugins and upstream services. The parameter names become available in the request context for use by plugins like `proxy-rewrite` or for logging purposes.

#### Host Matching
```yaml
# Single host
host: api.example.com

# Multiple hosts
hosts: ["api.example.com", "www.api.example.com"]
```

#### Method Matching
```yaml
methods: ["GET", "POST", "PUT", "DELETE"]
```

#### Priority-Based Routing
```yaml
routes:
  - id: "specific-route"
    uri: /api/users/admin
    priority: 100  # Higher priority - static routes
    upstream: { ... }
  
  - id: "user-by-id"
    uri: /api/users/{id}
    priority: 50   # Medium priority - named parameter
    upstream: { ... }
  
  - id: "catch-all-route"
    uri: /api/{*path}
    priority: 10   # Lower priority - catch-all
    upstream: { ... }
```

**Route Matching Priority:**
1. **Static routes** (e.g., `/api/users/admin`) - highest priority
2. **Named parameter routes** (e.g., `/api/users/{id}`) - medium priority  
3. **Catch-all routes** (e.g., `/api/{*path}`) - lowest priority
4. **Custom priority** - use the `priority` field to override default ordering

### Route Timeouts

Configure request timeouts:

```yaml
routes:
  - id: "timeout-example"
    uri: /api/{*path}           # Catch-all for /api/* requests
    timeout:
      connect: 5    # Connection timeout (seconds)
      send: 10      # Send timeout (seconds)
      read: 30      # Read timeout (seconds)
    upstream: { ... }
```

## Upstreams

### Basic Upstream Configuration

Nodes accept two wire forms. Both normalize to the same in-memory list after load.

**Map form** (legacy — weight only; priority defaults to `0`):

```yaml
upstreams:
  - id: "backend-pool"
    nodes:
      "server1.example.com:8080": 1    # Weight 1
      "server2.example.com:8080": 2    # Weight 2
      "server3.example.com:8080": 1    # Weight 1
    type: roundrobin
```

**List form** (APISIX-compatible — `host`, `port`, `weight`, `priority`):

```yaml
upstreams:
  - id: "backend-pool-priority"
    type: roundrobin
    scheme: https
    nodes:
      - host: primary.example.com
        port: 443
        weight: 1
        priority: 10          # Higher priority is preferred
      - host: standby.example.com
        port: 443
        weight: 1
        priority: 0           # Used when priority 10 has no ready node
      - host: cold.example.com
        port: 443
        weight: 1
        priority: -1          # i8 range: -128..=127; lower than 0
```

**Node fields:**
- **`weight`**: Relative share inside a priority group. `0` keeps the node in config but excludes it from selection and from health checks (a `weight: 0` node never becomes a backend, so it is not probed either).
- **`priority`**: Selection group (`i8`: -128..=127, default `0`). Higher values win. Same priority = same group.
- **`port`**: Optional; when omitted the upstream scheme default is used (80 for `http`/`grpc`, 443 for `https`/`grpcs`). An explicit `0` is invalid — either omit the port or set it to a real one.

**Priority selection (with health checks):**
1. Group enabled nodes (`weight > 0`) by `priority`.
2. Prefer the highest priority group that still has at least one ready (healthy) backend.
3. Inside that group, use the upstream `type` algorithm (roundrobin, random, fnv, ketama) and weights. Each group is balanced independently, so weights and `fnv`/`ketama` key mappings among the primary nodes do not change when you add, remove, or fail over a lower-priority group.
4. If a higher group becomes healthy again, the next request uses it.
5. If no group has a ready backend, selection retries in the same priority order while ignoring health. Without health checks, all nodes are treated as ready, so traffic stays on the highest priority. Note that this fallback still selects a (possibly dead) backend, so a fully down upstream costs connection attempts/retries instead of failing instantly.

**Constraints:**
- Each enabled node must resolve to a unique address, because Pingora backends are keyed by address and duplicates cannot carry different priorities. The comparison uses the *effective* port, so over `scheme: http` a node without `port` collides with an explicit `port: 80`.
- DNS-resolved IPs inherit the parent node's priority, and DNS refreshes rebuild the priority groups.

### Load Balancing Algorithms

#### Round Robin (Default)
```yaml
type: roundrobin  # Distributes requests evenly
```

#### Random
```yaml
type: random      # Random selection
```

#### Consistent Hashing
```yaml
type: ketama      # Consistent hashing
hash_on: vars     # Hash based on variables
key: uri          # Hash key (uri, cookie, header)
```

#### FNV Hashing
```yaml
type: fnv         # FNV hash algorithm
hash_on: head     # Hash based on headers
key: user-id      # Header name to hash
```

### Request Retries

Configure automatic retries on connection failures:

```yaml
upstreams:
  - id: "backend-with-retry"
    nodes:
      "unstable-server.example.com:8080": 1
    retries: 3           # Number of retry attempts on connection failure
    retry_timeout: 5     # Total time in seconds allowed for all retry attempts
```

### Health Checks

Configure active health checking:

```yaml
upstreams:
  - id: "monitored-backend"
    nodes:
      "api1.example.com:443": 1
      "api2.example.com:443": 1
    type: roundrobin
    scheme: https
    checks:
      active:
        type: https                    # http, https, or tcp
        timeout: 5                     # Health check timeout
        host: api.example.com          # Host header for health checks
        http_path: /health             # Health check endpoint
        https_verify_certificate: true # Verify SSL certificates
        req_headers: 
          - "User-Agent: PingSIX-HealthCheck/1.0"
        healthy:
          interval: 10                 # Check interval (seconds)
          http_statuses: [200, 201]    # Healthy status codes
          successes: 2                 # Consecutive successes needed
        unhealthy:
          http_failures: 3             # HTTP failures before marking unhealthy
          tcp_failures: 2              # TCP failures before marking unhealthy
      passive:                         # Optional: real-traffic based checking
        type: http
        healthy:
          http_statuses: [200, 201, 204, 302]  # Statuses counted as healthy
          successes: 5                 # Consecutive healthy responses to restore
        unhealthy:
          http_statuses: [429, 500, 503]       # Statuses counted as unhealthy
          http_failures: 5             # Consecutive HTTP failures to trip
          tcp_failures: 2              # Consecutive TCP failures to trip
          timeouts: 7                  # Consecutive timeouts to trip
```

Passive checking observes real request outcomes (no probe traffic): after
`unhealthy.*` consecutive failures a node is pulled from rotation, and after
`healthy.successes` consecutive healthy responses it is restored. The three
failure categories are counted independently.

`active` is optional: a `checks` block may specify only `passive` to enable
real-traffic health checking without any probe traffic. At least one of
`active` or `passive` must be present.

#### Shared Health Check Lifecycle

PingSIX runs all upstream health checks through a single global executor (`SHARED_HEALTH_CHECK_SERVICE`)
so workers do not duplicate TCP/TLS probes. The lifecycle looks like:

```
┌──────────┐   register_upstream()   ┌──────────────────────┐
│  Config  │ ─────────────────────▶  │ HealthCheckRegistry  │
│ (route & │                         │  (DashMap + events)  │
│ upstream)│ ◀────────────────────── └─────────┬────────────┘
└──────────┘    unregister_upstream()          │broadcast
                                               │RegistryUpdate
                                               ▼
                                     ┌──────────────────────┐
                                     │ HealthCheckExecutor │
                                     │  tokio task router  │
                                     └─────────┬────────────┘
                                               │spawn
                                               ▼
                                     ┌──────────────────────┐
                                     │ LoadBalancer task   │
                                     │ (one per upstream) │
                                     └──────────────────────┘
```

- Registering an upstream pushes a `RegistryUpdate::Added` event; the executor spawns a tokio task
  that runs the Pingora load balancer's active probe loop until the shutdown channel flips.
- Removing or replacing an upstream sends `RegistryUpdate::Removed`, and the executor aborts the
  previous task before the new configuration is applied.
- During graceful shutdown the executor listens on `ShutdownWatch` so every probe stops cleanly.

Because registrations are idempotent, updating an upstream simply unregisters the old task and
installs the new one with fresh thresholds and destinations.

### Host Header Handling

Control how the Host header is passed to upstream:

```yaml
upstreams:
  - id: "host-rewrite-example"
    nodes:
      "internal-api.local:8080": 1
    pass_host: rewrite              # Options: pass, rewrite, node
    upstream_host: internal-api.local  # Required when pass_host is rewrite
```

**Pass Host Options:**
- **`pass`** (default): Pass the client's original Host header to the upstream
- **`rewrite`**: Replace the Host header with the value specified in `upstream_host`
- **`node`**: Use the upstream node's hostname as the Host header

### Keepalive Connection Pool (keepalive_pool)

APISIX `keepalive_pool.idle_timeout` compatible, per upstream:

```yaml
upstreams:
  - id: "pooled-upstream"
    nodes:
      "backend.local:8080": 1
    keepalive_pool:
      idle_timeout: 60             # Seconds before an idle connection is closed
```

- **`idle_timeout`** (seconds, fractional values allowed, default `60`, minimum `0`)
  maps onto Pingora's per-peer idle timeout: how long an idle upstream
  connection stays reusable before it is closed. Lower it for fast-churning
  backends, raise it to maximize connection reuse behind slow handshakes.
- APISIX `size`/`requests` are not part of the schema: Pingora 0.8 does not
  expose per-upstream pool size or per-connection request caps, and the
  process-global `pingora.upstream_keepalive_pool_size` applies instead.

Route-level `timeout` overrides still apply to `connect`/`read`/`write` on
the same connections; `idle_timeout` is independent and survives route
override.

## Services

Services provide reusable configurations:

```yaml
services:
  - id: "user-service"
    hosts: ["users.api.example.com"]
    upstream_id: "user-backend"     # Reference to upstream
    plugins:
      jwt-auth:
        secret: "your-jwt-secret"
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100

routes:
  - id: "user-routes"
    uri: /users/{*path}             # Catch-all for /users/* requests
    service_id: "user-service"      # Reference to service
```

## Global Rules

Apply plugins globally to all requests:

```yaml
global_rules:
  - id: "monitoring"
    plugins:
      prometheus: {}                # Enable metrics collection
      file-logger:                  # Enable access logging
        log_format: '$remote_addr - [$time_local] "$request" $status $body_bytes_sent'
  
  - id: "security"
    plugins:
      cors:                         # Enable CORS for all routes
        allow_origins: "*"
        allow_methods: "GET,POST,PUT,DELETE"
        allow_headers: "*"
```

## Plugins

PingSIX includes 29 built-in plugins for various functionalities:

### Plugin Execution Order

PingSIX runs plugins in two layers, mirroring APISIX's phase model:

1. **Global-rule plugins** run first. These come from `global_rules` and are
   sorted by `priority` in **descending** order (higher priority executes
   first). Ties are broken by plugin name for determinism.
2. **Route/service plugins** run next, also sorted by `priority` in
   descending order. When a route and its service define a plugin with the
   same name, the route-level definition wins and the service-level one is
   skipped.

A plugin short-circuits the request when its `request_filter` returns
`true`. **A global-rule plugin that short-circuits prevents every route
plugin from running — including authentication plugins.** This is intentional:
it lets global redirect/fault-injection rules respond before any upstream work, but it
also means a global short-circuit can bypass route-level authentication.

> **Warning:** Do not combine a global short-circuit plugin (e.g. redirect or
> fault-injection abort) that needs authentication protection with route-level auth plugins.
> The global plugin will respond before the route auth plugin ever runs, so
> the request is never authenticated. Put such protective logic at the global
> layer instead, or avoid short-circuiting globally.

This ordering is enforced in `HttpService::request_filter`
(`src/service/http.rs`) and is pinned by the semantic tests in
`tests/plugin_order.rs`.

### Authentication Plugins

#### JWT Authentication
```yaml
plugins:
  jwt-auth:
    header: authorization        # Header containing JWT
    query: token                # Query parameter name
    cookie: jwt                 # Cookie name
    # For HMAC algorithms (HS256, HS512)
    secret: "your-secret-key"
    base64_secret: false        # Set to true if the secret is base64 encoded
    # For RSA/ECDSA algorithms (RS256, ES256)
    public_key: |
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
    algorithm: HS256            # HS256/384/512, RS256/384/512, PS256/384/512, ES256/384, EdDSA
    lifetime_grace_period: 60   # Optional: 60 seconds grace period for token expiration
    hide_credentials: true      # Remove JWT from request
    store_in_ctx: true         # Store payload in context
    realm: jwt                  # Optional: APISIX-style realm; omit for legacy pingsix challenge
    claims_to_verify: ["exp", "nbf"]  # Optional: verify the listed claims (nbf value checked when listed)
```

#### API Key Authentication
```yaml
plugins:
  key-auth:
    header: apikey                 # Header name (preferred)
    # query: apikey                # Explicit opt-in; disabled by default and not recommended
    key: "your-api-key"           # Single key
    # OR multiple keys for rotation
    keys: 
      - "key1"
      - "key2"
      - "key3"
    hide_credentials: true         # Remove credentials before proxying upstream
    realm: key                     # Optional: APISIX-style realm; omit for legacy pingsix challenge
```

#### Basic Authentication
```yaml
plugins:
  basic-auth:
    username: "admin"              # Username for authentication
    password: "secret"             # Password for authentication
    hide_credentials: true         # Remove Authorization header from upstream request
    realm: basic                   # Optional: APISIX-style realm; omit for legacy pingsix challenge
```

**Basic Authentication Features:**
- **Simple Credentials**: Username and password-based authentication
- **HTTP 401 Response**: Returns 401 Unauthorized with `WWW-Authenticate: Basic realm="<realm>"` header on invalid credentials
- **Constant-Time Comparison**: Uses constant-time string comparison to prevent timing attacks
- **Credential Hiding**: Optionally removes Authorization header before forwarding to upstream services
- **Standard Compliance**: Follows RFC 7617 HTTP Basic Authentication specification

**Common Use Cases:**
- Protecting development or staging environments
- Internal service authentication
- Simple API access control

### Security Plugins

#### IP Restriction
```yaml
plugins:
  ip-restriction:
    whitelist:                     # Allow only these IPs/networks
      - "192.168.1.0/24"
      - "10.0.0.0/8"
    blacklist:                     # Block these IPs/networks
      - "192.168.1.100"
      - "172.16.0.0/12"
    message: "Access denied"       # Custom rejection message (default APISIX message; JSON body)
    response_code: 403             # 403 or 404 (default: 403)
    use_forwarded_headers: true    # Parse forwarded headers only from a trusted direct proxy
    trusted_proxies:               # Trusted proxy networks; X-Forwarded-For is walked right-to-left
      - "10.0.0.0/8"
    # If XFF is present but illegal: `direct` (default) uses the peer IP; `deny` rejects the request.
    # Illegal XFF never falls back to an unverified X-Real-IP. X-Real-IP is only used when XFF is absent.
    forwarded_header_error_policy: direct
```

When every hop in XFF is trusted, PingSIX returns the leftmost address (farthest trusted source).

#### URI Blocker (uri-blocker)

APISIX `uri-blocker` compatible. Intercepts requests whose URI (path plus
query string, like nginx `$request_uri`) matches any configured regex and
rejects them. Matches are unanchored: a rule matches when the pattern occurs
anywhere in the URI.

```yaml
plugins:
  uri-blocker:
    block_rules:                   # Regex list, matched against path + query
      - "^/admin"
      - "token=[0-9]+"
      - "\\.sql$"
    rejected_code: 403             # Status for blocked requests (200-599)
    rejected_msg: "blocked"        # JSON body: {"error_msg":"blocked"} when set
    case_insensitive: false        # Compile all rules case-insensitively
```

With `rejected_msg` set the rejection body is `{"error_msg": "..."}` with
`Content-Type: application/json`; otherwise the body is empty. Duplicate
rules are rejected at configuration time, as are invalid regexes.

#### CORS (Cross-Origin Resource Sharing)
```yaml
plugins:
  cors:
    allow_origins: "https://example.com,https://app.example.com"
    allow_methods: "GET,POST,PUT,DELETE,OPTIONS"
    allow_headers: "Content-Type,Authorization,X-Requested-With"
    expose_headers: "X-Request-ID"
    max_age: 86400                 # Preflight cache time
    allow_credential: true         # Allow credentials
    allow_origins_by_regex:        # Regex patterns for origins
      - "https://.*\\.example\\.com"
    timing_allow_origins: "https://example.com"  # Timing-Allow-Origin list
    timing_allow_origins_by_regex:                # Or regex list
      - "https://.*\\.example\\.com"
```

#### CSRF (Cross-Site Request Forgery Protection)
```yaml
plugins:
  csrf:
    key: "your-csrf-secret-key"    # Secret key for token generation and validation
    expires: 7200                  # Token expiration time in seconds (default: 7200)
    name: "pingsix-csrf-token"     # Cookie/header name for CSRF token (default: pingsix-csrf-token)
```

**CSRF Protection Features:**
- **Double Submit Cookie Pattern**: Validates that token in header matches token in cookie
- **Token Expiration**: Automatically expires tokens based on configured TTL
- **Signature Validation**: Uses SHA256 to sign tokens with configurable secret key
- **Safe Methods**: Skips validation for GET, HEAD, and OPTIONS requests
- **Automatic Token Generation**: Generates and distributes tokens in response cookies
- **SameSite Cookie**: Sets SameSite=Lax for enhanced security

> **HTTPS-only:** The CSRF cookie is always emitted with the `Secure`
> attribute. Browsers only send `Secure` cookies over TLS, so this plugin is
> only effective behind an HTTPS listener; on plain HTTP the double-submit
> check cannot pass. This differs from a configurable `secure` flag and is a
> deliberate fail-closed default.

**Token Validation Flow:**
1. Client receives token in response cookie and header
2. For state-changing requests (POST, PUT, DELETE, PATCH), client must include token in request header
3. Server validates:
   - Token is present in both cookie and header
   - Cookie and header tokens match
   - Token signature is valid
   - Token has not expired

**Common Use Cases:**
- Protecting form submissions from CSRF attacks
- Securing API endpoints that modify data
- Web application security in traditional request-response patterns

### Rate Limiting

#### Request Rate Limiting (limit-count)
```yaml
plugins:
  limit-count:
    key_type: vars                 # var, var_combination, constant, head, cookie
    key: remote_addr              # Key to rate limit on
    time_window: 60               # Time window in seconds
    count: 100                    # Max requests per window
    window_type: fixed            # fixed, sliding
    rejected_code: 429            # HTTP status for rejected requests
    rejected_msg: "Rate limit exceeded"
    show_limit_quota_header: true # Include rate limit headers
                                  # Success: X-RateLimit-Limit/-Remaining/-Reset + X-RateLimit-Scope;
                                  # rejection additionally X-RateLimit-Used + Retry-After
    key_missing_policy: allow     # allow, deny, default
    scope: local                  # Only process-local scope is supported
    group: tenant-a               # Optional local counter namespace (not with rules)
    # rules (mutually exclusive with count/time_window):
    # rules:
    #   - key: "$http_x-user"
    #     count: 10
    #     time_window: 10
    #     header_prefix: user
```

#### Leaky Bucket Rate Limiting (limit-req)
```yaml
plugins:
  limit-req:
    rate: 10                      # Max requests per second (bucket drain rate)
    burst: 20                     # Requests allowed to be delayed above rate
    key: remote_addr              # APISIX variable or combination, e.g. "$remote_addr $http_x_forwarded_for"
    key_type: var                 # var, var_combination
    rejected_code: 503            # HTTP status for rejected requests
    rejected_msg: "Requests are too frequent"
    nodelay: false                # true = serve burst without delay; further requests are rejected
    policy: local                 # Only process-local is supported
```

Requests above `rate` but within `rate + burst` are delayed (queued); requests
above `rate + burst` are rejected. With `nodelay: true` the burst is consumed
at full speed (no delay), and subsequent requests are rejected until the
bucket drains.

#### Concurrency Limiting (limit-conn)
```yaml
plugins:
  limit-conn:
    conn: 2                       # Max concurrent requests
    burst: 1                      # Extra requests allowed to be delayed
    default_conn_delay: 0.1       # Delay (seconds) applied in the burst range
    only_use_default_delay: false # false = adapt delay from observed request latency
    key: remote_addr              # APISIX variable or combination
    key_type: var
    rejected_code: 503            # HTTP status for rejected requests
    rejected_msg: "Too many concurrent requests"
    policy: local                 # Only process-local is supported
    # rules (mutually exclusive with conn/burst/key):
    # rules:
    #   - key: "$http_x-user"
    #     conn: 5
    #     burst: 2
```

Requests up to `conn` pass immediately; requests between `conn` and
`conn + burst` are delayed before being allowed; requests above `conn + burst`
are rejected.

### Traffic Management

#### Traffic Split (A/B Testing & Canary Deployment)
```yaml
plugins:
  traffic-split:
    rules:
      - vars:                                  # Match conditions (optional)
          - ["arg_version", "==", "v2"]        # Query parameter match
          - ["http_x-user-type", "==", "beta"] # Header match
        weighted_upstreams:
          - upstream_id: "backend-v2"          # Reference to existing upstream
            weight: 50                         # 50% traffic
          - upstream:                          # Or inline upstream definition
              nodes:
                "canary-server:8080": 1
              type: roundrobin
            weight: 50                         # 50% traffic
      
      - vars: []                               # Default rule (matches all)
        weighted_upstreams:
          - upstream_id: "stable-backend"
            weight: 90                         # 90% to stable
          - upstream_id: "canary-backend"
            weight: 10                         # 10% to canary
```

**Traffic Split Features:**
- **Weighted Distribution**: Distribute traffic across multiple upstreams based on weights
- **Conditional Routing**: Match requests based on query parameters, headers, or cookies
- **Variable Matching**: Support for `==` (equals) and `!=` (not equals) operators
- **Inline or Referenced Upstreams**: Use `upstream_id` to reference existing upstreams or define inline
- **Pass-through targets (APISIX-compatible)**: A weighted entry with `weight > 0` but neither
  `upstream_id` nor inline `upstream` keeps the route's default upstream for that weight interval
- **Weight rules**: Weight `0` does not participate in selection; total weight must be `> 0`;
  named upstreams must exist; weight sums use checked `u64` arithmetic
- **Inline health checks**: Inline upstreams get independent health-check tasks
- **Retry / Host rewrite**: Uses the actually selected upstream; pass-through uses the route default

**Common Use Cases:**
- A/B testing different backend versions
- Canary deployments with gradual traffic shifting
- Blue-green deployments
- Feature flag-based routing

#### Request Modification (Proxy Rewrite)
```yaml
plugins:
  proxy-rewrite:
    uri: /new/path                # Rewrite request URI (must start with '/', ≤ 4096 chars)
    method: POST                  # GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/CONNECT/TRACE
    host: new-host.example.com    # Change Host header
    headers:                      # Add/modify/remove headers (pingsix entry shape)
      set:
        - name: "X-Header-To-Set"
          value: "new-value"
      add:
        - name: "X-Header-To-Add"
          value: "another-value"
      remove:
        - "X-Header-To-Remove"
    regex_uri:                    # Regex-based URI rewriting
      - "^/old/(.*)"              # Pattern
      - "/new/$1"                 # Replacement
```

**APISIX-compatible `headers` map shape** (also accepted):
```yaml
plugins:
  proxy-rewrite:
    headers:
      X-Api-Version: "2"          # Plain keys map to `set`
      X-Count: 42                 # Numeric values are accepted
      X-Multi: ["a", "b"]        # Arrays expand to multiple values (add/set only)
      set:
        X-Other: "replaces-all-existing-values"
      remove:
        - "X-Old"
```
Operations run in APISIX order — `add` (append), then `set` (remove-then-append
all values), then `remove`. Mixing plain keys with `add`/`set`/`remove` in one
map is rejected (APISIX `additionalProperties: false`); header names and
values are validated at config time.

#### Response Modification (Response Rewrite)
```yaml
plugins:
  response-rewrite:
    status_code: 200              # Rewrite response status code
    headers:                      # Modify response headers (simple mode)
      X-Custom-Header: "value"
      X-Another-Header: 42       # Numeric values are accepted
    body: '{"error": false}'      # Replace the response body
    body_base64: false            # Decode body from base64 first
    filters:                      # Regex replacements on the response body
      - regex: "old"
        replace: "new"
        scope: global             # once (default), global
    max_resp_body_size: 67108864  # Body buffer cap for filters (default)
    # OR structured mode for add/set/remove
    headers:
      set:
        X-Response-Header: "new-value"
        X-Client-IP: "$remote_addr"  # Variables supported: $remote_addr, $upstream_addr, $request_id
      add:
        - "X-Added-Header: appended-value"
      remove:
        - "X-Remove-This-Header"
    vars:                         # Conditional rewrite based on request matching
      - ["arg_version", "==", "v2"]    # Query parameter match
      - ["http_x-user-type", "==", "premium"]  # Header match
```

**Response Rewrite Features:**
- **Status Code Modification**: Change response HTTP status codes conditionally
- **Header Manipulation**: Set, add, or remove response headers
- **Body Replacement**: Replace the whole response body (`body`, optional `body_base64`)
- **Body Filters**: Ordered regex substitutions (`once`/`global`) applied to the buffered body; compressed upstream bodies pass through unchanged (no gzip/brotli decode)
- **Variable Substitution**: Support for variables like `$remote_addr`, `$upstream_addr`, `$request_id` in header values
- **Conditional Rewriting**: Apply rewrites only when request conditions match
- **Flexible Configuration**: Both simple (key-value) and structured (add/set/remove) header modes

**Variable Placeholders:**
- `$remote_addr` - Client IP address
- `$upstream_addr` - Selected upstream server address (empty when no upstream was selected)
- `$request_id` - Request tracking ID (empty unless the request-id plugin set it)

Only these documented placeholders are expanded. Unknown `$name` placeholders
are preserved literally, making configuration mistakes visible rather than
silently changing header values.

**Common Use Cases:**
- Adding security headers (X-Content-Type-Options, X-Frame-Options)
- Injecting custom headers for downstream processing
- Rewriting status codes based on request type
- Adding request tracing headers

#### Redirect
```yaml
plugins:
  redirect:
    http_to_https: true           # Redirect HTTP to HTTPS
    redirect_host: example.com    # Required with http_to_https (Location host)
    # trusted_proxies:            # Optional: only then honor X-Forwarded-Proto
    #   - 10.0.0.0/8
    ret_code: 301                 # Redirect status code
    uri: "/new/$request_uri"      # Static redirect; templates expand (see below)
    encode_uri: true              # Percent-encode the rewritten path
    append_query_string: true     # Preserve query parameters
    regex_uri:                    # Regex-based redirects
      - "^/old/(.*)"
      - "/new/$1"
```

**URI templates**: redirect templates share the request-phase variable
registry used by limiter keys and upstream hashing: `$host` (URI authority
first, then the `Host` header), `$request_uri`, `$uri`, `$query_string`,
`$remote_addr`, `$remote_port`, `$server_addr`, `$scheme`, `$request_method`,
any `$arg_<name>` query argument, and any `$http_<name>` request header
(nginx naming: `X-Custom-Id` -> `$http_x_custom_id`). Both `$name` and
`${name}` spell a variable; escape a literal `$` with `\$`, and unknown
variables expand to an empty string (config validation does not reject them).

> **Behavior note**: only `$host`, `$request_uri`, `$uri`, `$scheme`, and
> `$request_method` expanded in earlier releases — `$remote_addr`,
> `$server_addr`, `$remote_port`, `$arg_*`, and `$http_*` rendered as
> "" — and `$host` preferred the `Host` header over the URI authority. Both
> now match every other plugin's variable resolution.

`encode_uri` percent-encodes the rewritten path but, unlike APISIX's
`ngx_escape_uri`, preserves existing `%XX` sequences and unreserved characters
instead of double-encoding `%` and reserved characters.

#### Fault Injection (Testing & Chaos Engineering)
```yaml
plugins:
  fault-injection:
    delay:                        # Inject latency into requests
      duration: 2.5               # Delay in seconds (supports decimals)
      percentage: 50              # Apply to 50% of requests (optional, omit for all)
    
    abort:                        # Return error response
      http_status: 503            # HTTP status code to return
      body: "Service Unavailable" # Optional response body
      percentage: 10              # Apply to 10% of requests (optional, omit for all)
      headers:                    # Optional custom headers
        X-Fault-Injected: "true"
        Retry-After: "60"
```

**Fault Injection Features:**
- **Delay Injection**: Inject artificial latency to test timeout handling and performance under degraded conditions
- **Abort Injection**: Return error responses to simulate service failures
- **Percentage-Based**: Apply faults to a percentage of requests for realistic testing
- **Combined Faults**: Can use both delay and abort together
- **Custom Responses**: Define response status, body, and headers for abort responses

**Common Use Cases:**
- Chaos engineering and resilience testing

#### Request Mirroring (proxy-mirror)
```yaml
plugins:
  proxy-mirror:
    host: http://127.0.0.1:9797    # Mirror target URL (http/https)
    path: /shadow                  # Optional path rewrite
    path_concat_mode: replace      # replace (default) or prefix
    sample_ratio: 1.0              # Proportion of requests to mirror (0.00001 - 1)
```

A sampled portion of requests is asynchronously duplicated to the shadow
upstream (headers + streaming body). Mirror failures never affect the primary
request.

#### Circuit Breaker (api-breaker)
```yaml
plugins:
  api-breaker:
    break_response_code: 502       # Response code while the circuit is open
    break_response_body: "Service Unavailable"  # Optional body
    break_response_headers:        # Optional headers (values support $vars)
      - key: X-Client-Addr
        value: "$remote_addr:$remote_port"
    max_breaker_sec: 300           # Max breaker window (seconds, >= 3)
    unhealthy:
      http_statuses: [500, 503]    # Statuses counted as failures
      failures: 3                  # Failures before tripping
    healthy:
      http_statuses: [200]         # Statuses counted as success
      successes: 1                 # Consecutive successes to recover
```

Trips per-route after `unhealthy.failures` failures; while tripped, requests
are answered with `break_response_code` for an exponentially backed-off window
(2, 4, 8, ... seconds, capped at `max_breaker_sec`).

#### Client Request Control (client-control)
```yaml
plugins:
  client-control:
    max_body_size: 1048576         # Max request body size in bytes (0 = unlimited)
```

Rejects requests whose body exceeds `max_body_size` with `413 Payload Too
Large`. A declared `Content-Length` is rejected immediately; chunked or lying
bodies are caught by counting streamed bytes.

#### Request Validation (request-validation)

APISIX `request-validation` compatible. Validates requests against JSON
Schemas before they reach the upstream. At least one of `header_schema` or
`body_schema` is required; schemas are compiled at configuration time, so an
invalid schema fails the update instead of failing requests.

```yaml
plugins:
  request-validation:
    header_schema:                # JSON Schema for the request headers
      type: object
      required: ["X-Api-Version"]
      properties:
        X-Api-Version:
          type: string
          pattern: "^v[0-9]+$"
    body_schema:                  # JSON Schema for the decoded request body
      type: object
      required: ["quantity"]
      properties:
        quantity:
          type: integer
          minimum: 1
    max_req_body_size: 67108864   # Body buffer cap in bytes (default 64 MiB)
    rejected_code: 400             # Status for rejected requests (200-599)
    rejected_msg: "invalid request" # Rejection body (default: first schema error)
```

Semantics (APISIX parity):

- Headers are validated as a JSON object: single-valued headers become
  strings and repeated headers become arrays. Names are canonicalized to
  title case (`User-Agent`), matching what browsers send and APISIX sees.
- The body is **buffered and never forwarded** until it validates.
  `application/x-www-form-urlencoded` bodies are decoded as form objects
  (duplicate keys become arrays); anything else is parsed as JSON, the APISIX
  default.
- With `body_schema` set, a request without a body is rejected (fail-closed),
  as is a duplicated `Content-Type` header.
- Body-phase rejections carry `rejected_code` over Pingora's error path with
  an empty body; configure an `exit-transformer` rule when you need a body
  there. A `$ref` to a remote schema document is rejected at configuration
  time — validation is strictly offline.

> **Memory model:** `body_schema` buffers the entire request body in memory up
> to `max_req_body_size` (default 64 MiB) before validating it. Peak memory is
> therefore `concurrent buffered requests × default/configured cap`; size
> `max_req_body_size` and replica count accordingly. Streaming validation is
> not supported in this release.

#### Gateway Exit Transformer (exit-transformer)

Declarative counterpart of APISIX's `exit-transformer`: rewrites responses
**generated by the gateway itself** — authentication failures, rate-limit
rejections, blocked URIs, upstream 502/504s, no-route 404s — before they
reach the client. Upstream responses are not affected; use
  `response-rewrite` for those.

```yaml
plugins:
  exit-transformer:
    rules:                        # First match wins on the exit status
      - codes: [401, 403]
        status_code: 403          # Optional remap of the status
        body: '{"error":true,"status":$status,"message":"$message"}'
        headers:
          Content-Type: application/json   # Sets the rewritten body's type
          X-Error-Code: "$status"
      - codes: [502, 504]
        body: "upstream unavailable (request $request_id)"
```

- `codes` lists the gateway exit statuses a rule matches (first-match-wins).
- `body`/header values support `$status` (final status), `$message`
  (original exit body when one exists), and `$request_id`.
- Route-level rules override global-rule rules when both configure the
  plugin. Because the rewrite runs in the shared exit path, the plugin needs
  no phase of its own and never delays the hot path.

#### WebSocket Support (enable_websocket)
```yaml
routes:
  - id: "ws-route"
    uri: /ws/*
    enable_websocket: true         # Keep upstream timeouts disabled for upgrades
    upstream:
      nodes:
        "ws-backend.example.com:8080": 1
```

When enabled (or when a request carries an `Upgrade` header), upstream
read/write timeouts are disabled so long-lived bidirectional WebSocket
connections are not killed while idle.
- Testing timeout handling and retry logic
- Load testing under failure scenarios
- Circuit breaker and fallback validation
- SLA compliance testing

**Configuration Examples:**
```yaml
# Delay only - add 1 second latency to 20% of requests
delay:
  duration: 1.0
  percentage: 20

# Abort only - return 500 error for 5% of requests
abort:
  http_status: 500
  percentage: 5

# Combined - both delay and abort
delay:
  duration: 3.0
  percentage: 10
abort:
  http_status: 503
  body: "Gateway Timeout"
  percentage: 5
```

### AI Plugins

#### AI Proxy (`ai-proxy`)

APISIX-compatible LLM proxy (v1). Clients send **OpenAI Chat-format**
requests; the plugin injects provider authentication, transforms the request
body, switches the request onto the provider's upstream (per-provider
keepalive/timeout settings), and passes responses through untouched —
including SSE streaming responses (`"stream": true`).

```yaml
routes:
  - id: llm-proxy
    uri: /llm/*
    upstream:                       # placeholder: ai-proxy overrides it per request
      nodes:
        "127.0.0.1:1980": 1
    plugins:
      ai-proxy:
        provider: openai            # openai | openai-compatible | deepseek | anthropic
        auth:
          header:
            Authorization: "Bearer ${OPENAI_API_KEY}"
        options:                    # deep-merged into the client body (options win)
          model: gpt-4o
          temperature: 0.2
        override:
          llm_options:
            max_tokens: 1024        # forced; mapped per provider
        timeout: 30000              # ms, 1..=600000
        max_req_body_size: 67108864 # request body cap, larger → 413
        keepalive: true
        keepalive_timeout: 60000    # ms, >= 1000
        ssl_verify: true
```

**Configuration reference (v1):**

| Field | Type | Default | Notes |
|---|---|---|---|
| `provider` | string | — (required) | `openai`, `openai-compatible`, `deepseek`, `anthropic` |
| `auth.header` | map | — | header name → value, injected verbatim (`Authorization`, `x-api-key`, …); names/values validated at config time; gateway-managed framing headers (`Host`, `Content-Length`, `Transfer-Encoding`, `Content-Type`) and hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization`) are rejected |
| `auth.query` | map | — | query parameter → value; values are non-overridable |
| `auth` | — | — | at least one of `header`/`query` must be non-empty (v1 has no gcp/aws auth) |
| `options` | object | — | deep-merged into the client body; objects recurse, arrays/scalars replace |
| `override.endpoint` | string | — | replaces the provider endpoint; an endpoint path wins over the provider default chat path |
| `override.llm_options.max_tokens` | int ≥ 1 | — | forced token limit; openai → `max_completion_tokens` (legacy `max_tokens` removed), others → `max_tokens` |
| `timeout` | ms | 30000 | upstream connect/send (seconds granularity, min 1s); the upstream read timeout is floored at 600s for provider responses — see Streaming |
| `max_req_body_size` | bytes | 67108864 | request body cap; larger bodies → 413 |
| `keepalive` | bool | true | `false` disables connection reuse |
| `keepalive_timeout` | ms | 60000 | idle timeout, ≥ 1000 |
| `ssl_verify` | bool | true | `false` disables provider certificate verification |

**Provider defaults:**

| Provider | Endpoint | `max_tokens` maps to |
|---|---|---|
| `openai` | `https://api.openai.com/v1/chat/completions` | `max_completion_tokens` (deletes `max_tokens`) |
| `deepseek` | `https://api.deepseek.com/chat/completions` | `max_tokens` |
| `openai-compatible` | — (requires `override.endpoint`) | `max_tokens` |
| `anthropic` | `https://api.anthropic.com/v1/messages` | `max_tokens` |

**Anthropic conversion.** For `provider: anthropic` the client's OpenAI body
is converted to Anthropic Messages format: `system`-role messages are
extracted into the top-level `system` string; `user`/`assistant` messages
pass through; `max_completion_tokens` falls back to `max_tokens`; `stop`
becomes `stop_sequences`; a whitelist of compatible fields (`stream`,
`temperature`, `top_p`, `top_k`) passes through and other OpenAI-only fields
are dropped. The plugin injects `anthropic-version: 2023-06-01` (your
`auth.header` entry, if any, wins).

**Streaming.** The upstream read timeout is floored at a generous 600 seconds
for every ai-proxy request — LLM upstreams legitimately go silent between
reads, whether a non-streaming completion thinking before its first byte or
an SSE stream between chunks, and pingora's `read_timeout` bounds the gap
*between* reads. The floor keeps that relaxation bounded: a stalled provider
connection is dropped after at most 10 minutes instead of being held
forever. `timeout` still bounds connect and write. A total-duration bound
(`max_stream_duration_ms`) is planned for v2. Responses are passed through
unmodified (no re-buffering, no SSE normalization).

> **Memory model:** the client request body is fully buffered in memory up to
> `max_req_body_size` (default 64 MiB) while it is transformed, so peak memory
> scales with concurrent ai-proxy requests. Size the cap and replica count
> accordingly; a streaming transform is planned for v2.

**Scope precedence.** At most ONE ai-proxy instance handles a request. A
route/service-scoped `ai-proxy` overrides a global-rule one (APISIX merge
semantics), and any further instance is a no-op — provider credentials, TLS
settings, and the body transform always come from a single instance and can
never mix across scopes.

**Security notes**

- The client's `Authorization` header is **deleted** before proxying (the
  provider never sees client credentials; provider auth comes from
  `auth.header`/`auth.query`). This intentionally differs from APISIX,
  which forwards client headers and overlays `auth.header`.
- `auth.header.*` and `auth.query.*` values are field-encrypted at rest
  (see [Encrypting Sensitive Plugin Fields](#encrypting-sensitive-plugin-fields))
  and redacted in Admin API reads.
- `Accept-Encoding` is stripped so responses reach clients uncompressed.

**Request handling.** A `Content-Type` that is not exactly `application/json`
(parameters like `charset=utf-8` are fine; look-alikes such as
`application/jsonp` and duplicated `Content-Type` headers are rejected), or a
bodyless request, is rejected early with **400** (`{"error": "..."}`). Invalid
JSON, a non-object body, a missing/malformed `messages` array, well-known
fields with wrong types (`stream`, `max_tokens`), a body that the `options`
merge would break, or a body larger than `max_req_body_size` are detected
while streaming the body and surface as **400**/**413** with an empty body
(`exit-transformer` can supply one). For `provider: anthropic`, missing
required fields (`model`, `max_tokens`, an all-`system` conversation) also
fail fast locally with **400** instead of a provider round trip. All gateway
exits flow through `exit-transformer`.

The upstream request is sent with `Transfer-Encoding: chunked` framing
(the transformed body length is unknown until the client body completes),
which every HTTP/1.1 provider accepts.

**Caveats**

- The route still needs an upstream configured (`Route` schema requires
  one); ai-proxy overrides it at request time, so any placeholder works.
- When ai-proxy and `request-validation` share a route scope, body schemas
  are skipped once ai-proxy has transformed the body (the client-format
  schema would misreject the provider-format body); header schemas still
  apply. A *global*-scope request-validation still buffers before a
  *route*-scope ai-proxy injects — avoid that combination.
- `timeout` is applied at seconds granularity (500ms → 1s); the upstream read
  timeout is floored at 600s (see Streaming).
- When `ai-proxy` is configured both in a global rule and on the matched
  route/service, the route/service instance wins and the global instance is
  skipped for those requests (see Scope precedence).

**APISIX compatibility matrix (v1):**

| Capability | Status |
|---|---|
| `provider`/`auth`/`options`/`override.llm_options`/`timeout`/`max_req_body_size`/`keepalive`/`ssl_verify` | ✅ identical semantics and bounds |
| openai / openai-compatible / deepseek / anthropic providers | ✅ |
| SSE streaming passthrough | ✅ (read timeout floored at 600s instead of removed) |
| global-rule + route configuration of ai-proxy | ✅ route/service overrides global (single instance owns a request) |
| client `Authorization` header | ⚠️ deleted (APISIX forwards it; `auth.header` overlays) |
| `anthropic-version` header | ⚠️ auto-injected `2023-06-01` (APISIX ≥ 3.17 expects the client or `auth.header`) |
| `options` merge | ⚠️ deep merge; APISIX overwrites top-level keys wholesale (identical for scalar options) |
| error bodies | ⚠️ JSON `{"error": ...}` (APISIX returns plain text messages) |
| `override.request_body` / `request_body_force_override` | ❌ not supported; ignored (v2+) |
| protocol auto-detection (`/v1/responses`, embeddings, anthropic-native clients, converters) | ❌ v1 accepts OpenAI Chat-format clients only |
| response transforms, `max_response_bytes`, `max_stream_duration_ms`, token-usage vars | ❌ v2/v3 |
| `auth.gcp` / `auth.aws` (SigV4), azure/gemini/openrouter/aimlapi/vertex-ai/bedrock | ❌ out of v1 scope |
| `ai-proxy-multi` (multi-instance load balancing, fallback strategies) | ❌ planned |

### Compression

#### Gzip Compression
```yaml
plugins:
  gzip:
    comp_level: 6                 # Compression level (0-9)
    decompression: false          # Enable decompression if needed
```

#### Brotli Compression
```yaml
plugins:
  brotli:
    comp_level: 6                 # Compression level (0-11)
    decompression: false          # Enable decompression if needed
```

### Caching

#### Response Caching

> **Breaking rename:** the plugin is `proxy-cache`; the old pingsix key `cache`
> is not accepted as an alias. **Migrate before upgrading**: rewrite every
> `cache:` plugin key in static configs AND in etcd route/global-rule data to
> `proxy-cache:` first — a single stale `cache` key fails the whole config
> snapshot build (initial load never becomes ready; subsequent hot reloads
> are rejected) until every key is rewritten.

```yaml
plugins:
  proxy-cache:                  # APISIX-compatible plugin name
    ttl: 3600                   # Cache TTL in seconds (default: 300 when omitted)
    cache_http_methods: ["GET", "HEAD"]  # Default: ["GET", "HEAD"]
    cache_http_statuses: [200, 301, 404] # Default: [200]
    no_cache_str:               # Regex patterns to skip caching
      - ".*private.*"
      - ".*no-cache.*"
    vary: ["Accept-Encoding"]   # Vary headers for cache keys
    hide_cache_headers: false   # Hide cache-related headers (default: false)
    enable_purge: false         # Accept PURGE requests (default: false; no built-in auth)
    scope: local                # Entries, locks and SWR state are process-local
    max_file_size_bytes: 1048576  # Max cacheable response size (bytes, 0 = no limit)
    stale_while_revalidate_secs: 60  # Serve stale content while revalidating (optional)
    respect_s_maxage: true      # Respect Cache-Control s-maxage directive (default: true)
    # Disabled by default: shared caching skips requests with Authorization/Cookie
    # headers and responses with Set-Cookie to prevent cross-user reuse.
    cache_authenticated_requests: false
    # Separate high-risk opt-in; remains false even when authenticated caching is enabled.
    cache_set_cookie_responses: false
    # --- APISIX proxy-cache aliases (also accepted) ---
    cache_ttl: 300              # Alias for ttl; overrides ttl when present
    cache_method: ["GET", "HEAD"]      # Alias for cache_http_methods
    cache_http_status: [200, 301, 404] # Alias for cache_http_statuses
    cache_key: ["$host", "$request_uri"] # Optional APISIX cache key templates (explicit opt-in;
                                    # `$request_method` is rejected like APISIX)
    cache_bypass: ["$arg_nocache"]     # Skip cache LOOKUP when a template renders truthy
    no_cache: ["$http_x_private"]      # Suppress STORING the response (hits are still served)
    # APISIX `cache_control` — only meaningful when written explicitly:
    #   true  -> honor request Cache-Control (no-cache/no-store bypass) and let
    #            origin max-age/s-maxage override ttl
    #   false -> the configured ttl governs; request Cache-Control is ignored
    #   (absent keeps pingsix legacy behavior: request no-cache bypasses and
    #    origin freshness is honored per respect_s_maxage)
    cache_control: false
    consumer_isolation: true           # Add credential digest when caching authenticated requests
    cache_set_cookie: false            # Alias for cache_set_cookie_responses
    # APISIX alias for max_file_size_bytes — applies ONLY when the pingsix
    # field above is absent (use one or the other):
    max_resp_body_size: 67108864
    cache_strategy: memory             # Explicit `disk` is rejected
```

**Cache Plugin Features:**
- **TTL Management**: Configure cache expiration with `ttl` parameter
- **Stale-While-Revalidate**: Serve stale cached content while fetching fresh content in the background, improving perceived performance
- **s-maxage Support**: When enabled (default), respects `Cache-Control: s-maxage` directive from origin, overriding configured TTL for shared cache scenarios
- **Selective Caching**: Control which HTTP methods and status codes are cacheable
- **Pattern-Based Exclusion**: Use regex patterns to exclude specific URIs from caching
- **APISIX aliases**: `cache_ttl`/`cache_method`/`cache_http_status` map onto the
  pingsix fields above when present; `cache_key` templates support `$host`,
  `$request_uri`, `$uri`, `$args`, `$arg_*`, `$http_*` (`$request_method` is
  rejected — the method is not part of the cache identity and would break the
  PURGE→GET key alias); an explicit `cache_key` containing `$http_authorization`
  opts out of `consumer_isolation` (the operator owns the identity scheme).
  `cache_bypass` skips cache lookup and `no_cache` suppresses storing for a
  request when the **concatenated** rendering of the templates is non-empty
  and not `"0"` (so `["0", "0"]` renders `"00"` and counts as truthy, like APISIX).
- **Size Limits**: Prevent memory exhaustion by limiting cacheable response size
- **Credential Safety**: Requests with `Authorization`, `Proxy-Authorization`, or `Cookie`, and any
  request where `basic-auth` / `key-auth` / `jwt-auth` observed credentials (custom header, query,
  or cookie carriers), bypass the shared cache by default—even if plugins later strip those
  headers. With `cache_authenticated_requests: true`, `consumer_isolation` partitions the cache
  by a SHA-256 digest of the ORIGINAL standard credential headers (captured before any plugin
  can strip them) combined with the digest of the credential each auth plugin verified — custom
  header/query/cookie carriers included. Note the authenticated path additionally requires the
  origin to mark responses `public` (or `must-revalidate`/`s-maxage`) before pingora stores them.
- **Cookie Safety**: Responses with `Set-Cookie` bypass caching independently. Enabling authenticated request caching does not enable cookie-response caching; `cache_set_cookie_responses: true` is a separate high-risk opt-in that can replay cookies across shared-cache clients.
- **Vary Support**: Generate cache keys based on specified request headers
- **PURGE (opt-in)**: `enable_purge: true` makes the cache plugin intercept
  `PURGE` requests and delete the matching key. It is **disabled by default**
  because an unauthenticated `PURGE` would let any client force cache misses
  (stampede DoS). There is no built-in PURGE authentication; front the proxy
  with your own ACL or a management path before enabling it. While disabled, a
  `PURGE` request is treated as an ordinary client request and is forwarded
  upstream.
- **Client Bypass Header**: A request carrying `X-ByPass-Cache` (any value)
  skips the shared cache for that request; `Cache-Control: no-cache` (or
  `no-store`) has the same effect unless `cache_control: false` is set
  explicitly. These headers are honored on every request and are not
  authenticated — treat them as a cache-bypass capability available to all
  clients.

**Common Use Cases:**
- CDN-like caching for static assets
- API response caching with TTL
- Serving stale content during origin failures
- Respecting origin cache control policies

### Observability

#### Prometheus Metrics
```yaml
plugins:
  prometheus:
    max_label_length: 100         # Maximum path label length (default: 100)
    max_unique_paths: 1000        # Maximum unique paths tracked (default: 1000)
    max_unique_hosts: 100         # Maximum unique matched_host labels (default: 100)
    prefer_name: false            # Use route/service name instead of id in labels
  # OR zero-configuration
  prometheus: {}                  # Use defaults above
```

**Prometheus Plugin Configuration:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_label_length` | integer | 100 | Maximum length for path template labels. Paths exceeding this length will be truncated with "..." suffix to prevent memory issues and Prometheus label size limits. |
| `max_unique_paths` | integer | 1000 | Maximum number of unique normalized path templates to track. Once this limit is reached, new paths will be collapsed to `/...` pattern to prevent metric cardinality explosion. |
| `max_unique_hosts` | integer | 100 | Maximum number of unique `matched_host` label values to track. Additional hosts collapse to `*` to bound cardinality. |
| `prefer_name` | boolean | false | When `true`, export route/service `name` in metric labels instead of `id`. Falls back to `id` when name is missing or empty. Ensure names are unique across routes/services to avoid misleading aggregated metrics. |

**Prometheus Plugin Features:**
- **Cardinality Control**: Limits metric cardinality by normalizing URI paths and enforcing label length limits
- **Path Normalization**: Automatically replaces dynamic path segments with placeholders:
  - Numeric IDs: `/users/123` → `/users/{id}`
  - UUIDs: `/items/550e8400-e29b-41d4-a716-446655440000` → `/items/{uuid}`
  - Hash values: `/files/a1b2c3d4e5f6...` → `/files/{hash}`
  - Deep paths: Limits to 8 segments, e.g., `/a/b/c/d/e/f/g/h/i` → `/a/b/c/d/e/f/g/...`
- **Prefer Name**: Optionally labels metrics with route/service names for readable dashboards (APISIX-compatible `prefer_name`)
- **Label Length Limit**: Truncates long path labels to `max_label_length` characters (with "..." suffix) to prevent memory issues
- **Path Tracking Limit**: After tracking `max_unique_paths` unique normalized paths, new paths are collapsed to `/...` to prevent unbounded metric growth
- **Efficient Tracking**: Uses DashMap for thread-safe path deduplication with minimal overhead

**Process lifetime:** Prometheus collectors are process-global registrations.
They are intentionally shared by repeated in-process gateway builds; metrics
accumulate for the lifetime of the process rather than being reset per runtime.

**Collected Metrics:**
- `http_requests_total` (Counter) - Total number of client requests since PingSIX started
- `http_status` (Counter) - HTTP status codes with labels: `code`, `route`, `path_template`, `matched_host`, `service`, `node`
- `http_latency` (Histogram) - HTTP request latency in milliseconds with labels: `type`, `route`, `service`, `node`
  - Default buckets (ms): 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000, 60000
- `bandwidth` (Counter) - Total bandwidth in bytes with labels: `type` (ingress/egress), `route`, `service`, `node`
- `http_request_size_bytes` (Histogram) - HTTP request size distribution with labels: `route`, `service`
  - Buckets (bytes): 100, 1000, 10000, 100000, 1000000, 10000000
- `http_response_size_bytes` (Histogram) - HTTP response size distribution with labels: `route`, `service`
  - Buckets (bytes): 100, 1000, 10000, 100000, 1000000, 10000000

**Configuration Best Practices:**
- **max_label_length**: Keep under 200 characters to avoid Prometheus label size limits and memory issues
  - Too small (< 50): May truncate useful path information
  - Too large (> 200): Risk of Prometheus performance degradation
  - Recommended: 100-150 for most use cases
- **max_unique_paths**: Set based on your API diversity and traffic patterns
  - Small APIs (< 100 endpoints): 500-1000
  - Medium APIs (100-500 endpoints): 1000-5000
  - Large APIs (> 500 endpoints): 5000-10000
  - Monitor actual unique path count in your metrics to tune this value
- **prefer_name**: Prefer unique names when enabled; duplicate names merge series and can mislead dashboards
- **Monitoring**: Regularly check metric cardinality in Prometheus using queries like:
  ```promql
  count(http_status)
  count by(path_template) (http_status)
  ```
- **Tuning**: If you see paths collapsed to `/...`, increase `max_unique_paths`. If Prometheus performance degrades, decrease both limits.

#### File Logging
```yaml
plugins:
  file-logger:
    # Legacy behavior (no path): render the custom string below via the log crate.
    log_format: '$remote_addr "$request_method $uri" $status'
    # APISIX-compatible file mode: append one JSON line per request.
    # path: /var/log/pingsix/access.log
    include_req_body: false       # Include base64 request body in JSON entries
    include_resp_body: false      # Include base64 response body in JSON entries
    max_req_body_bytes: 524288    # Request body collection cap
    max_resp_body_bytes: 524288   # Response body collection cap
```

#### Request ID
```yaml
plugins:
  request-id:
    header_name: X-Request-ID     # Header name for request ID
    include_in_response: true     # Include in response headers
    algorithm: uuid               # uuid, nanoid, range_id, ksuid, uuidv7
    # Optional: configuration for 'range_id' algorithm
    range_id:
      char_set: "ABCDEF0123456789"
      length: 32
```

### Utility Plugins

#### Echo (Testing)

APISIX semantics: the upstream response is proxied and its body is wrapped or
replaced in the response phase (`before_body` prefix, `body` replacement at end
of stream, `after_body` suffix). Compressed upstream bodies pass through
unmodified.

```yaml
plugins:
  echo:
    before_body: "["             # Optional prefix (any one of the three is required)
    body: "Hello, World!"         # Replace the upstream response body
    after_body: "]"              # Optional suffix
    headers:                      # Response headers
      Content-Type: "text/plain"
      X-Echo: "true"
```

#### gRPC Web

Like APISIX, the plugin is strict: `OPTIONS` is answered locally as a CORS
preflight (204, `Access-Control-Allow-Methods: POST`), only `POST` with a
`application/grpc-web*` content type is proxied, and the body limit applies
only to gRPC-Web requests.

```yaml
plugins:
  grpc-web:
    max_req_body_size: 67108864  # Request body cap (default)
    cors_allow_headers: content-type,x-grpc-web,x-user-agent  # CORS allow headers
```

## Plugin Development

New plugins live under `src/plugins/`. Add a `PluginMeta` entry to the
`PLUGIN_META` inventory in `src/plugins/mod.rs` and implement `ProxyPlugin`.

### Required Phase Declaration (Breaking Change)

`ProxyPlugin` execution is fail-closed: the executor invokes a hook **only** if
`phases()` includes its corresponding `PluginPhases` bit. The default is an
empty set, so a hook implementation without an explicit declaration is never
called. Existing source plugins must add declarations for every hook they
implement before upgrading.

```rust
use async_trait::async_trait;
use pingsix::core::{PluginPhases, ProxyContext, ProxyPlugin};

struct MyPlugin;

#[async_trait]
impl ProxyPlugin for MyPlugin {
    fn name(&self) -> &str { "my-plugin" }
    fn priority(&self) -> i32 { 1000 }

    fn phases(&self) -> PluginPhases {
        PluginPhases::REQUEST | PluginPhases::RESPONSE
    }

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> pingora_error::Result<bool> {
        Ok(false)
    }
}
```

The valid bits are `EARLY_REQUEST`, `REQUEST`, `UPSTREAM_REQUEST`,
`REQUEST_BODY`, `RESPONSE`, `RESPONSE_BODY`, and `LOGGING`. The builtin phase
registry test enforces this contract for every bundled plugin.

`ProxyContext::selected` is now `Option<SelectedUpstream>`. Pingora owns the
`HttpPeer` after upstream selection, so custom plugins must use the remaining
`upstream`, `backend`, `sni`, and `node` fields rather than `selected.peer`.
This is an intentional source-breaking migration.

### Encrypting Sensitive Plugin Fields

If the plugin config stores secrets in etcd (passwords, API keys, HMAC keys),
mark them with `EncryptFields` so Admin write / etcd load encrypt and decrypt
automatically when `pingsix.data_encryption.enable` is true.

**1. Derive and mark fields** on the plugin config struct. Put `#[encrypt_fields(export)]` only on the **root** config (not on
nested types) so the derive emits a module-level `SECRETS_TRANSFORM`:

```rust
use pingsix_macros::EncryptFields;
use crate::utils::encryption::EncryptFields;

#[derive(Debug, Serialize, Deserialize, EncryptFields)]
struct Credentials {
    #[encrypt]
    token: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, EncryptFields)]
#[encrypt_fields(export)]
struct PluginConfig {
    username: String,          // not a secret — leave unmarked

    #[encrypt]
    password: String,          // string secret

    #[encrypt]
    keys: Vec<String>,         // each array element is encrypted

    #[encrypt(nested)]
    credentials: Credentials,  // nested struct that also derives EncryptFields

    #[encrypt(nested)]
    optional: Option<Credentials>,  // null is skipped
}
```

**2. Register** the exported transform in the plugin's `PluginMeta` entry in
`PLUGIN_META` (`src/plugins/mod.rs`):

```rust
PluginMeta {
    name: my_plugin::PLUGIN_NAME,
    factory: PluginFactory::Plain(my_plugin::create_my_plugin),
    secrets_transform: Some(my_plugin::SECRETS_TRANSFORM),
    validate: None,
    upstream_refs: None,
    upstream_jobs: None,
},
```

`SECRETS_TRANSFORM` is a module-level `const` from `#[encrypt_fields(export)]`. Do not add a hand-written wrapper.

**Rules of thumb:**

- Encrypt credentials and private material only (not public keys, usernames,
  header *names*, or non-secret selectors like `limit-count.key`).
- Nested secrets use `#[encrypt(nested)]`; the nested type must also derive
  `EncryptFields` but must **not** use `#[encrypt_fields(export)]` (one export
  per plugin module).
- `#[serde(rename = "...")]` is honoured: encryption uses the JSON field name.
- Admin GET/LIST redaction is automatic: it reuses the same `#[encrypt]` walk
  (`SecretOp::Redact`), so a marked field is masked in API responses without any
  extra bookkeeping.

Resource-level secrets outside plugins (SSL `key`, upstream `tls.client_key`)
are wired in the Admin encrypt path and control-plane decrypt path the same
way — see [Data Encryption](#data-encryption).

## Admin API

The Admin API allows dynamic configuration management when etcd is enabled.

### Configuration

```yaml
pingsix:
  etcd:
    host: ["http://127.0.0.1:2379"]
    prefix: /pingsix
  
  admin:
    address: "127.0.0.1:9181"   # Non-loopback plaintext binds are rejected by default
    api_key: "your-secure-api-key"
    # allow_insecure_remote: true  # Required for intentional non-loopback cleartext binds
    # Note: Admin has no TLS listener; remote binds must use allow_insecure_remote or stay on loopback.

  status:
    address: "127.0.0.1:7085"
    config_stale_after: 300
    fail_readiness_when_stale: true  # Default; set false only for legacy opt-out
    # Non-loopback diagnostics require both settings below; plaintext is high risk.
    # diagnostics_api_key: "separate-diagnostics-key"
    # allow_insecure_remote: true
```

`/status/live` and `/status/ready` are unauthenticated public probes and expose only stable
status/reason fields. `/status/config` is available by default only on a loopback listener;
non-loopback plaintext access requires both a diagnostics API key and explicit insecure opt-in.
`/status/config` reports `observed_revision` (last successful etcd list/watch cursor),
`published_revision` (runtime snapshot revision), plus source/connected/last sync/degraded reason.
`revision` remains an alias of `observed_revision` for compatibility. Stale readiness only applies
to etcd-backed configs and fails readiness by default after the configured disconnection threshold.

Rate limits and response caches are local to each PingSIX process. With multiple replicas, the
aggregate effective limit is approximately `count × replicas` (subject to traffic distribution),
and cache entries, locks, eviction and stale-while-revalidate state are not shared.

### API Endpoints

All Admin API requests require the `X-API-KEY` header:

```bash
curl -H "X-API-KEY: your-secure-api-key" \
     -H "Content-Type: application/json" \
     http://127.0.0.1:9181/apisix/admin/routes/1
```

**Available Operations:**
- **PUT** `/apisix/admin/{resource_type}/{id}` - Create or update a resource
- **GET** `/apisix/admin/{resource_type}/{id}` - Get a specific resource
- **DELETE** `/apisix/admin/{resource_type}/{id}` - Delete a resource
- **GET** `/apisix/admin/{resource_type}` - List all resources of a type

**Supported Resource Types:**
- `routes` - Route configurations
- `upstreams` - Upstream server pools
- `services` - Service definitions
- `global_rules` - Global plugin rules
- `ssls` - SSL certificates

#### Routes Management

**Create/Update Route**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/api/*",
    "host": "api.example.com",
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend1.example.com:8080": 1,
        "backend2.example.com:8080": 1
      }
    },
    "plugins": {
      "limit-count": {
        "key_type": "vars",
        "key": "remote_addr",
        "time_window": 60,
        "count": 100
      }
    }
  }'
```

**Get Route**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-api-key"
```

**List All Routes**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/routes \
  -H "X-API-KEY: your-api-key"
```

Response format:
```json
{
  "total": 2,
  "list": [
    {
      "key": "routes/1",
      "value": { /* route configuration */ },
      "createdIndex": 10,
      "modifiedIndex": 15
    },
    {
      "key": "routes/2",
      "value": { /* route configuration */ },
      "createdIndex": 20,
      "modifiedIndex": 20
    }
  ]
}
```

**Delete Route**:
```bash
curl -X DELETE http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-api-key"
```

#### Upstreams Management

**Create/Update Upstream**: (map form — weight only, priority defaults to `0`):
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/upstreams/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "roundrobin",
    "nodes": {
      "backend1.example.com:8080": 1,
      "backend2.example.com:8080": 2
    },
    "checks": {
      "active": {
        "type": "http",
        "http_path": "/health",
        "healthy": {
          "interval": 10,
          "successes": 2
        },
        "unhealthy": {
          "http_failures": 3
        }
      }
    }
  }'
```

**Create/Update Upstream** (list form — priority-based selection):
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/upstreams/2 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "roundrobin",
    "scheme": "https",
    "pass_host": "rewrite",
    "upstream_host": "api.example.com",
    "nodes": [
      {
        "host": "primary.example.com",
        "port": 443,
        "weight": 1,
        "priority": 10
      },
      {
        "host": "standby.example.com",
        "port": 443,
        "weight": 1,
        "priority": 0
      },
      {
        "host": "cold.example.com",
        "port": 443,
        "weight": 1,
        "priority": -1
      }
    ],
    "checks": {
      "active": {
        "type": "https",
        "timeout": 1,
        "host": "api.example.com",
        "http_path": "/health",
        "https_verify_certificate": true,
        "healthy": {
          "interval": 5,
          "http_statuses": [200, 201],
          "successes": 2
        },
        "unhealthy": {
          "http_failures": 2,
          "tcp_failures": 1
        }
      }
    }
  }'
```

Selection uses the highest priority group that still has a ready backend, balancing each group independently (see [Basic Upstream Configuration](#basic-upstream-configuration)). Enable `checks` so lower-priority nodes are used only after higher ones fail health checks. Two enabled nodes must not resolve to the same address; the check compares effective ports, so omitting `port` over `http` conflicts with an explicit `80`.

**List All Upstreams**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/upstreams \
  -H "X-API-KEY: your-api-key"
```

#### Services Management

**Create/Update Service**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/services/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "upstream_id": "1",
    "plugins": {
      "jwt-auth": {
        "secret": "your-jwt-secret"
      }
    }
  }'
```

**List All Services**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/services \
  -H "X-API-KEY: your-api-key"
```

#### Global Rules Management

**Create/Update Global Rule**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/global_rules/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "plugins": {
      "prometheus": {},
      "cors": {
        "allow_origins": "*",
        "allow_methods": "GET,POST,PUT,DELETE"
      }
    }
  }'
```

**List All Global Rules**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/global_rules \
  -H "X-API-KEY: your-api-key"
```

#### SSL Certificates Management

**Create/Update SSL Certificate**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/ssls/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "snis": ["example.com", "www.example.com"]
  }'
```

**List All SSL Certificates**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/ssls \
  -H "X-API-KEY: your-api-key"
```

## SSL/TLS Configuration

### Static SSL Configuration

Configure SSL certificates in the configuration file:

```yaml
pingsix:
  listeners:
    - address: 0.0.0.0:443
      tls:
        cert_path: /etc/ssl/certs/server.crt
        key_path: /etc/ssl/private/server.key
      offer_h2: true

ssls:
  - id: "example-com-cert"
    cert: |
      -----BEGIN CERTIFICATE-----
      MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
      ...
      -----END CERTIFICATE-----
    key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGtJmWmWWKvO
      ...
      -----END PRIVATE KEY-----
    snis: ["example.com", "www.example.com"]
```

### Dynamic SSL with SNI

When using etcd, SSL certificates can be loaded dynamically based on Server Name Indication (SNI):

```bash
# Add certificate via Admin API
curl -X PUT http://127.0.0.1:9181/apisix/admin/ssls/example-com \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "snis": ["example.com", "*.example.com"]
  }'
```

With [`data_encryption`](#data-encryption) enabled, the Admin API encrypts the
`key` field before writing it to etcd. Submit plaintext PEM as usual; GET
responses continue to redact the private key.

## Monitoring and Observability

### Prometheus Metrics

Enable Prometheus metrics collection:

```yaml
pingsix:
  prometheus:
    address: 0.0.0.0:9091

global_rules:
  - id: "metrics"
    plugins:
      prometheus:
        max_label_length: 100      # Optional: Max path label length (default: 100)
        max_unique_paths: 1000     # Optional: Max unique paths (default: 1000)
        max_unique_hosts: 100      # Optional: Max unique matched_host values (default: 100)
        prefer_name: false         # Optional: use route/service name instead of id
      # OR use zero-configuration with defaults
      prometheus: {}
```

**Plugin Configuration Parameters:**
- `max_label_length` (default: 100) - Maximum length for path template labels. Paths exceeding this length are truncated with "..." suffix.
- `max_unique_paths` (default: 1000) - Maximum number of unique normalized paths to track. After this limit, new paths are collapsed to `/...`.
- `max_unique_hosts` (default: 100) - Maximum number of unique `matched_host` labels. Additional hosts collapse to `*`.
- `prefer_name` (default: false) - When `true`, `route`/`service` labels use the resource `name` instead of `id` (falls back to `id` if name is missing or empty).

**Available Metrics:**
- `http_requests_total` (Counter) - Total number of client requests since PingSIX started
- `http_status{code, route, path_template, matched_host, service, node}` (Counter) - Request count by status and normalized path
- `http_latency{type, route, service, node}` (Histogram) - Request duration in milliseconds
  - Buckets (ms): 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000, 60000
- `bandwidth{type, route, service, node}` (Counter) - Ingress/egress bandwidth in bytes
- `http_request_size_bytes{route, service}` (Histogram) - Request size distribution
  - Buckets (bytes): 100, 1000, 10000, 100000, 1000000, 10000000
- `http_response_size_bytes{route, service}` (Histogram) - Response size distribution
  - Buckets (bytes): 100, 1000, 10000, 100000, 1000000, 10000000

**Metric Labels:**
- `path_template` - Normalized URI path to avoid high cardinality (e.g., `/users/{id}` instead of `/users/123`)
- `route` - Route ID, or route name when `prefer_name` is `true`
- `service` - Service ID, or service name when `prefer_name` is `true`
- `node` - Upstream node address
- `matched_host` - Matched host from route configuration
- `type` - Request type (for latency) or traffic direction (ingress/egress for bandwidth)
- `code` - HTTP status code

**Path Normalization:**
The Prometheus plugin automatically normalizes paths to prevent metric cardinality explosion:
- Numeric IDs: `/users/123` → `/users/{id}`
- UUIDs: `/items/550e8400-e29b-41d4-a716-446655440000` → `/items/{uuid}`
- Hashes: `/files/a1b2c3d4e5f6...` → `/files/{hash}`
- Deep paths: Limits to 8 segments, e.g., `/a/b/c/d/e/f/g/h/i` → `/a/b/c/d/e/f/g/...`
- Long paths: Truncates to `max_label_length` characters with "..." suffix
- Cardinality limit: After `max_unique_paths` unique paths, new paths become `/...`

For detailed configuration options and best practices, see the [Prometheus Plugin](#prometheus-metrics) section in the Plugins chapter.

### Sentry Integration

Configure Sentry for error tracking:

```yaml
pingsix:
  sentry:
    dsn: "https://your-dsn@sentry.io/project-id"
```

### File Logging

Configure access logging:

```yaml
pingsix:
  log:
    path: /var/log/pingsix/access.log

global_rules:
  - id: "logging"
    plugins:
      file-logger:
        log_format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time'
```

Both the `$name` and `${name}` spellings are accepted in `log_format`; a
bare `$` not followed by a variable name stays literal, and unknown
variables render empty.

Available log variables:
- `$remote_addr` - Client IP address
- `$remote_port` - Client port
- `$remote_user` - Remote user (if authenticated)
- `$time_local` - Local time
- `$request` - Full request line (`$request_method $uri $server_protocol`)
- `$request_method` - Request method (e.g., GET)
- `$request_id` - The unique request ID
- `$status` - Response status code
- `$body_bytes_sent` - Response body size in bytes
- `$http_host` - The host from the request URI
- `$http_referer` - Referer header
- `$http_user_agent` - User-Agent header
- `$request_time` - Total request processing time in milliseconds
- `$server_addr` - The server address PingSIX listened on
- `$server_protocol` - The request protocol (e.g., http/1.1)
- `$uri` - The request URI path
- `$query_string` - The request query string
- `$error` - The error message if an error occurred

## Examples

### Example 1: Simple API Gateway

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:8080

routes:
  - id: "api-gateway"
    uri: /api/{*path}               # Catch-all for /api/* requests
    upstream:
      nodes:
        "api-server1.example.com:8080": 1
        "api-server2.example.com:8080": 1
      type: roundrobin
      checks:
        active:
          type: http
          http_path: /health
          healthy:
            interval: 10
            successes: 2
          unhealthy:
            http_failures: 3
```

### Example 2: Multi-Service Architecture

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:80
    - address: 0.0.0.0:443
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true

upstreams:
  - id: "user-service"
    nodes:
      "user-api1.internal:8080": 1
      "user-api2.internal:8080": 1
    type: roundrobin
    
  - id: "order-service"
    nodes:
      "order-api1.internal:8080": 1
      "order-api2.internal:8080": 1
    type: roundrobin

services:
  - id: "authenticated-service"
    upstream_id: "user-service"
    plugins:
      jwt-auth:
        secret: "your-jwt-secret"
        algorithm: HS256
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 1000

routes:
  - id: "user-api"
    uri: /api/users/{*path}         # Catch-all for /api/users/* requests
    host: api.example.com
    service_id: "authenticated-service"
    
  - id: "order-api"
    uri: /api/orders/{*path}        # Catch-all for /api/orders/* requests
    host: api.example.com
    upstream_id: "order-service"
    plugins:
      key-auth:
        key: "order-service-key"

global_rules:
  - id: "monitoring"
    plugins:
      prometheus: {}
      cors:
        allow_origins: "https://app.example.com"
        allow_methods: "GET,POST,PUT,DELETE"
        allow_credentials: true
```

### Example 3: High-Performance Caching Gateway

```yaml
pingora:
  version: 1
  threads: 8

pingsix:
  listeners:
    - address: 0.0.0.0:80
  
  prometheus:
    address: 0.0.0.0:9091

upstreams:
  - id: "cdn-origin"
    nodes:
      "origin1.example.com:80": 1
      "origin2.example.com:80": 1
    type: roundrobin
    checks:
      active:
        type: http
        http_path: /health
        healthy:
          interval: 30
          successes: 2
        unhealthy:
          http_failures: 3

routes:
  - id: "static-assets"
    uri: /static/{*filepath}        # Catch-all for /static/* requests
    upstream_id: "cdn-origin"
    plugins:
      proxy-cache:
        ttl: 86400  # 24 hours
        cache_http_methods: ["GET", "HEAD"]
        cache_http_statuses: [200, 301, 404]
        vary: ["Accept-Encoding"]
        max_file_size_bytes: 10485760  # 10MB limit
        stale_while_revalidate_secs: 300  # Serve stale for 5 min while revalidating
        respect_s_maxage: true
      gzip:
        comp_level: 6
  
  - id: "api-content"
    uri: /api/{*path}               # Catch-all for /api/* requests
    upstream_id: "cdn-origin"
    plugins:
      proxy-cache:
        ttl: 300  # 5 minutes
        cache_http_methods: ["GET"]
        cache_http_statuses: [200]
        stale_while_revalidate_secs: 60
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100

global_rules:
  - id: "observability"
    plugins:
      prometheus:
        max_label_length: 150
        max_unique_paths: 2000
      request-id:
        header_name: X-Request-ID
        include_in_response: true
```

### Example 4: Microservices with Authentication

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:443
      tls:
        cert_path: /etc/ssl/api.crt
        key_path: /etc/ssl/api.key
      offer_h2: true
  
  etcd:
    host: ["http://etcd1:2379", "http://etcd2:2379"]
    prefix: /pingsix
  
  admin:
    address: "127.0.0.1:9181"
    api_key: "secure-admin-key"

upstreams:
  - id: "auth-service"
    nodes:
      "auth-svc.k8s.local:8080": 1
    type: roundrobin
    
  - id: "user-service"
    nodes:
      "user-svc.k8s.local:8080": 1
    type: roundrobin
    
  - id: "payment-service"
    nodes:
      "payment-svc.k8s.local:8080": 1
    type: roundrobin

routes:
  # Public authentication endpoint
  - id: "auth-login"
    uri: /auth/login
    host: api.example.com
    methods: ["POST"]
    upstream_id: "auth-service"
    plugins:
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 300
        count: 5  # 5 login attempts per 5 minutes
  
  # Protected user endpoints
  - id: "user-api"
    uri: /api/users/{*path}         # Catch-all for /api/users/* requests
    host: api.example.com
    upstream_id: "user-service"
    plugins:
      jwt-auth:
        secret: "your-jwt-secret"
        algorithm: HS256
        store_in_ctx: true
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100
  
  # High-security payment endpoints
  - id: "payment-api"
    uri: /api/payments/{*path}      # Catch-all for /api/payments/* requests
    host: api.example.com
    upstream_id: "payment-service"
    plugins:
      jwt-auth:
        secret: "your-jwt-secret"
        algorithm: HS256
      ip-restriction:
        whitelist: ["10.0.0.0/8", "192.168.0.0/16"]
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 10  # Strict rate limiting

global_rules:
  - id: "security-headers"
    plugins:
      proxy-rewrite:
        headers:
          add:
            - name: "X-Frame-Options"
              value: "DENY"
            - name: "X-Content-Type-Options"
              value: "nosniff"
            - name: "X-XSS-Protection"
              value: "1; mode=block"
            - name: "Strict-Transport-Security"
              value: "max-age=31536000; includeSubDomains"
  
  - id: "monitoring"
    plugins:
      prometheus: {}
      file-logger:
        log_format: '$remote_addr - [$time_local] "$request" $status $body_bytes_sent $request_time'
```

### Example 5: Canary Deployment with Traffic Split

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:8080
  
  prometheus:
    address: 0.0.0.0:9091

upstreams:
  - id: "production-v1"
    nodes:
      "prod-v1-1.example.com:8080": 1
      "prod-v1-2.example.com:8080": 1
    type: roundrobin
    pass_host: pass
    checks:
      active:
        type: http
        http_path: /health
        healthy:
          interval: 10
          successes: 2
        unhealthy:
          http_failures: 3
  
  - id: "canary-v2"
    nodes:
      "canary-v2-1.example.com:8080": 1
    type: roundrobin
    pass_host: node                    # Use node hostname as Host header
    checks:
      active:
        type: http
        http_path: /health
        healthy:
          interval: 10
          successes: 2
        unhealthy:
          http_failures: 3

routes:
  # Beta users get 100% canary traffic
  - id: "api-beta"
    uri: /api/{*path}
    host: api.example.com
    priority: 100
    upstream_id: "production-v1"
    plugins:
      traffic-split:
        rules:
          - vars:
              - ["http_x-user-type", "==", "beta"]
            weighted_upstreams:
              - upstream_id: "canary-v2"
                weight: 100              # 100% to canary for beta users
      
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 1000
  
  # General users get 90/10 split
  - id: "api-general"
    uri: /api/{*path}
    host: api.example.com
    upstream_id: "production-v1"
    plugins:
      traffic-split:
        rules:
          - vars: []                     # Match all requests
            weighted_upstreams:
              - upstream_id: "production-v1"
                weight: 90               # 90% to stable
              - upstream_id: "canary-v2"
                weight: 10               # 10% to canary
      
      request-id:
        header_name: X-Request-ID
        include_in_response: true
      
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 1000

global_rules:
  - id: "monitoring"
    plugins:
      prometheus:
        max_label_length: 100
        max_unique_paths: 1000
```

## Troubleshooting

### Common Issues

#### 1. Route Not Matching

**Problem**: Requests are not matching expected routes.

**Solutions**:
- Check route priority - higher priority routes are matched first
- Verify URI patterns - use `/path/{*subpath}` for catch-all matching or `/path/{id}` for named parameters
- Check host matching - ensure host headers match exactly
- Review method restrictions
- Remember that static routes have higher priority than dynamic routes

```yaml
# Debug route matching
routes:
  - id: "debug-route"
    uri: /debug/{*path}             # Catch-all for /debug/* requests
    priority: 1000  # High priority for debugging
    plugins:
      echo:
        body: "Route matched successfully"
```

#### 2. Upstream Connection Failures

**Problem**: 502 Bad Gateway or connection timeouts.

**Solutions**:
- Verify upstream server addresses and ports
- Check network connectivity from PingSIX to upstream
- Review timeout configurations
- Enable health checks to monitor upstream status

```yaml
# Debug upstream connectivity
upstreams:
  - id: "debug-upstream"
    nodes:
      "upstream-server:8080": 1
    timeout:
      connect: 10
      send: 30
      read: 30
    checks:
      active:
        type: http
        http_path: /health
        timeout: 5
```

#### 3. Plugin Configuration Errors

**Problem**: Plugins not working as expected.

**Solutions**:
- Validate plugin configuration syntax in `config.yaml`.
- Check plugin execution order (priority).
- Review plugin-specific requirements in this guide.
- Check PingSIX startup logs for plugin-related errors.

#### 4. SSL/TLS Issues

**Problem**: SSL handshake failures or certificate errors.

**Solutions**:
- Verify certificate and key file paths
- Check certificate validity and expiration
- Ensure SNI configuration matches certificate domains
- Validate certificate chain completeness

#### 5. Performance Issues

**Problem**: High latency or low throughput.

**Solutions**:
- Increase thread count in `pingora` configuration to match CPU cores.
- Optimize upstream connection pooling.
- Enable compression for large responses.
- Use caching for frequently accessed content.
- Monitor resource usage (CPU, memory, network).

### Debug Configuration

Enable detailed logging for troubleshooting:

```yaml
pingsix:
  log:
    path: /var/log/pingsix/debug.log
    rotation: internal       # internal (default), external, or disabled
    # external/disabled do not reopen after logrotate rename; use copytruncate
    # or restart Pingsix after rotation.
    max_size_bytes: 104857600
    max_backups: 5

global_rules:
  - id: "debug-logging"
    plugins:
      file-logger:
        log_format: 'DEBUG: $remote_addr $request_method $uri $status $request_time $error'
```

### Health Check Monitoring

Monitor upstream health status:

```yaml
upstreams:
  - id: "monitored-upstream"
    nodes:
      "server1:8080": 1
      "server2:8080": 1
    checks:
      active:
        type: http
        http_path: /health
        timeout: 5
        req_headers: ["X-Health-Check: PingSIX"]
        healthy:
          interval: 10
          http_statuses: [200]
          successes: 2
        unhealthy:
          interval: 5
          http_failures: 3
          tcp_failures: 2
```

### Performance Tuning

Optimize PingSIX performance:

```yaml
pingora:
  version: 1
  threads: 8              # Match CPU cores
  work_stealing: true     # Enable work stealing
  
pingsix:
  listeners:
    - address: 0.0.0.0:80
      tcp_fast_open: true  # Enable TCP Fast Open
      tcp_keepalive: 600   # TCP keepalive timeout
```

For additional support and advanced configuration options, refer to the [PingSIX Documentation](https://deepwiki.com/zhu327/pingsix) or open an issue on the GitHub repository.
