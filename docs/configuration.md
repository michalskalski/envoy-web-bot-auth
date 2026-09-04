# Configuration

Unknown module fields are rejected. Resolver options are validated during
startup. Run `web-bot-auth-resolver serve --help` for the complete command line
reference.

## Module configuration

Set module fields under `EnvoyExtensionPolicy.spec.dynamicModule[].config`, or
when configuring Envoy directly, under the Dynamic Module HTTP filter's
`filter_config.value`.

| Field | Default | Meaning |
|---|---|---|
| `mode` | `observe` | `observe`, `optional`, or `required` |
| `resolver.cluster` | `web-bot-auth-key-resolver` | Envoy cluster for the local resolver |
| `resolver.timeout_ms` | `2000` | Callout timeout, from 1 to 2000 ms |
| `max_signature_lifetime_seconds` | `86400` | Maximum accepted signature lifetime |
| `clock_skew_seconds` | `5` | Accepted future clock skew |
| `required_components` | `[]` | Extra components that every signature must cover |
| `accept_legacy_signature_agent` | `false` | Accept the older item form of `Signature-Agent` |
| `forward_identity_headers` | `true` | Send trusted status, identity, and key ID headers downstream |

By default, verification requires `@authority` or `@target-uri` and the
matching `Signature-Agent` member. `required_components` can contain only:

```text
@method @authority @scheme @target-uri @path @query
signature signature-input signature-agent
```

Set `forward_identity_headers: false` when later filters should read dynamic
metadata instead of request headers.

## Trusted outputs

The module removes these request headers before it parses a request. A caller
cannot set them for an upstream service:

| Header | When present | Meaning |
|---|---|---|
| `x-web-bot-auth-status` | When header forwarding is enabled | Verification outcome such as `verified`, `invalid`, or `unverified` |
| `x-web-bot-auth-identity` | Verified only | Normalized Web Bot Auth identifier |
| `x-web-bot-auth-keyid` | Verified only | Ed25519 JWK thumbprint used to verify the signature |

The module sets the status header for every outcome when
`forward_identity_headers` is true. It sets identity and key ID only for a
verified request. Upstreams can use those values for their own authorization or
rate policy. They must not treat an absent identity as a verified caller.

Envoy dynamic metadata is always available in the namespace
`envoy.filters.http.web_bot_auth`. It contains `status`, `reason`, and
`verified`. Verified requests also contain `identity` and `keyid`. Use metadata
when the trusted data should remain inside Envoy rather than travel as request
headers.

## Resolver configuration

The resolver starts with `serve`.

| Option | Default | Meaning |
|---|---|---|
| `--listen` | `tcp://127.0.0.1:8081` | TCP socket address or a Unix socket URI. Non loopback TCP exposes the unauthenticated API |
| `--egress-mode` | `direct` | `direct` or `proxy` |
| `--allowed-port` | `443` | Repeat to allow destination ports |
| `--allow-test-keys` | off | Permit known RFC test keys for development |
| `--resolution-timeout-ms` | `1800` | End to end resolver budget |
| `--inbound-body-bytes` | `8192` | Maximum resolver JSON request body |
| `--active-handlers` | `64` | Maximum concurrent handlers |
| `--outbound-fetches` | `32` | Maximum concurrent discovery fetches |
| `--state-entries` | `1024` | Maximum entries in each cache and control store |
| `--max-keys` | `32` | Maximum JWKs in one response |

The rate and burst options are `--global-fetch-rate`,
`--global-fetch-burst`, `--origin-fetch-rate`, `--origin-fetch-burst`,
`--ip-fetch-rate`, and `--ip-fetch-burst`. Burst values must be at least
their matching rate. `--new-origins-per-minute` defaults to `256`.

## Egress

Direct mode rejects proxy environment variables. It resolves and validates DNS
answers, then pins the selected address.

Proxy mode requires uppercase `HTTPS_PROXY`. It rejects conflicting
`HTTP_PROXY`, `ALL_PROXY`, and lowercase proxy variables. It ignores
`NO_PROXY` and never falls back to direct egress. The proxy is responsible for
final destination enforcement.

The resolver accepts HTTPS discovery only. Port 443 is allowed by default.
Redirects and response content decoding are disabled.
